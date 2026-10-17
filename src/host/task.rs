//! The host's side of the relays, on the worker thread: everything that needs the host's keys.
//!
//! It publishes and refreshes the listing (and its tombstone at the end), reads join requests,
//! refuses the ones the host would refuse, answers repeats, and passes the game thread only the
//! requests it accepted, decrypted. Decrypting is capped per second ([`RateBudget`]), so a
//! flood of requests costs bounded work here and none on the game thread.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Event, Keys, PublicKey, Timestamp};
use tracing::{debug, info, warn};

use crate::Config;
use crate::handshake::{self, IceParams, Message, RateBudget, RefuseReason};
use crate::listing::{Listing, MAX_NAME, MAX_VERSION, PROTOCOL, clean, listing_event};
use crate::worker::{Inbox, Published, Sink, TaskContext};

/// Joiners being connected at once; more are told to wait.
pub(super) const MAX_JOINERS: usize = 16;
/// The quickest a changed listing is republished.
const PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// The quickest an accept is sent again to a joiner repeating its request.
const RESEND_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// Refusals published per second at most. Anyone who reads the listing can send requests the
/// host refuses, and each refusal is an event for every relay: unlimited, they would get the
/// host rate-limited by the relays, its listing with it. A refused joiner repeats its request,
/// so one turned away unanswered is answered later.
const REFUSALS_PER_SECOND: u32 = 4;
/// How long a joiner the game is done with is remembered, and the oldest a request may be:
/// a late repeat, or a request a relay replays, must not start a join over again.
const FORGET_FINISHED: Duration = Duration::from_secs(600);

/// From the game thread.
pub(super) enum ToTask {
    /// The listing changed.
    SetListing(Listing),
    /// Accept a joiner the task passed on, with the host's side of the checks.
    Accept {
        /// The joiner's key.
        to: PublicKey,
        /// The joiner's attempt.
        attempt: String,
        /// The host's side of the checks.
        ice: IceParams,
    },
    /// The game is done with a joiner (connected, or failed): it no longer counts as joining.
    JoinerDone(PublicKey),
}

/// A join request the task accepted.
pub(super) struct JoinRequest {
    /// The joiner's key for this attempt.
    pub(super) from: PublicKey,
    /// The attempt, to answer.
    pub(super) attempt: String,
    /// The player's name, cleaned.
    pub(super) player_name: String,
    /// The joiner's side of the checks.
    pub(super) ice: IceParams,
}

/// To the game thread.
pub(super) enum FromTask {
    /// A request to connect: the game runs the checks and answers with [`ToTask::Accept`].
    Request(JoinRequest),
    /// A player the task refused (already answered).
    Refused {
        /// The player's name, cleaned.
        name: String,
        /// Why.
        reason: RefuseReason,
    },
}

/// A joiner between its request and the game being done with it. Each join attempt signs with
/// a key of its own, so the key identifies the attempt.
struct Active {
    /// The accept, once the game has made it: sent again if the joiner repeats its request.
    accept: Option<Message>,
    /// When the accept last went out.
    last_sent: Option<Instant>,
}

/// The host's task on the worker: see the module documentation.
pub(super) struct HostTask {
    /// The worker's relay client.
    pub(super) ctx: TaskContext,
    /// The game's configuration.
    pub(super) config: Config,
    /// The game's key, which signs the listing and the handshake.
    pub(super) keys: Keys,
    /// The listing as the game last set it.
    pub(super) listing: Listing,
    /// From the game thread; closed when the host is dropped.
    pub(super) commands: Inbox<ToTask>,
    /// Handshake events addressed to the host.
    pub(super) requests: Inbox<Event>,
    /// To the game thread.
    pub(super) notices: Sink<FromTask>,
    /// How the relays took each copy of the listing, to the game thread.
    pub(super) published: Sink<Published>,
}

impl HostTask {
    /// Runs until the game drops its end, then replaces the listing with a tombstone.
    pub(super) async fn run(mut self) {
        let mut state = State {
            listing_changed: true,
            last_publish: None,
            last_created: None,
            active: HashMap::new(),
            finished: HashMap::new(),
            budget: RateBudget::new(self.config.handshake_rate, "handshake messages unread"),
            refusals: RateBudget::new(REFUSALS_PER_SECOND, "refusals unsent"),
        };
        loop {
            let due = state.listing_due(&self.config);
            tokio::select! {
                command = self.commands.recv() => match command {
                    None => break,
                    Some(c) => self.command(&mut state, c),
                },
                Some(event) = self.requests.recv() => self.request(&mut state, &event),
                () = tokio::time::sleep_until(due.into()) => self.publish_listing(&mut state),
            }
        }
        // Browsers drop the game now rather than at the listing's expiry.
        if state.last_created.is_some()
            && let Some(e) = listing_event(
                &self.config,
                &self.keys,
                &self.listing,
                true,
                state.last_created,
            )
        {
            self.ctx.publish(&e).await;
        }
    }

    /// Carries out what the game thread asks.
    fn command(&mut self, state: &mut State, command: ToTask) {
        match command {
            ToTask::SetListing(l) => {
                self.listing = l;
                state.listing_changed = true;
            }
            ToTask::Accept { to, attempt, ice } => {
                let Some(active) = state.active.get_mut(&to) else {
                    return;
                };
                let accept = Message::Accept { attempt, ice };
                self.ctx.send_sealed(&self.keys, &to, &accept, None);
                active.accept = Some(accept);
                active.last_sent = Some(Instant::now());
            }
            ToTask::JoinerDone(key) => {
                state.active.remove(&key);
                let now = Instant::now();
                state.finished.retain(|_, t| now - *t < FORGET_FINISHED);
                state.finished.insert(key, now);
            }
        }
    }

    /// Publishes the listing as it stands.
    fn publish_listing(&mut self, state: &mut State) {
        let previous = state.last_created;
        // Whether or not it can be signed, it is next published at the refresh, not in a
        // tight loop.
        state.last_publish = Some(Instant::now());
        state.listing_changed = false;
        if let Some(event) = listing_event(&self.config, &self.keys, &self.listing, false, previous)
        {
            state.last_created = Some(event.created_at);
            self.ctx
                .publish_in_background(event, Some(self.published.clone()));
        } else {
            warn!("could not sign the listing");
        }
    }

    /// Reads a handshake event: a join request, or one repeated.
    fn request(&mut self, state: &mut State, event: &Event) {
        let from = event.pubkey;
        // A joiner repeating its request (each attempt has its own key): answer again, unread.
        if let Some(active) = state.active.get_mut(&from) {
            let now = Instant::now();
            if let Some(accept) = &active.accept
                && active
                    .last_sent
                    .is_none_or(|t| now - t >= RESEND_MIN_INTERVAL)
                && self.ctx.send_sealed(&self.keys, &from, accept, None)
            {
                active.last_sent = Some(now);
            }
            return;
        }
        if state.finished.contains_key(&from) {
            debug!("ignoring a request from a joiner already done with");
            return;
        }
        if event.created_at + FORGET_FINISHED.as_secs() < Timestamp::now() {
            debug!("ignoring a stale handshake message");
            return;
        }
        if !state.budget.take() {
            debug!("dropping a handshake message unread");
            return;
        }
        let Some(Message::Request {
            attempt,
            game_id,
            version,
            protocol,
            player_name,
            ice,
        }) = handshake::open(&self.keys, event)
        else {
            debug!("ignoring an unreadable handshake message");
            return;
        };
        if game_id != self.config.game_id {
            debug!("ignoring a join request for another game");
            return;
        }
        let player_name = clean(&player_name, MAX_NAME);
        let version = clean(&version, MAX_VERSION);
        let refusal = if protocol != PROTOCOL || !self.config.is_compatible(&version) {
            Some(RefuseReason::IncompatibleVersion {
                host_version: self.config.game_version.clone(),
            })
        } else if !self.listing.joinable {
            Some(RefuseReason::NotAccepting)
        } else if state.active.len() >= MAX_JOINERS {
            Some(RefuseReason::Busy)
        } else {
            None
        };
        if let Some(reason) = refusal {
            if !state.refusals.take() {
                return;
            }
            info!("refusing {player_name} (version {version}): {reason:?}");
            let refuse = Message::Refuse {
                attempt,
                reason: reason.clone(),
            };
            self.ctx.send_sealed(&self.keys, &from, &refuse, None);
            let _ = self.notices.send(FromTask::Refused {
                name: player_name,
                reason,
            });
            return;
        }
        state.active.insert(
            from,
            Active {
                accept: None,
                last_sent: None,
            },
        );
        let _ = self.notices.send(FromTask::Request(JoinRequest {
            from,
            attempt,
            player_name,
            ice,
        }));
    }
}

/// What the task keeps track of.
struct State {
    /// The listing changed since it was last published.
    listing_changed: bool,
    /// When the listing was last published.
    last_publish: Option<Instant>,
    /// The date of the last listing published: each copy must be dated after the last.
    last_created: Option<Timestamp>,
    /// Joiners between their request and the game being done with them.
    active: HashMap<PublicKey, Active>,
    /// Joiners the game is done with, and when.
    finished: HashMap<PublicKey, Instant>,
    /// Handshake messages decrypted a second.
    budget: RateBudget,
    /// Refusals published a second.
    refusals: RateBudget,
}

impl State {
    /// When the listing is next published: at once at first, soon after a change, and at the
    /// refresh interval otherwise.
    fn listing_due(&self, config: &Config) -> Instant {
        match self.last_publish {
            None => Instant::now(),
            Some(t) if self.listing_changed => t + PUBLISH_MIN_INTERVAL,
            Some(t) => t + config.listing_refresh,
        }
    }
}
