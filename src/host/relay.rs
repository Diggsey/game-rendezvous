//! The host's side of the relays, on the worker thread: everything that needs the host's keys.
//!
//! It publishes and refreshes the listing (and its tombstone at the end), reads join requests,
//! refuses the ones the host would refuse, answers repeats, and passes the game thread only the
//! requests it accepted, decrypted. Decrypting is capped per second ([`DecryptBudget`]), so a
//! flood of requests costs bounded work here and none on the game thread.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Event, Keys, PublicKey, Timestamp};
use tracing::{debug, info, warn};

use crate::Config;
use crate::handshake::{self, DecryptBudget, IceParams, Message, RefuseReason};
use crate::listing::{Listing, PROTOCOL, listing_event};
use crate::signal::{Inbox, Published, Sink, TaskContext};

/// Joiners being connected at once; more are told to wait.
pub(super) const MAX_JOINERS: usize = 16;
/// The quickest a changed listing is republished.
const PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// The quickest an accept is sent again to a joiner repeating its request.
const RESEND_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// From the game thread.
pub(super) enum ToRelay {
    /// The listing changed.
    SetListing(Listing),
    /// Accept a joiner the relay passed on, with the host's side of the checks.
    Accept {
        to: PublicKey,
        attempt: String,
        ice: IceParams,
    },
    /// The game is done with a joiner (connected, or failed): it no longer counts as joining.
    JoinerDone(PublicKey),
}

/// A join request the relay accepted.
pub(super) struct JoinRequest {
    pub from: PublicKey,
    pub attempt: String,
    pub player_name: String,
    pub ice: IceParams,
}

/// To the game thread.
pub(super) enum FromRelay {
    /// A request to connect: the game runs the checks and answers with [`ToRelay::Accept`].
    Request(JoinRequest),
    /// A player the relay refused (already answered).
    Refused { name: String, reason: RefuseReason },
}

/// A joiner between its request and the game being done with it. Each join attempt signs with
/// a key of its own, so the key identifies the attempt.
struct Active {
    /// The accept, once the game has made it: sent again if the joiner repeats its request.
    accept: Option<Message>,
    last_sent: Option<Instant>,
}

pub(super) struct Relay {
    pub ctx: TaskContext,
    pub config: Config,
    pub keys: Keys,
    pub listing: Listing,
    pub commands: Inbox<ToRelay>,
    pub requests: Inbox<Event>,
    pub notices: Sink<FromRelay>,
    pub published: Sink<Published>,
}

impl Relay {
    /// Runs until the game drops its end, then replaces the listing with a tombstone.
    pub async fn run(mut self) {
        let mut state = State {
            listing_changed: true,
            last_publish: None,
            last_created: None,
            active: HashMap::new(),
            budget: DecryptBudget::new(self.config.handshake_rate),
        };
        loop {
            let due = state.listing_due(&self.config);
            tokio::select! {
                command = self.commands.recv() => match command {
                    None => break,
                    Some(c) => self.command(&mut state, c),
                },
                Some(event) = self.requests.recv() => self.request(&mut state, &event),
                _ = tokio::time::sleep_until(due.into()) => self.publish_listing(&mut state),
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

    fn command(&mut self, state: &mut State, command: ToRelay) {
        match command {
            ToRelay::SetListing(l) => {
                self.listing = l;
                state.listing_changed = true;
            }
            ToRelay::Accept { to, attempt, ice } => {
                let Some(active) = state.active.get_mut(&to) else {
                    return;
                };
                let accept = Message::Accept { attempt, ice };
                if let Some(event) = handshake::seal(&self.keys, &to, &accept) {
                    self.ctx.publish_in_background(event, None);
                }
                active.accept = Some(accept);
                active.last_sent = Some(Instant::now());
            }
            ToRelay::JoinerDone(key) => {
                state.active.remove(&key);
            }
        }
    }

    fn publish_listing(&mut self, state: &mut State) {
        let previous = state.last_created;
        match listing_event(&self.config, &self.keys, &self.listing, false, previous) {
            Some(event) => {
                state.last_created = Some(event.created_at);
                state.last_publish = Some(Instant::now());
                state.listing_changed = false;
                self.ctx
                    .publish_in_background(event, Some(self.published.clone()));
            }
            None => {
                warn!("could not sign the listing");
                // Try again at the next refresh, not in a tight loop.
                state.last_publish = Some(Instant::now());
                state.listing_changed = false;
            }
        }
    }

    fn request(&mut self, state: &mut State, event: &Event) {
        let from = event.pubkey;
        // A joiner repeating its request (each attempt has its own key): answer again, unread.
        if let Some(active) = state.active.get_mut(&from) {
            let now = Instant::now();
            // Sealed afresh: relays (and subscribers) drop an event they have already seen.
            if let Some(accept) = &active.accept
                && active
                    .last_sent
                    .is_none_or(|t| now - t >= RESEND_MIN_INTERVAL)
                && let Some(event) = handshake::seal(&self.keys, &from, accept)
            {
                active.last_sent = Some(now);
                self.ctx.publish_in_background(event, None);
            }
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
            info!("refusing {player_name} (version {version}): {reason:?}");
            let refuse = Message::Refuse {
                attempt,
                reason: reason.clone(),
            };
            if let Some(e) = handshake::seal(&self.keys, &from, &refuse) {
                self.ctx.publish_in_background(e, None);
            }
            let _ = self.notices.send(FromRelay::Refused {
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
        let _ = self.notices.send(FromRelay::Request(JoinRequest {
            from,
            attempt,
            player_name,
            ice,
        }));
    }
}

struct State {
    listing_changed: bool,
    last_publish: Option<Instant>,
    /// The date of the last listing published: each copy must be dated after the last.
    last_created: Option<Timestamp>,
    active: HashMap<PublicKey, Active>,
    budget: DecryptBudget,
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
