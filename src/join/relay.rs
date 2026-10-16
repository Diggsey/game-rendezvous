//! The joiner's side of the relays, on the worker thread: sealing its join request, repeating
//! it until the host answers, and opening the answer. The game thread sends the request's
//! contents and gets the host's answer back as plain data.

use std::time::Duration;

use nostr_sdk::prelude::{Event, Keys, PublicKey};
use tracing::debug;

use crate::handshake::{self, DecryptBudget, IceParams, Message, RefuseReason};
use crate::signal::{Inbox, Published, Sink, TaskContext};

/// How often the join request is repeated until the host answers: relays may lose an
/// ephemeral event.
const REQUEST_INTERVAL: Duration = Duration::from_secs(2);

/// From the game thread: the request to send, once this side's candidates are known.
pub(super) struct SendRequest(pub Message);

/// To the game thread.
pub(super) enum FromRelay {
    /// How the relays took the first copy of the request.
    Published(Published),
    /// The host accepted: its side of the checks.
    Accepted(IceParams),
    Refused(RefuseReason),
}

pub(super) struct Relay {
    pub ctx: TaskContext,
    pub keys: Keys,
    pub host: PublicKey,
    pub attempt: String,
    pub handshake_rate: u32,
    pub commands: Inbox<SendRequest>,
    pub replies: Inbox<Event>,
    pub notices: Sink<FromRelay>,
}

impl Relay {
    /// Runs until the host answers or the game drops its end.
    pub async fn run(mut self) {
        let Some(SendRequest(request)) = self.commands.recv().await else {
            return;
        };
        let Some(event) = handshake::seal(&self.keys, &self.host, &request) else {
            let _ = self.notices.send(FromRelay::Published(Published {
                accepted: 0,
                errors: vec!["could not sign the request".into()],
            }));
            return;
        };
        let (published_tx, mut published) = crate::signal::channel();
        self.ctx.publish_in_background(event, Some(published_tx));
        let mut budget = DecryptBudget::new(self.handshake_rate);
        let mut repeat = tokio::time::interval(REQUEST_INTERVAL);
        repeat.tick().await; // the first tick is immediate: the request has just gone out
        loop {
            tokio::select! {
                // The game dropped the join.
                None = self.commands.recv() => return,
                Some(p) = published.recv() => {
                    let _ = self.notices.send(FromRelay::Published(p));
                }
                // Sealed afresh: relays (and subscribers) drop an event they have already seen.
                _ = repeat.tick() => {
                    if let Some(event) = handshake::seal(&self.keys, &self.host, &request) {
                        self.ctx.publish_in_background(event, None);
                    }
                }
                Some(reply) = self.replies.recv() => {
                    if let Some(answer) = self.open(&mut budget, &reply) {
                        let _ = self.notices.send(answer);
                        return;
                    }
                }
            }
        }
    }

    /// The host's answer to this attempt in `reply`, if that is what it is.
    fn open(&self, budget: &mut DecryptBudget, reply: &Event) -> Option<FromRelay> {
        if reply.pubkey != self.host || !budget.take() {
            return None;
        }
        match handshake::open(&self.keys, reply) {
            Some(Message::Accept { attempt, ice }) if attempt == self.attempt => {
                Some(FromRelay::Accepted(ice))
            }
            Some(Message::Refuse { attempt, reason }) if attempt == self.attempt => {
                Some(FromRelay::Refused(reason))
            }
            _ => {
                debug!("ignoring a handshake message that is not for this attempt");
                None
            }
        }
    }
}
