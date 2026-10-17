//! The joiner's side of the relays, on the worker thread: sealing its join request, repeating
//! it until the host answers, and opening the answer. The game thread sends the request's
//! contents and gets the host's answer back as plain data.

use std::time::Duration;

use nostr_sdk::prelude::{Event, Keys, PublicKey};
use tracing::debug;

use crate::handshake::{self, IceParams, Message, RateBudget, RefuseReason};
use crate::worker::{Inbox, Published, Sink, TaskContext};

/// How often the join request is repeated until the host answers: relays may lose an
/// ephemeral event.
const REQUEST_INTERVAL: Duration = Duration::from_secs(2);

/// From the game thread: the request to send, once this side's candidates are known.
pub(super) struct SendRequest(pub Message);

/// To the game thread.
pub(super) enum FromTask {
    /// How the relays took a copy of the request: each copy is reported until one is taken.
    Published(Published),
    /// The host accepted: its side of the checks.
    Accepted(IceParams),
    Refused(RefuseReason),
}

pub(super) struct JoinTask {
    pub ctx: TaskContext,
    pub keys: Keys,
    pub host: PublicKey,
    pub attempt: String,
    pub handshake_rate: u32,
    pub commands: Inbox<SendRequest>,
    pub replies: Inbox<Event>,
    pub notices: Sink<FromTask>,
}

impl JoinTask {
    /// Runs until the host answers or the game drops its end.
    pub async fn run(mut self) {
        let Some(SendRequest(request)) = self.commands.recv().await else {
            return;
        };
        let (published_tx, mut published) = crate::worker::channel();
        let sent = self
            .ctx
            .send_sealed(&self.keys, &self.host, &request, Some(published_tx.clone()));
        if !sent {
            let _ = self.notices.send(FromTask::Published(Published {
                accepted: 0,
                errors: vec!["could not sign the request".into()],
            }));
            return;
        }
        // Until a relay takes a copy, the game hears how each one went.
        let mut taken = false;
        let mut budget = RateBudget::new(self.handshake_rate, "handshake messages unread");
        let mut repeat = tokio::time::interval(REQUEST_INTERVAL);
        repeat.tick().await; // the first tick is immediate: the request has just gone out
        loop {
            tokio::select! {
                // The game dropped the join, or it finished.
                None = self.commands.recv() => return,
                Some(p) = published.recv() => {
                    if !taken {
                        taken = p.accepted > 0;
                        let _ = self.notices.send(FromTask::Published(p));
                    }
                }
                _ = repeat.tick() => {
                    let done = (!taken).then(|| published_tx.clone());
                    self.ctx.send_sealed(&self.keys, &self.host, &request, done);
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
    fn open(&self, budget: &mut RateBudget, reply: &Event) -> Option<FromTask> {
        if reply.pubkey != self.host || !budget.take() {
            return None;
        }
        match handshake::open(&self.keys, reply) {
            Some(Message::Accept { attempt, ice }) if attempt == self.attempt => {
                Some(FromTask::Accepted(ice))
            }
            Some(Message::Refuse { attempt, reason }) if attempt == self.attempt => {
                Some(FromTask::Refused(reason))
            }
            _ => {
                debug!("ignoring a handshake message that is not for this attempt");
                None
            }
        }
    }
}
