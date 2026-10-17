//! The joiner's side of the relays, on the worker thread: sealing its join request, repeating
//! it until the host answers, and opening the answer; then, if no path worked, telling the
//! host so. The game thread sends the messages' contents and gets the host's answer back as
//! plain data.

use std::time::Duration;

use nostr_sdk::prelude::{Event, Keys, PublicKey};
use tracing::debug;

use crate::handshake::{self, IceParams, Message, RateBudget, RefuseReason};
use crate::worker::{Inbox, Published, Sink, TaskContext};

/// How often the join request is repeated until the host answers: relays may lose an
/// ephemeral event.
const REQUEST_INTERVAL: Duration = Duration::from_secs(2);

/// From the game thread.
pub(super) enum ToTask {
    /// The request to send, once this side's candidates are known.
    Request(Message),
    /// No path worked: tell the host (once).
    Report(Message),
}

/// To the game thread.
pub(super) enum FromTask {
    /// How the relays took a copy of the request: each copy is reported until one is taken.
    Published(Published),
    /// The host accepted: its side of the checks.
    Accepted(IceParams),
    /// The host refused.
    Refused(RefuseReason),
}

/// The joiner's task on the worker: see the module documentation.
pub(super) struct JoinTask {
    /// The worker's relay client.
    pub(super) ctx: TaskContext,
    /// This attempt's key.
    pub(super) keys: Keys,
    /// The host's key.
    pub(super) host: PublicKey,
    /// This attempt, as the request names it.
    pub(super) attempt: String,
    /// Handshake messages decrypted a second at most.
    pub(super) handshake_rate: u32,
    /// From the game thread; closed when the join ends.
    pub(super) commands: Inbox<ToTask>,
    /// Handshake events from the host.
    pub(super) replies: Inbox<Event>,
    /// To the game thread.
    pub(super) notices: Sink<FromTask>,
}

impl JoinTask {
    /// Runs until the game drops its end.
    pub(super) async fn run(mut self) {
        let Some(ToTask::Request(request)) = self.commands.recv().await else {
            return;
        };
        let (published_tx, mut published) = crate::worker::channel();
        let sent =
            self.ctx
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
                command = self.commands.recv() => match command {
                    Some(ToTask::Report(m)) => {
                        self.ctx.send_sealed(&self.keys, &self.host, &m, None);
                    }
                    _ => return,
                },
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
                        break;
                    }
                }
            }
        }
        // Answered: the game may still have word for the host, until it lets go.
        while let Some(command) = self.commands.recv().await {
            if let ToTask::Report(m) = command {
                self.ctx.send_sealed(&self.keys, &self.host, &m, None);
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
