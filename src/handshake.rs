//! The join handshake: a joiner and a host swap ICE credentials and address candidates
//! through the relays, encrypted to each other (NIP-44), in ephemeral events that relays pass
//! on but do not store.
//!
//! The joiner signs with a key it makes up for the attempt, so the host learns nothing about it
//! but its game version and player name.

use std::time::{Duration, Instant};

use nostr_sdk::prelude::nip44;
use nostr_sdk::prelude::{Event, EventBuilder, FinalizeEvent, Keys, Kind, PublicKey, Tag};
use serde::{Deserialize, Serialize};

/// An ephemeral kind (20000-29999): relays forward it to subscribers and drop it.
pub(crate) const HANDSHAKE_KIND: Kind = Kind::Custom(21_059);

/// One side's ICE credentials and address candidates (SDP `candidate:` lines).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct IceParams {
    /// The ICE username fragment.
    pub(crate) ufrag: String,
    /// The ICE password.
    pub(crate) pwd: String,
    /// The candidates, as SDP `candidate:` lines.
    pub(crate) candidates: Vec<String>,
}

/// What the handshake's events carry, as JSON, encrypted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Message {
    /// Joiner to host. Repeated until answered: the relays may lose an ephemeral event.
    Request {
        /// Tells this attempt's answer from another's.
        attempt: String,
        /// The joiner's game id ([`Config::game_id`](crate::Config::game_id)).
        game_id: String,
        /// The joiner's game version.
        version: String,
        /// The joiner's listing and handshake protocol (`listing::PROTOCOL`).
        protocol: u32,
        /// The player's name, for the host to show.
        player_name: String,
        /// The joiner's side of the checks.
        ice: IceParams,
    },
    /// Host to joiner: go ahead and check these addresses.
    Accept {
        /// The request's attempt.
        attempt: String,
        /// The host's side of the checks.
        ice: IceParams,
    },
    /// Host to joiner: not joinable.
    Refuse {
        /// The request's attempt.
        attempt: String,
        /// Why.
        reason: RefuseReason,
    },
}

/// Why a host refused a join request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RefuseReason {
    /// The host's version does not accept the joiner's.
    IncompatibleVersion {
        /// The host's version, for the player to see which they need.
        host_version: String,
    },
    /// The host is not taking players now (its listing is not joinable).
    NotAccepting,
    /// The host is handling too many join attempts at once.
    Busy,
}

/// The event carrying `message` from `keys` to `to`.
pub(crate) fn seal(keys: &Keys, to: &PublicKey, message: &Message) -> Option<Event> {
    let json = serde_json::to_string(message).ok()?;
    let content = nip44::encrypt(keys.secret_key(), to, json, nip44::Version::V2).ok()?;
    EventBuilder::new(HANDSHAKE_KIND, content)
        .tag(Tag::public_key(*to))
        .finalize(keys)
        .ok()
}

/// The message in `event`, if it is a handshake for `keys` (signatures were checked by the
/// relay client).
pub(crate) fn open(keys: &Keys, event: &Event) -> Option<Message> {
    if event.kind != HANDSHAKE_KIND {
        return None;
    }
    // A cap on what a stranger can make us decrypt.
    if event.content.len() > 16 * 1024 {
        return None;
    }
    let json = nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content).ok()?;
    serde_json::from_str(&json).ok()
}

/// Caps how often per second something a stranger can cause happens: decrypting a handshake
/// message, or publishing a refusal.
pub(crate) struct RateBudget {
    /// How many times a second it may happen.
    per_second: u32,
    /// What is dropped over budget, for the log, e.g. "handshake messages unread".
    what: &'static str,
    /// When the current one-second window began.
    window: Instant,
    /// Times it happened in the current window.
    used: u32,
    /// Times dropped in the current window, reported once it ends.
    dropped: u32,
}

impl RateBudget {
    /// A budget of `per_second`; `what` names what is dropped over it, for the log.
    pub(crate) fn new(per_second: u32, what: &'static str) -> Self {
        RateBudget {
            per_second,
            what,
            window: Instant::now(),
            used: 0,
            dropped: 0,
        }
    }

    /// Whether it may happen once more now.
    pub(crate) fn take(&mut self) -> bool {
        let now = Instant::now();
        if now - self.window >= Duration::from_secs(1) {
            if self.dropped > 0 {
                tracing::warn!(
                    "dropped {} {} (over {} a second)",
                    self.dropped,
                    self.what,
                    self.per_second
                );
            }
            self.window = now;
            self.used = 0;
            self.dropped = 0;
        }
        if self.used < self.per_second {
            self.used += 1;
            true
        } else {
            self.dropped += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_recipient_reads_a_message() {
        let host = Keys::generate();
        let joiner = Keys::generate();
        let snoop = Keys::generate();
        let msg = Message::Refuse {
            attempt: "a".into(),
            reason: RefuseReason::Busy,
        };
        let event = seal(&host, &joiner.public_key(), &msg).unwrap();
        assert_eq!(open(&joiner, &event), Some(msg));
        assert_eq!(open(&snoop, &event), None);
        assert!(event.verify().is_ok());
    }
}
