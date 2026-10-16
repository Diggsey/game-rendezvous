//! Browsing: the games advertised on the relays for this game id, every version included.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nostr_sdk::prelude::{Event, Filter, SubscriptionId, Timestamp};

use crate::Inner;
use crate::listing::{GameId, GameInfo, LISTING_KIND, Parsed, listing_tag, parse_listing};
use crate::signal::{Command, Inbox};

/// How far back to ask relays for listings. Live ones are refreshed far more often; expired
/// ones are dropped anyway.
const LOOKBACK: Duration = Duration::from_secs(600);

/// The games advertised online. Poll it every frame (or so) while the list is shown; drop it
/// to stop listening.
pub struct Browser {
    inner: Arc<Inner>,
    subscription: SubscriptionId,
    events: Inbox<Event>,
    found: HashMap<GameId, (GameInfo, Timestamp)>,
    /// `found`, sorted for showing.
    sorted: Vec<GameInfo>,
}

impl Browser {
    pub(crate) fn new(inner: Arc<Inner>) -> Browser {
        let filter = Filter::new()
            .kind(LISTING_KIND)
            .identifier(listing_tag(&inner.config.game_id))
            .since(Timestamp::now() - LOOKBACK.as_secs())
            .limit(500);
        let (subscription, events) = inner.signal.subscribe(filter);
        Browser {
            inner,
            subscription,
            events,
            found: HashMap::new(),
            sorted: Vec::new(),
        }
    }

    /// Takes in new listings and drops expired ones. Returns whether the list changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(event) = self.events.try_recv() {
            match parse_listing(&self.inner.config, &event) {
                Some(Parsed::Open(game)) => {
                    // Relays may deliver an older copy after a newer one.
                    let newer = self
                        .found
                        .get(&game.id)
                        .is_none_or(|(_, at)| event.created_at >= *at);
                    if newer {
                        self.found.insert(game.id, (game, event.created_at));
                        changed = true;
                    }
                }
                Some(Parsed::Closed(id)) => changed |= self.found.remove(&id).is_some(),
                None => {}
            }
        }
        let now = SystemTime::now();
        let before = self.found.len();
        self.found.retain(|_, (g, _)| g.expires > now);
        changed |= self.found.len() != before;
        if changed {
            self.sort();
        }
        changed
    }

    fn sort(&mut self) {
        self.sorted = self.found.values().map(|(g, _)| g.clone()).collect();
        // Joinable games first, then those of this version that are not taking players, then
        // other versions; by name within each, the id keeping the order stable.
        let key = |g: &GameInfo| (!g.compatible, !g.joinable, g.name.to_lowercase(), g.id);
        self.sorted.sort_by_cached_key(key);
    }

    /// The games found: joinable ones first, then ones not taking players, then other versions.
    pub fn games(&self) -> &[GameInfo] {
        &self.sorted
    }

    /// How many relays are connected, of how many configured.
    pub fn relays(&self) -> (usize, usize) {
        self.inner.relays()
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.inner
            .signal
            .send(Command::Unsubscribe(self.subscription.clone()));
    }
}
