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
/// The most listings read per poll, so that a flood of them costs a frame little; the rest
/// wait for the next poll.
const MAX_EVENTS_PER_POLL: usize = 256;
/// The most games (and closed games' tombstones) kept. Anyone can publish listings for a game
/// id; past this, new ones are ignored until others expire.
const MAX_GAMES: usize = 500;

/// The games advertised online. Poll it every frame (or so) while the list is shown; drop it
/// to stop listening.
pub struct Browser {
    inner: Arc<Inner>,
    subscription: SubscriptionId,
    events: Inbox<Event>,
    games: Games,
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
            games: Games::default(),
        }
    }

    /// Takes in new listings and drops expired ones. Returns whether the list changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        for _ in 0..MAX_EVENTS_PER_POLL {
            let Ok(event) = self.events.try_recv() else {
                break;
            };
            if let Some(parsed) = parse_listing(&self.inner.config, &event) {
                changed |= self.games.apply(parsed, event.created_at);
            }
        }
        changed |= self.games.expire(SystemTime::now());
        if changed {
            self.games.sort();
        }
        changed
    }

    /// The games found: joinable ones first, then ones not taking players, then other versions.
    pub fn games(&self) -> &[GameInfo] {
        &self.games.sorted
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

/// A game's latest listing: open, or its tombstone.
struct Entry {
    /// `None` once the game has closed.
    game: Option<GameInfo>,
    /// When the listing was made, to tell a newer copy from an older one.
    created_at: Timestamp,
    expires: SystemTime,
}

/// The games heard of, by id.
#[derive(Default)]
struct Games {
    found: HashMap<GameId, Entry>,
    /// The open games, sorted for showing.
    sorted: Vec<GameInfo>,
}

impl Games {
    /// Takes in a listing made at `created_at`. Returns whether the open games changed.
    fn apply(&mut self, parsed: Parsed, created_at: Timestamp) -> bool {
        let (id, game, expires) = match parsed {
            Parsed::Open(game) => (game.id, Some(game.clone()), game.expires),
            Parsed::Closed { id, expires } => (id, None, expires),
        };
        // Relays may deliver an older copy after a newer one: one made before the game closed
        // must not bring it back.
        if let Some(entry) = self.found.get(&id)
            && created_at < entry.created_at
        {
            return false;
        }
        if !self.found.contains_key(&id) && self.found.len() >= MAX_GAMES {
            return false;
        }
        let open = game.is_some();
        let was_open = self
            .found
            .insert(
                id,
                Entry {
                    game,
                    created_at,
                    expires,
                },
            )
            .is_some_and(|e| e.game.is_some());
        open || was_open
    }

    /// Forgets the listings expired by `now`. Returns whether the open games changed.
    fn expire(&mut self, now: SystemTime) -> bool {
        let open = self.open_count();
        self.found.retain(|_, e| e.expires > now);
        self.open_count() != open
    }

    fn open_count(&self) -> usize {
        self.found.values().filter(|e| e.game.is_some()).count()
    }

    fn sort(&mut self) {
        self.sorted = self
            .found
            .values()
            .filter_map(|e| e.game.clone())
            .collect();
        // Joinable games first, then those of this version that are not taking players, then
        // other versions; by name within each, the id keeping the order stable.
        let key = |g: &GameInfo| (!g.compatible, !g.joinable, g.name.to_lowercase(), g.id);
        self.sorted.sort_by_cached_key(key);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nostr_sdk::prelude::Keys;

    use super::*;

    fn game(id: GameId, name: &str) -> GameInfo {
        GameInfo {
            id,
            name: name.into(),
            version: "1".into(),
            compatible: true,
            players: 1,
            max_players: 2,
            joinable: true,
            metadata: BTreeMap::new(),
            updated: SystemTime::now(),
            expires: SystemTime::now() + Duration::from_secs(60),
        }
    }

    fn names(games: &mut Games) -> Vec<String> {
        games.sort();
        games.sorted.iter().map(|g| g.name.clone()).collect()
    }

    #[test]
    fn a_closed_game_stays_closed_when_an_older_copy_comes_late() {
        let id = GameId(Keys::generate().public_key());
        let t = Timestamp::from(1_000_000);
        let mut games = Games::default();
        assert!(games.apply(Parsed::Open(game(id, "Ann's")), t));
        assert_eq!(names(&mut games), ["Ann's"]);
        let expires = SystemTime::now() + Duration::from_secs(60);
        assert!(games.apply(Parsed::Closed { id, expires }, t + 5));
        assert!(names(&mut games).is_empty());
        // Another relay still had the listing from before the game closed.
        assert!(!games.apply(Parsed::Open(game(id, "Ann's")), t));
        assert!(names(&mut games).is_empty());
    }

    #[test]
    fn newer_copies_replace_older_ones() {
        let id = GameId(Keys::generate().public_key());
        let t = Timestamp::from(1_000_000);
        let mut games = Games::default();
        games.apply(Parsed::Open(game(id, "Old name")), t);
        assert!(games.apply(Parsed::Open(game(id, "New name")), t + 1));
        assert!(!games.apply(Parsed::Open(game(id, "Old name")), t));
        assert_eq!(names(&mut games), ["New name"]);
    }

    #[test]
    fn games_expire_and_the_list_is_bounded() {
        let t = Timestamp::from(1_000_000);
        let mut games = Games::default();
        for i in 0..MAX_GAMES + 10 {
            let id = GameId(Keys::generate().public_key());
            games.apply(Parsed::Open(game(id, &format!("Game {i}"))), t);
        }
        assert_eq!(games.found.len(), MAX_GAMES);
        assert!(games.expire(SystemTime::now() + Duration::from_secs(120)));
        assert!(games.found.is_empty());
    }
}
