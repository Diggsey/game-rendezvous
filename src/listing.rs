//! Game listings: what a host advertises on the relays, and what browsers see.
//!
//! A listing is an addressable Nostr event (kind 30078, "application data") signed with a key
//! the host makes up for that one game, so the key identifies the game and each refresh
//! replaces the last. It carries a NIP-40 expiration, so relays and browsers drop it soon after
//! the host stops refreshing it, and a closing host replaces it with a "closed" tombstone.
//!
//! A listing holds no addresses: those go only to a joiner, encrypted, in the handshake.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nostr_sdk::prelude::{
    Event, EventBuilder, FinalizeEvent, Keys, Kind, PublicKey, Tag, Timestamp,
};
use serde::{Deserialize, Serialize};

use crate::Config;
use crate::nat::NatSummary;

/// NIP-78: addressable "arbitrary custom app data".
pub(crate) const LISTING_KIND: Kind = Kind::Custom(30078);
/// Bumped when the listing or handshake format changes incompatibly; games of another
/// protocol are shown as incompatible.
pub(crate) const PROTOCOL: u32 = 1;

/// The most characters kept of a name a stranger sends: a game's or a player's.
pub(crate) const MAX_NAME: usize = 64;
/// The most characters kept of a game version from a listing or a join request.
pub(crate) const MAX_VERSION: usize = 64;
/// The most metadata entries kept from a listing, and the most characters of each key and
/// value.
const MAX_METADATA: (usize, usize, usize) = (32, 64, 256);

/// `text` from a stranger, made fit to show: without control characters (which could rewrite
/// a terminal or break a layout), and at most `max` characters long.
pub(crate) fn clean(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// What a host advertises about its game. `metadata` is the game's own (mode, map, ...).
///
/// The default is an unnamed, empty game that takes players:
///
/// ```
/// use game_rendezvous::Listing;
///
/// let mut listing = Listing { name: "Ann's game".into(), players: 1, max_players: 4, ..Listing::default() };
/// listing.metadata.insert("mode".into(), "capture the flag".into());
/// ```
///
/// Browsers show at most 64 characters of the name, and 32 metadata entries of at most 64
/// characters a key and 256 a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The game's name as players see it, e.g. the host's player name.
    pub name: String,
    /// Players in the game now.
    pub players: u32,
    /// Players the game takes at most.
    pub max_players: u32,
    /// Whether players can join now. A game whose match is under way (or that is full) can
    /// stay listed with this off: browsers show it as not joinable, and the host refuses
    /// joins until it is on again.
    pub joinable: bool,
    /// Free-form key-values for the game to show (mode, level, "in match", ...).
    pub metadata: BTreeMap<String, String>,
}

impl Default for Listing {
    fn default() -> Self {
        Listing {
            name: String::new(),
            players: 0,
            max_players: 0,
            joinable: true,
            metadata: BTreeMap::new(),
        }
    }
}

/// Identifies an advertised game: the public key its host signs with, made for that one game.
/// It displays as its first 12 hex digits, enough to tell games apart in a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GameId(pub(crate) PublicKey);

impl fmt::Display for GameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.to_hex();
        write!(f, "{}", &hex[..12])
    }
}

/// A game found on the relays.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GameInfo {
    /// Which game it is, whatever its name.
    pub id: GameId,
    /// The game's name as its host advertises it ([`Listing::name`]).
    pub name: String,
    /// The host's game version.
    pub version: String,
    /// Whether this build can join it; incompatible games are listed so that players know an
    /// update exists, but cannot be joined.
    pub compatible: bool,
    /// Players in the game ([`Listing::players`]).
    pub players: u32,
    /// Players the game takes at most ([`Listing::max_players`]).
    pub max_players: u32,
    /// Whether the host takes players now (see [`Listing::joinable`]).
    pub joinable: bool,
    /// The game's own key-values ([`Listing::metadata`]).
    pub metadata: BTreeMap<String, String>,
    /// When the host last refreshed the listing (the host's clock).
    pub updated: SystemTime,
    /// When the listing expires unless refreshed (the host's clock).
    pub expires: SystemTime,
    /// The host's router, as the host found it (`None` from older versions, or before the
    /// host knew). [`Browser::outlook`](crate::Browser::outlook) judges from it whether this
    /// player can probably connect.
    pub nat: Option<NatSummary>,
}

/// A listing's event content.
#[derive(Serialize, Deserialize)]
struct Content {
    /// The listing and handshake protocol ([`PROTOCOL`]).
    protocol: u32,
    /// [`Listing::name`].
    name: String,
    /// The host's game version.
    version: String,
    /// [`Listing::players`].
    players: u32,
    /// [`Listing::max_players`].
    max_players: u32,
    /// Listings from before this field are joinable.
    #[serde(default = "yes")]
    joinable: bool,
    /// [`Listing::metadata`].
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    /// A tombstone: the game has closed.
    #[serde(default)]
    closed: bool,
    /// The host's router, in [`NatSummary`]'s compact form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nat: Option<String>,
}

/// `true`, for serde's defaults.
fn yes() -> bool {
    true
}

/// The `d` tag value of a game's listings: relays filter on it.
pub(crate) fn listing_tag(game_id: &str) -> String {
    format!("game-rendezvous/{game_id}")
}

/// A listing event, signed by the game's `keys`, live for `config.listing_ttl`, with the
/// host's router summary `nat`.
///
/// Relays keep the newest copy by `created_at`, in whole seconds, and of two from the same
/// second the one with the lower id, so each copy must be dated after the last (`previous`).
pub(crate) fn listing_event(
    config: &Config,
    keys: &Keys,
    listing: &Listing,
    nat: Option<NatSummary>,
    closed: bool,
    previous: Option<Timestamp>,
) -> Option<Event> {
    let content = Content {
        protocol: PROTOCOL,
        name: listing.name.clone(),
        version: config.game_version.clone(),
        players: listing.players,
        max_players: listing.max_players,
        joinable: listing.joinable,
        metadata: listing.metadata.clone(),
        closed,
        nat: nat.map(|n| n.to_string()),
    };
    // A tombstone only has to outlive the browsers' copies of the listing it replaces.
    let ttl = config.listing_ttl.max(Duration::from_secs(5));
    let created = match previous {
        Some(p) => Timestamp::now().max(p + 1),
        None => Timestamp::now(),
    };
    let expires = created + ttl.as_secs();
    EventBuilder::new(
        LISTING_KIND,
        serde_json::to_string(&content).expect("a listing serialises"),
    )
    .tag(Tag::identifier(listing_tag(&config.game_id)))
    .tag(Tag::expiration(expires))
    .custom_created_at(created)
    .finalize(keys)
    .ok()
}

/// What a browser makes of a listing event.
pub(crate) enum Parsed {
    /// A game taking (or not taking) players.
    Open(GameInfo),
    /// A closed game's tombstone, until it expires.
    Closed {
        /// The game that closed.
        id: GameId,
        /// When the tombstone may be forgotten.
        expires: SystemTime,
    },
}

/// The largest listing content read, in bytes; real ones are a few hundred.
const MAX_CONTENT: usize = 4096;
/// The longest a listing is believed to live, whatever its expiration says (unless this
/// game's own listings live longer): a stranger's listing must not stay in the lists for good.
const MAX_TTL: Duration = Duration::from_secs(3600);

/// Reads a listing event, judging its compatibility by `config`. `None` if it is malformed,
/// for another game, or expired.
pub(crate) fn parse_listing(config: &Config, event: &Event) -> Option<Parsed> {
    if event.kind != LISTING_KIND
        || event.content.len() > MAX_CONTENT
        || event.tags.identifier().as_deref() != Some(listing_tag(&config.game_id).as_str())
    {
        return None;
    }
    let max_ttl = MAX_TTL.max(config.listing_ttl).as_secs();
    let expires = event.tags.expiration()?.min(event.created_at + max_ttl);
    if expires <= Timestamp::now() {
        return None;
    }
    let expires = to_system_time(expires);
    let id = GameId(event.pubkey);
    let content: Content = serde_json::from_str(&event.content).ok()?;
    if content.closed {
        return Some(Parsed::Closed { id, expires });
    }
    let version = clean(&content.version, MAX_VERSION);
    let compatible = content.protocol == PROTOCOL && config.is_compatible(&version);
    let (entries, key_len, value_len) = MAX_METADATA;
    let metadata = content
        .metadata
        .iter()
        .take(entries)
        .map(|(k, v)| (clean(k, key_len), clean(v, value_len)))
        .collect();
    Some(Parsed::Open(GameInfo {
        id,
        name: clean(&content.name, MAX_NAME),
        version,
        compatible,
        players: content.players,
        max_players: content.max_players,
        joinable: content.joinable,
        metadata,
        updated: to_system_time(event.created_at),
        expires,
        nat: crate::nat::parse_summary(content.nat.as_deref()),
    }))
}

/// A Nostr timestamp as a `SystemTime`.
fn to_system_time(t: Timestamp) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::new("test-game", "1.0")
    }

    /// A listing event with `content`, as anyone could publish it.
    fn event(content: &serde_json::Value, expires_in: u64) -> Event {
        EventBuilder::new(LISTING_KIND, content.to_string())
            .tag(Tag::identifier(listing_tag("test-game")))
            .tag(Tag::expiration(Timestamp::now() + expires_in))
            .finalize(&Keys::generate())
            .unwrap()
    }

    fn open(parsed: Option<Parsed>) -> GameInfo {
        match parsed {
            Some(Parsed::Open(game)) => game,
            _ => panic!("expected an open game"),
        }
    }

    #[test]
    fn a_listing_round_trips() {
        let config = config();
        let mut listing = Listing {
            name: "Ann's game".into(),
            players: 2,
            max_players: 4,
            ..Listing::default()
        };
        listing.metadata.insert("mode".into(), "ctf".into());
        let keys = Keys::generate();
        let event = listing_event(
            &config,
            &keys,
            &listing,
            Some("eim;6".parse().unwrap()),
            false,
            None,
        )
        .unwrap();
        let game = open(parse_listing(&config, &event));
        assert_eq!(game.id, GameId(keys.public_key()));
        assert_eq!(
            (game.name.as_str(), game.version.as_str()),
            ("Ann's game", "1.0")
        );
        assert_eq!((game.players, game.max_players), (2, 4));
        assert!(game.compatible && game.joinable);
        assert_eq!(game.metadata, listing.metadata);
        assert_eq!(game.nat, Some("eim;6".parse().unwrap()));

        let closed =
            listing_event(&config, &keys, &listing, None, true, Some(event.created_at)).unwrap();
        assert!(closed.created_at > event.created_at);
        assert!(matches!(
            parse_listing(&config, &closed),
            Some(Parsed::Closed { id, .. }) if id == game.id
        ));
    }

    #[test]
    fn hostile_text_is_cut_short_and_cleaned() {
        let mut metadata: serde_json::Map<_, _> =
            (0..40).map(|i| (format!("k{i:02}"), "v".into())).collect();
        metadata.insert("a long one".into(), "v".repeat(300).into());
        let content = serde_json::json!({
            "protocol": PROTOCOL, "name": format!("Evil\u{1b}[2J{}", "x".repeat(100)),
            "version": "1.0", "players": 1, "max_players": 2, "metadata": metadata,
        });
        let game = open(parse_listing(&config(), &event(&content, 60)));
        assert_eq!(game.name.chars().count(), MAX_NAME);
        assert!(game.name.starts_with("Evil[2J"));
        let (entries, _, value_len) = MAX_METADATA;
        assert_eq!(game.metadata.len(), entries);
        assert_eq!(game.metadata["a long one"].len(), value_len);
    }

    #[test]
    fn a_listing_lives_an_hour_at_most() {
        let content = serde_json::json!({
            "protocol": PROTOCOL, "name": "Forever", "version": "1.0",
            "players": 1, "max_players": 2,
        });
        let game = open(parse_listing(
            &config(),
            &event(&content, 100 * 365 * 24 * 3600),
        ));
        let left = game.expires.duration_since(SystemTime::now()).unwrap();
        assert!(left <= MAX_TTL, "{left:?}");
    }

    #[test]
    fn malformed_listings_are_ignored() {
        let config = config();
        assert!(parse_listing(&config, &event(&serde_json::json!({ "name": "x" }), 60)).is_none());
        let huge = serde_json::json!({
            "protocol": PROTOCOL, "name": "Huge", "version": "1.0", "players": 1,
            "max_players": 2, "padding": "x".repeat(MAX_CONTENT),
        });
        assert!(parse_listing(&config, &event(&huge, 60)).is_none());
        let other_protocol = serde_json::json!({
            "protocol": PROTOCOL + 1, "name": "Future", "version": "1.0",
            "players": 1, "max_players": 2,
        });
        assert!(!open(parse_listing(&config, &event(&other_protocol, 60))).compatible);
        let other_game = EventBuilder::new(LISTING_KIND, other_protocol.to_string())
            .tag(Tag::identifier(listing_tag("another-game")))
            .tag(Tag::expiration(Timestamp::now() + 60))
            .finalize(&Keys::generate())
            .unwrap();
        assert!(parse_listing(&config, &other_game).is_none());
    }
}
