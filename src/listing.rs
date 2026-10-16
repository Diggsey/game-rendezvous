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

/// NIP-78: addressable "arbitrary custom app data".
pub(crate) const LISTING_KIND: Kind = Kind::Custom(30078);
/// Bumped when the listing or handshake format changes incompatibly; games of another
/// protocol are shown as incompatible.
pub(crate) const PROTOCOL: u32 = 1;

/// What a host advertises about its game. `metadata` is the game's own (mode, map, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The game's name as players see it, e.g. the host's player name.
    pub name: String,
    pub players: u32,
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

/// Identifies an advertised game: the public key its host signs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GameId(pub(crate) PublicKey);

impl fmt::Display for GameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.to_hex();
        write!(f, "{}", &hex[..12])
    }
}

/// A game found on the relays.
#[derive(Clone, Debug, PartialEq)]
pub struct GameInfo {
    pub id: GameId,
    pub name: String,
    /// The host's game version.
    pub version: String,
    /// Whether this build can join it; incompatible games are listed so that players know an
    /// update exists, but cannot be joined.
    pub compatible: bool,
    pub players: u32,
    pub max_players: u32,
    /// Whether the host takes players now (see [`Listing::joinable`]).
    pub joinable: bool,
    pub metadata: BTreeMap<String, String>,
    /// When the host last refreshed the listing (the host's clock).
    pub updated: SystemTime,
    /// When the listing expires unless refreshed (the host's clock).
    pub expires: SystemTime,
}

/// A listing's event content.
#[derive(Serialize, Deserialize)]
struct Content {
    protocol: u32,
    name: String,
    version: String,
    players: u32,
    max_players: u32,
    /// Listings from before this field are joinable.
    #[serde(default = "yes")]
    joinable: bool,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    /// A tombstone: the game has closed.
    #[serde(default)]
    closed: bool,
}

fn yes() -> bool {
    true
}

/// The `d` tag value of a game's listings: relays filter on it.
pub(crate) fn listing_tag(game_id: &str) -> String {
    format!("game-rendezvous/{game_id}")
}

/// A listing event, signed by the game's `keys`, live for `config.listing_ttl`.
///
/// Relays keep the newest copy by `created_at`, in whole seconds, and of two from the same
/// second the one with the lower id, so each copy must be dated after the last (`previous`).
pub(crate) fn listing_event(
    config: &Config,
    keys: &Keys,
    listing: &Listing,
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
    Open(GameInfo),
    Closed(GameId),
}

/// Reads a listing event, judging its compatibility by `config`. `None` if it is malformed,
/// for another game, or expired.
pub(crate) fn parse_listing(config: &Config, event: &Event) -> Option<Parsed> {
    if event.kind != LISTING_KIND
        || event.tags.identifier().as_deref() != Some(listing_tag(&config.game_id).as_str())
    {
        return None;
    }
    let expires = event.tags.expiration()?;
    if expires <= Timestamp::now() {
        return None;
    }
    let id = GameId(event.pubkey);
    let content: Content = serde_json::from_str(&event.content).ok()?;
    if content.closed {
        return Some(Parsed::Closed(id));
    }
    let compatible = content.protocol == PROTOCOL && config.is_compatible(&content.version);
    Some(Parsed::Open(GameInfo {
        id,
        name: content.name,
        version: content.version,
        compatible,
        players: content.players,
        max_players: content.max_players,
        joinable: content.joinable,
        metadata: content.metadata,
        updated: to_system_time(event.created_at),
        expires: to_system_time(expires),
    }))
}

fn to_system_time(t: Timestamp) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.as_secs())
}
