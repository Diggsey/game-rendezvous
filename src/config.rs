//! What a game tells the library: who it is, and which public services to use.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Public Nostr relays that accept events from anyone without an account or payment.
/// Listings and handshakes go to all of them at once, so that any one of them is enough.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://offchain.pub",
];

/// Public STUN servers. Asking several at once gives an answer even when one is down, and
/// tells a NAT that maps each destination to a different port from one that does not.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
];

/// Decides whether a game of version `theirs` can play with this game, of version `ours`.
pub type CompatibilityFn = dyn Fn(&str, &str) -> bool + Send + Sync;

/// The library's configuration. [`Config::new`] gives the defaults for public play; the fields
/// are public for tests and special setups.
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {
    /// Identifies the game among all games using this library, e.g. `"stick-suicide-2"`.
    /// Only games with the same id see each other.
    pub game_id: String,
    /// This build's version. Players see other versions' games but can only join compatible
    /// ones (see `compatible`).
    pub game_version: String,
    /// Nostr relay URLs (`wss://...`).
    pub relays: Vec<String>,
    /// STUN servers, as `host:port`.
    pub stun_servers: Vec<String>,
    /// Whether a host asks its router to open its port (UPnP IGD, NAT-PMP, PCP). Without the
    /// `port-mapping` feature, a host only reports [`PortMapEvent::Failed`](crate::PortMapEvent).
    pub port_mapping: bool,
    /// The addresses to offer peers instead of this machine's own, e.g. `127.0.0.1` in tests.
    /// `None` uses every LAN and global IPv6 address of the machine.
    pub local_addresses: Option<Vec<IpAddr>>,
    /// Version compatibility; exact equality by default.
    pub compatible: Arc<CompatibilityFn>,
    /// How long a listing lives on the relays without being refreshed. A host that vanishes
    /// without closing its listing disappears from the lists after this.
    pub listing_ttl: Duration,
    /// How often a host republishes its listing (well within `listing_ttl`).
    pub listing_refresh: Duration,
    /// How long to wait for STUN servers.
    pub gather_timeout: Duration,
    /// How long a joiner waits for the host's answer to its join request.
    pub handshake_timeout: Duration,
    /// How long connectivity checks may take once both sides know each other's addresses.
    pub connect_timeout: Duration,
    /// How many handshake messages a host (or joiner) decrypts per second, on the worker
    /// thread. Anyone can send a host handshake messages; beyond this many a second they are
    /// dropped unread, so a flood costs bounded work. Joiners repeat their requests, so a real
    /// one still gets through a flood that is not overwhelming.
    pub handshake_rate: u32,
}

impl Config {
    /// The configuration for a game: its id and version, with the default relays and STUN
    /// servers, port mapping on, and exact version matching.
    pub fn new(game_id: impl Into<String>, game_version: impl Into<String>) -> Self {
        Config {
            game_id: game_id.into(),
            game_version: game_version.into(),
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            port_mapping: true,
            local_addresses: None,
            compatible: Arc::new(|ours, theirs| ours == theirs),
            listing_ttl: Duration::from_secs(90),
            listing_refresh: Duration::from_secs(30),
            gather_timeout: Duration::from_millis(1500),
            handshake_timeout: Duration::from_secs(12),
            connect_timeout: Duration::from_secs(10),
            handshake_rate: 100,
        }
    }

    /// Uses these relays instead of the default ones.
    pub fn with_relays<I: IntoIterator<Item = S>, S: Into<String>>(mut self, relays: I) -> Self {
        self.relays = relays.into_iter().map(Into::into).collect();
        self
    }

    /// Uses these STUN servers instead of the default ones.
    pub fn with_stun_servers<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        servers: I,
    ) -> Self {
        self.stun_servers = servers.into_iter().map(Into::into).collect();
        self
    }

    /// Decides version compatibility with `f(ours, theirs)` instead of exact equality. Both the
    /// joiner and the host apply their own rule; either can refuse.
    pub fn with_compatibility(
        mut self,
        f: impl Fn(&str, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.compatible = Arc::new(f);
        self
    }

    /// Whether a game of version `theirs` can play with this one.
    pub fn is_compatible(&self, theirs: &str) -> bool {
        (self.compatible)(&self.game_version, theirs)
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("game_id", &self.game_id)
            .field("game_version", &self.game_version)
            .field("relays", &self.relays)
            .field("stun_servers", &self.stun_servers)
            .field("port_mapping", &self.port_mapping)
            .field("local_addresses", &self.local_addresses)
            .field("listing_ttl", &self.listing_ttl)
            .field("listing_refresh", &self.listing_refresh)
            .field("gather_timeout", &self.gather_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_rate", &self.handshake_rate)
            // `compatible` is a function.
            .finish_non_exhaustive()
    }
}
