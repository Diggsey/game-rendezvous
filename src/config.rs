//! What a game tells the library: who it is, and which public services to use.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
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

/// A TURN server and a long-term credential for it (RFC 8656), as a TURN provider gives them.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TurnServer {
    /// The server, as `host:port` (UDP), e.g. `"relay.example.com:3478"`. A `turn:` prefix
    /// and a `?transport=udp` suffix, as in WebRTC's `iceServers`, are accepted.
    pub address: String,
    /// The username.
    pub username: String,
    /// The password.
    pub password: String,
}

impl TurnServer {
    /// A server at `address` with a username and password.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> TurnServer {
        TurnServer {
            address: address.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    /// The `host:port` to look up, without a `turn:` prefix or a query.
    pub(crate) fn host_port(&self) -> String {
        let a = self.address.trim();
        let a = a.strip_prefix("turn:").unwrap_or(a);
        let a = a.split('?').next().unwrap_or(a);
        let has_port = a.parse::<std::net::SocketAddr>().is_ok()
            || (a.matches(':').count() == 1
                && a.rsplit_once(':')
                    .is_some_and(|(_, p)| p.parse::<u16>().is_ok()));
        if has_port {
            a.to_string()
        } else if a.contains(':') && !a.starts_with('[') {
            // A bare IPv6 address.
            format!("[{a}]:3478")
        } else {
            format!("{a}:3478")
        }
    }
}

impl fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnServer")
            .field("address", &self.address)
            .field("username", &self.username)
            // The password stays out of logs.
            .finish_non_exhaustive()
    }
}

/// What a credential provider returns: a server and short-lived credentials, or why not.
pub type TurnCredentialFuture = Pin<Box<dyn Future<Output = Result<TurnServer, String>> + Send>>;

/// Makes short-lived TURN credentials, e.g. by calling a TURN provider's REST API. It runs on
/// the library's background thread (a Tokio runtime), when hosting starts and again whenever
/// the server stops taking the last credentials.
/// [`RelayProvider::config`](crate::RelayProvider::config) makes one for providers with an API.
pub type TurnCredentialFn = dyn Fn() -> TurnCredentialFuture + Send + Sync;

/// A host's TURN relay: lets players whose routers defeat hole punching connect through a
/// relay server, at the cost of a detour. Only the host needs one, and only the host's
/// credentials are used: joiners send to the relayed address like to any other.
#[derive(Clone)]
#[non_exhaustive]
pub enum TurnConfig {
    /// A fixed server and long-term credential.
    Static(TurnServer),
    /// Credentials made when needed (see [`TurnCredentialFn`]).
    Provider(Arc<TurnCredentialFn>),
}

impl TurnConfig {
    /// A fixed server and credential.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> TurnConfig {
        TurnConfig::Static(TurnServer::new(address, username, password))
    }

    /// Credentials from `provider`, e.g. a call to a TURN provider's REST API:
    ///
    /// ```
    /// use game_rendezvous::{TurnConfig, TurnServer};
    ///
    /// let turn = TurnConfig::provider(|| {
    ///     Box::pin(async {
    ///         // ... ask the provider for credentials ...
    ///         Ok(TurnServer::new("relay.example.com:3478", "1700000000:ann", "secret"))
    ///     })
    /// });
    /// ```
    #[must_use]
    pub fn provider(provider: impl Fn() -> TurnCredentialFuture + Send + Sync + 'static) -> Self {
        TurnConfig::Provider(Arc::new(provider))
    }
}

impl fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TurnConfig::Static(s) => f.debug_tuple("Static").field(s).finish(),
            TurnConfig::Provider(_) => f.write_str("Provider(..)"),
        }
    }
}

/// The library's configuration. [`Config::new`] gives the defaults for public play; change
/// fields after that for tests and special setups.
///
/// ```
/// use std::time::Duration;
/// use game_rendezvous::Config;
///
/// let mut config = Config::new("my-game", "1.2.0").with_compatibility(|ours, theirs| {
///     // Any 1.2.x plays with any other.
///     let minor = |v: &str| v.rsplit_once('.').map(|(minor, _)| minor.to_owned());
///     minor(ours) == minor(theirs)
/// });
/// config.port_mapping = false;
/// config.connect_timeout = Duration::from_secs(15);
/// assert!(config.is_compatible("1.2.7"));
/// ```
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
    /// TURN relays for hosting, for players who cannot connect otherwise; none by default. The
    /// first that works is used. See [`DEFAULT_RELAY_PROVIDERS`](crate::DEFAULT_RELAY_PROVIDERS)
    /// for providers a player can sign up with.
    pub turn: Vec<TurnConfig>,
    /// Whether a host asks its router to open its port (UPnP IGD, NAT-PMP, PCP). Without the
    /// `port-mapping` feature, a host only reports
    /// [`PortMapEvent::Failed`](crate::PortMapEvent::Failed).
    pub port_mapping: bool,
    /// The addresses to offer peers instead of this machine's own, e.g. `127.0.0.1` in tests.
    /// `None` uses every LAN and global IPv6 address of the machine.
    pub local_addresses: Option<Vec<IpAddr>>,
    /// Version compatibility, as `compatible(ours, theirs)`; exact equality by default (see
    /// [`with_compatibility`](Self::with_compatibility)).
    pub compatible: Arc<CompatibilityFn>,
    /// How long a listing lives on the relays without being refreshed. A host that vanishes
    /// without closing its listing disappears from the lists after this. Browsers believe at
    /// most an hour of a listing's life, or their own `listing_ttl` if longer.
    pub listing_ttl: Duration,
    /// How often a host republishes its listing (well within `listing_ttl`).
    pub listing_refresh: Duration,
    /// How long to wait for STUN servers.
    pub gather_timeout: Duration,
    /// How long a joiner waits for the host's answer to its join request.
    pub handshake_timeout: Duration,
    /// How long connectivity checks may take once both sides know each other's addresses.
    /// When one side's router hands out random ports and the other's does not, punching
    /// through it may take up to 10 seconds more after the first 4.
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
    #[must_use]
    pub fn new(game_id: impl Into<String>, game_version: impl Into<String>) -> Self {
        Config {
            game_id: game_id.into(),
            game_version: game_version.into(),
            relays: DEFAULT_RELAYS.iter().map(ToString::to_string).collect(),
            stun_servers: DEFAULT_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect(),
            turn: Vec::new(),
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
    #[must_use]
    pub fn with_relays<I: IntoIterator<Item = S>, S: Into<String>>(mut self, relays: I) -> Self {
        self.relays = relays.into_iter().map(Into::into).collect();
        self
    }

    /// Uses these STUN servers instead of the default ones.
    #[must_use]
    pub fn with_stun_servers<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        servers: I,
    ) -> Self {
        self.stun_servers = servers.into_iter().map(Into::into).collect();
        self
    }

    /// Hosts with this TURN relay too, tried after those already given.
    #[must_use]
    pub fn with_turn(mut self, turn: TurnConfig) -> Self {
        self.turn.push(turn);
        self
    }

    /// Decides version compatibility with `f(ours, theirs)` instead of exact equality. Both the
    /// joiner and the host apply their own rule; either can refuse.
    #[must_use]
    pub fn with_compatibility(
        mut self,
        f: impl Fn(&str, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.compatible = Arc::new(f);
        self
    }

    /// Whether a game of version `theirs` can play with this one.
    #[must_use]
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
            .field("turn", &self.turn)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_addresses_take_the_usual_forms() {
        let host_port = |a: &str| TurnServer::new(a, "u", "p").host_port();
        assert_eq!(
            host_port("relay.example.com:3478"),
            "relay.example.com:3478"
        );
        assert_eq!(
            host_port("turn:relay.example.com:80?transport=udp"),
            "relay.example.com:80"
        );
        assert_eq!(host_port(" relay.example.com "), "relay.example.com:3478");
        assert_eq!(host_port("[2001:db8::1]:3479"), "[2001:db8::1]:3479");
        assert_eq!(host_port("2001:db8::1"), "[2001:db8::1]:3478");
        assert!(!format!("{:?}", TurnServer::new("a:1", "u", "hunter2")).contains("hunter2"));
    }
}
