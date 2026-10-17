//! Internet game discovery and peer-to-peer UDP connections, without servers of your own.
//!
//! A game gives its id and version ([`Config`]); the library does the rest:
//!
//! - **Discovery.** A host advertises its game on several public [Nostr] relays at once
//!   ([`Rendezvous::host`]). Players list every game with the same id, other versions included
//!   and flagged as incompatible ([`Rendezvous::browse`]). Listings expire unless refreshed, so
//!   games that vanish leave the lists within a minute or two. They hold no addresses.
//! - **Handshake.** A joiner and the host swap their address candidates through the relays,
//!   encrypted to each other ([NIP-44]), in ephemeral events that relays do not store.
//! - **Connection.** Candidates come from the machine's LAN and IPv6 addresses, public STUN
//!   servers (asked from the game's own socket), a port the host's router was asked to open
//!   (UPnP, NAT-PMP or PCP), ports predicted for routers that hand them out in sequence, and
//!   the host's TURN relay, if it has one. Both sides then run ICE connectivity checks over the
//!   game's socket, punching through NATs, and the best working path wins
//!   ([`Rendezvous::join`]). When one side's router hands out random ports and the other's
//!   does not, the strict side opens 256 more sockets and the other probes random ports until
//!   one pair meets (the birthday paradox makes that likely within seconds).
//!
//! The result is a plain non-blocking [`UdpSocket`] and the peer's address: the game keeps its
//! own protocol.
//!
//! # Hosting
//!
//! The host plays on a [`GameSocket`], which it shares with the library: the game sends and
//! receives through it, and it keeps the library's datagrams (STUN, which a game's own
//! packets must never look like: [`is_stun`]) for the host. Players connected through the
//! relay, or through one of the extra sockets, look like any other.
//!
//! ```no_run
//! use game_rendezvous::{Config, GameSocket, HostEvent, Listing, Rendezvous};
//!
//! let rv = Rendezvous::new(Config::new("my-game", "1.2.0"))?;
//! let socket = GameSocket::bind(7777)?;
//! let listing = Listing { name: "Ann's game".into(), max_players: 4, ..Default::default() };
//! let mut host = rv.host(&socket, listing)?;
//! let mut buf = [0u8; 65_536];
//! loop {
//!     // Every frame: the socket first...
//!     while let Ok((n, from)) = socket.recv_from(&mut buf) {
//!         // ... the game's own packet, from `from`
//!     }
//!     // ...then what happened.
//!     while let Some(event) = host.poll() {
//!         if let HostEvent::PeerConnected { addr, name, .. } = event {
//!             println!("{name} is in: their packets come from {addr}");
//!         }
//!     }
//!     # break;
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Whether players can reach a host, and relays
//!
//! Some routers defeat every way through: when both players' routers hand out a random port
//! for each destination, or a mobile carrier's NAT sits in front. A game can find out before
//! hosting ([`Rendezvous::check_nat`], whose [`NatReport::reachability`] says whether to
//! suggest a relay), while hosting ([`HostEvent::Network`], [`HostStatus::failed_joins`]),
//! and in the game list ([`Browser::outlook`]). Joiners who could not connect tell the host
//! ([`JoinFailure::Unreachable`]).
//!
//! A TURN relay ([`Config::turn`]) gets every player in, through a detour. Only the host needs
//! one; joiners need no account. [`DEFAULT_RELAY_PROVIDERS`] lists providers with a free tier,
//! each with where to sign up and what to enter, for a game's relay settings
//! ([`RelayProvider::config`] turns what the player entered into a [`TurnConfig`]). The library
//! never asks the player anything itself: the game decides when to suggest a relay.
//!
//! # Joining
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let rv = game_rendezvous::Rendezvous::new(game_rendezvous::Config::new("my-game", "1.2.0"))?;
//! let mut browser = rv.browse();
//! // Every frame while the list is shown:
//! browser.poll();
//! for game in browser.games() {
//!     let note = if game.compatible { String::new() } else { format!(" (version {})", game.version) };
//!     println!("{} {}/{}{note}", game.name, game.players, game.max_players);
//! }
//! // When the player picks one:
//! # let game = browser.games()[0].clone();
//! let mut join = rv.join(&game, "Bob")?;
//! // Every frame until it finishes:
//! match join.poll() {
//!     Some(Ok(connection)) => {
//!         // The host's game may have spoken already.
//!         for datagram in &connection.received { /* ... */ }
//!         // From now on: `connection.socket`, to and from `connection.peer`.
//!     }
//!     Some(Err(e)) => println!("Could not join: {e}"),
//!     None => println!("{:?}", join.stage()),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Threads, and shutting down
//!
//! [`Rendezvous`], [`Host`], [`Browser`] and [`Join`] are `Send + Sync`, and nothing they do
//! blocks: they are made to be polled from a game loop. Everything that talks to relays, or
//! needs a player's keys (signing and encrypting), runs on one background thread with its own
//! single-threaded tokio runtime, so a game needs no async runtime, and nothing a stranger sends
//! costs the game's frame time. Connectivity checks run on the game's thread, when it polls,
//! because they need the game's socket.
//!
//! The thread stops once the [`Rendezvous`] and everything made from it are dropped. Dropping a
//! [`Host`] closes its listing (browsers drop the game at once) and removes its port mapping;
//! dropping the last handle waits for that to get out, for a few seconds at most (up to 9 if
//! a port mapping was still being made).
//!
//! # Privacy and abuse
//!
//! Listings are public and carry no addresses. A host's addresses go only to players who ask to
//! join, encrypted to each of them; each game and each join attempt signs with a key of its own,
//! so nothing ties them to a player across games. Anyone can read a listing and ask to join, so
//! a host bounds what that costs it ([`Config::handshake_rate`], at most 16 joiners at once, and
//! few refusals a second), and browsers bound what listings cost them.
//!
//! # Features
//!
//! - `port-mapping` (on by default): asks the host's router to forward its port, with UPnP IGD,
//!   NAT-PMP or PCP. Without it, [`Config::port_mapping`] has no effect.
//! - `relay-api` (on by default): fetches TURN credentials from a relay provider's API
//!   ([`RelayCredentials::Api`]), over HTTPS. Without it, only a username and password work.
//!
//! # Testing without the public relays
//!
//! [`Config::with_relays`] and [`Config::with_stun_servers`] point a game at a private network,
//! such as the `test_network` example's relay and STUN server on localhost ([`stun::serve`]).
//!
//! [Nostr]: https://nostr.com
//! [NIP-44]: https://github.com/nostr-protocol/nips/blob/master/44.md

#![warn(
    missing_docs,
    unreachable_pub,
    clippy::pedantic,
    clippy::missing_docs_in_private_items
)]
#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs, rustdoc::bare_urls)]

mod browse;
mod check;
mod config;
mod error;
#[cfg(feature = "relay-api")]
mod fetch;
mod handshake;
mod host;
mod ice;
mod join;
mod listing;
mod nat;
mod net;
mod portmap;
mod providers;
mod punch;
#[cfg(test)]
mod sim;
mod socket;
pub mod stun;
mod survey;
mod traverse;
mod turn;
mod wire;
mod worker;

use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

pub use browse::Browser;
pub use check::NatCheck;
pub use config::{
    CompatibilityFn, Config, DEFAULT_RELAYS, DEFAULT_STUN_SERVERS, TurnConfig, TurnCredentialFn,
    TurnCredentialFuture, TurnServer,
};
pub use error::JoinError;
pub use handshake::RefuseReason;
pub use host::{Host, HostEvent, HostStatus, JoinFailure, PeerPath};
pub use join::{Connection, Join, JoinStage};
pub use listing::{GameId, GameInfo, Listing};
pub use nat::{NatMapping, NatReport, NatSummary, Outlook, PortAllocation, Reachability};
pub use net::{bind_dual_stack, canonical, for_socket, send_to};
pub use portmap::{PortMapEvent, PortMapMethod};
pub use providers::{
    CUSTOM_RELAY, CredentialApi, DEFAULT_RELAY_PROVIDERS, HttpMethod, RelayCredentials, RelayField,
    RelayProvider, relay_provider,
};
pub use socket::GameSocket;
pub use stun::is_stun;

use worker::Worker;

/// The handles live in game engines' shared state (a Bevy resource needs `Send + Sync`).
const _: () = {
    /// Compiles only for `Send + Sync` types.
    const fn check<T: Send + Sync>() {}
    check::<Rendezvous>();
    check::<Host>();
    check::<Browser>();
    check::<Join>();
    check::<GameSocket>();
    check::<NatCheck>();
};

/// How many of the configured relays are connected, from [`Rendezvous::relays`] and the
/// like.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RelayCount {
    /// Relays connected now.
    pub connected: usize,
    /// Relays configured ([`Config::relays`]).
    pub total: usize,
}

/// What hosts, browsers and joins share: the configuration and the background worker.
pub(crate) struct Inner {
    /// The game's configuration.
    pub(crate) config: Config,
    /// The background worker, which stops when the last `Inner` goes.
    pub(crate) worker: Worker,
}

impl Inner {
    /// How many of the configured relays are connected.
    fn relays(&self) -> RelayCount {
        RelayCount {
            connected: self.worker.relays_connected(),
            total: self.config.relays.len(),
        }
    }
}

/// The library's entry point: one per game, cheap to clone. It connects to the relays at once,
/// so make it when the multiplayer menu opens (or at start-up).
///
/// The background work stops once this and every [`Host`], [`Browser`] and [`Join`] made from
/// it are dropped, after closing any listing and port mapping (see the
/// [crate documentation](crate#threads-and-shutting-down)).
#[derive(Clone)]
pub struct Rendezvous {
    /// The configuration and worker, shared with what this makes.
    inner: Arc<Inner>,
}

impl Rendezvous {
    /// Starts the background worker, which connects to the relays.
    ///
    /// # Errors
    ///
    /// If the worker's thread or runtime cannot be started.
    pub fn new(config: Config) -> io::Result<Rendezvous> {
        let worker = Worker::start(config.relays.clone(), config.stun_servers.clone())?;
        Ok(Rendezvous {
            inner: Arc::new(Inner { config, worker }),
        })
    }

    /// The configuration it was made with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// How many relays are connected, of how many configured.
    #[must_use]
    pub fn relays(&self) -> RelayCount {
        self.inner.relays()
    }

    /// Lists the games advertised for this game id: poll the [`Browser`] while the list is
    /// shown.
    #[must_use]
    pub fn browse(&self) -> Browser {
        Browser::new(self.inner.clone())
    }

    /// Advertises a game played on `socket`. The game keeps sending and receiving through it
    /// (see [`GameSocket`]); the host takes the library's datagrams from it.
    ///
    /// A dual-stack socket ([`GameSocket::bind`]) also lets IPv6 players in.
    ///
    /// # Errors
    ///
    /// If the socket has no local address, or another host is attached to it.
    pub fn host(&self, socket: &GameSocket, listing: Listing) -> io::Result<Host> {
        Host::new(self.inner.clone(), socket, listing)
    }

    /// Checks this machine's network as a host would see it, on a socket of its own: whether
    /// players could probably reach a game hosted here, before hosting one (see
    /// [`NatReport::reachability`]). It also tests the configured TURN relay.
    ///
    /// # Errors
    ///
    /// If no socket can be bound.
    pub fn check_nat(&self) -> io::Result<NatCheck> {
        NatCheck::new(self.inner.clone())
    }

    /// Joins `game` on a new dual-stack socket.
    ///
    /// # Errors
    ///
    /// At once, without asking the host, if the listing says this build cannot play `game`
    /// ([`JoinError::IncompatibleVersion`]) or it is not taking players
    /// ([`JoinError::NotJoinable`]), or if no socket can be bound ([`JoinError::Io`]).
    pub fn join(&self, game: &GameInfo, player_name: &str) -> Result<Join, JoinError> {
        let socket = bind_dual_stack(0)?;
        self.join_with_socket(game, player_name, socket)
    }

    /// Joins `game` from `socket`, which is made non-blocking and handed back in the
    /// [`Connection`] once connected.
    ///
    /// # Errors
    ///
    /// As for [`join`](Self::join); [`JoinError::Io`] if the socket cannot be made
    /// non-blocking or has no local address.
    pub fn join_with_socket(
        &self,
        game: &GameInfo,
        player_name: &str,
        socket: UdpSocket,
    ) -> Result<Join, JoinError> {
        Join::new(self.inner.clone(), game, player_name, socket)
    }
}
