//! Internet game discovery and peer-to-peer UDP connections, without servers of your own.
//!
//! A game gives its id and version ([`Config`]); the library does the rest:
//!
//! - **Discovery.** A host advertises its game on several public Nostr relays at once
//!   ([`Rendezvous::host`]); players list every game with the same id, other versions
//!   included and flagged as incompatible ([`Rendezvous::browse`]). Listings expire unless
//!   refreshed, so games that vanish leave the lists within a minute or two, and hold no
//!   addresses.
//! - **Handshake.** A joiner and the host swap their address candidates through the relays,
//!   encrypted to each other (NIP-44), in ephemeral events.
//! - **Connection.** Candidates come from the machine's LAN and IPv6 addresses, public STUN
//!   servers (asked from the game's own socket), and a port the host's router was asked to open
//!   (UPnP, NAT-PMP or PCP). Both sides then run ICE connectivity checks over the game's socket,
//!   punching through NATs, and the best working path wins ([`Rendezvous::join`]).
//!
//! The result is a plain non-blocking [`UdpSocket`] and the peer's address: the game keeps its
//! own protocol. Everything is poll-based and never blocks, for calling from a game loop; the
//! network work happens on one background thread.
//!
//! ```no_run
//! use game_rendezvous::{Config, HostEvent, Listing, Rendezvous, bind_dual_stack};
//!
//! let rv = Rendezvous::new(Config::new("my-game", "1.2.0")).unwrap();
//! // Host: advertise, and let the library see the datagrams that are not the game's.
//! let socket = bind_dual_stack(7777).unwrap();
//! let listing = Listing { name: "Ann's game".into(), max_players: 4, ..Default::default() };
//! let mut host = rv.host(&socket, listing).unwrap();
//! let mut buf = [0u8; 1500];
//! loop {
//!     while let Ok((n, from)) = socket.recv_from(&mut buf) {
//!         if host.handle_datagram(from, &buf[..n]) {
//!             continue;
//!         }
//!         // ... the game's own packet
//!     }
//!     while let Some(event) = host.poll() {
//!         if let HostEvent::PeerConnected { addr, name } = event {
//!             println!("{name} is in, from {addr}");
//!         }
//!     }
//!     # break;
//! }
//! ```
//!
//! A player's side:
//!
//! ```no_run
//! # let rv = game_rendezvous::Rendezvous::new(game_rendezvous::Config::new("my-game", "1.2.0")).unwrap();
//! let mut browser = rv.browse();
//! // Every frame:
//! browser.poll();
//! for game in browser.games() {
//!     let note = if game.compatible { String::new() } else { format!(" (version {})", game.version) };
//!     println!("{} {}/{}{note}", game.name, game.players, game.max_players);
//! }
//! // On a click:
//! # let game = browser.games()[0].clone();
//! let mut join = rv.join(&game, "Bob").expect("a compatible game");
//! // Every frame until it finishes:
//! match join.poll() {
//!     Some(Ok(connection)) => { /* talk to connection.peer on connection.socket */ }
//!     Some(Err(e)) => println!("Could not join: {e}"),
//!     None => { /* show join.stage() */ }
//! }
//! ```

mod browse;
mod config;
mod error;
mod handshake;
mod host;
mod ice;
mod join;
mod listing;
mod net;
mod portmap;
mod worker;
pub mod stun;

use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

pub use browse::Browser;
pub use config::{CompatibilityFn, Config, DEFAULT_RELAYS, DEFAULT_STUN_SERVERS};
pub use error::JoinError;
pub use handshake::RefuseReason;
pub use host::{Host, HostEvent, HostStatus};
pub use join::{Connection, Join, JoinStage};
pub use listing::{GameId, GameInfo, Listing};
pub use net::{bind_dual_stack, canonical, for_socket, send_to};
pub use portmap::{PortMapEvent, PortMapMethod};
pub use stun::is_stun;

use worker::Worker;

/// The handles live in game engines' shared state (a Bevy resource needs `Send + Sync`).
#[allow(dead_code)]
fn assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Rendezvous>();
    check::<Host>();
    check::<Browser>();
    check::<Join>();
}

/// How many of the configured relays are connected, from [`Rendezvous::relays`] and the
/// like.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RelayCount {
    /// Relays connected now.
    pub connected: usize,
    /// Relays configured ([`Config::relays`]).
    pub total: usize,
}

/// What hosts, browsers and joins share: the configuration and the background worker.
pub(crate) struct Inner {
    pub config: Config,
    pub worker: Worker,
}

impl Inner {
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
/// it are dropped, after closing any listing and port mapping (waiting up to a few seconds).
#[derive(Clone)]
pub struct Rendezvous {
    inner: Arc<Inner>,
}

impl Rendezvous {
    /// Starts the background worker and connects to the relays.
    pub fn new(config: Config) -> io::Result<Rendezvous> {
        let worker = Worker::start(config.relays.clone(), config.stun_servers.clone())?;
        Ok(Rendezvous {
            inner: Arc::new(Inner { config, worker }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// How many relays are connected, of how many configured.
    pub fn relays(&self) -> RelayCount {
        self.inner.relays()
    }

    /// Lists the games advertised for this game id.
    pub fn browse(&self) -> Browser {
        Browser::new(self.inner.clone())
    }

    /// Advertises a game played on `socket` (which the game keeps using; the host sends from a
    /// clone of it). The game must pass its datagrams to [`Host::handle_datagram`].
    ///
    /// A socket from [`bind_dual_stack`] also lets IPv6 players in.
    pub fn host(&self, socket: &UdpSocket, listing: Listing) -> io::Result<Host> {
        Host::new(self.inner.clone(), socket, listing)
    }

    /// Joins `game` on a new dual-stack socket. Fails at once if the game's version is not
    /// compatible.
    pub fn join(&self, game: &GameInfo, player_name: &str) -> Result<Join, JoinError> {
        let socket = bind_dual_stack(0)?;
        self.join_with_socket(game, player_name, socket)
    }

    /// Joins `game` from `socket`, which the [`Connection`] hands back once connected.
    pub fn join_with_socket(
        &self,
        game: &GameInfo,
        player_name: &str,
        socket: UdpSocket,
    ) -> Result<Join, JoinError> {
        Join::new(self.inner.clone(), game, player_name, socket)
    }
}
