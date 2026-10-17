//! The socket a host plays on, shared between the game and the library.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::net;
use crate::stun::is_stun;
use crate::wire::{self, Class, Message, attr, method};

/// The most library datagrams kept for the host between its polls.
const MAX_INBOX: usize = 512;
/// The most `ConnectionReset`s skipped in one read (Windows reports an ICMP "port unreachable"
/// for an earlier send this way, once per packet).
const MAX_RESETS: usize = 64;

/// The UDP socket a game plays on, shared with the library: the game sends and receives its
/// own datagrams through it, and a [`Host`](crate::Host) attached to it
/// ([`Rendezvous::host`](crate::Rendezvous::host)) gets the library's.
///
/// Cheap to clone (the clones share one socket) and `Send + Sync`. Without a host attached it
/// is a plain socket. With one, it also:
///
/// - keeps the library's datagrams (STUN: connectivity checks and the like) from the game;
/// - carries the traffic of players connected through the host's TURN relay, unwrapped: such
///   a player looks like any other, at the address the relay saw them at;
/// - carries the traffic of players reached by punching from one of the extra sockets the
///   library opens when the host's router is strict, from and to that socket.
///
/// So a host must send and receive everything through it ([`send_to`](Self::send_to),
/// [`recv_from`](Self::recv_from)), not through the socket it was made from.
///
/// ```no_run
/// use game_rendezvous::GameSocket;
///
/// let socket = GameSocket::bind(7777)?;
/// let mut buf = [0u8; 1500];
/// while let Ok((n, from)) = socket.recv_from(&mut buf) {
///     // The game's own datagram, from `from`.
///     socket.send_to(&buf[..n], from)?;
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone)]
pub struct GameSocket {
    /// The socket and the routes, shared.
    inner: Arc<Inner>,
}

impl std::fmt::Debug for GameSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GameSocket")
            .field("local_addr", &self.inner.socket.local_addr().ok())
            .finish_non_exhaustive()
    }
}

/// What the clones share.
struct Inner {
    /// The game's socket.
    socket: UdpSocket,
    /// Where datagrams go.
    routes: Mutex<Routes>,
}

/// How a library datagram arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// On the game's socket, straight from `from`.
    Direct,
    /// Through the host's TURN relay, from `from`.
    Relayed,
}

/// A library datagram, kept for the host.
#[derive(Debug)]
pub(crate) struct Incoming {
    /// How it arrived.
    pub(crate) arrival: Arrival,
    /// From whom.
    pub(crate) from: SocketAddr,
    /// What.
    pub(crate) data: Vec<u8>,
}

/// A peer connected through the TURN relay.
#[derive(Debug, Default)]
struct RelayedPeer {
    /// Its channel, once bound.
    channel: Option<u16>,
    /// When it last sent something.
    last_heard: Option<Instant>,
}

/// A peer reached from an extra socket.
struct ExtraPeer {
    /// The socket.
    socket: UdpSocket,
    /// When it last sent something.
    last_heard: Option<Instant>,
}

/// Where datagrams go: what the host set up.
#[derive(Default)]
struct Routes {
    /// A host is attached.
    attached: bool,
    /// Library datagrams for the host.
    inbox: VecDeque<Incoming>,
    /// The TURN server, while the host has a relay.
    turn_server: Option<SocketAddr>,
    /// Peers connected through the relay, by address.
    relayed: HashMap<SocketAddr, RelayedPeer>,
    /// Peers reached from extra sockets, by address.
    extra: HashMap<SocketAddr, ExtraPeer>,
}

impl GameSocket {
    /// Binds a non-blocking dual-stack socket on `port` (0 for any), as
    /// [`bind_dual_stack`](crate::bind_dual_stack).
    ///
    /// # Errors
    ///
    /// If no socket can be bound, e.g. because `port` is taken.
    pub fn bind(port: u16) -> io::Result<GameSocket> {
        Ok(GameSocket::new(net::bind_dual_stack(port)?))
    }

    /// Wraps `socket`, which is made non-blocking.
    #[must_use]
    pub fn new(socket: UdpSocket) -> GameSocket {
        let _ = socket.set_nonblocking(true);
        GameSocket {
            inner: Arc::new(Inner {
                socket,
                routes: Mutex::new(Routes::default()),
            }),
        }
    }

    /// The socket's local address.
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    /// The underlying socket, for options (the game must not read it: see the type's
    /// documentation).
    #[must_use]
    pub fn socket(&self) -> &UdpSocket {
        &self.inner.socket
    }

    /// Sends `data` to `to`, however that player is reached: straight from the socket
    /// ([`send_to`](crate::send_to)), through the TURN relay, or from an extra socket.
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::send_to`].
    pub fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        let to = net::canonical(to);
        let routes = self.routes();
        if let Some(peer) = routes.extra.get(&to) {
            return net::send_to(&peer.socket, data, to);
        }
        if let (Some(server), Some(peer)) = (routes.turn_server, routes.relayed.get(&to)) {
            let framed = match peer.channel {
                Some(channel) => wire::channel_data(channel, data),
                None => send_indication(to, data),
            };
            drop(routes);
            net::send_to(&self.inner.socket, &framed, server)?;
            return Ok(data.len());
        }
        drop(routes);
        net::send_to(&self.inner.socket, data, to)
    }

    /// Receives the game's next datagram and its sender, [`canonical`](crate::canonical);
    /// `WouldBlock` once there is none. The library's datagrams are kept for the host.
    ///
    /// # Errors
    ///
    /// `WouldBlock` when nothing is waiting; otherwise as [`UdpSocket::recv_from`].
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut resets = 0;
        loop {
            let (n, from) = match self.inner.socket.recv_from(buf) {
                Ok((n, from)) => (n, net::canonical(from)),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset && resets < MAX_RESETS => {
                    resets += 1;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return self.recv_extra(buf),
                Err(e) => return Err(e),
            };
            if let Some(n) = self.sort(from, buf, n) {
                return Ok(n);
            }
        }
    }

    /// Reads the extra sockets.
    fn recv_extra(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut routes = self.routes();
        let now = Instant::now();
        for (peer, extra) in &mut routes.extra {
            loop {
                match extra.socket.recv_from(buf) {
                    Ok((n, from)) if net::canonical(from) == *peer => {
                        extra.last_heard = Some(now);
                        if !is_stun(&buf[..n]) {
                            return Ok((n, *peer));
                        }
                        // Keepalives and late checks: nothing for anyone.
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(_) => break,
                }
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    /// Sorts the datagram of `n` bytes in `buf` from `from`: the library's go to the host;
    /// the game's own (unwrapped, if relayed) stay in `buf`, and their size and sender are
    /// returned.
    fn sort(&self, from: SocketAddr, buf: &mut [u8], n: usize) -> Option<(usize, SocketAddr)> {
        let mut routes = self.routes();
        if !routes.attached {
            return Some((n, from));
        }
        let data = &buf[..n];
        if routes.turn_server == Some(from) {
            if let Some((channel, payload)) = wire::parse_channel_data(data) {
                let peer = routes
                    .relayed
                    .iter()
                    .find(|(_, p)| p.channel == Some(channel))
                    .map(|(a, _)| *a)?;
                let payload = payload.to_vec();
                return routes.relayed_in(peer, &payload, buf);
            }
            if let Some(msg) = Message::parse(data)
                && msg.method == method::DATA
                && msg.class == Class::Indication
                && let (Some(peer), Some(payload)) =
                    (msg.xor_addr(attr::XOR_PEER_ADDRESS), msg.get(attr::DATA))
            {
                let peer = net::canonical(peer);
                let payload = payload.to_vec();
                return routes.relayed_in(peer, &payload, buf);
            }
        }
        if is_stun(data) {
            routes.keep(Arrival::Direct, from, data.to_vec());
            return None;
        }
        Some((n, from))
    }

    /// Locks the routes (a poisoned lock is still usable: the routes stay consistent).
    fn routes(&self) -> MutexGuard<'_, Routes> {
        self.inner
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Attaches a host. Fails if one already is.
    pub(crate) fn attach(&self) -> io::Result<()> {
        let mut routes = self.routes();
        if routes.attached {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "a host is already attached to this socket",
            ));
        }
        routes.attached = true;
        Ok(())
    }

    /// Detaches the host, forgetting every route it set up.
    pub(crate) fn detach(&self) {
        *self.routes() = Routes::default();
    }

    /// The library datagrams received since the last call.
    pub(crate) fn take_incoming(&self) -> VecDeque<Incoming> {
        std::mem::take(&mut self.routes().inbox)
    }

    /// Sends a library datagram straight from the socket.
    pub(crate) fn send_direct(&self, data: &[u8], to: SocketAddr) {
        let _ = net::send_to(&self.inner.socket, data, to);
    }

    /// Sets the TURN server (`None` when the relay is gone, which forgets the relayed peers).
    pub(crate) fn set_turn_server(&self, server: Option<SocketAddr>) {
        let mut routes = self.routes();
        if routes.turn_server != server {
            routes.turn_server = server;
            routes.relayed.clear();
        }
    }

    /// Routes `peer`'s traffic through the relay.
    pub(crate) fn add_relayed(&self, peer: SocketAddr) {
        self.routes().relayed.entry(peer).or_default();
    }

    /// Sets the relayed peers' channels.
    pub(crate) fn set_channels(&self, channels: impl Iterator<Item = (SocketAddr, u16)>) {
        let mut routes = self.routes();
        for (peer, channel) in channels {
            if let Some(p) = routes.relayed.get_mut(&peer) {
                p.channel = Some(channel);
            }
        }
    }

    /// Routes `peer`'s traffic through `socket`, an extra one.
    pub(crate) fn add_extra(&self, peer: SocketAddr, socket: UdpSocket) {
        self.routes().extra.insert(
            peer,
            ExtraPeer {
                socket,
                last_heard: Some(Instant::now()),
            },
        );
    }

    /// Forgets the relayed and extra-socket peers not heard from since `since`; returns the
    /// relayed ones forgotten.
    pub(crate) fn forget_idle(&self, since: Instant) -> Vec<SocketAddr> {
        let mut routes = self.routes();
        routes
            .extra
            .retain(|_, p| p.last_heard.is_some_and(|t| t >= since));
        let idle: Vec<SocketAddr> = routes
            .relayed
            .iter()
            .filter(|(_, p)| p.last_heard.is_none_or(|t| t < since))
            .map(|(a, _)| *a)
            .collect();
        for a in &idle {
            routes.relayed.remove(a);
        }
        idle
    }

    /// Marks the relayed peers as heard now (when they connect, before their first datagram).
    pub(crate) fn touch_relayed(&self, peer: SocketAddr) {
        if let Some(p) = self.routes().relayed.get_mut(&peer) {
            p.last_heard = Some(Instant::now());
        }
    }
}

impl Routes {
    /// Keeps a library datagram for the host.
    fn keep(&mut self, arrival: Arrival, from: SocketAddr, data: Vec<u8>) {
        if self.inbox.len() < MAX_INBOX {
            self.inbox.push_back(Incoming {
                arrival,
                from,
                data,
            });
        }
    }

    /// A datagram the relay passed on from `peer`: the library's is kept, the game's copied
    /// into `buf`.
    fn relayed_in(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
        buf: &mut [u8],
    ) -> Option<(usize, SocketAddr)> {
        if is_stun(payload) {
            self.keep(Arrival::Relayed, peer, payload.to_vec());
            return None;
        }
        let p = self.relayed.get_mut(&peer)?;
        p.last_heard = Some(Instant::now());
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Some((n, peer))
    }
}

/// A TURN Send indication carrying `data` to `peer`.
fn send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    wire::Builder::new(method::SEND, Class::Indication, wire::transaction_id())
        .xor_addr(attr::XOR_PEER_ADDRESS, peer)
        .attr(attr::DATA, data)
        .finish()
}
