//! A host's TURN client (RFC 8656), sans-IO: an allocation on a relay server, kept alive, with
//! permissions for the joiners' addresses and channels for their traffic.
//!
//! It runs on the game thread over the game's own socket, as the ICE checks do: the owner
//! sends what [`TurnClient::poll_transmit`] returns to the server, feeds it the server's STUN
//! messages, and drives its timers. The relayed address becomes the host's lowest-priority ICE
//! candidate; joiners send to it like any other address and need no credentials. The host's
//! credentials never leave the host: they only sign its requests to the server.
//!
//! Hand-rolled rather than webrtc-rs's `turn` client, which owns its socket and reads it on an
//! async task: here the game owns the socket and reads it every frame, and TURN messages are
//! a handful of STUN requests.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::wire::{self, Builder, Class, Message, attr, method};

/// The allocation's lifetime asked for, in seconds.
const LIFETIME: u32 = 600;
/// Permissions last five minutes on the server; refreshed this often.
const PERMISSION_REFRESH: Duration = Duration::from_secs(120);
/// Channels last ten minutes on the server; refreshed this often.
const CHANNEL_REFRESH: Duration = Duration::from_secs(300);
/// The first retransmission timeout; it doubles each time, up to [`MAX_RTO`].
const RTO: Duration = Duration::from_millis(500);
/// The longest retransmission timeout. Shorter than RFC 8489's doubling, so a server that
/// does not answer is given up within ten seconds and the next relay tried.
const MAX_RTO: Duration = Duration::from_secs(2);
/// Transmissions of a request before it is given up.
const MAX_TRIES: u32 = 6;
/// The first channel number (RFC 8656: 0x4000 to 0x4FFF).
const FIRST_CHANNEL: u16 = 0x4000;
/// The last channel number.
const LAST_CHANNEL: u16 = 0x4FFF;
/// A cap on permissions and channels, whatever the joiners send.
const MAX_PEERS: usize = 256;

/// What the TURN client reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TurnEvent {
    /// The server gave this relayed address.
    Allocated {
        /// The relayed address: the candidate to offer joiners.
        relayed: SocketAddr,
        /// This socket's public address, as the server saw it.
        mapped: Option<SocketAddr>,
    },
    /// No allocation could be made, or it was lost; why.
    Failed(String),
}

/// What a request was for.
#[derive(Debug, Clone)]
enum Kind {
    /// Allocate.
    Allocate,
    /// Refresh (lifetime 0 to free the allocation).
    Refresh(u32),
    /// `CreatePermission` for an address.
    Permission(IpAddr),
    /// `ChannelBind` of a channel to a peer.
    Channel(SocketAddr, u16),
}

/// A request awaiting its answer.
struct Pending {
    /// What it was for.
    kind: Kind,
    /// When it next goes out again.
    resend_at: Instant,
    /// Transmissions so far.
    tries: u32,
    /// The request as sent.
    msg: Vec<u8>,
    /// It already carried credentials (a second 401 means they are wrong).
    authenticated: bool,
}

/// The allocation's state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// Not started.
    Idle,
    /// Asking.
    Allocating,
    /// Allocated, until `expires`.
    Allocated {
        /// The relayed address.
        relayed: SocketAddr,
        /// When to refresh.
        refresh_at: Instant,
    },
    /// Failed for good (bad credentials, refused); why.
    Failed(String),
    /// Freed.
    Closed,
}

/// A peer's channel.
struct Channel {
    /// Its number.
    number: u16,
    /// The server confirmed it.
    bound: bool,
    /// When to bind it again.
    refresh_at: Instant,
}

/// A TURN client: see the module documentation.
pub(crate) struct TurnClient {
    /// The server.
    server: SocketAddr,
    /// The long-term credential's username.
    username: String,
    /// Its password.
    password: String,
    /// The realm and nonce the server gave, once it has.
    realm: Option<(String, String)>,
    /// The key for MESSAGE-INTEGRITY, once the realm is known.
    key: Option<[u8; 16]>,
    /// The allocation.
    state: State,
    /// Requests awaiting answers.
    pending: HashMap<[u8; 12], Pending>,
    /// Addresses joiners send from, with when to refresh their permission.
    permissions: HashMap<IpAddr, Instant>,
    /// Channels, by peer.
    channels: HashMap<SocketAddr, Channel>,
    /// The next channel number to hand out.
    next_channel: u16,
    /// Messages for the server.
    outbox: VecDeque<Vec<u8>>,
    /// Events not yet taken.
    events: VecDeque<TurnEvent>,
}

/// A datagram the server relayed from a peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Relayed {
    /// The peer, as the server saw it.
    pub(crate) peer: SocketAddr,
    /// What it sent.
    pub(crate) data: Vec<u8>,
}

impl TurnClient {
    /// A client for `server` with a long-term credential; [`start`](Self::start) allocates.
    pub(crate) fn new(server: SocketAddr, username: String, password: String) -> TurnClient {
        TurnClient {
            server,
            username,
            password,
            realm: None,
            key: None,
            state: State::Idle,
            pending: HashMap::new(),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            next_channel: FIRST_CHANNEL,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// The server's address: datagrams from it are this client's.
    pub(crate) fn server(&self) -> SocketAddr {
        self.server
    }

    /// The relayed address, while allocated.
    pub(crate) fn relayed(&self) -> Option<SocketAddr> {
        match self.state {
            State::Allocated { relayed, .. } => Some(relayed),
            _ => None,
        }
    }

    /// Why the allocation failed, if it did.
    pub(crate) fn failure(&self) -> Option<&str> {
        match &self.state {
            State::Failed(why) => Some(why),
            _ => None,
        }
    }

    /// Asks for an allocation.
    pub(crate) fn start(&mut self, now: Instant) {
        if self.state == State::Idle {
            self.state = State::Allocating;
            self.request(now, Kind::Allocate);
        }
    }

    /// Frees the allocation (fire and forget).
    pub(crate) fn close(&mut self, now: Instant) {
        if self.relayed().is_some() {
            self.request(now, Kind::Refresh(0));
        }
        self.state = State::Closed;
    }

    /// The next message for the server.
    pub(crate) fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    /// The next event.
    pub(crate) fn poll_event(&mut self) -> Option<TurnEvent> {
        self.events.pop_front()
    }

    /// Lets `ip` send to the relayed address (kept until [`revoke`](Self::revoke)).
    pub(crate) fn permit(&mut self, now: Instant, ip: IpAddr) {
        let ip = crate::net::canonical(SocketAddr::new(ip, 0)).ip();
        if self.permissions.contains_key(&ip) || self.permissions.len() >= MAX_PEERS {
            return;
        }
        self.permissions.insert(ip, now + PERMISSION_REFRESH);
        if self.relayed().is_some() {
            self.request(now, Kind::Permission(ip));
        }
    }

    /// Stops refreshing `ip`'s permission and its channels: the server drops them soon.
    pub(crate) fn revoke(&mut self, ip: IpAddr) {
        self.permissions.remove(&ip);
        self.channels.retain(|peer, _| peer.ip() != ip);
    }

    /// Binds a channel to `peer`, for lighter framing of its traffic.
    pub(crate) fn bind(&mut self, now: Instant, peer: SocketAddr) {
        if self.channels.contains_key(&peer)
            || self.channels.len() >= MAX_PEERS
            || self.relayed().is_none()
        {
            return;
        }
        let number = self.next_channel;
        self.next_channel = if number >= LAST_CHANNEL {
            FIRST_CHANNEL
        } else {
            number + 1
        };
        self.channels.insert(
            peer,
            Channel {
                number,
                bound: false,
                refresh_at: now + CHANNEL_REFRESH,
            },
        );
        self.request(now, Kind::Channel(peer, number));
    }

    /// The peers with a bound channel, and the channels' numbers.
    pub(crate) fn bound_channels(&self) -> impl Iterator<Item = (SocketAddr, u16)> + '_ {
        self.channels
            .iter()
            .filter(|(_, c)| c.bound)
            .map(|(p, c)| (*p, c.number))
    }

    /// `data` for `peer`, framed for the server: `ChannelData` on a bound channel, else a Send
    /// indication. `None` while nothing is allocated.
    pub(crate) fn wrap(&self, peer: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        self.relayed()?;
        if let Some(c) = self.channels.get(&peer).filter(|c| c.bound) {
            return Some(wire::channel_data(c.number, data));
        }
        Some(
            Builder::new(method::SEND, Class::Indication, wire::transaction_id())
                .xor_addr(attr::XOR_PEER_ADDRESS, peer)
                .attr(attr::DATA, data)
                .finish(),
        )
    }

    /// Takes a datagram from the server: an answer, or relayed data (returned) in a Data
    /// indication or on a bound channel.
    pub(crate) fn handle(&mut self, now: Instant, data: &[u8]) -> Option<Relayed> {
        if let Some((number, payload)) = wire::parse_channel_data(data) {
            let (peer, _) = self
                .channels
                .iter()
                .find(|(_, c)| c.bound && c.number == number)?;
            return Some(Relayed {
                peer: *peer,
                data: payload.to_vec(),
            });
        }
        let msg = Message::parse(data)?;
        if msg.method == method::DATA && msg.class == Class::Indication {
            let peer = msg.xor_addr(attr::XOR_PEER_ADDRESS)?;
            let data = msg.get(attr::DATA)?.to_vec();
            return Some(Relayed {
                peer: crate::net::canonical(peer),
                data,
            });
        }
        let pending = self.pending.remove(&msg.tid)?;
        // Answers to authenticated requests must be signed with the same key.
        // (A 401 cannot be: the server could not check the credentials.)
        if pending.authenticated
            && msg.class == Class::Success
            && let Some(key) = self.key
            && !msg.verify(&key)
        {
            debug!("TURN: ignoring an answer with a bad signature");
            self.pending.insert(msg.tid, pending);
            return None;
        }
        match msg.class {
            Class::Success => self.succeeded(now, &pending.kind, &msg),
            Class::Error => self.failed(now, pending, &msg),
            _ => {}
        }
        None
    }

    /// Runs the timers: retransmissions and refreshes.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        let mut give_up = Vec::new();
        for (tid, p) in &mut self.pending {
            if now < p.resend_at {
                continue;
            }
            if p.tries >= MAX_TRIES {
                give_up.push(*tid);
                continue;
            }
            p.tries += 1;
            p.resend_at = now + (RTO * 2u32.pow(p.tries.min(6))).min(MAX_RTO);
            self.outbox.push_back(p.msg.clone());
        }
        for tid in give_up {
            if let Some(p) = self.pending.remove(&tid) {
                self.timed_out(&p.kind);
            }
        }
        let State::Allocated { refresh_at, .. } = self.state else {
            return;
        };
        if now >= refresh_at && !self.is_pending(|k| matches!(k, Kind::Refresh(_))) {
            self.request(now, Kind::Refresh(LIFETIME));
            if let State::Allocated { refresh_at, .. } = &mut self.state {
                *refresh_at = now + Duration::from_secs(u64::from(LIFETIME / 2));
            }
        }
        let due: Vec<IpAddr> = self
            .permissions
            .iter()
            .filter(|(_, t)| now >= **t)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in due {
            self.permissions.insert(ip, now + PERMISSION_REFRESH);
            self.request(now, Kind::Permission(ip));
        }
        let due: Vec<(SocketAddr, u16)> = self
            .channels
            .iter_mut()
            .filter(|(_, c)| now >= c.refresh_at)
            .map(|(p, c)| {
                c.refresh_at = now + CHANNEL_REFRESH;
                (*p, c.number)
            })
            .collect();
        for (peer, number) in due {
            self.request(now, Kind::Channel(peer, number));
        }
    }

    /// Whether a request of a kind matching `f` awaits its answer.
    fn is_pending(&self, f: impl Fn(&Kind) -> bool) -> bool {
        self.pending.values().any(|p| f(&p.kind))
    }

    /// Sends a request for `kind`, signed once the realm is known.
    fn request(&mut self, now: Instant, kind: Kind) {
        let tid = wire::transaction_id();
        let msg = self.build(tid, &kind);
        self.outbox.push_back(msg.clone());
        self.pending.insert(
            tid,
            Pending {
                kind,
                resend_at: now + RTO,
                tries: 1,
                msg,
                authenticated: self.key.is_some(),
            },
        );
    }

    /// The request for `kind`.
    fn build(&self, tid: [u8; 12], kind: &Kind) -> Vec<u8> {
        let b = match kind {
            Kind::Allocate => Builder::new(method::ALLOCATE, Class::Request, tid)
                // UDP (17), then three reserved bytes.
                .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
                .u32(attr::LIFETIME, LIFETIME),
            Kind::Refresh(lifetime) => {
                Builder::new(method::REFRESH, Class::Request, tid).u32(attr::LIFETIME, *lifetime)
            }
            Kind::Permission(ip) => Builder::new(method::CREATE_PERMISSION, Class::Request, tid)
                .xor_addr(attr::XOR_PEER_ADDRESS, SocketAddr::new(*ip, 0)),
            Kind::Channel(peer, number) => Builder::new(method::CHANNEL_BIND, Class::Request, tid)
                .attr(
                    attr::CHANNEL_NUMBER,
                    &[number.to_be_bytes(), [0, 0]].concat(),
                )
                .xor_addr(attr::XOR_PEER_ADDRESS, *peer),
        };
        let b = b.attr(attr::SOFTWARE, b"game_rendezvous");
        match (&self.realm, &self.key) {
            (Some((realm, nonce)), Some(key)) => b
                .attr(attr::USERNAME, self.username.as_bytes())
                .attr(attr::REALM, realm.as_bytes())
                .attr(attr::NONCE, nonce.as_bytes())
                .integrity(key)
                .fingerprint(),
            _ => b.fingerprint(),
        }
    }

    /// A request succeeded.
    fn succeeded(&mut self, now: Instant, kind: &Kind, msg: &Message<'_>) {
        match kind {
            Kind::Allocate => {
                let Some(relayed) = msg.xor_addr(attr::XOR_RELAYED_ADDRESS) else {
                    self.fail("the TURN server gave no relayed address".into());
                    return;
                };
                let relayed = crate::net::canonical(relayed);
                let lifetime = msg.u32(attr::LIFETIME).unwrap_or(LIFETIME).max(60);
                let mapped = msg
                    .xor_addr(attr::XOR_MAPPED_ADDRESS)
                    .map(crate::net::canonical);
                info!("TURN relay allocated at {relayed} (we are {mapped:?})");
                self.state = State::Allocated {
                    relayed,
                    refresh_at: now + Duration::from_secs(u64::from(lifetime / 2)),
                };
                self.events
                    .push_back(TurnEvent::Allocated { relayed, mapped });
                // Permissions asked for before the allocation.
                let ips: Vec<IpAddr> = self.permissions.keys().copied().collect();
                for ip in ips {
                    self.request(now, Kind::Permission(ip));
                }
            }
            Kind::Refresh(_) | Kind::Permission(_) => {}
            Kind::Channel(peer, number) => {
                if let Some(c) = self.channels.get_mut(peer)
                    && c.number == *number
                {
                    c.bound = true;
                }
            }
        }
    }

    /// A request failed: authenticate and try again, or give up.
    fn failed(&mut self, now: Instant, pending: Pending, msg: &Message<'_>) {
        let (code, reason) = msg.error_code().unwrap_or((0, ""));
        let realm = msg.text(attr::REALM);
        let nonce = msg.text(attr::NONCE);
        // 401: credentials needed (first time) or wrong. 438: the nonce went stale.
        let retry = match code {
            401 if !pending.authenticated => true,
            438 => true,
            _ => false,
        };
        if retry && let Some(nonce) = nonce {
            let realm = realm
                .map(str::to_owned)
                .or_else(|| self.realm.as_ref().map(|(r, _)| r.clone()))
                .unwrap_or_default();
            self.key = Some(wire::long_term_key(&self.username, &realm, &self.password));
            self.realm = Some((realm, nonce.to_owned()));
            self.request(now, pending.kind);
            return;
        }
        let why = match code {
            401 => "the TURN server refused the username or password".to_string(),
            _ => format!("the TURN server refused: {code} {reason}"),
        };
        match pending.kind {
            Kind::Allocate | Kind::Refresh(LIFETIME) => self.fail(why),
            Kind::Refresh(_) => {}
            Kind::Permission(ip) => warn!("TURN permission for {ip}: {why}"),
            Kind::Channel(peer, _) => {
                warn!("TURN channel for {peer}: {why}");
                self.channels.remove(&peer);
            }
        }
    }

    /// A request went unanswered.
    fn timed_out(&mut self, kind: &Kind) {
        match kind {
            Kind::Allocate | Kind::Refresh(LIFETIME) => {
                self.fail("the TURN server did not answer".into());
            }
            Kind::Channel(peer, _) => {
                self.channels.remove(peer);
            }
            Kind::Refresh(_) | Kind::Permission(_) => {}
        }
    }

    /// Gives the allocation up.
    fn fail(&mut self, why: String) {
        if self.state == State::Closed {
            return;
        }
        warn!("TURN: {why}");
        self.state = State::Failed(why.clone());
        self.pending.clear();
        self.channels.clear();
        self.events.push_back(TurnEvent::Failed(why));
    }
}

/// A minimal TURN server for tests: one realm, one user, UDP allocations on simulated
/// addresses. Sans-IO like the client.
#[cfg(test)]
pub(crate) mod server {
    use super::*;

    /// An allocation on the test server.
    struct Allocation {
        /// The relayed address.
        relayed: SocketAddr,
        /// Addresses allowed to send to it.
        permissions: Vec<IpAddr>,
        /// Channels, by number.
        channels: HashMap<u16, SocketAddr>,
    }

    /// A TURN server: see the module documentation.
    pub(crate) struct TestTurnServer {
        /// Its public address.
        pub(crate) addr: SocketAddr,
        /// The realm.
        realm: String,
        /// The key of the one user.
        key: [u8; 16],
        /// The user's name.
        user: String,
        /// Allocations, by client address.
        allocations: HashMap<SocketAddr, Allocation>,
        /// The next relayed port.
        next_port: u16,
    }

    /// What the server sends: (from, to, data).
    pub(crate) type Out = Vec<(SocketAddr, SocketAddr, Vec<u8>)>;

    impl TestTurnServer {
        /// A server at `addr` for one user.
        pub(crate) fn new(addr: SocketAddr, user: &str, password: &str) -> TestTurnServer {
            TestTurnServer {
                addr,
                realm: "test".into(),
                key: wire::long_term_key(user, "test", password),
                user: user.into(),
                allocations: HashMap::new(),
                next_port: 50_000,
            }
        }

        /// Whether `addr` is one of its relayed addresses.
        pub(crate) fn owns(&self, addr: SocketAddr) -> bool {
            addr == self.addr || self.allocations.values().any(|a| a.relayed == addr)
        }

        /// Takes a datagram from `from` to `to` (the server or a relayed address).
        pub(crate) fn receive(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) -> Out {
            if to == self.addr {
                self.on_client(from, data)
            } else {
                self.on_peer(from, to, data)
            }
        }

        /// A peer's datagram to a relayed address.
        fn on_peer(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) -> Out {
            let Some((client, a)) = self.allocations.iter().find(|(_, a)| a.relayed == to) else {
                return Vec::new();
            };
            if !a.permissions.contains(&from.ip()) {
                return Vec::new();
            }
            let framed = match a.channels.iter().find(|(_, p)| **p == from) {
                Some((n, _)) => wire::channel_data(*n, data),
                None => Builder::new(method::DATA, Class::Indication, wire::transaction_id())
                    .xor_addr(attr::XOR_PEER_ADDRESS, from)
                    .attr(attr::DATA, data)
                    .finish(),
            };
            vec![(self.addr, *client, framed)]
        }

        /// A client's message to the server.
        fn on_client(&mut self, from: SocketAddr, data: &[u8]) -> Out {
            if let Some((n, payload)) = wire::parse_channel_data(data) {
                let Some(a) = self.allocations.get(&from) else {
                    return Vec::new();
                };
                return match a.channels.get(&n) {
                    Some(peer) => vec![(a.relayed, *peer, payload.to_vec())],
                    None => Vec::new(),
                };
            }
            let Some(msg) = Message::parse(data) else {
                return Vec::new();
            };
            if msg.method == method::SEND && msg.class == Class::Indication {
                let (Some(a), Some(peer), Some(payload)) = (
                    self.allocations.get(&from),
                    msg.xor_addr(attr::XOR_PEER_ADDRESS),
                    msg.get(attr::DATA),
                ) else {
                    return Vec::new();
                };
                if !a.permissions.contains(&peer.ip()) {
                    return Vec::new();
                }
                return vec![(a.relayed, peer, payload.to_vec())];
            }
            if msg.class != Class::Request {
                return Vec::new();
            }
            let reply = |b: Builder| vec![(self.addr, from, b.integrity(&self.key).fingerprint())];
            if msg.text(attr::USERNAME) != Some(self.user.as_str()) || !msg.verify(&self.key) {
                let b = Builder::new(msg.method, Class::Error, msg.tid)
                    .attr(attr::ERROR_CODE, &[0, 0, 4, 1])
                    .attr(attr::REALM, self.realm.as_bytes())
                    .attr(attr::NONCE, b"nonce");
                return vec![(self.addr, from, b.finish())];
            }
            match msg.method {
                method::ALLOCATE => {
                    let relayed = SocketAddr::new(self.addr.ip(), self.next_port);
                    self.next_port += 1;
                    let relayed = self
                        .allocations
                        .entry(from)
                        .or_insert(Allocation {
                            relayed,
                            permissions: Vec::new(),
                            channels: HashMap::new(),
                        })
                        .relayed;
                    reply(
                        Builder::new(msg.method, Class::Success, msg.tid)
                            .xor_addr(attr::XOR_RELAYED_ADDRESS, relayed)
                            .xor_addr(attr::XOR_MAPPED_ADDRESS, from)
                            .u32(attr::LIFETIME, LIFETIME),
                    )
                }
                method::CREATE_PERMISSION | method::CHANNEL_BIND => {
                    let (Some(a), Some(peer)) = (
                        self.allocations.get_mut(&from),
                        msg.xor_addr(attr::XOR_PEER_ADDRESS),
                    ) else {
                        return Vec::new();
                    };
                    if !a.permissions.contains(&peer.ip()) {
                        a.permissions.push(peer.ip());
                    }
                    if msg.method == method::CHANNEL_BIND
                        && let Some(n) = msg.get(attr::CHANNEL_NUMBER)
                    {
                        a.channels.insert(u16::from_be_bytes([n[0], n[1]]), peer);
                    }
                    reply(Builder::new(msg.method, Class::Success, msg.tid))
                }
                method::REFRESH => reply(
                    Builder::new(msg.method, Class::Success, msg.tid).u32(attr::LIFETIME, LIFETIME),
                ),
                _ => Vec::new(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::server::TestTurnServer;
    use super::*;

    /// Runs `client` (at `me`) against `server` until nothing more goes out.
    fn exchange(
        client: &mut TurnClient,
        server: &mut TestTurnServer,
        me: SocketAddr,
        now: Instant,
    ) {
        while let Some(msg) = client.poll_transmit() {
            for (_, _, reply) in server.receive(me, server.addr, &msg) {
                client.handle(now, &reply);
            }
        }
    }

    #[test]
    fn allocates_with_a_long_term_credential_and_relays() {
        let me: SocketAddr = "203.0.113.1:7777".parse().unwrap();
        let peer: SocketAddr = "198.51.100.9:4000".parse().unwrap();
        let mut server = TestTurnServer::new("192.0.2.1:3478".parse().unwrap(), "ann", "pw");
        let mut client = TurnClient::new(server.addr, "ann".into(), "pw".into());
        let now = Instant::now();
        client.start(now);
        exchange(&mut client, &mut server, me, now);
        let relayed = client.relayed().expect("allocated");
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::Allocated { mapped: Some(m), .. }) if m == me)
        );

        // Nothing gets through before the permission.
        assert!(server.receive(peer, relayed, b"hi").is_empty());
        client.permit(now, peer.ip());
        exchange(&mut client, &mut server, me, now);
        let out = server.receive(peer, relayed, b"hi");
        let relayed_in = client.handle(now, &out[0].2).unwrap();
        assert_eq!(
            relayed_in,
            Relayed {
                peer,
                data: b"hi".to_vec()
            }
        );

        // A channel, and back.
        client.bind(now, peer);
        exchange(&mut client, &mut server, me, now);
        let out = server.receive(peer, relayed, b"again");
        assert!(wire::is_channel_data(&out[0].2));
        assert_eq!(client.handle(now, &out[0].2).unwrap().data, b"again");
        let back = client.wrap(peer, b"reply").unwrap();
        assert_eq!(
            server.receive(me, server.addr, &back),
            vec![(relayed, peer, b"reply".to_vec())]
        );
    }

    #[test]
    fn wrong_credentials_fail_once() {
        let me: SocketAddr = "203.0.113.1:7777".parse().unwrap();
        let mut server = TestTurnServer::new("192.0.2.1:3478".parse().unwrap(), "ann", "pw");
        let mut client = TurnClient::new(server.addr, "ann".into(), "wrong".into());
        let now = Instant::now();
        client.start(now);
        exchange(&mut client, &mut server, me, now);
        assert!(client.relayed().is_none());
        assert!(client.failure().unwrap().contains("username or password"));
    }

    #[test]
    fn unanswered_requests_are_retried_then_given_up() {
        let mut client = TurnClient::new("192.0.2.1:3478".parse().unwrap(), "a".into(), "b".into());
        let mut now = Instant::now();
        client.start(now);
        let mut sent = 0;
        while client.failure().is_none() {
            while client.poll_transmit().is_some() {
                sent += 1;
            }
            now += Duration::from_millis(100);
            client.handle_timeout(now);
        }
        assert_eq!(sent, MAX_TRIES);
        assert_eq!(
            client.poll_event(),
            Some(TurnEvent::Failed("the TURN server did not answer".into()))
        );
    }
}
