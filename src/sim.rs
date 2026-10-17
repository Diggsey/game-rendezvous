//! A simulated internet for tests: machines behind NATs of every kind, STUN servers and a TURN
//! server, on virtual time and seeded randomness, so every run is the same.
//!
//! The library's NAT work is sans-IO (the gatherer, the traversal, the TURN client), so tests
//! drive it here as the host and the joiner drive it over real sockets.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::turn::server::TestTurnServer;

/// How a simulated NAT picks public ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NatKind {
    /// One random public port per socket, for every destination.
    Independent,
    /// A mapping per destination that keeps the socket's port whenever that port and
    /// destination are not taken (as Linux's conntrack does).
    PortPreserving,
    /// A mapping per destination, on the last port given out plus a step.
    Sequential(i32),
    /// A mapping per destination, on a random port.
    Random,
}

/// A mapping in a NAT.
#[derive(Debug)]
struct Entry {
    /// The inside socket.
    internal: SocketAddr,
    /// The destination, for a per-destination mapping.
    dest: Option<SocketAddr>,
    /// The public port.
    port: u16,
    /// Who may send back through it: everyone it sent to (address- and port-dependent
    /// filtering, the strictest common kind).
    allowed: HashSet<SocketAddr>,
}

/// A simulated NAT.
pub(crate) struct Nat {
    /// Its public address.
    public: Ipv4Addr,
    /// The inside network and prefix length.
    inside: (Ipv4Addr, u8),
    /// How it maps.
    kind: NatKind,
    /// Its mappings.
    entries: Vec<Entry>,
    /// Sequential: the last port given out.
    last_port: u16,
    /// Picks random ports.
    rng: StdRng,
}

impl Nat {
    /// Whether `ip` is inside.
    fn is_inside(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(ip) = ip else { return false };
        let mask = u32::MAX << (32 - u32::from(self.inside.1));
        u32::from(ip) & mask == u32::from(self.inside.0) & mask
    }

    /// The public source for a datagram from `from` (inside) to `to`.
    fn outbound(&mut self, from: SocketAddr, to: SocketAddr) -> SocketAddr {
        let per_destination = self.kind != NatKind::Independent;
        let found = self
            .entries
            .iter()
            .position(|e| e.internal == from && (!per_destination || e.dest == Some(to)));
        let i = found.unwrap_or_else(|| {
            let port = self.allocate(from, to);
            self.entries.push(Entry {
                internal: from,
                dest: per_destination.then_some(to),
                port,
                allowed: HashSet::new(),
            });
            self.entries.len() - 1
        });
        self.entries[i].allowed.insert(to);
        SocketAddr::new(self.public.into(), self.entries[i].port)
    }

    /// A public port for a new mapping of `from` towards `to`.
    fn allocate(&mut self, from: SocketAddr, to: SocketAddr) -> u16 {
        loop {
            let port = match self.kind {
                NatKind::Independent | NatKind::Random => self.rng.random_range(1024..=u16::MAX),
                NatKind::PortPreserving => {
                    let taken = self.entries.iter().any(|e| {
                        e.port == from.port() && (e.dest == Some(to) || e.internal != from)
                    });
                    if taken {
                        self.rng.random_range(1024..=u16::MAX)
                    } else {
                        return from.port();
                    }
                }
                NatKind::Sequential(step) => {
                    let next = i32::from(self.last_port) + step;
                    let next = if (1024..=65535).contains(&next) {
                        next
                    } else {
                        1024
                    };
                    self.last_port = u16::try_from(next).unwrap();
                    self.last_port
                }
            };
            if !self.entries.iter().any(|e| e.port == port) {
                return port;
            }
        }
    }

    /// The inside socket a datagram from `from` to public `port` goes to, if any lets it.
    fn inbound(&self, from: SocketAddr, port: u16) -> Option<SocketAddr> {
        self.entries
            .iter()
            .find(|e| e.port == port && e.allowed.contains(&from))
            .map(|e| e.internal)
    }
}

/// A datagram in flight.
struct Packet {
    /// When it arrives.
    at: Instant,
    /// Its source, as the receiver sees it.
    from: SocketAddr,
    /// Its destination, before inbound translation.
    to: SocketAddr,
    /// What.
    data: Vec<u8>,
}

/// The simulated internet.
pub(crate) struct Net {
    /// Virtual time.
    pub(crate) now: Instant,
    /// The NATs; one may sit inside another (carrier-grade NAT).
    nats: Vec<Nat>,
    /// The machines' sockets, with what they received.
    sockets: Vec<(SocketAddr, Datagrams)>,
    /// STUN servers.
    pub(crate) stun: Vec<SocketAddr>,
    /// The TURN server, if any.
    pub(crate) turn: Option<TestTurnServer>,
    /// In flight.
    packets: Vec<Packet>,
    /// For the NATs' seeds.
    rng: StdRng,
    /// Datagrams sent, for checking traffic stays modest.
    pub(crate) sent: usize,
}

/// Datagrams and their senders.
type Datagrams = Vec<(SocketAddr, Vec<u8>)>;

/// One way's delay.
const LATENCY: Duration = Duration::from_millis(20);

impl Net {
    /// An internet with three STUN servers and a TURN server for `user`/`password`.
    pub(crate) fn new(seed: u64) -> Net {
        Net {
            now: Instant::now(),
            nats: Vec::new(),
            sockets: Vec::new(),
            stun: [
                "198.51.100.1:3478",
                "198.51.100.2:3478",
                "198.51.100.3:3478",
            ]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
            turn: Some(TestTurnServer::new(
                "198.51.100.10:3478".parse().unwrap(),
                "host",
                "secret",
            )),
            packets: Vec::new(),
            rng: StdRng::seed_from_u64(seed),
            sent: 0,
        }
    }

    /// Adds a NAT with public address `public` over `inside`.
    pub(crate) fn add_nat(&mut self, public: Ipv4Addr, inside: (Ipv4Addr, u8), kind: NatKind) {
        let seed = self.rng.random();
        self.nats.push(Nat {
            public,
            inside,
            kind,
            entries: Vec::new(),
            last_port: 30_000,
            rng: StdRng::seed_from_u64(seed),
        });
    }

    /// Adds a machine's socket.
    pub(crate) fn add_socket(&mut self, addr: SocketAddr) {
        self.sockets.push((addr, Vec::new()));
    }

    /// Sends `data` from the socket `from` to `to`.
    pub(crate) fn send(&mut self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) {
        self.sent += 1;
        let mut src = from;
        // Out through every NAT on the way (the home router, then the provider's).
        while let Some(n) = self
            .nats
            .iter_mut()
            .find(|n| n.is_inside(src.ip()) && IpAddr::V4(n.public) != src.ip())
        {
            src = n.outbound(src, to);
        }
        self.packets.push(Packet {
            at: self.now + LATENCY,
            from: src,
            to,
            data,
        });
    }

    /// Moves time on by `dt`, delivering what arrives.
    pub(crate) fn advance(&mut self, dt: Duration) {
        self.now += dt;
        let now = self.now;
        let (due, later): (Vec<Packet>, Vec<Packet>) = std::mem::take(&mut self.packets)
            .into_iter()
            .partition(|p| p.at <= now);
        self.packets = later;
        for p in due {
            self.deliver(p);
        }
    }

    /// Delivers `p`.
    fn deliver(&mut self, p: Packet) {
        if self.stun.contains(&p.to) {
            if let Some(reply) = crate::stun::respond(&p.data, p.from) {
                self.reply(p.to, p.from, reply);
            }
            return;
        }
        if let Some(turn) = &mut self.turn
            && turn.owns(p.to)
        {
            for (from, to, data) in turn.receive(p.from, p.to, &p.data) {
                self.reply(from, to, data);
            }
            return;
        }
        let mut to = p.to;
        // In through every NAT on the way.
        while let Some(n) = self.nats.iter().find(|n| IpAddr::V4(n.public) == to.ip()) {
            match n.inbound(p.from, to.port()) {
                Some(inside) => to = inside,
                None => return,
            }
        }
        if let Some((_, inbox)) = self.sockets.iter_mut().find(|(a, _)| *a == to) {
            inbox.push((p.from, p.data));
        }
    }

    /// A server's datagram (servers are not behind NATs).
    fn reply(&mut self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) {
        self.packets.push(Packet {
            at: self.now + LATENCY,
            from,
            to,
            data,
        });
    }

    /// What the socket `addr` received.
    pub(crate) fn recv(&mut self, addr: SocketAddr) -> Vec<(SocketAddr, Vec<u8>)> {
        self.sockets
            .iter_mut()
            .find(|(a, _)| *a == addr)
            .map(|(_, inbox)| std::mem::take(inbox))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::LocalCandidates;
    use crate::nat::{self, NatMapping, NatSummary, PortAllocation};
    use crate::net::LocalAddr;
    use crate::punch::MAIN;
    use crate::stun::Gatherer;
    use crate::traverse::{PREDICTION_WINDOW, Route, Traversal, Via};
    use crate::turn::TurnClient;

    /// The tick.
    const TICK: Duration = Duration::from_millis(10);

    /// A player in the simulation: a machine's socket, its extra sockets, its traversal.
    struct Player {
        /// The game's socket.
        addr: SocketAddr,
        /// Extra sockets, socket `i + 1`.
        extra: Vec<SocketAddr>,
        /// The machine's addresses.
        locals: Vec<LocalAddr>,
        /// What STUN servers saw.
        observed: Vec<SocketAddr>,
        /// The router, as classified.
        nat: Option<NatSummary>,
        /// The relay, for a host with one.
        turn: Option<TurnClient>,
        /// The connection attempt.
        traversal: Option<Traversal>,
    }

    impl Player {
        fn new(net: &mut Net, addr: SocketAddr) -> Player {
            net.add_socket(addr);
            Player {
                addr,
                extra: Vec::new(),
                locals: vec![LocalAddr {
                    ip: addr.ip(),
                    prefix: 24,
                    default: true,
                }],
                observed: Vec::new(),
                nat: None,
                turn: None,
                traversal: None,
            }
        }

        /// Asks the STUN servers and classifies the router, as a host or join does.
        fn gather(&mut self, net: &mut Net) {
            let mut g = Gatherer::new(net.stun.clone(), net.now, Duration::from_secs(2));
            while !g.is_done(net.now) {
                for (server, req) in g.poll_transmit(net.now) {
                    net.send(self.addr, server, req.to_vec());
                }
                net.advance(TICK);
                for (_, data) in net.recv(self.addr) {
                    g.handle(net.now, &data);
                }
            }
            self.observed = g.observed();
            let mapping = nat::classify(&self.observed, self.addr.port(), &self.locals);
            self.nat = Some(NatSummary {
                mapping,
                open: false,
                ipv6: false,
                carrier_grade: false,
            });
        }

        /// Allocates a relay on the simulated TURN server.
        fn allocate_relay(&mut self, net: &mut Net) {
            let server = net.turn.as_ref().unwrap().addr;
            let mut t = TurnClient::new(server, "host".into(), "secret".into());
            t.start(net.now);
            for _ in 0..50 {
                while let Some(m) = t.poll_transmit() {
                    net.send(self.addr, server, m);
                }
                net.advance(TICK);
                for (_, data) in net.recv(self.addr) {
                    t.handle(net.now, &data);
                }
            }
            assert!(t.relayed().is_some(), "relay allocated");
            self.turn = Some(t);
            if let Some(n) = &mut self.nat {
                n.open = true;
            }
        }

        fn candidates(&self) -> LocalCandidates {
            let predicted = self
                .nat
                .map(|n| {
                    nat::predicted_ports(
                        n.mapping,
                        &self.observed,
                        self.addr.port(),
                        PREDICTION_WINDOW,
                    )
                })
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| Some(SocketAddr::new(self.observed.first()?.ip(), p)))
                .collect();
            LocalCandidates {
                addrs: self.locals.clone(),
                port: self.addr.port(),
                reflexive: self.observed.clone(),
                predicted,
                relay: self.turn.as_ref().and_then(TurnClient::relayed),
            }
        }

        /// One tick of the player's work.
        fn step(&mut self, net: &mut Net) {
            let now = net.now;
            let t = self.traversal.as_mut().unwrap();
            for id in 0..=self.extra.len() {
                let addr = if id == MAIN {
                    self.addr
                } else {
                    self.extra[id - 1]
                };
                for (from, data) in net.recv(addr) {
                    if let Some(turn) = &mut self.turn
                        && from == turn.server()
                    {
                        if let Some(r) = turn.handle(now, &data) {
                            t.handle_relayed(now, r.peer, &r.data);
                        }
                        continue;
                    }
                    t.handle(now, id, from, &data);
                }
            }
            t.drive(now);
            if let Some(n) = t.wants_sockets() {
                let ip = self.addr.ip();
                self.extra = (0..n)
                    .map(|i| SocketAddr::new(ip, 20_000 + u16::try_from(i).unwrap()))
                    .collect();
                for a in &self.extra {
                    net.add_socket(*a);
                }
                t.sockets_opened(now, (1..=n).collect());
            }
            while let Some(out) = t.poll_transmit() {
                match out.via {
                    Via::Socket(id) => {
                        let from = if id == MAIN {
                            self.addr
                        } else {
                            self.extra[id - 1]
                        };
                        net.send(from, out.to, out.data);
                    }
                    Via::Relay => {
                        let turn = self.turn.as_mut().unwrap();
                        let framed = turn.wrap(out.to, &out.data).unwrap();
                        net.send(self.addr, turn.server(), framed);
                    }
                }
            }
            if let Some(turn) = &mut self.turn {
                turn.handle_timeout(now);
                while let Some(m) = turn.poll_transmit() {
                    net.send(self.addr, turn.server(), m);
                }
            }
        }
    }

    /// How a join went.
    #[derive(Debug)]
    struct Outcome {
        /// The joiner's path, if any.
        joiner: Option<Route>,
        /// The host's path, if any.
        host: Option<Route>,
        /// How long it took.
        took: Duration,
        /// Whether the joiner judged a relay needed.
        needs_relay: bool,
    }

    /// A host and a joiner behind NATs of the given kinds connect, as far as they can.
    /// `relay`: the host has a TURN relay.
    fn join(seed: u64, joiner_nat: NatKind, host_nat: NatKind, relay: bool) -> Outcome {
        let mut net = Net::new(seed);
        net.add_nat(
            [203, 0, 113, 1].into(),
            ([192, 168, 1, 0].into(), 24),
            host_nat,
        );
        net.add_nat(
            [203, 0, 113, 2].into(),
            ([192, 168, 2, 0].into(), 24),
            joiner_nat,
        );
        let mut host = Player::new(&mut net, "192.168.1.10:7777".parse().unwrap());
        let mut joiner = Player::new(&mut net, "192.168.2.20:40000".parse().unwrap());
        connect(&mut net, &mut host, &mut joiner, seed, relay)
    }

    fn connect(
        net: &mut Net,
        host: &mut Player,
        joiner: &mut Player,
        seed: u64,
        relay: bool,
    ) -> Outcome {
        if host.nat.is_none() {
            host.gather(net);
        }
        if relay {
            host.allocate_relay(net);
        }
        if joiner.nat.is_none() {
            joiner.gather(net);
        }
        let mut jt = Traversal::new(true, &joiner.candidates(), joiner.nat);
        jt.set_seed(seed);
        let mut ht = Traversal::new(false, &host.candidates(), host.nat);
        ht.set_seed(seed + 1);
        let (jp, hp) = (jt.params(), ht.params());
        // The handshake: the host answers at once, the joiner hears it a moment later.
        ht.set_remote(net.now, &jp);
        if let Some(turn) = &mut host.turn {
            for sdp in &jp.candidates {
                let c = is::Candidate::from_sdp_string(sdp).unwrap();
                turn.permit(net.now, c.addr().ip());
            }
        }
        host.traversal = Some(ht);
        joiner.traversal = Some(jt);
        let start = net.now;
        let timeout = Duration::from_secs(10);
        let mut answered = false;
        loop {
            if !answered && net.now - start >= Duration::from_millis(150) {
                joiner.traversal.as_mut().unwrap().set_remote(net.now, &hp);
                answered = true;
            }
            host.step(net);
            if answered {
                joiner.step(net);
            }
            net.advance(TICK);
            let jt = joiner.traversal.as_ref().unwrap();
            let done = jt.route().is_some() && host.traversal.as_ref().unwrap().route().is_some();
            let deadline = jt.deadline(timeout).is_some_and(|d| net.now > d);
            if done || deadline {
                // A moment more, as the join settles.
                for _ in 0..30 {
                    host.step(net);
                    joiner.step(net);
                    net.advance(TICK);
                }
                return Outcome {
                    joiner: joiner.traversal.as_ref().unwrap().route(),
                    host: host.traversal.as_ref().unwrap().route(),
                    took: net.now - start,
                    needs_relay: joiner.traversal.as_ref().unwrap().needs_relay(),
                };
            }
        }
    }

    /// The two sides agree on the path: each sends to where the other's traffic comes from.
    fn assert_connected(o: &Outcome, joiner_via: Via, host_via: Via) {
        let (j, h) = (
            o.joiner.expect("the joiner found a path"),
            o.host.expect("the host found a path"),
        );
        assert_eq!((j.via, h.via), (joiner_via, host_via), "{o:?}");
    }

    fn mapping(kind: NatKind, seed: u64) -> NatMapping {
        let mut net = Net::new(seed);
        net.add_nat([203, 0, 113, 1].into(), ([192, 168, 1, 0].into(), 24), kind);
        let mut p = Player::new(&mut net, "192.168.1.10:7777".parse().unwrap());
        p.gather(&mut net);
        p.nat.unwrap().mapping
    }

    #[test]
    fn routers_are_classified() {
        for seed in 0..5 {
            assert_eq!(
                mapping(NatKind::Independent, seed),
                NatMapping::EndpointIndependent
            );
            // Keeping the port for every destination behaves as one mapping.
            assert_eq!(
                mapping(NatKind::PortPreserving, seed),
                NatMapping::EndpointIndependent
            );
            assert_eq!(
                mapping(NatKind::Sequential(1), seed),
                NatMapping::EndpointDependent(PortAllocation::Sequential { step: 1 })
            );
            assert_eq!(
                mapping(NatKind::Sequential(2), seed),
                NatMapping::EndpointDependent(PortAllocation::Sequential { step: 2 })
            );
            assert_eq!(
                mapping(NatKind::Random, seed),
                NatMapping::EndpointDependent(PortAllocation::Random)
            );
        }
    }

    #[test]
    fn carrier_grade_nat_is_seen_through() {
        let mut net = Net::new(7);
        // The provider's NAT, and the home router inside it at 100.64.0.2.
        net.add_nat(
            [203, 0, 113, 50].into(),
            ([100, 64, 0, 0].into(), 10),
            NatKind::Independent,
        );
        net.add_nat(
            [100, 64, 0, 2].into(),
            ([192, 168, 1, 0].into(), 24),
            NatKind::Independent,
        );
        let mut p = Player::new(&mut net, "192.168.1.10:7777".parse().unwrap());
        p.gather(&mut net);
        assert_eq!(p.nat.unwrap().mapping, NatMapping::EndpointIndependent);
        assert!(
            p.observed
                .iter()
                .all(|a| a.ip() == IpAddr::from([203, 0, 113, 50]))
        );
        // The home router reports its own public address when it forwards a port.
        let router_says = Some(IpAddr::from([100, 64, 0, 2]));
        assert!(nat::carrier_grade(router_says, &p.observed, &p.locals));
        let mut report = crate::NatReport {
            mapping: NatMapping::EndpointIndependent,
            public_addresses: p.observed.clone(),
            carrier_grade: true,
            ..Default::default()
        };
        assert_eq!(report.reachability(), crate::Reachability::Good);
        report.mapping = NatMapping::EndpointDependent(PortAllocation::Random);
        assert!(report.reachability().suggests_relay());
    }

    #[test]
    fn lenient_routers_connect_directly() {
        for seed in 0..3 {
            for (j, h) in [
                (NatKind::Independent, NatKind::Independent),
                (NatKind::PortPreserving, NatKind::Independent),
                (NatKind::Independent, NatKind::PortPreserving),
            ] {
                let o = join(seed, j, h, false);
                assert_connected(&o, Via::Socket(MAIN), Via::Socket(MAIN));
                assert!(o.took < Duration::from_secs(2), "{o:?}");
            }
        }
    }

    #[test]
    fn sequential_ports_are_predicted() {
        for seed in 0..3 {
            for step in [1, 2] {
                let o = join(seed, NatKind::Sequential(step), NatKind::Independent, false);
                assert_connected(&o, Via::Socket(MAIN), Via::Socket(MAIN));
                let o = join(seed, NatKind::Independent, NatKind::Sequential(step), false);
                assert_connected(&o, Via::Socket(MAIN), Via::Socket(MAIN));
            }
        }
    }

    #[test]
    fn a_random_router_is_punched_by_the_birthday_paradox() {
        // Joiner strict: it opens the sockets, and connects from one of them.
        let mut punched = 0;
        for seed in 0..10 {
            let o = join(seed, NatKind::Random, NatKind::Independent, false);
            if let (Some(j), Some(h)) = (o.joiner, o.host) {
                assert!(matches!(j.via, Via::Socket(id) if id != MAIN), "{o:?}");
                assert_eq!(h.via, Via::Socket(MAIN));
                punched += 1;
            }
        }
        assert!(punched >= 8, "{punched} of 10 punched");
        // Host strict.
        let mut punched = 0;
        for seed in 0..10 {
            let o = join(seed, NatKind::Independent, NatKind::Random, false);
            if let (Some(j), Some(h)) = (o.joiner, o.host) {
                assert_eq!(j.via, Via::Socket(MAIN));
                assert!(matches!(h.via, Via::Socket(id) if id != MAIN), "{o:?}");
                punched += 1;
            }
        }
        assert!(punched >= 8, "{punched} of 10 punched");
    }

    #[test]
    fn punching_traffic_is_bounded() {
        let mut net = Net::new(3);
        net.add_nat(
            [203, 0, 113, 1].into(),
            ([192, 168, 1, 0].into(), 24),
            NatKind::Random,
        );
        net.add_nat(
            [203, 0, 113, 2].into(),
            ([192, 168, 2, 0].into(), 24),
            NatKind::Random,
        );
        let mut host = Player::new(&mut net, "192.168.1.10:7777".parse().unwrap());
        let mut joiner = Player::new(&mut net, "192.168.2.20:40000".parse().unwrap());
        host.gather(&mut net);
        joiner.gather(&mut net);
        // The joiner claims a lenient router: the punching runs its full course, in vain.
        joiner.nat = Some("eim".parse().unwrap());
        let sent_before = net.sent;
        let o = connect(&mut net, &mut host, &mut joiner, 3, false);
        assert!(o.joiner.is_none());
        let sent = net.sent - sent_before;
        // ICE's checks, 256 sockets three times, and at most 1,400 probes.
        assert!(sent < 3_500, "{sent} datagrams");
        assert!(o.took <= Duration::from_secs(15), "{o:?}");
    }

    #[test]
    fn two_strict_routers_need_a_relay_and_get_one() {
        let o = join(1, NatKind::Random, NatKind::Random, false);
        assert!(o.joiner.is_none() && o.needs_relay, "{o:?}");
        let o = join(1, NatKind::Random, NatKind::Sequential(1), false);
        assert!(o.needs_relay, "{o:?}");
        // With a relay the host is reachable whatever the joiner's router does.
        for seed in 0..3 {
            let o = join(seed, NatKind::Random, NatKind::Random, true);
            assert_connected(&o, Via::Socket(MAIN), Via::Relay);
            assert_eq!(o.joiner.unwrap().peer, net_relay_addr(&o));
        }
    }

    /// The relayed address the joiner connected to (the test server hands out port 50000 on).
    fn net_relay_addr(o: &Outcome) -> SocketAddr {
        let peer = o.joiner.unwrap().peer;
        assert_eq!(peer.ip(), IpAddr::from([198, 51, 100, 10]));
        peer
    }

    #[test]
    fn a_relay_is_the_last_resort() {
        // Lenient routers on both sides: the relay is offered but the direct path wins.
        let o = join(2, NatKind::Independent, NatKind::Independent, true);
        assert_connected(&o, Via::Socket(MAIN), Via::Socket(MAIN));
    }
}
