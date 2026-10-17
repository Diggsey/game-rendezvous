//! Hosting: advertising a game and letting joiners through to the game's socket.
//!
//! The work is split between two threads. The game thread ([`Host`]) owns what needs the
//! game's socket: learning the public address and the router's ways ([`Survey`]), the TURN
//! relay, and the connectivity checks. The worker ([`task`]) owns what needs the host's keys:
//! the listing, and reading and answering join requests. They exchange plain data.

mod task;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Filter, Keys, PublicKey, SubscriptionId};
use tracing::{debug, info, warn};

use crate::handshake::{HANDSHAKE_KIND, IceParams, RefuseReason};
use crate::ice::LocalCandidates;
use crate::listing::Listing;
use crate::nat::{NatReport, NatSummary};
use crate::net::{self, LocalAddr};
use crate::portmap::PortMapEvent;
use crate::punch::{MAIN, SocketId};
use crate::socket::{Arrival, GameSocket};
use crate::survey::{Finding, Handled, Survey};
use crate::traverse::{Route, Transmit, Traversal, Via};
use crate::worker::{self, Command, Inbox, Published, Sink};
use crate::{Inner, RelayCount};
use task::{FromTask, HostTask, JoinRequest, ToTask};

/// How long a connected joiner's checks are still answered, for its retransmissions.
const LINGER: Duration = Duration::from_secs(5);
/// How long a joiner has, from the host's answer, to send its first check. One that sends none
/// gives up its place among the joiners being connected (of which there are a few at most)
/// sooner than the connection timeout: anyone can send requests, and else a request a second
/// would keep every place taken and turn every real player away. (A joiner whose router calls
/// for punching is given until the punching ends: its checks may not get through before.)
const SILENT_JOINER: Duration = Duration::from_secs(6);
/// How long, after giving up on a joiner, the host waits for it to say it could not connect.
const REPORT_WAIT: Duration = Duration::from_secs(20);
/// A peer on the relay or an extra socket that sends nothing for this long is forgotten (its
/// relay permission lapses, its socket closes).
const ROUTE_IDLE: Duration = Duration::from_secs(60);

/// What happened while hosting, from [`Host::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostEvent {
    /// The listing reached this many relays (reported when that changes).
    Listed {
        /// How many relays took the latest copy.
        relays: usize,
    },
    /// No relay took the listing; why, per relay.
    ListingFailed(String),
    /// The router was (or could not be) asked to open the port.
    PortMapping(PortMapEvent),
    /// The TURN relay ([`Config::turn`](crate::Config::turn)) was allocated, at this address,
    /// or could not be (why).
    Relay(Result<SocketAddr, String>),
    /// What is known of the host's network changed: see [`NatReport::reachability`] for
    /// whether players can probably reach the host.
    Network(NatReport),
    /// A player was refused, e.g. for running an incompatible version.
    JoinRefused {
        /// The player's name, as they sent it (cut short, without control characters).
        name: String,
        /// Why; the player was told.
        reason: RefuseReason,
    },
    /// A player's connection works: game traffic from `addr` is theirs.
    PeerConnected {
        /// The player's address, [`canonical`](crate::canonical): where the
        /// [`GameSocket`] says their datagrams come from, and sends to.
        addr: SocketAddr,
        /// The player's name, as they sent it (cut short, without control characters).
        name: String,
        /// How the connection runs.
        path: PeerPath,
    },
    /// A player could not connect.
    PeerFailed {
        /// The player's name.
        name: String,
        /// What went wrong.
        reason: JoinFailure,
    },
}

/// How a connected player's traffic runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerPath {
    /// Straight between the two, through the routers' holes.
    Direct,
    /// Through the host's TURN relay.
    Relay,
    /// From one of the extra sockets the host opened to punch through its router.
    Punched,
}

/// Why a player could not connect, in [`HostEvent::PeerFailed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinFailure {
    /// The player said no path to the host worked: players probably cannot reach this host.
    /// Their router, if they said, tells whether a relay is needed (see [`NatSummary`]).
    Unreachable {
        /// The player's router.
        joiner_nat: Option<NatSummary>,
    },
    /// The checks started, but no path worked in time, and the player did not say why.
    TimedOut,
    /// Nothing came from the player after the host answered: it may have given up, or never
    /// been a player at all (anyone can send requests), so this one does not count as a
    /// failed join.
    Silent,
}

/// A summary of the host's reachability, for showing to the player.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostStatus {
    /// Relays connected, of how many configured.
    pub relays: RelayCount,
    /// Relays that took the latest listing.
    pub listed_on: usize,
    /// The host's network: its router, port mapping, relay, public addresses.
    pub nat: NatReport,
    /// Players who could not connect since hosting began ([`JoinFailure::Unreachable`] and
    /// [`JoinFailure::TimedOut`]).
    pub failed_joins: u32,
}

/// A joiner in the middle of connecting.
struct Joiner {
    /// The player's name.
    name: String,
    /// The checks with them.
    traversal: Traversal,
    /// When the host accepted them.
    started: Instant,
    /// When their path was found.
    connected_at: Option<Instant>,
    /// A check (or answer) came from the joiner.
    heard: bool,
    /// Extra sockets opened for punching (socket `i + 1`); the winner is taken out.
    sockets: Vec<Option<UdpSocket>>,
    /// Addresses the relay was told to let through for them.
    permitted: Vec<IpAddr>,
}

/// A joiner the host gave up on, awaiting its word on why.
struct Awaiting {
    /// The player's name.
    name: String,
    /// What the host saw.
    reason: JoinFailure,
    /// When to stop waiting.
    until: Instant,
}

/// An advertised game. The game plays on a [`GameSocket`], which passes the library its
/// datagrams; it calls [`poll`](Host::poll) every frame. Dropping the host closes the listing,
/// the router's port mapping and the TURN allocation.
pub struct Host {
    /// The configuration and worker.
    inner: Arc<Inner>,
    /// The game's socket.
    socket: GameSocket,
    /// When hosting began.
    started: Instant,

    /// The listing as the game last set it.
    listing: Listing,
    /// Dropping it ends the worker task, which closes the listing.
    to_task: Sink<ToTask>,
    /// Join requests and refusals from the worker task.
    from_task: Inbox<FromTask>,
    /// How the relays took each copy of the listing.
    published: Inbox<Published>,
    /// Relays that took the latest copy.
    listed_on: usize,

    /// This machine's addresses.
    locals: Vec<LocalAddr>,
    /// The socket's port.
    port: u16,
    /// The public address, the router, the relay.
    survey: Survey,
    /// The network as last reported.
    reported: Option<NatReport>,

    /// The join requests' subscription, closed on drop.
    subscription: SubscriptionId,
    /// Requests that came before the public address was known.
    early_requests: Vec<JoinRequest>,
    /// Joiners being connected, by their attempt's key.
    joiners: HashMap<PublicKey, Joiner>,
    /// Joiners given up on, awaiting their word.
    awaiting: HashMap<PublicKey, Awaiting>,
    /// Players who could not connect.
    failed_joins: u32,
    /// Events not yet polled.
    events: VecDeque<HostEvent>,
}

impl Host {
    /// Starts hosting on `socket`: the listing, its worker task, the port mapping and relay.
    pub(crate) fn new(
        inner: Arc<Inner>,
        socket: &GameSocket,
        listing: Listing,
    ) -> io::Result<Host> {
        let port = socket.local_addr()?.port();
        socket.attach()?;
        let keys = Keys::generate();
        let locals = net::local_addrs(socket.socket(), inner.config.local_addresses.as_deref());
        let survey = Survey::new(&inner, socket.socket(), locals.clone(), true);
        // No `since`: nothing can be addressed to a key made just now, and a `since` from this
        // clock would hide the requests of a joiner whose clock is behind.
        let filter = Filter::new().kind(HANDSHAKE_KIND).pubkey(keys.public_key());
        let (subscription, requests) = inner.worker.subscribe(filter);
        info!(
            "hosting {} as {} on port {port}",
            inner.config.game_id,
            keys.public_key()
        );
        let (to_task, commands) = worker::channel();
        let (notices, from_task) = worker::channel();
        let (published_tx, published) = worker::channel();
        let relay_parts = (inner.config.clone(), listing.clone());
        inner.worker.spawn(move |ctx| {
            let (config, listing) = relay_parts;
            HostTask {
                ctx,
                config,
                keys,
                listing,
                commands,
                requests,
                notices,
                published: published_tx,
                nat: None,
            }
            .run()
        });
        Ok(Host {
            inner,
            socket: socket.clone(),
            started: Instant::now(),
            listing,
            to_task,
            from_task,
            published,
            listed_on: 0,
            locals,
            port,
            survey,
            reported: None,
            subscription,
            early_requests: Vec::new(),
            joiners: HashMap::new(),
            awaiting: HashMap::new(),
            failed_joins: 0,
            events: VecDeque::new(),
        })
    }

    /// Does the periodic work and returns what happened, one event per call: call it until it
    /// returns `None`, every frame (during a match too: the relay and the router's mapping are
    /// kept alive from here).
    ///
    /// The library's datagrams reach the host as the game reads the [`GameSocket`]
    /// ([`GameSocket::recv_from`]), so the game must read it every frame too.
    pub fn poll(&mut self) -> Option<HostEvent> {
        if self.events.is_empty() {
            let now = Instant::now();
            self.incoming(now);
            self.drive_survey(now);
            self.listing_outcomes();
            self.join_requests(now);
            self.drive_joiners(now);
            self.reports(now);
            self.forget_idle(now);
            self.network_changes();
        }
        self.events.pop_front()
    }

    /// Changes the listing (players, metadata, ...); it is republished shortly.
    pub fn set_listing(&mut self, listing: Listing) {
        if listing != self.listing {
            self.listing = listing.clone();
            let _ = self.to_task.send(ToTask::SetListing(listing));
        }
    }

    /// The listing as last set.
    #[must_use]
    pub fn listing(&self) -> &Listing {
        &self.listing
    }

    /// What is known of the host's network so far.
    #[must_use]
    pub fn nat(&self) -> NatReport {
        self.survey.report()
    }

    /// How reachable the host is, for showing to the player.
    #[must_use]
    pub fn status(&self) -> HostStatus {
        HostStatus {
            relays: self.inner.relays(),
            listed_on: self.listed_on,
            nat: self.nat(),
            failed_joins: self.failed_joins,
        }
    }

    /// The public address is known (or could not be learned in time), and the relay is set
    /// up if there is one, so joiners get every candidate there will be.
    fn ready(&self, now: Instant) -> bool {
        let relay_known = self.inner.config.turn.is_empty()
            || self.survey.relay().is_some()
            || self.survey.relay_error().is_some();
        (self.survey.gathered() && relay_known)
            || now - self.started > self.inner.config.gather_timeout + Duration::from_secs(3)
    }

    /// Takes the library's datagrams the game's socket received.
    fn incoming(&mut self, now: Instant) {
        for d in self.socket.take_incoming() {
            match d.arrival {
                Arrival::Direct => match self.survey.handle(now, d.from, &d.data) {
                    Handled::Taken => {}
                    Handled::Relayed(peer, data) => self.relayed_in(now, peer, &data),
                    Handled::NotMine => {
                        if let Some(j) = self
                            .joiners
                            .values_mut()
                            .find(|j| j.traversal.accepts(&d.data))
                        {
                            j.heard |= j.traversal.handle(now, MAIN, d.from, &d.data);
                        }
                    }
                },
                Arrival::Relayed => self.relayed_in(now, d.from, &d.data),
            }
        }
    }

    /// A STUN message that came through the relay from `peer`.
    fn relayed_in(&mut self, now: Instant, peer: SocketAddr, data: &[u8]) {
        if let Some(j) = self
            .joiners
            .values_mut()
            .find(|j| j.traversal.accepts(data))
        {
            j.heard |= j.traversal.handle_relayed(now, peer, data);
        }
    }

    /// Drives the survey, and takes its findings as events.
    fn drive_survey(&mut self, now: Instant) {
        let socket = &self.socket;
        self.survey.drive(&self.inner, now, &mut |data, to| {
            socket.send_direct(data, to);
        });
        while let Some(f) = self.survey.poll_finding() {
            match f {
                Finding::PortMapping(e) => self.events.push_back(HostEvent::PortMapping(e)),
                Finding::Relay(r) => {
                    let server = self.survey.turn().map(|t| t.server());
                    self.socket
                        .set_turn_server(if r.is_ok() { server } else { None });
                    self.events.push_back(HostEvent::Relay(r));
                }
            }
        }
        if let Some(t) = self.survey.turn() {
            self.socket.set_channels(t.bound_channels());
        }
    }

    /// Reports the network when what joiners would make of it changes, and puts it in the
    /// listing.
    fn network_changes(&mut self) {
        if !self.survey.gathered() {
            return;
        }
        let report = self.survey.report();
        let changed = self.reported.as_ref().is_none_or(|r| {
            r.summary() != report.summary() || r.reachability() != report.reachability()
        });
        if changed {
            let _ = self.to_task.send(ToTask::SetNat(Some(report.summary())));
            self.events.push_back(HostEvent::Network(report.clone()));
            self.reported = Some(report);
        }
    }

    /// The relays' answers to the listings the worker task published.
    fn listing_outcomes(&mut self) {
        while let Ok(p) = self.published.try_recv() {
            if p.accepted == 0 {
                warn!("listing not published: {}", p.errors.join("; "));
                self.events
                    .push_back(HostEvent::ListingFailed(p.errors.join("; ")));
            } else if p.accepted != self.listed_on {
                self.events
                    .push_back(HostEvent::Listed { relays: p.accepted });
            }
            self.listed_on = p.accepted;
        }
    }

    /// Join requests the worker task accepted (and refusals it sent, and joiners' reports).
    fn join_requests(&mut self, now: Instant) {
        while let Ok(notice) = self.from_task.try_recv() {
            match notice {
                FromTask::Request(r) => self.early_requests.push(r),
                FromTask::Refused { name, reason } => self
                    .events
                    .push_back(HostEvent::JoinRefused { name, reason }),
                FromTask::Unreachable { from, nat } => self.unreachable(from, nat),
            }
        }
        // Joiners get every candidate there will be, so they wait for the public address.
        if !self.ready(now) {
            return;
        }
        for r in std::mem::take(&mut self.early_requests) {
            self.join_request(now, r);
        }
    }

    /// A joiner said it could not reach the host.
    fn unreachable(&mut self, from: PublicKey, joiner_nat: Option<NatSummary>) {
        let name = if let Some(j) = self.joiners.remove(&from) {
            let _ = self.to_task.send(ToTask::JoinerDone(from));
            self.revoke(&j.permitted, None);
            j.name
        } else if let Some(a) = self.awaiting.remove(&from) {
            a.name
        } else {
            return;
        };
        info!("{name} could not reach this host (their router: {joiner_nat:?})");
        self.failed_joins += 1;
        self.events.push_back(HostEvent::PeerFailed {
            name,
            reason: JoinFailure::Unreachable { joiner_nat },
        });
    }

    /// The candidates to offer joiners.
    fn candidates(&self) -> LocalCandidates {
        LocalCandidates {
            addrs: self.locals.clone(),
            port: self.port,
            reflexive: self.survey.reflexive(),
            predicted: self.survey.predicted(),
            relay: self.survey.relay(),
        }
    }

    /// Accepts `r`: answers with the host's side of the checks, and starts them.
    fn join_request(&mut self, now: Instant, r: JoinRequest) {
        let nat = self
            .survey
            .gathered()
            .then(|| self.survey.report().summary());
        let mut traversal = Traversal::new(false, &self.candidates(), nat);
        traversal.set_remote(now, &r.ice);
        info!(
            "{} is joining: checking {} addresses",
            r.player_name,
            traversal.remote_candidates()
        );
        // The relay lets the joiner's addresses through: it sends from one of them.
        let mut permitted = Vec::new();
        if let Some(turn) = self.survey.turn()
            && turn.relayed().is_some()
        {
            for ip in candidate_ips(&r.ice) {
                turn.permit(now, ip);
                permitted.push(ip);
            }
        }
        let _ = self.to_task.send(ToTask::Accept {
            to: r.from,
            attempt: r.attempt,
            ice: traversal.params(),
        });
        self.joiners.insert(
            r.from,
            Joiner {
                name: r.player_name,
                traversal,
                started: now,
                connected_at: None,
                heard: false,
                sockets: Vec::new(),
                permitted,
            },
        );
    }

    /// Runs the joiners' checks, and lets go of those connected or failed.
    fn drive_joiners(&mut self, now: Instant) {
        let timeout = self.inner.config.connect_timeout;
        let mut done = Vec::new();
        let mut extra_in_use = self.joiners.values().any(|j| !j.sockets.is_empty());
        let keys: Vec<PublicKey> = self.joiners.keys().copied().collect();
        for key in keys {
            let Some(j) = self.joiners.get_mut(&key) else {
                continue;
            };
            read_extra(now, j);
            j.traversal.drive(now);
            if let Some(n) = j.traversal.wants_sockets() {
                // One punching from extra sockets at a time: each takes hundreds of sockets.
                let ids = if extra_in_use {
                    Vec::new()
                } else {
                    j.sockets = open_extra_sockets(n);
                    extra_in_use = !j.sockets.is_empty();
                    (1..=j.sockets.len()).collect()
                };
                j.traversal.sockets_opened(now, ids);
            }
            while let Some(t) = j.traversal.poll_transmit() {
                send(&self.socket, &mut self.survey, &j.sockets, &t);
            }
            if j.connected_at.is_none()
                && let Some(route) = j.traversal.route()
            {
                j.connected_at = Some(now);
                let path = self.connected(key, route);
                let j = &self.joiners[&key];
                info!("{} connected from {} ({path:?})", j.name, route.peer);
                self.events.push_back(HostEvent::PeerConnected {
                    addr: route.peer,
                    name: j.name.clone(),
                    path,
                });
            }
            let j = &self.joiners[&key];
            let deadline = j.traversal.deadline(timeout).unwrap_or(j.started + timeout)
                + Duration::from_secs(5);
            let silent_for = if j.traversal.plans_fallback() {
                deadline - j.started
            } else {
                SILENT_JOINER
            };
            let silent = !j.heard && now - j.started > silent_for;
            match j.connected_at {
                Some(t) if now - t > LINGER => done.push((key, None)),
                None if silent => done.push((key, Some(JoinFailure::Silent))),
                None if now > deadline => done.push((key, Some(JoinFailure::TimedOut))),
                _ => {}
            }
        }
        for (key, failure) in done {
            let Some(j) = self.joiners.remove(&key) else {
                continue;
            };
            let _ = self.to_task.send(ToTask::JoinerDone(key));
            let kept = j
                .traversal
                .route()
                .filter(|r| r.via == Via::Relay)
                .map(|r| r.peer.ip());
            self.revoke(&j.permitted, kept);
            if let Some(reason) = failure {
                debug!(
                    "{} could not connect ({reason:?}); waiting for its word",
                    j.name
                );
                self.awaiting.insert(
                    key,
                    Awaiting {
                        name: j.name,
                        reason,
                        until: now + REPORT_WAIT,
                    },
                );
            }
        }
    }

    /// Sets up the route to a joiner whose path was found.
    fn connected(&mut self, key: PublicKey, route: Route) -> PeerPath {
        let Some(j) = self.joiners.get_mut(&key) else {
            return PeerPath::Direct;
        };
        match route.via {
            Via::Socket(MAIN) => PeerPath::Direct,
            Via::Relay => {
                self.socket.add_relayed(route.peer);
                self.socket.touch_relayed(route.peer);
                if let Some(t) = self.survey.turn() {
                    t.bind(Instant::now(), route.peer);
                }
                PeerPath::Relay
            }
            Via::Socket(id) => {
                if let Some(s) = j.sockets.get_mut(id - 1).and_then(Option::take) {
                    self.socket.add_extra(route.peer, s);
                }
                // The other sockets close.
                j.sockets.clear();
                PeerPath::Punched
            }
        }
    }

    /// Stops the relay letting `ips` through, but for `keep`.
    fn revoke(&mut self, ips: &[IpAddr], keep: Option<IpAddr>) {
        if let Some(t) = self.survey.turn() {
            for &ip in ips {
                if Some(ip) != keep {
                    t.revoke(ip);
                }
            }
        }
    }

    /// Gives up waiting for the word of joiners that failed.
    fn reports(&mut self, now: Instant) {
        let expired: Vec<PublicKey> = self
            .awaiting
            .iter()
            .filter(|(_, a)| now >= a.until)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            let Some(a) = self.awaiting.remove(&key) else {
                continue;
            };
            if a.reason != JoinFailure::Silent {
                self.failed_joins += 1;
            }
            self.events.push_back(HostEvent::PeerFailed {
                name: a.name,
                reason: a.reason,
            });
        }
    }

    /// Forgets relayed and punched peers gone quiet.
    fn forget_idle(&mut self, now: Instant) {
        let Some(since) = now.checked_sub(ROUTE_IDLE) else {
            return;
        };
        let idle = self.socket.forget_idle(since);
        if let Some(t) = self.survey.turn() {
            for peer in idle {
                debug!("forgetting relayed peer {peer}");
                t.revoke(peer.ip());
            }
        }
    }
}

/// Sends `t` the way it says.
fn send(socket: &GameSocket, survey: &mut Survey, sockets: &[Option<UdpSocket>], t: &Transmit) {
    match t.via {
        Via::Socket(MAIN) => socket.send_direct(&t.data, t.to),
        Via::Socket(id) => {
            if let Some(Some(s)) = sockets.get(id - 1) {
                let _ = net::send_to(s, &t.data, t.to);
            }
        }
        Via::Relay => {
            if let Some(turn) = survey.turn()
                && let Some(framed) = turn.wrap(t.to, &t.data)
            {
                socket.send_direct(&framed, turn.server());
            }
        }
    }
}

/// Reads a joiner's extra sockets into its checks.
fn read_extra(now: Instant, j: &mut Joiner) {
    let mut buf = [0u8; 1500];
    for (i, s) in j.sockets.iter().enumerate() {
        let Some(s) = s else { continue };
        loop {
            match s.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let id: SocketId = i + 1;
                    j.heard |= j.traversal.handle(now, id, net::canonical(from), &buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            }
        }
    }
}

/// Opens up to `n` IPv4 sockets for punching (fewer if the system runs out).
pub(crate) fn open_extra_sockets(n: usize) -> Vec<Option<UdpSocket>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        match UdpSocket::bind("0.0.0.0:0").and_then(|s| s.set_nonblocking(true).map(|()| s)) {
            Ok(s) => out.push(Some(s)),
            Err(e) => {
                debug!("opened {} sockets for punching: {e}", out.len());
                break;
            }
        }
    }
    out
}

/// The IPv4 addresses among a peer's candidates: the ones its traffic may come from.
fn candidate_ips(params: &IceParams) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for sdp in &params.candidates {
        if let Ok(c) = is::Candidate::from_sdp_string(sdp) {
            let ip = net::canonical(c.addr()).ip();
            if ip.is_ipv4() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

impl Drop for Host {
    fn drop(&mut self) {
        // The worker task sees `to_task` close, and replaces the listing with a tombstone.
        self.inner
            .worker
            .send(Command::Unsubscribe(self.subscription.clone()));
        let socket = &self.socket;
        self.survey
            .close(Instant::now(), &mut |data, to| socket.send_direct(data, to));
        self.socket.detach();
    }
}
