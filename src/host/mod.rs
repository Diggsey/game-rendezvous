//! Hosting: advertising a game and letting joiners through to the game's socket.
//!
//! The work is split between two threads. The game thread ([`Host`]) owns what needs the
//! game's socket: learning the public address and the connectivity checks. The worker
//! ([`relay`]) owns what needs the host's keys: the listing, and reading and answering join
//! requests. They exchange plain data.

mod relay;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Filter, Keys, PublicKey, SubscriptionId};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::Inner;
use crate::handshake::{HANDSHAKE_KIND, RefuseReason};
use crate::ice::{self, Link, LocalCandidates};
use crate::listing::Listing;
use crate::net::{self, LocalAddr};
use crate::portmap::{PortMapEvent, PortMapMethod};
use crate::signal::{self, Command, Inbox, Published, Sink};
use crate::stun::{self, Gatherer};
use relay::{FromRelay, JoinRequest, Relay, ToRelay};

/// How long a connected joiner's checks are still answered, for its retransmissions.
const LINGER: Duration = Duration::from_secs(5);
/// How often the public address is checked again with the STUN servers. This also keeps the
/// NAT's mapping for the socket alive while nobody is connected.
const REGATHER: Duration = Duration::from_secs(25);
/// How long a joiner has, from the host's answer, to send its first check. One that sends none
/// gives up its place among the joiners being connected (of which there are a few at most)
/// sooner than the connection timeout: anyone can send requests, and else a request a second
/// would keep every place taken and turn every real player away.
const SILENT_JOINER: Duration = Duration::from_secs(6);

/// What happened while hosting, from [`Host::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// The listing reached this many relays (reported when that changes).
    Listed { relays: usize },
    /// No relay took the listing.
    ListingFailed(String),
    /// The router was (or could not be) asked to open the port.
    PortMapping(PortMapEvent),
    /// A player was refused, e.g. for running an incompatible version.
    JoinRefused { name: String, reason: RefuseReason },
    /// A player's connection works: game traffic from `addr` is theirs.
    PeerConnected { addr: SocketAddr, name: String },
    /// A player's connectivity checks all failed.
    PeerFailed { name: String },
}

/// A summary of the host's reachability, for showing to the player.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostStatus {
    /// Relays connected, of how many configured.
    pub relays: (usize, usize),
    /// Relays that took the latest listing.
    pub listed_on: usize,
    /// The router's forwarded address and the protocol that opened it.
    pub port_mapping: Option<(SocketAddr, PortMapMethod)>,
    /// The public addresses STUN servers saw.
    pub public_addresses: Vec<SocketAddr>,
}

/// A joiner in the middle of connecting.
struct Joiner {
    name: String,
    link: Link,
    started: Instant,
    connected_at: Option<Instant>,
    /// A check (or answer) came from the joiner.
    heard: bool,
}

/// An advertised game. The game keeps its own socket and passes every datagram that is not its
/// own to [`handle_datagram`](Host::handle_datagram); it calls [`poll`](Host::poll) every frame.
/// Dropping the host closes the listing and the router's port mapping.
pub struct Host {
    inner: Arc<Inner>,
    /// A clone of the game's socket, for sending.
    socket: UdpSocket,
    started: Instant,

    listing: Listing,
    /// Dropping it ends the relay task, which closes the listing.
    to_relay: Sink<ToRelay>,
    from_relay: Inbox<FromRelay>,
    published: Inbox<Published>,
    listed_on: usize,

    locals: Vec<LocalAddr>,
    port: u16,
    gatherer: Option<Gatherer>,
    last_gather: Option<Instant>,
    reflexive: Vec<SocketAddr>,
    port_events: Inbox<PortMapEvent>,
    /// The router's public address (if it said), port and mapping protocol.
    port_mapping: Option<(Option<IpAddr>, u16, PortMapMethod)>,
    /// Dropping it removes the port mapping.
    _port_mapping_stop: Option<oneshot::Sender<()>>,

    subscription: SubscriptionId,
    /// Requests that came before the public address was known.
    early_requests: Vec<JoinRequest>,
    joiners: HashMap<PublicKey, Joiner>,
    events: VecDeque<HostEvent>,
}

impl Host {
    pub(crate) fn new(inner: Arc<Inner>, socket: &UdpSocket, listing: Listing) -> io::Result<Host> {
        let socket = socket.try_clone()?;
        let keys = Keys::generate();
        let port = socket.local_addr()?.port();
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        // No `since`: nothing can be addressed to a key made just now, and a `since` from this
        // clock would hide the requests of a joiner whose clock is behind.
        let filter = Filter::new()
            .kind(HANDSHAKE_KIND)
            .pubkey(keys.public_key());
        let (subscription, requests) = inner.signal.subscribe(filter);
        let (port_tx, port_events) = signal::channel();
        let stop = if inner.config.port_mapping {
            let (stop_tx, stop) = oneshot::channel();
            inner.signal.send(Command::MapPort {
                port,
                events: port_tx,
                stop,
            });
            Some(stop_tx)
        } else {
            None
        };
        info!(
            "hosting {} as {} on port {port}",
            inner.config.game_id,
            keys.public_key()
        );
        let (to_relay, commands) = signal::channel();
        let (notices, from_relay) = signal::channel();
        let (published_tx, published) = signal::channel();
        let relay_parts = (inner.config.clone(), listing.clone());
        inner.signal.spawn(move |ctx| {
            let (config, listing) = relay_parts;
            Relay {
                ctx,
                config,
                keys,
                listing,
                commands,
                requests,
                notices,
                published: published_tx,
            }
            .run()
        });
        Ok(Host {
            inner,
            socket,
            started: Instant::now(),
            listing,
            to_relay,
            from_relay,
            published,
            listed_on: 0,
            locals,
            port,
            gatherer: None,
            last_gather: None,
            reflexive: Vec::new(),
            port_events,
            port_mapping: None,
            _port_mapping_stop: stop,
            subscription,
            early_requests: Vec::new(),
            joiners: HashMap::new(),
            events: VecDeque::new(),
        })
    }

    /// Takes a datagram the game received, if it is this library's (STUN). Returns whether it
    /// was; the game handles the others itself.
    pub fn handle_datagram(&mut self, from: SocketAddr, data: &[u8]) -> bool {
        if !stun::is_stun(data) {
            return false;
        }
        let now = Instant::now();
        if let Some(g) = &mut self.gatherer
            && g.handle(now, data)
        {
            return true;
        }
        if let Some(msg) = ice::parse(data)
            && let Some(j) = self.joiners.values_mut().find(|j| j.link.accepts(&msg))
        {
            j.heard = true;
            j.link.handle(now, from, msg);
        }
        true
    }

    /// Does the periodic work and returns what happened, one event per call: call it until it
    /// returns `None`, every frame.
    pub fn poll(&mut self) -> Option<HostEvent> {
        if self.events.is_empty() {
            let now = Instant::now();
            self.gather(now);
            self.port_mapping_events();
            self.listing_outcomes();
            self.join_requests(now);
            self.drive_joiners(now);
        }
        self.events.pop_front()
    }

    /// Changes the listing (players, metadata, ...); it is republished shortly.
    pub fn set_listing(&mut self, listing: Listing) {
        if listing != self.listing {
            self.listing = listing.clone();
            let _ = self.to_relay.send(ToRelay::SetListing(listing));
        }
    }

    pub fn listing(&self) -> &Listing {
        &self.listing
    }

    pub fn status(&self) -> HostStatus {
        HostStatus {
            relays: self.inner.relays(),
            listed_on: self.listed_on,
            port_mapping: self.mapped_address(),
            public_addresses: self.reflexive.clone(),
        }
    }

    /// The public address is known (or could not be learned in time), so joiners get every
    /// candidate there will be.
    fn ready(&self, now: Instant) -> bool {
        self.last_gather.is_some()
            || now - self.started > self.inner.config.gather_timeout + Duration::from_secs(3)
    }

    /// Learns (again) what the socket looks like from outside.
    fn gather(&mut self, now: Instant) {
        if self.gatherer.is_none() && self.last_gather.is_none_or(|t| now - t >= REGATHER) {
            let Some(servers) = self.inner.signal.stun_servers() else {
                return; // still resolving
            };
            let timeout = self.inner.config.gather_timeout;
            self.gatherer = Some(Gatherer::for_socket(&self.socket, servers, now, timeout));
        }
        let Some(g) = &mut self.gatherer else { return };
        g.send_due(now, &self.socket);
        if g.is_done(now) {
            let mapped = g.mapped();
            if !mapped.is_empty() || self.last_gather.is_none() {
                if mapped != self.reflexive {
                    info!("public addresses: {mapped:?}");
                }
                self.reflexive = mapped;
            }
            self.gatherer = None;
            self.last_gather = Some(now);
        }
    }

    fn port_mapping_events(&mut self) {
        while let Ok(e) = self.port_events.try_recv() {
            match &e {
                PortMapEvent::Mapped {
                    external_ip,
                    external_port,
                    method,
                } => self.port_mapping = Some((*external_ip, *external_port, *method)),
                PortMapEvent::Lost(_) => self.port_mapping = None,
                PortMapEvent::Failed(_) => {}
            }
            self.events.push_back(HostEvent::PortMapping(e));
        }
    }

    /// The router's forwarded address and the protocol that opened it.
    fn mapped_address(&self) -> Option<(SocketAddr, PortMapMethod)> {
        let (ip, port, method) = self.port_mapping?;
        // NAT-PMP does not say the public address; STUN does.
        let ip = ip.or_else(|| self.reflexive.iter().find(|a| a.is_ipv4()).map(|a| a.ip()))?;
        Some((SocketAddr::new(ip, port), method))
    }

    fn candidates(&self) -> LocalCandidates {
        let mut reflexive = self.reflexive.clone();
        if let Some((addr, _)) = self.mapped_address()
            && !reflexive.contains(&addr)
        {
            // The mapped port first: it works whatever the joiner's NAT does.
            reflexive.insert(0, addr);
        }
        LocalCandidates {
            addrs: self.locals.clone(),
            port: self.port,
            reflexive,
        }
    }

    /// The relays' answers to the listings the relay task published.
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

    /// Join requests the relay task accepted (and refusals it sent).
    fn join_requests(&mut self, now: Instant) {
        while let Ok(notice) = self.from_relay.try_recv() {
            match notice {
                FromRelay::Request(r) => self.early_requests.push(r),
                FromRelay::Refused { name, reason } => self
                    .events
                    .push_back(HostEvent::JoinRefused { name, reason }),
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

    fn join_request(&mut self, now: Instant, r: JoinRequest) {
        let mut link = Link::new(false, &self.candidates());
        link.set_remote(&r.ice);
        info!(
            "{} is joining: checking {} addresses",
            r.player_name,
            link.remote_candidates()
        );
        let _ = self.to_relay.send(ToRelay::Accept {
            to: r.from,
            attempt: r.attempt,
            ice: link.params(),
        });
        self.joiners.insert(
            r.from,
            Joiner {
                name: r.player_name,
                link,
                started: now,
                connected_at: None,
                heard: false,
            },
        );
    }

    fn drive_joiners(&mut self, now: Instant) {
        let timeout = self.inner.config.connect_timeout + Duration::from_secs(5);
        let mut done = Vec::new();
        for (key, j) in &mut self.joiners {
            j.link.drive(now, &self.socket);
            if j.connected_at.is_none()
                && let Some(addr) = j.link.nominated()
            {
                info!("{} connected from {addr}", j.name);
                j.connected_at = Some(now);
                self.events.push_back(HostEvent::PeerConnected {
                    addr,
                    name: j.name.clone(),
                });
            }
            let silent = !j.heard && now - j.started > SILENT_JOINER;
            match j.connected_at {
                Some(t) if now - t > LINGER => done.push(*key),
                None if silent || now - j.started > timeout => {
                    debug!("{} could not connect", j.name);
                    self.events.push_back(HostEvent::PeerFailed {
                        name: j.name.clone(),
                    });
                    done.push(*key);
                }
                _ => {}
            }
        }
        for key in done {
            self.joiners.remove(&key);
            let _ = self.to_relay.send(ToRelay::JoinerDone(key));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // The relay task sees `to_relay` close, and replaces the listing with a tombstone.
        self.inner
            .signal
            .send(Command::Unsubscribe(self.subscription.clone()));
        // Dropping `_port_mapping_stop` removes the port mapping.
    }
}
