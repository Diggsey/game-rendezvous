//! Hosting: advertising a game and letting joiners through to the game's socket.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Event, Filter, Keys, PublicKey, SubscriptionId, Timestamp};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::Inner;
use crate::handshake::{self, HANDSHAKE_KIND, Message, RefuseReason};
use crate::ice::{self, Link, LocalCandidates};
use crate::listing::{Listing, PROTOCOL, listing_event};
use crate::net::{self, LocalAddr};
use crate::portmap::PortMapEvent;
use crate::signal::{self, Command, Inbox, Published};
use crate::stun::{self, Gatherer};

/// Joiners being connected at once; more are told to wait.
const MAX_JOINERS: usize = 16;
/// How long a connected joiner's checks are still answered, for its retransmissions.
const LINGER: Duration = Duration::from_secs(5);
/// How often the public address is checked again with the STUN servers. This also keeps the
/// NAT's mapping for the socket alive while nobody is connected.
const REGATHER: Duration = Duration::from_secs(25);
/// The quickest a changed listing is republished.
const PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(1);

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
    pub port_mapping: Option<(SocketAddr, &'static str)>,
    /// The public addresses STUN servers saw.
    pub public_addresses: Vec<SocketAddr>,
}

/// A joiner in the middle of connecting.
struct Joiner {
    attempt: String,
    name: String,
    link: Link,
    started: Instant,
    /// The accept message, sent again if the joiner repeats its request.
    accept: Event,
    connected_at: Option<Instant>,
}

/// An advertised game. The game keeps its own socket and passes every datagram that is not its
/// own to [`handle_datagram`](Host::handle_datagram); it calls [`poll`](Host::poll) every frame.
/// Dropping the host closes the listing and the router's port mapping.
pub struct Host {
    inner: Arc<Inner>,
    /// A clone of the game's socket, for sending.
    socket: UdpSocket,
    keys: Keys,
    started: Instant,

    listing: Listing,
    listing_changed: bool,
    last_publish: Option<Instant>,
    /// The date of the last listing published.
    last_listing: Option<Timestamp>,
    publishing: Option<Inbox<Published>>,
    listed_on: usize,

    locals: Vec<LocalAddr>,
    port: u16,
    gatherer: Option<Gatherer>,
    last_gather: Option<Instant>,
    reflexive: Vec<SocketAddr>,
    port_events: Inbox<PortMapEvent>,
    /// The router's public address (if it said), port and mapping protocol.
    port_mapping: Option<(Option<IpAddr>, u16, &'static str)>,
    /// Dropping it removes the port mapping.
    _port_mapping_stop: Option<oneshot::Sender<()>>,

    subscription: SubscriptionId,
    requests: Inbox<Event>,
    /// Requests that came before the public address was known.
    early_requests: Vec<Event>,
    joiners: HashMap<PublicKey, Joiner>,
    events: VecDeque<HostEvent>,
}

impl Host {
    pub(crate) fn new(inner: Arc<Inner>, socket: &UdpSocket, listing: Listing) -> io::Result<Host> {
        let socket = socket.try_clone()?;
        let keys = Keys::generate();
        let port = socket.local_addr()?.port();
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        let filter = Filter::new()
            .kind(HANDSHAKE_KIND)
            .pubkey(keys.public_key())
            .since(Timestamp::now() - 10);
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
        Ok(Host {
            inner,
            socket,
            keys,
            started: Instant::now(),
            listing,
            listing_changed: true,
            last_publish: None,
            last_listing: None,
            publishing: None,
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
            requests,
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
            self.publish(now);
            self.join_requests(now);
            self.drive_joiners(now);
        }
        self.events.pop_front()
    }

    /// Changes the listing (players, metadata, ...); it is republished shortly.
    pub fn set_listing(&mut self, listing: Listing) {
        if listing != self.listing {
            self.listing = listing;
            self.listing_changed = true;
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
            let dual = net::is_dual_stack(&self.socket);
            let servers = servers
                .into_iter()
                .filter(|s| s.is_ipv4() || dual)
                .collect();
            self.gatherer = Some(Gatherer::new(
                servers,
                now,
                self.inner.config.gather_timeout,
            ));
        }
        let Some(g) = &mut self.gatherer else { return };
        for (server, request) in g.poll_transmit(now) {
            let _ = net::send_to(&self.socket, &request, server);
        }
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
            if let PortMapEvent::Mapped {
                external_ip,
                external_port,
                method,
            } = &e
            {
                self.port_mapping = Some((*external_ip, *external_port, method));
            }
            self.events.push_back(HostEvent::PortMapping(e));
        }
    }

    /// The router's forwarded address and the protocol that opened it.
    fn mapped_address(&self) -> Option<(SocketAddr, &'static str)> {
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

    fn publish(&mut self, now: Instant) {
        if let Some(rx) = &mut self.publishing
            && let Ok(p) = rx.try_recv()
        {
            self.publishing = None;
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
        let due = match self.last_publish {
            None => true,
            Some(t) => {
                now - t >= self.inner.config.listing_refresh
                    || (self.listing_changed && now - t >= PUBLISH_MIN_INTERVAL)
            }
        };
        if !due || self.publishing.is_some() {
            return;
        }
        let previous = self.last_listing;
        match listing_event(
            &self.inner.config,
            &self.keys,
            &self.listing,
            false,
            previous,
        ) {
            Some(event) => {
                self.last_listing = Some(event.created_at);
                self.publishing = Some(self.inner.signal.publish_tracked(event));
                self.last_publish = Some(now);
                self.listing_changed = false;
            }
            None => warn!("could not sign the listing"),
        }
    }

    fn join_requests(&mut self, now: Instant) {
        let mut requests: Vec<Event> = Vec::new();
        if self.ready(now) {
            requests.append(&mut self.early_requests);
        }
        while let Ok(e) = self.requests.try_recv() {
            requests.push(e);
        }
        for event in requests {
            if !self.ready(now) {
                if self.early_requests.len() < MAX_JOINERS {
                    self.early_requests.push(event);
                }
                continue;
            }
            self.join_request(now, &event);
        }
    }

    fn join_request(&mut self, now: Instant, event: &Event) {
        let Some(Message::Request {
            attempt,
            game_id,
            version,
            protocol,
            player_name,
            ice,
        }) = handshake::open(&self.keys, event)
        else {
            return;
        };
        let config = &self.inner.config;
        if game_id != config.game_id {
            return;
        }
        let from = event.pubkey;
        if let Some(j) = self.joiners.get(&from)
            && j.attempt == attempt
        {
            // The joiner did not hear the answer yet.
            self.inner.signal.publish(j.accept.clone());
            return;
        }
        let refusal = if protocol != PROTOCOL || !config.is_compatible(&version) {
            Some(RefuseReason::IncompatibleVersion {
                host_version: config.game_version.clone(),
            })
        } else if !self.listing.joinable {
            Some(RefuseReason::NotAccepting)
        } else if self.joiners.len() >= MAX_JOINERS {
            Some(RefuseReason::Busy)
        } else {
            None
        };
        if let Some(reason) = refusal {
            info!("refusing {player_name} (version {version}): {reason:?}");
            let refuse = Message::Refuse {
                attempt,
                reason: reason.clone(),
            };
            if let Some(e) = handshake::seal(&self.keys, &from, &refuse) {
                self.inner.signal.publish(e);
            }
            self.events.push_back(HostEvent::JoinRefused {
                name: player_name,
                reason,
            });
            return;
        }
        let mut link = Link::new(false, &self.candidates());
        link.set_remote(&ice);
        let accept = Message::Accept {
            attempt: attempt.clone(),
            ice: link.params(),
        };
        let Some(accept) = handshake::seal(&self.keys, &from, &accept) else {
            return;
        };
        info!(
            "{player_name} is joining: checking {} addresses",
            link.remote_candidates()
        );
        self.inner.signal.publish(accept.clone());
        self.joiners.insert(
            from,
            Joiner {
                attempt,
                name: player_name,
                link,
                started: now,
                accept,
                connected_at: None,
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
            match j.connected_at {
                Some(t) if now - t > LINGER => done.push(*key),
                None if now - j.started > timeout => {
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
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // Replace the listing with a tombstone so that browsers drop it now, not at expiry.
        let (config, previous) = (&self.inner.config, self.last_listing);
        if previous.is_some()
            && let Some(e) = listing_event(config, &self.keys, &self.listing, true, previous)
        {
            self.inner.signal.publish(e);
        }
        self.inner
            .signal
            .send(Command::Unsubscribe(self.subscription.clone()));
        // Dropping `_port_mapping_stop` removes the port mapping.
    }
}
