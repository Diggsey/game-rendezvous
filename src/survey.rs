//! Learning what a socket looks like from outside, for a host or a check before hosting: its
//! public addresses and the router's mapping (STUN), the router's port forwarding, and a TURN
//! relay, all on the game thread over the socket in question. See [`nat`](crate::nat) for what
//! the findings mean.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::Inner;
use crate::nat::{self, NatMapping, NatReport};
use crate::net::LocalAddr;
use crate::portmap::{PortMapEvent, PortMapMethod};
use crate::stun::Gatherer;
use crate::turn::{TurnClient, TurnEvent};
use crate::worker::{self, Command, Inbox, ResolvedTurn};

/// How often the public address is checked again. This also keeps the router's mapping for
/// the socket alive while nobody is connected.
const REGATHER: Duration = Duration::from_secs(25);

/// What the survey found out, for the host's events.
#[derive(Debug)]
pub(crate) enum Finding {
    /// The router was (or could not be) asked to forward the port.
    PortMapping(PortMapEvent),
    /// The TURN relay was allocated (`Ok`) or not.
    Relay(Result<SocketAddr, String>),
}

/// The survey: see the module documentation.
pub(crate) struct Survey {
    /// This machine's addresses.
    locals: Vec<LocalAddr>,
    /// The socket's port.
    port: u16,
    /// The address families the socket reaches.
    families: crate::net::Families,
    /// Gather again every [`REGATHER`] (a host), or once (a check).
    periodic: bool,
    /// Asking STUN servers, when under way.
    gatherer: Option<Gatherer>,
    /// When asking last finished.
    last_gather: Option<Instant>,
    /// The public addresses the servers saw, in the order asked.
    observed: Vec<SocketAddr>,
    /// The router's mapping, from them.
    mapping: NatMapping,
    /// What the router said about the port mapping.
    port_events: Option<Inbox<PortMapEvent>>,
    /// The router's public address (if it said), port and mapping protocol.
    port_mapping: Option<(Option<IpAddr>, u16, PortMapMethod)>,
    /// The router has answered (or the attempt failed).
    port_mapping_known: bool,
    /// Dropping it removes the port mapping.
    port_mapping_stop: Option<oneshot::Sender<()>>,
    /// The relays configured, tried in order.
    turn_configs: Vec<crate::config::TurnConfig>,
    /// The one in use or being set up.
    turn_index: usize,
    /// It has been set up again after it failed (new credentials, once).
    turn_retried: bool,
    /// The TURN server's credentials and address, being fetched.
    turn_setup: Option<Inbox<Result<ResolvedTurn, String>>>,
    /// The TURN client, once set up.
    turn: Option<TurnClient>,
    /// Why there is no relay, if there is none for good.
    turn_error: Option<String>,
    /// Findings not yet taken.
    findings: VecDeque<Finding>,
}

impl Survey {
    /// Starts surveying the socket on `port`: the port mapping and the TURN setup start now
    /// (if configured); STUN once the servers are resolved, when driven.
    pub(crate) fn new(
        inner: &Inner,
        socket: &std::net::UdpSocket,
        locals: Vec<LocalAddr>,
        periodic: bool,
    ) -> Survey {
        let port = socket.local_addr().map_or(0, |a| a.port());
        let (port_events, port_mapping_stop) = if inner.config.port_mapping {
            let (tx, rx) = worker::channel();
            let (stop_tx, stop) = oneshot::channel();
            inner.worker.send(Command::MapPort {
                port,
                events: tx,
                stop,
            });
            (Some(rx), Some(stop_tx))
        } else {
            (None, None)
        };
        let turn_configs = inner.config.turn.clone();
        let turn_setup = turn_configs
            .first()
            .map(|config| resolve(inner, config.clone()));
        Survey {
            locals,
            port,
            families: crate::net::Families::of(socket),
            periodic,
            gatherer: None,
            last_gather: None,
            observed: Vec::new(),
            mapping: NatMapping::Unknown,
            port_mapping_known: port_events.is_none(),
            port_events,
            port_mapping: None,
            port_mapping_stop,
            turn_configs,
            turn_index: 0,
            turn_retried: false,
            turn_setup,
            turn: None,
            turn_error: None,
            findings: VecDeque::new(),
        }
    }

    /// Takes a STUN datagram from `from` if it is the survey's (a STUN server's or the TURN
    /// server's answer). A Data indication from the TURN server comes back unwrapped.
    pub(crate) fn handle(&mut self, now: Instant, from: SocketAddr, data: &[u8]) -> Handled {
        if let Some(g) = &mut self.gatherer
            && g.handle(now, data)
        {
            return Handled::Taken;
        }
        if let Some(t) = &mut self.turn
            && t.server() == from
        {
            return match t.handle(now, data) {
                Some(r) => Handled::Relayed(r.peer, r.data),
                None => Handled::Taken,
            };
        }
        Handled::NotMine
    }

    /// Does what is due: STUN requests, TURN requests and renewals, and takes in the router's
    /// and the worker's answers. Sends with `send`.
    pub(crate) fn drive(
        &mut self,
        inner: &Inner,
        now: Instant,
        send: &mut dyn FnMut(&[u8], SocketAddr),
    ) {
        self.gather(inner, now, send);
        self.port_mapping_events();
        self.turn_setup(inner, now);
        let mut failed = None;
        if let Some(t) = &mut self.turn {
            t.handle_timeout(now);
            while let Some(msg) = t.poll_transmit() {
                send(&msg, t.server());
            }
            while let Some(e) = t.poll_event() {
                match e {
                    TurnEvent::Allocated { relayed, .. } => {
                        self.turn_retried = false;
                        self.findings.push_back(Finding::Relay(Ok(relayed)));
                    }
                    TurnEvent::Failed(why) => failed = Some(why),
                }
            }
        }
        if let Some(why) = failed {
            self.turn = None;
            self.turn_failed(inner, why);
        }
    }

    /// The relay in use failed, or could not be set up: a provider's is tried once more with
    /// new credentials (they may have expired), then the next relay. The failure is reported
    /// (and the relayed address withdrawn) only when no relay is left.
    fn turn_failed(&mut self, inner: &Inner, why: String) {
        info!("TURN relay {} failed: {why}", self.turn_index + 1);
        let provider = matches!(
            self.turn_configs.get(self.turn_index),
            Some(crate::config::TurnConfig::Provider(_))
        );
        if provider && !self.turn_retried {
            self.turn_retried = true;
        } else {
            self.turn_index += 1;
            self.turn_retried = false;
        }
        if let Some(config) = self.turn_configs.get(self.turn_index) {
            self.turn_setup = Some(resolve(inner, config.clone()));
        } else {
            self.findings.push_back(Finding::Relay(Err(why.clone())));
            self.turn_error = Some(why);
        }
    }

    /// Asks the STUN servers (again), and takes in their answers when done.
    fn gather(&mut self, inner: &Inner, now: Instant, send: &mut dyn FnMut(&[u8], SocketAddr)) {
        let due = match self.last_gather {
            None => true,
            Some(t) => self.periodic && now - t >= REGATHER,
        };
        if self.gatherer.is_none() && due {
            let Some(servers) = inner.worker.stun_servers() else {
                return; // still resolving
            };
            let families = self.families;
            let servers = servers
                .into_iter()
                .filter(|s| families.reaches(s.ip()))
                .collect();
            self.gatherer = Some(Gatherer::new(servers, now, inner.config.gather_timeout));
        }
        let Some(g) = &mut self.gatherer else { return };
        for (server, request) in g.poll_transmit(now) {
            send(&request, server);
        }
        if g.is_done(now) {
            let observed = g.observed();
            if !observed.is_empty() || self.last_gather.is_none() {
                let mapping = nat::classify(&observed, self.port, &self.locals);
                if observed != self.observed || mapping != self.mapping {
                    info!("public addresses: {observed:?} ({mapping:?})");
                }
                // A regather that sees fewer servers keeps the better classification.
                if mapping != NatMapping::Unknown || self.mapping == NatMapping::Unknown {
                    self.mapping = mapping;
                }
                self.observed = observed;
            }
            self.gatherer = None;
            self.last_gather = Some(now);
        }
    }

    /// Takes in what the router said about the port mapping.
    fn port_mapping_events(&mut self) {
        let Some(events) = &mut self.port_events else {
            return;
        };
        while let Ok(e) = events.try_recv() {
            self.port_mapping_known = true;
            match &e {
                PortMapEvent::Mapped {
                    external_ip,
                    external_port,
                    method,
                } => self.port_mapping = Some((*external_ip, *external_port, *method)),
                PortMapEvent::Lost(_) => self.port_mapping = None,
                PortMapEvent::Failed(_) => {}
            }
            self.findings.push_back(Finding::PortMapping(e));
        }
    }

    /// Starts the TURN client once the worker has the server's address and credentials.
    fn turn_setup(&mut self, inner: &Inner, now: Instant) {
        let Some(setup) = &mut self.turn_setup else {
            return;
        };
        match setup.try_recv() {
            Ok(Ok(r)) => {
                debug!(
                    "TURN relay {}: allocating on {}",
                    self.turn_index + 1,
                    r.server
                );
                let mut client = TurnClient::new(r.server, r.username, r.password);
                client.start(now);
                self.turn = Some(client);
                self.turn_setup = None;
            }
            Ok(Err(why)) => {
                self.turn_setup = None;
                self.turn_failed(inner, why);
            }
            Err(_) => {}
        }
    }

    /// The next finding.
    pub(crate) fn poll_finding(&mut self) -> Option<Finding> {
        self.findings.pop_front()
    }

    /// The public addresses are known (or could not be learned).
    pub(crate) fn gathered(&self) -> bool {
        self.last_gather.is_some()
    }

    /// Everything asked has been answered: STUN, the router, and the relay.
    pub(crate) fn complete(&self) -> bool {
        let turn_known = self.turn_setup.is_none()
            && self
                .turn
                .as_ref()
                .is_none_or(|t| t.relayed().is_some() || t.failure().is_some());
        self.gathered() && self.port_mapping_known && turn_known
    }

    /// The TURN client, if the relay is set up.
    pub(crate) fn turn(&mut self) -> Option<&mut TurnClient> {
        self.turn.as_mut()
    }

    /// The relayed address, while allocated.
    pub(crate) fn relay(&self) -> Option<SocketAddr> {
        self.turn.as_ref().and_then(TurnClient::relayed)
    }

    /// Why there is no relay, if one was configured and failed.
    pub(crate) fn relay_error(&self) -> Option<&str> {
        self.turn_error
            .as_deref()
            .or_else(|| self.turn.as_ref().and_then(TurnClient::failure))
    }

    /// The router's forwarded address and protocol, unless carrier-grade NAT makes it useless.
    fn mapped_address(&self, carrier_grade: bool) -> Option<(SocketAddr, PortMapMethod)> {
        let (ip, port, method) = self.port_mapping?;
        if carrier_grade {
            return None;
        }
        // NAT-PMP does not say the public address; STUN does.
        let ip = ip.or_else(|| {
            self.observed
                .iter()
                .find(|a| a.is_ipv4())
                .map(SocketAddr::ip)
        })?;
        Some((SocketAddr::new(ip, port), method))
    }

    /// The findings so far.
    pub(crate) fn report(&self) -> NatReport {
        let carrier_grade = nat::carrier_grade(
            self.port_mapping.and_then(|(ip, _, _)| ip),
            &self.observed,
            &self.locals,
        );
        NatReport {
            mapping: self.mapping,
            public_addresses: self.observed.clone(),
            carrier_grade,
            port_mapping: self.mapped_address(carrier_grade),
            global_ipv6: nat::global_ipv6(&self.locals),
            relay: self.relay(),
        }
    }

    /// The public addresses to offer joiners: the forwarded port first (it works whatever the
    /// joiner's router does), then what STUN servers saw.
    pub(crate) fn reflexive(&self) -> Vec<SocketAddr> {
        let report = self.report();
        let mut out = self.observed.clone();
        if let Some((addr, _)) = report.port_mapping
            && !out.contains(&addr)
        {
            out.insert(0, addr);
        }
        out
    }

    /// The public addresses the router will probably hand out next.
    pub(crate) fn predicted(&self) -> Vec<SocketAddr> {
        let Some(ip) = self
            .observed
            .iter()
            .find(|a| a.is_ipv4())
            .map(SocketAddr::ip)
        else {
            return Vec::new();
        };
        nat::predicted_ports(
            self.mapping,
            &self.observed,
            self.port,
            crate::traverse::PREDICTION_WINDOW,
        )
        .into_iter()
        .map(|p| SocketAddr::new(ip, p))
        .filter(|a| !self.observed.contains(a))
        .collect()
    }

    /// Frees the relay and stops the port mapping.
    pub(crate) fn close(&mut self, now: Instant, send: &mut dyn FnMut(&[u8], SocketAddr)) {
        if let Some(t) = &mut self.turn {
            t.close(now);
            while let Some(msg) = t.poll_transmit() {
                send(&msg, t.server());
            }
        }
        self.port_mapping_stop = None;
    }
}

/// What became of a datagram offered to the survey.
pub(crate) enum Handled {
    /// It was not the survey's.
    NotMine,
    /// The survey took it.
    Taken,
    /// The TURN server passed on a peer's datagram in a Data indication.
    Relayed(SocketAddr, Vec<u8>),
}

/// Asks the worker for the server address and credentials of `config`.
fn resolve(
    inner: &Inner,
    config: crate::config::TurnConfig,
) -> Inbox<Result<ResolvedTurn, String>> {
    let (reply, rx) = worker::channel();
    inner.worker.send(Command::ResolveTurn { config, reply });
    rx
}
