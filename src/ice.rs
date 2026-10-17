//! Connectivity checks between a host and a joiner, with str0m's sans-IO ICE agent (`is`).
//!
//! Each side offers its candidates (LAN and IPv6 addresses, the address STUN servers saw, the
//! router's mapped port), then both send STUN checks to every pair at once. The simultaneous
//! checks open both NATs' pinholes ("hole punching"); the joiner, controlling, nominates the
//! best pair that worked. The game's own socket carries the checks, so the pinholes are the
//! game's.
//!
//! Beyond the usual candidates, a side behind a router with guessable ports offers the ports it
//! will probably get next ("predicted"), and a host with a TURN relay offers the relayed
//! address, the lowest-priority candidate of all. Sans-IO: the owner sends what
//! [`Link::poll_transmit`] returns, through the relay when it says so.

use std::net::SocketAddr;
#[cfg(test)]
use std::net::UdpSocket;
use std::time::Instant;

use is::stun::{StunMessage, StunPacket};
use is::{Candidate, IceAgent, IceAgentEvent, IceCreds, Protocol};
use tracing::{debug, trace};

use crate::handshake::IceParams;
use crate::net::{self, LocalAddr};

/// The addresses a side can offer.
#[derive(Clone, Debug, Default)]
pub(crate) struct LocalCandidates {
    /// The machine's addresses (host candidates, at `port`).
    pub addrs: Vec<LocalAddr>,
    /// The socket's port.
    pub port: u16,
    /// Public addresses for the socket: from STUN, or the router's port mapping.
    pub reflexive: Vec<SocketAddr>,
    /// Public addresses the router will probably give the socket for new destinations.
    pub predicted: Vec<SocketAddr>,
    /// The TURN relay's address for this side, if it has one.
    pub relay: Option<SocketAddr>,
}

impl LocalCandidates {
    /// The local address a public address belongs to: one of the same family, preferring the
    /// default interface.
    fn base_for(&self, public: SocketAddr) -> Option<SocketAddr> {
        let family = || {
            self.addrs
                .iter()
                .filter(|a| a.ip.is_ipv4() == public.is_ipv4())
        };
        family()
            .find(|a| a.default)
            .or_else(|| family().next())
            .map(|a| SocketAddr::new(a.ip, self.port))
    }
}

/// One side of a connection attempt.
pub(crate) struct Link {
    /// The ICE agent, which knows both sides' candidates and runs the checks.
    agent: IceAgent,
    /// This machine's addresses, to guess which one a check arrived on.
    locals: Vec<LocalAddr>,
    /// The socket's port.
    port: u16,
    /// The relayed address, if this side offers one.
    relay: Option<SocketAddr>,
    /// The nominated pair, once there is one.
    nominated: Option<Nominated>,
}

/// A link's nominated pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nominated {
    /// The peer's address.
    pub(crate) peer: SocketAddr,
    /// The pair runs through this side's TURN relay.
    pub(crate) relayed: bool,
}

/// A datagram for the link's owner to send.
#[derive(Debug)]
pub(crate) struct Transmit {
    /// To whom.
    pub(crate) to: SocketAddr,
    /// It goes through this side's TURN relay, not straight from the socket.
    pub(crate) relayed: bool,
    /// What.
    pub(crate) data: Vec<u8>,
}

impl Link {
    /// A link offering `locals`. The joiner is `controlling`: it picks the pair.
    pub(crate) fn new(controlling: bool, locals: &LocalCandidates) -> Link {
        let mut agent = IceAgent::new(IceCreds::new());
        agent.set_controlling(controlling);
        agent.set_control_tie_breaker(rand::random());
        for a in &locals.addrs {
            let addr = SocketAddr::new(a.ip, locals.port);
            match Candidate::host(addr, "udp") {
                Ok(c) => {
                    agent.add_local_candidate(c);
                }
                Err(e) => debug!("skipping local address {addr}: {e}"),
            }
        }
        // Predicted ones after the seen ones: they get lower priorities.
        for &public in locals.reflexive.iter().chain(&locals.predicted) {
            let Some(base) = locals.base_for(public) else {
                continue;
            };
            if public == base {
                continue;
            }
            if let Ok(c) = Candidate::server_reflexive(public, base, "udp") {
                agent.add_local_candidate(c);
            }
        }
        if let Some(relay) = locals.relay
            && let Some(base) = locals.base_for(relay)
            && let Ok(c) = Candidate::relayed(relay, base, "udp")
        {
            agent.add_local_candidate(c);
        }
        Link {
            agent,
            locals: locals.addrs.clone(),
            port: locals.port,
            relay: locals.relay,
            nominated: None,
        }
    }

    /// The credentials and candidates to send to the other side.
    pub(crate) fn params(&self) -> IceParams {
        let creds = self.agent.local_credentials();
        IceParams {
            ufrag: creds.ufrag.clone(),
            pwd: creds.pass.clone(),
            candidates: self
                .agent
                .local_candidates()
                .map(|c| c.to_sdp_string())
                .collect(),
            nat: None,
        }
    }

    /// How many remote candidates were offered.
    pub(crate) fn remote_candidates(&self) -> usize {
        self.agent.remote_candidates().count()
    }

    /// Takes the other side's credentials and candidates; checks start.
    pub(crate) fn set_remote(&mut self, params: &IceParams) {
        self.agent.set_remote_credentials(IceCreds {
            ufrag: params.ufrag.clone(),
            pass: params.pwd.clone(),
        });
        // A small cap on what a peer can make us check (predicted ports included).
        for sdp in params.candidates.iter().take(MAX_REMOTE_CANDIDATES) {
            match Candidate::from_sdp_string(sdp) {
                Ok(c) if c.proto() == Protocol::Udp => self.agent.add_remote_candidate(c),
                Ok(_) => {}
                Err(e) => debug!("bad remote candidate {sdp:?}: {e}"),
            }
        }
    }

    /// Whether this link's agent takes `msg` (a check for it, or an answer to its own).
    pub(crate) fn accepts(&self, msg: &StunMessage<'_>) -> bool {
        self.agent.accepts_message(msg)
    }

    /// Feeds a STUN message received from `from`.
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the agent takes the message by value"
    )]
    pub(crate) fn handle(&mut self, now: Instant, from: SocketAddr, msg: StunMessage<'_>) {
        let from = net::canonical(from);
        let Some(dest) = net::guess_destination(&self.locals, from.ip()) else {
            return;
        };
        self.agent.handle_packet(
            now,
            StunPacket {
                proto: Protocol::Udp,
                source: from,
                destination: SocketAddr::new(dest, self.port),
                message: msg,
            },
        );
    }

    /// Feeds a STUN message that came through this side's TURN relay from `from`.
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the agent takes the message by value"
    )]
    pub(crate) fn handle_relayed(&mut self, now: Instant, from: SocketAddr, msg: StunMessage<'_>) {
        let Some(relay) = self.relay else { return };
        self.agent.handle_packet(
            now,
            StunPacket {
                proto: Protocol::Udp,
                source: net::canonical(from),
                destination: relay,
                message: msg,
            },
        );
    }

    /// Runs the agent's timers.
    pub(crate) fn drive(&mut self, now: Instant) {
        self.agent.handle_timeout(now);
        while let Some(event) = self.agent.poll_event() {
            if let IceAgentEvent::NominatedSend {
                source,
                destination,
                ..
            } = event
            {
                let relayed = Some(source) == self.relay;
                debug!(
                    "ICE nominated {destination}{}",
                    if relayed { " (relayed)" } else { "" }
                );
                self.nominated = Some(Nominated {
                    peer: net::canonical(destination),
                    relayed,
                });
            }
        }
    }

    /// The next datagram to send.
    pub(crate) fn poll_transmit(&mut self) -> Option<Transmit> {
        let t = self.agent.poll_transmit()?;
        trace!("ICE {} -> {}", t.source, t.destination);
        Some(Transmit {
            to: net::canonical(t.destination),
            relayed: Some(t.source) == self.relay,
            data: t.contents.to_vec(),
        })
    }

    /// Runs the timers and sends the checks from `socket` (none may need the relay).
    #[cfg(test)]
    pub(crate) fn drive_on(&mut self, now: Instant, socket: &UdpSocket) {
        self.drive(now);
        while let Some(t) = self.poll_transmit() {
            let _ = net::send_to(socket, &t.data, t.to);
        }
        self.drive(now);
    }

    /// The nominated pair, once there is one.
    pub(crate) fn nominated(&self) -> Option<Nominated> {
        self.nominated
    }
}

/// The most candidates taken from a peer.
const MAX_REMOTE_CANDIDATES: usize = 40;

/// Parses a datagram as a STUN message with ICE credentials.
pub(crate) fn parse(data: &[u8]) -> Option<StunMessage<'_>> {
    StunMessage::parse(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn loopback() -> LocalCandidates {
        LocalCandidates {
            addrs: vec![LocalAddr {
                ip: "127.0.0.1".parse().unwrap(),
                prefix: 8,
                default: true,
            }],
            port: 0,
            ..LocalCandidates::default()
        }
    }

    /// Two links on two localhost sockets find each other.
    #[test]
    fn links_connect_on_localhost() {
        let sockets: Vec<UdpSocket> = (0..2)
            .map(|_| {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.set_nonblocking(true).unwrap();
                s
            })
            .collect();
        let mut links: Vec<Link> = sockets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut c = loopback();
                c.port = s.local_addr().unwrap().port();
                Link::new(i == 0, &c)
            })
            .collect();
        let (p0, p1) = (links[0].params(), links[1].params());
        links[0].set_remote(&p1);
        links[1].set_remote(&p0);
        let start = Instant::now();
        let mut buf = [0u8; 1500];
        while links.iter().any(|l| l.nominated().is_none()) {
            assert!(start.elapsed() < Duration::from_secs(5), "no nomination");
            let now = Instant::now();
            for (link, socket) in links.iter_mut().zip(&sockets) {
                while let Ok((n, from)) = socket.recv_from(&mut buf) {
                    if let Some(msg) = parse(&buf[..n])
                        && link.accepts(&msg)
                    {
                        link.handle(now, from, msg);
                    }
                }
                link.drive_on(now, socket);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let peer = |l: &Link| l.nominated().map(|n| n.peer);
        assert_eq!(peer(&links[0]), Some(sockets[1].local_addr().unwrap()));
        assert_eq!(peer(&links[1]), Some(sockets[0].local_addr().unwrap()));
    }
}
