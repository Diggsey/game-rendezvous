//! Finding a path to one peer: ICE first, then, if it found none and the two routers call for
//! it, punching by the birthday paradox ([`punch`](crate::punch)).
//!
//! Both sides know both routers' summaries (they are swapped with the candidates), so both
//! decide the same fallback without talking about it: when ICE has found nothing for
//! [`ICE_ALONE`], the strict side opens its extra sockets and the lenient side starts probing.
//! Two strict sides are left to a TURN relay. The cheap fallbacks, the ports a strict router
//! will probably hand out next, are ICE candidates from the start (see [`ice`](crate::ice)).
//!
//! Sans-IO, like its parts: sockets are numbers ([`MAIN`] is the game's), and a datagram may
//! go through the host's TURN relay.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use is::CandidateKind;
use tracing::debug;

use crate::handshake::IceParams;
use crate::ice::{self, Link, LocalCandidates};
use crate::nat::{NatMapping, NatSummary, PortAllocation};
use crate::punch::{self, Birthday, Creds, Role, SocketId};

pub(crate) use crate::punch::MAIN;

/// How long ICE runs alone before a fallback starts.
pub(crate) const ICE_ALONE: Duration = Duration::from_secs(4);
/// How many ports beyond the last one seen a sequential router's side offers.
pub(crate) const PREDICTION_WINDOW: usize = 10;

/// Which way a datagram goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Via {
    /// From one of this side's sockets.
    Socket(SocketId),
    /// Through this side's TURN relay (from the game's socket, wrapped).
    Relay,
}

/// A datagram to send.
#[derive(Debug)]
pub(crate) struct Transmit {
    /// Which way.
    pub(crate) via: Via,
    /// To whom.
    pub(crate) to: SocketAddr,
    /// What.
    pub(crate) data: Vec<u8>,
}

/// The path found to the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    /// Which way this side sends.
    pub(crate) via: Via,
    /// The peer's address.
    pub(crate) peer: SocketAddr,
}

/// A connection attempt with one peer: see the module documentation.
pub(crate) struct Traversal {
    /// ICE.
    link: Link,
    /// The joiner controls.
    controlling: bool,
    /// This side's router.
    my_nat: Option<NatSummary>,
    /// The peer's router, once known.
    their_nat: Option<NatSummary>,
    /// The punching this side would do, decided when the peer's candidates came.
    plan: Option<Role>,
    /// Both sides' ICE credentials, for the punching.
    creds: Option<Creds>,
    /// When ICE started.
    started: Option<Instant>,
    /// The punching, once started.
    birthday: Option<Birthday>,
    /// The strict side waits for its owner to open this many sockets.
    wants_sockets: Option<usize>,
    /// Picks the probes' ports.
    seed: u64,
}

impl Traversal {
    /// A traversal offering `locals`; the joiner is `controlling`.
    pub(crate) fn new(
        controlling: bool,
        locals: &LocalCandidates,
        my_nat: Option<NatSummary>,
    ) -> Traversal {
        Traversal {
            link: Link::new(controlling, locals),
            controlling,
            my_nat,
            their_nat: None,
            plan: None,
            creds: None,
            started: None,
            birthday: None,
            wants_sockets: None,
            seed: rand::random(),
        }
    }

    /// Fixes the probes' ports, for tests.
    #[cfg(test)]
    pub(crate) fn set_seed(&mut self, seed: u64) {
        self.seed = seed;
    }

    /// This side's credentials, candidates and router summary, for the peer.
    pub(crate) fn params(&self) -> IceParams {
        let mut p = self.link.params();
        p.nat = self.my_nat.map(|n| n.to_string());
        p
    }

    /// How many candidates the peer offered.
    pub(crate) fn remote_candidates(&self) -> usize {
        self.link.remote_candidates()
    }

    /// The peer's router, as it said.
    pub(crate) fn their_nat(&self) -> Option<NatSummary> {
        self.their_nat
    }

    /// Takes the peer's side; the checks start, and the fallback is decided.
    pub(crate) fn set_remote(&mut self, now: Instant, params: &IceParams) {
        self.link.set_remote(params);
        self.their_nat = crate::nat::parse_summary(params.nat.as_deref());
        let mine = self.link.params();
        self.creds = Some(Creds {
            my_ufrag: mine.ufrag,
            my_pwd: mine.pwd,
            their_ufrag: params.ufrag.clone(),
            their_pwd: params.pwd.clone(),
        });
        self.plan = match (self.my_nat, self.their_nat) {
            (Some(me), Some(them)) => plan(me, them, &public_ipv4(params)),
            _ => None,
        };
        if let Some(p) = &self.plan {
            debug!("if ICE finds no path: {p:?}");
        }
        self.started = Some(now);
    }

    /// When the attempt gives up: ICE's time, and the punching's if there may be some.
    pub(crate) fn deadline(&self, connect_timeout: Duration) -> Option<Instant> {
        let extra = if self.plan.is_some() {
            punch::DURATION.saturating_sub(connect_timeout.saturating_sub(ICE_ALONE))
        } else {
            Duration::ZERO
        };
        self.started.map(|t| t + connect_timeout + extra)
    }

    /// Whether a fallback is planned should ICE find nothing.
    pub(crate) fn plans_fallback(&self) -> bool {
        self.plan.is_some()
    }

    /// Whether the punching is under way, without a path yet.
    pub(crate) fn punching(&self) -> bool {
        (self.birthday.is_some() || self.wants_sockets.is_some()) && self.route().is_none()
    }

    /// Both routers are strict: only a relay could connect them.
    pub(crate) fn needs_relay(&self) -> bool {
        matches!((self.my_nat, self.their_nat), (Some(a), Some(b)) if !a.open && !b.open && strict(a) && strict(b))
    }

    /// Takes a datagram that came on `socket` from `from`. Returns whether it was this
    /// attempt's.
    pub(crate) fn handle(
        &mut self,
        now: Instant,
        socket: SocketId,
        from: SocketAddr,
        data: &[u8],
    ) -> bool {
        if let Some(b) = &mut self.birthday
            && b.handle(now, socket, from, data)
        {
            return true;
        }
        if socket != MAIN {
            return false;
        }
        match ice::parse(data) {
            Some(msg) if self.link.accepts(&msg) => {
                self.link.handle(now, from, msg);
                true
            }
            _ => false,
        }
    }

    /// Takes a STUN message that came through this side's TURN relay from `from`.
    pub(crate) fn handle_relayed(&mut self, now: Instant, from: SocketAddr, data: &[u8]) -> bool {
        match ice::parse(data) {
            Some(msg) if self.link.accepts(&msg) => {
                self.link.handle_relayed(now, from, msg);
                true
            }
            _ => false,
        }
    }

    /// Whether a datagram is this attempt's, without taking it.
    pub(crate) fn accepts(&self, data: &[u8]) -> bool {
        self.birthday.as_ref().is_some_and(|b| b.accepts(data))
            || ice::parse(data).is_some_and(|m| self.link.accepts(&m))
    }

    /// Runs the timers, and starts the fallback when due.
    pub(crate) fn drive(&mut self, now: Instant) {
        self.link.drive(now);
        if self.link.nominated().is_none()
            && self.birthday.is_none()
            && self.wants_sockets.is_none()
            && self.started.is_some_and(|t| now >= t + ICE_ALONE)
        {
            match self.plan.clone() {
                Some(Role::Strict { .. }) => self.wants_sockets = Some(punch::SOCKETS),
                Some(role @ Role::Lenient { .. }) => self.start_birthday(now, role, vec![MAIN]),
                None => {}
            }
        }
        if let Some(b) = &mut self.birthday {
            b.drive(now);
        }
    }

    /// The strict side's extra sockets, when it wants them: the owner opens them and calls
    /// [`sockets_opened`](Self::sockets_opened).
    pub(crate) fn wants_sockets(&mut self) -> Option<usize> {
        self.wants_sockets.take()
    }

    /// The extra sockets are open (as many as could be): the punching starts.
    pub(crate) fn sockets_opened(&mut self, now: Instant, ids: Vec<SocketId>) {
        if let Some(role) = self.plan.clone()
            && !ids.is_empty()
        {
            self.start_birthday(now, role, ids);
        }
    }

    /// Starts punching.
    fn start_birthday(&mut self, now: Instant, role: Role, sockets: Vec<SocketId>) {
        if let Some(creds) = self.creds.clone() {
            self.birthday = Some(Birthday::new(
                now,
                role,
                self.controlling,
                creds,
                sockets,
                self.seed,
            ));
        }
    }

    /// The next datagram to send.
    pub(crate) fn poll_transmit(&mut self) -> Option<Transmit> {
        if let Some(t) = self.link.poll_transmit() {
            return Some(Transmit {
                via: if t.relayed {
                    Via::Relay
                } else {
                    Via::Socket(MAIN)
                },
                to: t.to,
                data: t.data,
            });
        }
        let t = self.birthday.as_mut()?.poll_transmit()?;
        Some(Transmit {
            via: Via::Socket(t.socket),
            to: t.to,
            data: t.data,
        })
    }

    /// The path found, once there is one: ICE's, else the punching's.
    pub(crate) fn route(&self) -> Option<Route> {
        if let Some(n) = self.link.nominated() {
            return Some(Route {
                via: if n.relayed {
                    Via::Relay
                } else {
                    Via::Socket(MAIN)
                },
                peer: n.peer,
            });
        }
        let p = self.birthday.as_ref()?.nominated()?;
        Some(Route {
            via: Via::Socket(p.socket),
            peer: p.peer,
        })
    }
}

/// Whether a router gives each destination its own port.
fn strict(n: NatSummary) -> bool {
    matches!(n.mapping, NatMapping::EndpointDependent(_))
}

/// Whether a router keeps one port for every destination (or there is none).
fn lenient(n: NatSummary) -> bool {
    matches!(
        n.mapping,
        NatMapping::Open | NatMapping::EndpointIndependent
    )
}

/// The punching this side (`me`) does if ICE fails, given the peer's router and public IPv4
/// addresses: only for one random-port router facing a lenient one, neither reachable anyway.
fn plan(me: NatSummary, them: NatSummary, their_public: &[SocketAddr]) -> Option<Role> {
    if me.open || them.open || their_public.is_empty() {
        return None;
    }
    let random = |n: NatSummary| n.mapping == NatMapping::EndpointDependent(PortAllocation::Random);
    if random(me) && lenient(them) {
        Some(Role::Strict {
            targets: their_public.to_vec(),
        })
    } else if lenient(me) && random(them) {
        Some(Role::Lenient {
            strict_ip: their_public[0].ip(),
        })
    } else {
        None
    }
}

/// The public IPv4 addresses (server-reflexive candidates) among `params`'s candidates.
fn public_ipv4(params: &IceParams) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for sdp in &params.candidates {
        if let Ok(c) = is::Candidate::from_sdp_string(sdp)
            && c.kind() == CandidateKind::ServerReflexive
            && c.addr().is_ipv4()
            && !out
                .iter()
                .any(|a| a.ip() == c.addr().ip() && a.port() == c.addr().port())
        {
            out.push(c.addr());
        }
    }
    // A lenient router shows one address; a second covers a multi-homed peer. More would
    // multiply the strict side's traffic.
    out.truncate(2);
    out
}
