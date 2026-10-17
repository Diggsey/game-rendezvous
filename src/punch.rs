//! Hole punching by the birthday paradox, for one side behind a router with random ports for
//! each destination ("strict") and the other behind one with a single port ("lenient"), when
//! ICE found no path. As Tailscale does it:
//!
//! - The strict side opens many sockets and sends from each to the lenient side's public
//!   address. Its router opens a port for each, at random; the lenient side's router drops
//!   them, but they leave the strict side's router expecting the lenient side.
//! - The lenient side sends probes to random ports on the strict side's public IP. One that
//!   lands on a port the strict side opened gets through, and its answer gets back.
//!
//! With 256 ports open and some 1,000 probes, a hit is nearly certain (98%); probes go at a
//! modest rate, up to a cap, for a bounded time. Two strict sides would need to meet both at
//! random; that is left to a TURN relay.
//!
//! The probes are STUN Binding requests carrying the receiver's ICE username fragment, signed
//! (MESSAGE-INTEGRITY) with its ICE password, which only the two sides know. The joiner,
//! controlling as in ICE, nominates the first path that worked both ways.
//!
//! Sans-IO: sockets are numbers the owner maps to real ones; [`MAIN`] is the game's.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tracing::{debug, info};

use crate::wire::{self, Builder, Class, Message, attr, method};

/// Identifies a socket: [`MAIN`], or one of the extra sockets the strict side opens.
pub(crate) type SocketId = usize;
/// The game's own socket.
pub(crate) const MAIN: SocketId = 0;

/// Extra sockets the strict side opens.
pub(crate) const SOCKETS: usize = 256;
/// Probes a second from the lenient side.
const PROBE_RATE: u32 = 150;
/// The most probes sent.
const MAX_PROBES: u32 = 1_400;
/// How long the punching goes on.
pub(crate) const DURATION: Duration = Duration::from_secs(10);
/// When the strict side's sockets send to the lenient side, from the start: enough to open
/// their ports (and again in case of loss) without much traffic.
const STRICT_ROUNDS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(1_500),
    Duration::from_secs(5),
];
/// How often a nomination is repeated until answered.
const NOMINATE_INTERVAL: Duration = Duration::from_millis(200);

/// Which side of the punching this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Many sockets, sending to the lenient side's public addresses.
    Strict {
        /// The lenient side's public IPv4 addresses.
        targets: Vec<SocketAddr>,
    },
    /// Probes to random ports on the strict side's public address.
    Lenient {
        /// The strict side's public IPv4 address.
        strict_ip: IpAddr,
    },
}

/// The two sides' ICE credentials, which sign the probes.
#[derive(Clone, Debug)]
pub(crate) struct Creds {
    /// This side's username fragment.
    pub(crate) my_ufrag: String,
    /// This side's password.
    pub(crate) my_pwd: String,
    /// The other side's username fragment.
    pub(crate) their_ufrag: String,
    /// The other side's password.
    pub(crate) their_pwd: String,
}

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transmit {
    /// From which socket.
    pub(crate) socket: SocketId,
    /// To whom.
    pub(crate) to: SocketAddr,
    /// What.
    pub(crate) data: Vec<u8>,
}

/// A path between the sides: a socket here, an address there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Path {
    /// This side's socket.
    pub(crate) socket: SocketId,
    /// The other side's address.
    pub(crate) peer: SocketAddr,
}

/// The punching: see the module documentation.
pub(crate) struct Birthday {
    /// This side's part.
    role: Role,
    /// The joiner controls: it nominates.
    controlling: bool,
    /// Both sides' credentials.
    creds: Creds,
    /// The sockets this side sends from.
    sockets: Vec<SocketId>,
    /// When it started.
    started: Instant,
    /// Strict side: rounds sent.
    rounds_sent: usize,
    /// Lenient side: probes sent.
    probes_sent: u32,
    /// Picks the probes' ports.
    rng: StdRng,
    /// Our requests awaiting answers, by transaction id.
    pending: HashMap<[u8; 12], Path>,
    /// The nomination being made (controlling side) and when it last went out.
    nominating: Option<(Path, [u8; 12], Instant)>,
    /// The path both sides use, once nominated.
    nominated: Option<Path>,
    /// Datagrams to send.
    outbox: VecDeque<Transmit>,
}

impl Birthday {
    /// Starts punching from `sockets` (the extra sockets on the strict side, [`MAIN`] on the
    /// lenient side). `seed` picks the probes' ports (random in use; fixed in tests).
    pub(crate) fn new(
        now: Instant,
        role: Role,
        controlling: bool,
        creds: Creds,
        sockets: Vec<SocketId>,
        seed: u64,
    ) -> Birthday {
        info!(
            "no direct path: punching through the {} side's router ({} sockets)",
            if matches!(role, Role::Strict { .. }) {
                "strict (our)"
            } else {
                "strict (their)"
            },
            sockets.len()
        );
        Birthday {
            role,
            controlling,
            creds,
            sockets,
            started: now,
            rounds_sent: 0,
            probes_sent: 0,
            rng: StdRng::seed_from_u64(seed),
            pending: HashMap::new(),
            nominating: None,
            nominated: None,
            outbox: VecDeque::new(),
        }
    }

    /// The path both sides use, once nominated.
    pub(crate) fn nominated(&self) -> Option<Path> {
        self.nominated
    }

    /// The next datagram to send.
    pub(crate) fn poll_transmit(&mut self) -> Option<Transmit> {
        self.outbox.pop_front()
    }

    /// A request to the other side: signed with its password, naming its ufrag.
    fn request(&mut self, path: Path, nominate: bool) -> [u8; 12] {
        let tid = wire::transaction_id();
        let data = self.message(Class::Request, tid, nominate);
        self.pending.insert(tid, path);
        self.outbox.push_back(Transmit {
            socket: path.socket,
            to: path.peer,
            data,
        });
        tid
    }

    /// A probe message of `class`.
    fn message(&self, class: Class, tid: [u8; 12], nominate: bool) -> Vec<u8> {
        let mut tag = self.creds.their_ufrag.as_bytes().to_vec();
        tag.push(u8::from(nominate));
        Builder::new(method::BINDING, class, tid)
            .attr(attr::PUNCH, &tag)
            .integrity(self.creds.their_pwd.as_bytes())
            .fingerprint()
    }

    /// Whether `data` is a probe meant for this side (signed by the other).
    pub(crate) fn accepts(&self, data: &[u8]) -> bool {
        Message::parse(data).is_some_and(|m| self.verify(&m).is_some())
    }

    /// The nominate flag of `msg` if it is a probe for this side, signed by the other.
    fn verify(&self, msg: &Message<'_>) -> Option<bool> {
        let tag = msg.get(attr::PUNCH)?;
        let (flag, ufrag) = tag.split_last()?;
        (msg.method == method::BINDING
            && ufrag == self.creds.my_ufrag.as_bytes()
            && msg.verify(self.creds.my_pwd.as_bytes()))
        .then_some(*flag == 1)
    }

    /// Takes a datagram that came on `socket` from `from`. Returns whether it was a probe.
    pub(crate) fn handle(
        &mut self,
        now: Instant,
        socket: SocketId,
        from: SocketAddr,
        data: &[u8],
    ) -> bool {
        let Some(msg) = Message::parse(data) else {
            return false;
        };
        let Some(nominate) = self.verify(&msg) else {
            return false;
        };
        let path = Path {
            socket,
            peer: crate::net::canonical(from),
        };
        match msg.class {
            Class::Request => {
                // Answer, and check the way back too.
                let reply = self.message(Class::Success, msg.tid, false);
                self.outbox.push_back(Transmit {
                    socket,
                    to: path.peer,
                    data: reply,
                });
                if nominate && !self.controlling && self.nominated.is_none() {
                    info!("punched through: {path:?}");
                    self.nominated = Some(path);
                } else if !self.pending.values().any(|p| *p == path) && self.nominated.is_none() {
                    self.request(path, false);
                }
            }
            Class::Success => {
                let Some(sent) = self.pending.remove(&msg.tid) else {
                    return true;
                };
                if sent != path {
                    return true;
                }
                if let Some((p, tid, _)) = self.nominating
                    && tid == msg.tid
                {
                    info!("punched through: {p:?}");
                    self.nominated = Some(p);
                } else if self.controlling && self.nominating.is_none() && self.nominated.is_none()
                {
                    debug!("punching: {path:?} works both ways; nominating it");
                    let tid = self.request(path, true);
                    self.nominating = Some((path, tid, now));
                }
            }
            _ => {}
        }
        true
    }

    /// Sends what is due by `now`.
    pub(crate) fn drive(&mut self, now: Instant) {
        if let Some((path, _, at)) = self.nominating
            && self.nominated.is_none()
            && now >= at + NOMINATE_INTERVAL
        {
            let tid = self.request(path, true);
            self.nominating = Some((path, tid, now));
        }
        if self.nominated.is_some() || self.nominating.is_some() || now >= self.started + DURATION {
            return;
        }
        let elapsed = now - self.started;
        match self.role.clone() {
            Role::Strict { targets } => {
                while self.rounds_sent < STRICT_ROUNDS.len()
                    && elapsed >= STRICT_ROUNDS[self.rounds_sent]
                {
                    self.rounds_sent += 1;
                    for socket in self.sockets.clone() {
                        for &peer in &targets {
                            self.request(Path { socket, peer }, false);
                        }
                    }
                }
            }
            Role::Lenient { strict_ip } => {
                let due = u32::try_from(elapsed.as_millis() * u128::from(PROBE_RATE) / 1000)
                    .unwrap_or(u32::MAX)
                    .min(MAX_PROBES);
                while self.probes_sent < due {
                    self.probes_sent += 1;
                    let port = self.rng.random_range(1024..=u16::MAX);
                    let path = Path {
                        socket: MAIN,
                        peer: SocketAddr::new(strict_ip, port),
                    };
                    self.request(path, false);
                }
            }
        }
    }
}
