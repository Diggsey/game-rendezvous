//! Joining: asking a host through the relays, then connecting directly.
//!
//! As for hosting, the game thread ([`Join`]) runs what needs the socket (the public address,
//! the connectivity checks), and a task on the worker ([`task`]) what needs the joiner's key
//! (sealing the request, opening the host's answer, telling the host when no path worked).

mod task;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Filter, Keys, SubscriptionId};
use tracing::{debug, info};

use crate::Inner;
use crate::error::JoinError;
use crate::handshake::{HANDSHAKE_KIND, Message};
use crate::ice::LocalCandidates;
use crate::listing::{GameInfo, PROTOCOL};
use crate::nat::{self, NatMapping, NatSummary};
use crate::net::{self, LocalAddr};
use crate::punch::{MAIN, SocketId};
use crate::stun::{self, Gatherer};
use crate::traverse::{PREDICTION_WINDOW, Traversal, Via};
use crate::worker::{self, Command, Inbox, Sink};
use task::{FromTask, JoinTask, ToTask};

/// After a path is found, how long the checks go on before the socket is handed over, so that
/// the host's side of it completes too.
const SETTLE: Duration = Duration::from_millis(300);
/// The most datagrams kept for the game from before the hand-over.
const MAX_EARLY_DATAGRAMS: usize = 64;
/// Room for the largest UDP payload, so that no datagram is too big to read.
const RECV_BUFFER: usize = 65_536;

/// How far a join has got, for showing to the player.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinStage {
    /// Asking STUN servers for this side's public address.
    Gathering,
    /// Waiting for the host to answer through the relays.
    WaitingForHost,
    /// Trying the paths between the two.
    Connecting,
    /// No ordinary path worked; punching through the strict router of one side, which may
    /// take a few more seconds.
    Punching,
}

/// A working connection to a host: send to `peer` from `socket`.
#[derive(Debug)]
#[non_exhaustive]
pub struct Connection {
    /// The socket a path worked on, non-blocking: the join's own (dual-stack sockets need
    /// [`send_to`](crate::send_to) for IPv4 peers and report them through
    /// [`canonical`](crate::canonical)), or, when this side's router hands out random ports
    /// and the path was punched through it, an IPv4 socket the library opened for that.
    pub socket: UdpSocket,
    /// The host's address on the path.
    pub peer: SocketAddr,
    /// Datagrams `peer` sent before the hand-over (once connected, the host's game may start
    /// talking while the checks settle), oldest first. Handle them before reading `socket`.
    pub received: Vec<Vec<u8>>,
}

/// Where a join is.
enum Stage {
    /// Asking STUN servers for the public address. The gatherer starts once the servers'
    /// names are resolved.
    Gathering(Option<Gatherer>),
    /// The request is out; waiting for the host's answer.
    WaitingForHost {
        /// When the request went out, then when a relay took it: the host's time to answer
        /// runs from there.
        since: Instant,
        /// A relay took the request.
        published: bool,
        /// Why the copies sent so far were not taken, while none has been.
        relay_errors: Option<String>,
    },
    /// Running the checks.
    Connecting,
    /// A path was found; the checks go on a moment for the host's side.
    Settling {
        /// When the path was found.
        since: Instant,
    },
    /// `poll` has returned the outcome.
    Finished,
}

/// A join in progress: call [`poll`](Join::poll) every frame until it returns the connection
/// or an error. Dropping it abandons the join.
pub struct Join {
    /// The configuration and worker.
    inner: Arc<Inner>,
    /// The socket, until it is handed over.
    socket: Option<UdpSocket>,
    /// Extra sockets opened for punching (socket `i + 1`).
    extra: Vec<Option<UdpSocket>>,
    /// Tells the host's answer to this attempt from another's.
    attempt: String,
    /// The player's name, for the host.
    player_name: String,
    /// This machine's addresses.
    locals: Vec<LocalAddr>,
    /// The socket's port.
    port: u16,
    /// Where the join is.
    stage: Stage,
    /// When the join began.
    started: Instant,
    /// The host's answers' subscription, closed when the join ends.
    subscription: SubscriptionId,
    /// Dropping it ends the worker task. `None` once the join has finished.
    to_task: Option<Sink<ToTask>>,
    /// The relays' and the host's answers, from the worker task.
    from_task: Inbox<FromTask>,
    /// The checks with the host, once this side's candidates are known.
    traversal: Option<Traversal>,
    /// This side's router, once gathered.
    nat: Option<NatSummary>,
    /// Datagrams that are not the library's, kept for the game: (socket, sender, payload).
    early: Vec<(SocketId, SocketAddr, Vec<u8>)>,
    /// Room to read a datagram into.
    buf: Box<[u8]>,
}

impl Join {
    /// Starts joining `game` from `socket`, unless the listing already rules it out.
    pub(crate) fn new(
        inner: Arc<Inner>,
        game: &GameInfo,
        player_name: &str,
        socket: UdpSocket,
    ) -> Result<Join, JoinError> {
        if !game.compatible {
            return Err(JoinError::IncompatibleVersion {
                ours: inner.config.game_version.clone(),
                theirs: game.version.clone(),
            });
        }
        if !game.joinable {
            return Err(JoinError::NotJoinable);
        }
        socket.set_nonblocking(true)?;
        let port = socket.local_addr()?.port();
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        let keys = Keys::generate();
        // No `since`: nothing can be addressed to a key made just now, and a `since` from this
        // clock would hide the answer of a host whose clock is behind.
        let filter = Filter::new()
            .kind(HANDSHAKE_KIND)
            .pubkey(keys.public_key())
            .author(game.id.0);
        let (subscription, replies) = inner.worker.subscribe(filter);
        let attempt = format!("{:016x}", rand::random::<u64>());
        let (to_task, commands) = worker::channel();
        let (notices, from_task) = worker::channel();
        let relay_parts = (game.id.0, attempt.clone(), inner.config.handshake_rate);
        inner.worker.spawn(move |ctx| {
            let (host, attempt, handshake_rate) = relay_parts;
            JoinTask {
                ctx,
                keys,
                host,
                attempt,
                handshake_rate,
                commands,
                replies,
                notices,
            }
            .run()
        });
        let now = Instant::now();
        info!("joining {} ({})", game.name, game.id);
        Ok(Join {
            inner,
            socket: Some(socket),
            extra: Vec::new(),
            attempt,
            player_name: player_name.to_string(),
            locals,
            port,
            stage: Stage::Gathering(None),
            started: now,
            subscription,
            to_task: Some(to_task),
            from_task,
            traversal: None,
            nat: None,
            early: Vec::new(),
            buf: vec![0; RECV_BUFFER].into_boxed_slice(),
        })
    }

    /// How far the join has got, for showing to the player.
    #[must_use]
    pub fn stage(&self) -> JoinStage {
        match self.stage {
            Stage::Gathering(_) => JoinStage::Gathering,
            Stage::WaitingForHost { .. } => JoinStage::WaitingForHost,
            Stage::Connecting | Stage::Settling { .. } | Stage::Finished => {
                if self.traversal.as_ref().is_some_and(Traversal::punching) {
                    JoinStage::Punching
                } else {
                    JoinStage::Connecting
                }
            }
        }
    }

    /// This side's router, once the STUN servers have answered.
    #[must_use]
    pub fn nat(&self) -> Option<NatSummary> {
        self.nat
    }

    /// Moves the join on. `Some` once it has finished: the connection, or why there is none.
    /// After that it returns `None`.
    pub fn poll(&mut self) -> Option<Result<Connection, JoinError>> {
        if matches!(self.stage, Stage::Finished) {
            return None;
        }
        let result = self.step(Instant::now());
        if let Some(r) = &result {
            if matches!(r, Err(JoinError::NoRoute { .. }))
                && let Some(to_task) = &self.to_task
            {
                // The host cannot tell this from a joiner that gave up.
                let _ = to_task.send(ToTask::Report(Message::Unreachable {
                    attempt: self.attempt.clone(),
                    nat: self.nat.map(|n| n.to_string()),
                }));
            }
            self.stage = Stage::Finished;
            // Stops the worker task (once it has sent any report).
            self.to_task = None;
            self.extra.clear();
            self.inner
                .worker
                .send(Command::Unsubscribe(self.subscription.clone()));
        }
        result
    }

    /// One poll's work; `Some` once the join has finished.
    fn step(&mut self, now: Instant) -> Option<Result<Connection, JoinError>> {
        if let Err(e) = self.receive(now) {
            return Some(Err(e));
        }
        self.drive(now);
        let mut public_addresses = None;
        match &mut self.stage {
            Stage::Gathering(gatherer) => {
                let socket = self.socket.as_ref()?;
                let deadline = self.started + self.inner.config.gather_timeout;
                if gatherer.is_none()
                    && let Some(servers) = self.inner.worker.stun_servers()
                {
                    let left = deadline.saturating_duration_since(now);
                    *gatherer = Some(Gatherer::for_socket(socket, servers, now, left));
                }
                if let Some(g) = gatherer {
                    g.send_due(now, socket);
                }
                let done = gatherer.as_ref().is_some_and(|g| g.is_done(now));
                if done || now >= deadline {
                    let observed = gatherer
                        .as_ref()
                        .map(Gatherer::observed)
                        .unwrap_or_default();
                    debug!("joiner public addresses: {observed:?}");
                    public_addresses = Some(observed);
                }
            }
            Stage::WaitingForHost {
                since,
                published,
                relay_errors,
            } => {
                let timeout = self.inner.config.handshake_timeout;
                if *published && now - *since > timeout {
                    return Some(Err(JoinError::HostNotResponding));
                }
                if !*published && now - *since > timeout * 2 {
                    let why = relay_errors
                        .take()
                        .unwrap_or_else(|| "no relay answered".into());
                    return Some(Err(JoinError::RelaysUnavailable(why)));
                }
            }
            Stage::Connecting => {
                let t = self.traversal.as_ref()?;
                if let Some(route) = t.route() {
                    info!("connected to the host at {}", route.peer);
                    self.stage = Stage::Settling { since: now };
                } else if t
                    .deadline(self.inner.config.connect_timeout)
                    .is_some_and(|d| now > d)
                {
                    return Some(Err(JoinError::NoRoute {
                        tried: t.remote_candidates(),
                        needs_relay: t.needs_relay(),
                        ours: self.nat,
                        host: t.their_nat(),
                    }));
                }
            }
            Stage::Settling { since } => {
                if now - *since >= SETTLE {
                    return self.hand_over().map(Ok);
                }
            }
            Stage::Finished => {}
        }
        if let Some(observed) = public_addresses {
            self.send_request(now, observed);
        }
        None
    }

    /// Hands the socket of the path over, with what the host sent on it.
    fn hand_over(&mut self) -> Option<Connection> {
        // The agent may have nominated a better pair while settling.
        let route = self.traversal.as_ref()?.route()?;
        let id = match route.via {
            Via::Socket(id) => id,
            Via::Relay => MAIN,
        };
        let socket = if id == MAIN {
            self.socket.take()?
        } else {
            self.extra.get_mut(id - 1)?.take()?
        };
        let received = std::mem::take(&mut self.early)
            .into_iter()
            .filter(|(s, from, _)| *s == id && *from == route.peer)
            .map(|(_, _, data)| data)
            .collect();
        Some(Connection {
            socket,
            peer: route.peer,
            received,
        })
    }

    /// Runs the checks, opening extra sockets when they call for them, and sends what is due.
    fn drive(&mut self, now: Instant) {
        let Some(t) = &mut self.traversal else { return };
        t.drive(now);
        if let Some(n) = t.wants_sockets() {
            self.extra = crate::host::open_extra_sockets(n);
            t.sockets_opened(now, (1..=self.extra.len()).collect());
        }
        while let Some(out) = t.poll_transmit() {
            let socket = match out.via {
                Via::Socket(MAIN) => self.socket.as_ref(),
                Via::Socket(id) => self.extra.get(id - 1).and_then(Option::as_ref),
                Via::Relay => None,
            };
            if let Some(s) = socket {
                let _ = net::send_to(s, &out.data, out.to);
            }
        }
    }

    /// This side's router, from what the STUN servers saw.
    fn summary(&self, observed: &[SocketAddr]) -> NatSummary {
        let mapping = nat::classify(observed, self.port, &self.locals);
        NatSummary {
            mapping,
            open: mapping == NatMapping::Open,
            ipv6: nat::global_ipv6(&self.locals),
            carrier_grade: nat::carrier_grade(None, observed, &self.locals),
        }
    }

    /// Makes the checks with the candidates gathered and sends the join request.
    fn send_request(&mut self, now: Instant, observed: Vec<SocketAddr>) {
        let summary = self.summary(&observed);
        self.nat = Some(summary);
        let predicted = observed
            .iter()
            .find(|a| a.is_ipv4())
            .map(|a| {
                nat::predicted_ports(summary.mapping, &observed, self.port, PREDICTION_WINDOW)
                    .into_iter()
                    .map(|p| SocketAddr::new(a.ip(), p))
                    .filter(|p| !observed.contains(p))
                    .collect()
            })
            .unwrap_or_default();
        let candidates = LocalCandidates {
            addrs: self.locals.clone(),
            port: self.port,
            reflexive: observed,
            predicted,
            relay: None,
        };
        let traversal = Traversal::new(true, &candidates, Some(summary));
        let request = Message::Request {
            attempt: self.attempt.clone(),
            game_id: self.inner.config.game_id.clone(),
            version: self.inner.config.game_version.clone(),
            protocol: PROTOCOL,
            player_name: self.player_name.clone(),
            ice: traversal.params(),
        };
        // Sealed, sent and repeated by the worker task.
        if let Some(to_task) = &self.to_task {
            let _ = to_task.send(ToTask::Request(request));
        }
        self.traversal = Some(traversal);
        self.stage = Stage::WaitingForHost {
            since: now,
            published: false,
            relay_errors: None,
        };
    }

    /// Reads the host's answers and every datagram on the sockets.
    fn receive(&mut self, now: Instant) -> Result<(), JoinError> {
        while let Ok(notice) = self.from_task.try_recv() {
            match notice {
                FromTask::Published(p) => {
                    let Stage::WaitingForHost {
                        since,
                        published,
                        relay_errors,
                    } = &mut self.stage
                    else {
                        continue;
                    };
                    if p.accepted > 0 {
                        // The host's time to answer runs from the first copy a relay took.
                        if !*published {
                            *since = now;
                            *published = true;
                        }
                    } else if !*published {
                        // With no relay connected, no repeat will do better.
                        if self.inner.worker.relays_connected() == 0 {
                            return Err(JoinError::RelaysUnavailable(p.errors.join("; ")));
                        }
                        *relay_errors = Some(p.errors.join("; "));
                    }
                }
                FromTask::Accepted(ice) => {
                    if let (Some(t), Stage::WaitingForHost { .. }) =
                        (&mut self.traversal, &self.stage)
                    {
                        t.set_remote(now, &ice);
                        info!(
                            "the host answered: checking {} addresses",
                            ice.candidates.len()
                        );
                        self.stage = Stage::Connecting;
                    }
                }
                FromTask::Refused(reason) => return Err(JoinError::Refused(reason)),
            }
        }
        if let Some(socket) = self.socket.take() {
            let r = self.read(now, MAIN, &socket);
            self.socket = Some(socket);
            r?;
        }
        for i in 0..self.extra.len() {
            if let Some(s) = self.extra[i].take() {
                let _ = self.read(now, i + 1, &s);
                self.extra[i] = Some(s);
            }
        }
        Ok(())
    }

    /// Reads everything waiting on `socket`, socket `id`.
    fn read(&mut self, now: Instant, id: SocketId, socket: &UdpSocket) -> Result<(), JoinError> {
        loop {
            let (n, from) = match socket.recv_from(&mut self.buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                // Windows: an ICMP "port unreachable" for an earlier check.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                // A datagram that cannot be read must not end a join that may still work; the
                // next poll reads on.
                Err(e) => {
                    debug!("joiner socket: {e}");
                    return Ok(());
                }
            };
            let from = net::canonical(from);
            let data = &self.buf[..n];
            if !stun::is_stun(data) {
                // The host's game may start talking before the hand-over.
                if self.traversal.is_some() && self.early.len() < MAX_EARLY_DATAGRAMS {
                    self.early.push((id, from, data.to_vec()));
                }
                continue;
            }
            if id == MAIN
                && let Stage::Gathering(Some(g)) = &mut self.stage
                && g.handle(now, data)
            {
                continue;
            }
            if let Some(t) = &mut self.traversal {
                t.handle(now, id, from, data);
            }
        }
    }
}

impl Drop for Join {
    fn drop(&mut self) {
        if !matches!(self.stage, Stage::Finished) {
            self.inner
                .worker
                .send(Command::Unsubscribe(self.subscription.clone()));
        }
    }
}
