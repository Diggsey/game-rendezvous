//! Joining: asking a host through the relays, then connecting directly.
//!
//! As for hosting, the game thread ([`Join`]) runs what needs the socket (the public address,
//! the connectivity checks), and a task on the worker ([`relay`]) what needs the joiner's key
//! (sealing the request, opening the host's answer).

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
use crate::ice::{self, Link, LocalCandidates};
use crate::listing::{GameInfo, PROTOCOL};
use crate::net::{self, LocalAddr};
use crate::worker::{self, Command, Inbox, Sink};
use crate::stun::{self, Gatherer};
use task::{FromTask, JoinTask, SendRequest};

/// After nomination, how long the checks go on before the socket is handed over, so that the
/// host's side of the nominated pair completes too.
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
}

/// A working connection to a host: send to `peer` from `socket`.
#[derive(Debug)]
#[non_exhaustive]
pub struct Connection {
    /// The socket the checks succeeded on, non-blocking. Dual-stack sockets need
    /// [`send_to`](crate::send_to) for IPv4 peers and report them through
    /// [`canonical`](crate::canonical).
    pub socket: UdpSocket,
    /// The host's address on the nominated path.
    pub peer: SocketAddr,
    /// Datagrams `peer` sent before the hand-over (once connected, the host's game may start
    /// talking while the checks settle), oldest first. Handle them before reading `socket`.
    pub received: Vec<Vec<u8>>,
}

enum Stage {
    /// The gatherer starts once the STUN servers' names are resolved.
    Gathering(Option<Gatherer>),
    WaitingForHost {
        /// When the request went out, then when a relay took it: the host's time to answer
        /// runs from there.
        since: Instant,
        /// A relay took the request.
        published: bool,
        /// Why the copies sent so far were not taken, while none has been.
        relay_errors: Option<String>,
    },
    Connecting {
        since: Instant,
    },
    Settling {
        since: Instant,
        peer: SocketAddr,
    },
    Finished,
}

/// A join in progress: call [`poll`](Join::poll) every frame until it returns the connection
/// or an error. Dropping it abandons the join.
pub struct Join {
    inner: Arc<Inner>,
    socket: Option<UdpSocket>,
    attempt: String,
    player_name: String,
    locals: Vec<LocalAddr>,
    port: u16,
    stage: Stage,
    started: Instant,
    subscription: SubscriptionId,
    /// Dropping it ends the worker task, which repeats the request until the host answers.
    /// `None` once the join has finished.
    to_task: Option<Sink<SendRequest>>,
    from_task: Inbox<FromTask>,
    link: Option<Link>,
    symmetric_nat: bool,
    /// Datagrams that are not the library's, kept for the game: (sender, payload).
    early: Vec<(SocketAddr, Vec<u8>)>,
    buf: Box<[u8]>,
}

impl Join {
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
            attempt,
            player_name: player_name.to_string(),
            locals,
            port,
            stage: Stage::Gathering(None),
            started: now,
            subscription,
            to_task: Some(to_task),
            from_task,
            link: None,
            symmetric_nat: false,
            early: Vec::new(),
            buf: vec![0; RECV_BUFFER].into_boxed_slice(),
        })
    }

    pub fn stage(&self) -> JoinStage {
        match self.stage {
            Stage::Gathering(_) => JoinStage::Gathering,
            Stage::WaitingForHost { .. } => JoinStage::WaitingForHost,
            _ => JoinStage::Connecting,
        }
    }

    /// Moves the join on. `Some` once it has finished: the connection, or why there is none.
    /// After that it returns `None`.
    pub fn poll(&mut self) -> Option<Result<Connection, JoinError>> {
        if matches!(self.stage, Stage::Finished) {
            return None;
        }
        let result = self.step(Instant::now());
        if result.is_some() {
            self.stage = Stage::Finished;
            // Stops the worker task repeating the request.
            self.to_task = None;
            self.inner
                .worker
                .send(Command::Unsubscribe(self.subscription.clone()));
        }
        result
    }

    fn step(&mut self, now: Instant) -> Option<Result<Connection, JoinError>> {
        if let Err(e) = self.receive(now) {
            return Some(Err(e));
        }
        let socket = self.socket.as_ref()?;
        // The link answers the host's checks as soon as it exists, even before the host's
        // answer arrives through the relays.
        if let Some(link) = &mut self.link {
            link.drive(now, socket);
        }
        let mut gathered = None;
        match &mut self.stage {
            Stage::Gathering(gatherer) => {
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
                    let reflexive = gatherer.as_ref().map(Gatherer::mapped).unwrap_or_default();
                    self.symmetric_nat = gatherer.as_ref().is_some_and(Gatherer::symmetric_nat);
                    debug!("joiner public addresses: {reflexive:?}");
                    gathered = Some(reflexive);
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
            Stage::Connecting { since } => {
                let link = self.link.as_ref()?;
                if let Some(peer) = link.nominated() {
                    info!("connected to the host at {peer}");
                    self.stage = Stage::Settling { since: now, peer };
                } else if now - *since > self.inner.config.connect_timeout {
                    return Some(Err(JoinError::NoRoute {
                        tried: link.remote_candidates(),
                        symmetric_nat: self.symmetric_nat,
                    }));
                }
            }
            Stage::Settling { since, peer } => {
                if now - *since >= SETTLE {
                    // The agent may have nominated a better pair while settling.
                    let peer = self.link.as_ref().and_then(Link::nominated).unwrap_or(*peer);
                    let socket = self.socket.take()?;
                    let received = std::mem::take(&mut self.early)
                        .into_iter()
                        .filter(|(from, _)| *from == peer)
                        .map(|(_, data)| data)
                        .collect();
                    return Some(Ok(Connection {
                        socket,
                        peer,
                        received,
                    }));
                }
            }
            Stage::Finished => {}
        }
        if let Some(reflexive) = gathered
            && let Err(e) = self.send_request(now, reflexive)
        {
            return Some(Err(e));
        }
        None
    }

    /// Makes the link with the candidates gathered and sends the join request.
    fn send_request(&mut self, now: Instant, reflexive: Vec<SocketAddr>) -> Result<(), JoinError> {
        let candidates = LocalCandidates {
            addrs: self.locals.clone(),
            port: self.port,
            reflexive,
        };
        let link = Link::new(true, &candidates);
        let request = Message::Request {
            attempt: self.attempt.clone(),
            game_id: self.inner.config.game_id.clone(),
            version: self.inner.config.game_version.clone(),
            protocol: PROTOCOL,
            player_name: self.player_name.clone(),
            ice: link.params(),
        };
        // Sealed, sent and repeated by the worker task.
        if let Some(to_task) = &self.to_task {
            let _ = to_task.send(SendRequest(request));
        }
        self.link = Some(link);
        self.stage = Stage::WaitingForHost {
            since: now,
            published: false,
            relay_errors: None,
        };
        Ok(())
    }

    /// Reads the host's answers and every datagram on the socket.
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
                    if let (Some(link), Stage::WaitingForHost { .. }) =
                        (&mut self.link, &self.stage)
                    {
                        link.set_remote(&ice);
                        info!(
                            "the host answered: checking {} addresses",
                            ice.candidates.len()
                        );
                        self.stage = Stage::Connecting { since: now };
                    }
                }
                FromTask::Refused(reason) => return Err(JoinError::Refused(reason)),
            }
        }
        let Some(socket) = &self.socket else {
            return Ok(());
        };
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
            let data = &self.buf[..n];
            if !stun::is_stun(data) {
                // The host's game may start talking before the hand-over.
                if self.link.is_some() && self.early.len() < MAX_EARLY_DATAGRAMS {
                    self.early.push((net::canonical(from), data.to_vec()));
                }
                continue;
            }
            if let Stage::Gathering(Some(g)) = &mut self.stage
                && g.handle(now, data)
            {
                continue;
            }
            if let Some(link) = &mut self.link
                && let Some(msg) = ice::parse(data)
                && link.accepts(&msg)
            {
                link.handle(now, from, msg);
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
