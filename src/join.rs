//! Joining: asking a host through the relays, then connecting directly.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::{Event, Filter, Keys, PublicKey, SubscriptionId, Timestamp};
use tracing::{debug, info};

use crate::Inner;
use crate::error::JoinError;
use crate::handshake::{self, HANDSHAKE_KIND, Message};
use crate::ice::{self, Link, LocalCandidates};
use crate::listing::{GameInfo, PROTOCOL};
use crate::net::{self, LocalAddr};
use crate::signal::{Command, Inbox, Published};
use crate::stun::{self, Gatherer};

/// How often the join request is repeated until the host answers.
const REQUEST_INTERVAL: Duration = Duration::from_secs(2);
/// After nomination, how long the checks go on before the socket is handed over, so that the
/// host's side of the nominated pair completes too.
const SETTLE: Duration = Duration::from_millis(300);

/// How far a join has got, for showing to the player.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
pub struct Connection {
    /// The socket the checks succeeded on, non-blocking. Dual-stack sockets need
    /// [`send_to`](crate::send_to) for IPv4 peers and report them through
    /// [`canonical`](crate::canonical).
    pub socket: UdpSocket,
    /// The host's address on the nominated path.
    pub peer: SocketAddr,
}

enum Stage {
    /// The gatherer starts once the STUN servers' names are resolved.
    Gathering(Option<Gatherer>),
    WaitingForHost {
        first_sent: Instant,
        last_sent: Instant,
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
    keys: Keys,
    host: PublicKey,
    attempt: String,
    player_name: String,
    locals: Vec<LocalAddr>,
    port: u16,
    stage: Stage,
    started: Instant,
    subscription: SubscriptionId,
    replies: Inbox<Event>,
    link: Option<Link>,
    request: Option<Event>,
    first_publish: Option<Inbox<Published>>,
    symmetric_nat: bool,
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
        socket.set_nonblocking(true)?;
        let port = socket.local_addr()?.port();
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        let keys = Keys::generate();
        let filter = Filter::new()
            .kind(HANDSHAKE_KIND)
            .pubkey(keys.public_key())
            .author(game.id.0)
            .since(Timestamp::now() - 10);
        let (subscription, replies) = inner.signal.subscribe(filter);
        let now = Instant::now();
        info!("joining {} ({})", game.name, game.id);
        Ok(Join {
            inner,
            socket: Some(socket),
            keys,
            host: game.id.0,
            attempt: format!("{:016x}", rand::random::<u64>()),
            player_name: player_name.to_string(),
            locals,
            port,
            stage: Stage::Gathering(None),
            started: now,
            subscription,
            replies,
            link: None,
            request: None,
            first_publish: None,
            symmetric_nat: false,
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
            self.inner
                .signal
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
                    && let Some(servers) = self.inner.signal.stun_servers()
                {
                    let dual = net::is_dual_stack(socket);
                    let servers = servers
                        .into_iter()
                        .filter(|s| s.is_ipv4() || dual)
                        .collect();
                    let left = deadline.saturating_duration_since(now);
                    *gatherer = Some(Gatherer::new(servers, now, left));
                }
                if let Some(g) = gatherer {
                    for (server, request) in g.poll_transmit(now) {
                        let _ = net::send_to(socket, &request, server);
                    }
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
                first_sent,
                last_sent,
            } => {
                // The host's time to answer runs from when a relay took the request.
                let timeout = self.inner.config.handshake_timeout;
                if let Some(rx) = &mut self.first_publish {
                    match rx.try_recv() {
                        Ok(p) if p.accepted == 0 => {
                            return Some(Err(JoinError::RelaysUnavailable(p.errors.join("; "))));
                        }
                        Ok(_) => {
                            self.first_publish = None;
                            *first_sent = now;
                        }
                        Err(_) if now - *first_sent > timeout * 2 => {
                            return Some(Err(JoinError::RelaysUnavailable(
                                "no relay answered".into(),
                            )));
                        }
                        Err(_) => {}
                    }
                } else if now - *first_sent > timeout {
                    return Some(Err(JoinError::HostNotResponding));
                }
                if now - *last_sent >= REQUEST_INTERVAL
                    && let Some(r) = &self.request
                {
                    *last_sent = now;
                    self.inner.signal.publish(r.clone());
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
                    let peer = *peer;
                    let socket = self.socket.take()?;
                    return Some(Ok(Connection { socket, peer }));
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
        let event = handshake::seal(&self.keys, &self.host, &request)
            .ok_or_else(|| JoinError::RelaysUnavailable("could not sign the request".into()))?;
        self.first_publish = Some(self.inner.signal.publish_tracked(event.clone()));
        self.request = Some(event);
        self.link = Some(link);
        self.stage = Stage::WaitingForHost {
            first_sent: now,
            last_sent: now,
        };
        Ok(())
    }

    /// Reads the host's answers and every datagram on the socket.
    fn receive(&mut self, now: Instant) -> Result<(), JoinError> {
        while let Ok(event) = self.replies.try_recv() {
            if event.pubkey != self.host {
                continue;
            }
            match handshake::open(&self.keys, &event) {
                Some(Message::Accept { attempt, ice }) if attempt == self.attempt => {
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
                Some(Message::Refuse { attempt, reason }) if attempt == self.attempt => {
                    return Err(JoinError::Refused(reason));
                }
                _ => {}
            }
        }
        let Some(socket) = &self.socket else {
            return Ok(());
        };
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                // Windows: an ICMP "port unreachable" for an earlier check.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e.into()),
            };
            let data = &buf[..n];
            if !stun::is_stun(data) {
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
                .signal
                .send(Command::Unsubscribe(self.subscription.clone()));
        }
    }
}
