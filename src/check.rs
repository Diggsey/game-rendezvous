//! Checking this machine's network before hosting, or for browsing: what [`NatReport`] a host
//! here would have, and so whether players could probably reach it.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Inner;
use crate::nat::{self, NatMapping, NatReport, NatSummary};
use crate::net::{self, LocalAddr};
use crate::stun::{self, Gatherer};
use crate::survey::{Handled, Survey};

/// How long a check waits for the router and the relay at most.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// A check of this machine's network as a host would see it, on a socket of its own: STUN
/// servers (the router's mapping), the router's port forwarding, and the TURN relay if one is
/// configured (so it also tests the relay's credentials). Made by
/// [`Rendezvous::check_nat`](crate::Rendezvous::check_nat); poll it every frame until it is
/// done. It forwards a port on the router briefly, and removes it when done.
pub struct NatCheck {
    /// The configuration and worker.
    inner: Arc<Inner>,
    /// The socket checked.
    socket: UdpSocket,
    /// The checking.
    survey: Survey,
    /// When it began.
    started: Instant,
    /// The outcome, once done.
    done: Option<NatReport>,
    /// Room to read a datagram into.
    buf: Box<[u8]>,
}

impl NatCheck {
    /// Starts checking on a new socket.
    pub(crate) fn new(inner: Arc<Inner>) -> io::Result<NatCheck> {
        let socket = net::bind_dual_stack(0)?;
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        let survey = Survey::new(&inner, &socket, locals, false);
        Ok(NatCheck {
            inner,
            socket,
            survey,
            started: Instant::now(),
            done: None,
            buf: vec![0; 2048].into_boxed_slice(),
        })
    }

    /// Moves the check on; the report once done (and every call after).
    pub fn poll(&mut self) -> Option<&NatReport> {
        if self.done.is_none() {
            let now = Instant::now();
            self.receive(now);
            let socket = &self.socket;
            let mut send = |data: &[u8], to: SocketAddr| {
                let _ = net::send_to(socket, data, to);
            };
            self.survey.drive(&self.inner, now, &mut send);
            while self.survey.poll_finding().is_some() {}
            if self.survey.complete() || now - self.started > CHECK_TIMEOUT {
                self.done = Some(self.survey.report());
                self.survey.close(now, &mut send);
            }
        }
        self.done.as_ref()
    }

    /// What is known so far.
    #[must_use]
    pub fn report(&self) -> NatReport {
        self.done.clone().unwrap_or_else(|| self.survey.report())
    }

    /// Why the configured TURN relay could not be used, if it could not (e.g. the username
    /// or password is wrong).
    #[must_use]
    pub fn relay_error(&self) -> Option<&str> {
        self.survey.relay_error()
    }

    /// Reads the socket.
    fn receive(&mut self, now: Instant) {
        loop {
            match self.socket.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    let from = net::canonical(from);
                    if let Handled::NotMine = self.survey.handle(now, from, &self.buf[..n]) {}
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(_) => return,
            }
        }
    }
}

/// A browser's look at its own router, on a socket of its own, as a joiner's would be: for
/// judging which games it can probably join.
pub(crate) struct SelfCheck {
    /// The socket.
    socket: UdpSocket,
    /// This machine's addresses.
    locals: Vec<LocalAddr>,
    /// Asking the STUN servers, once they are resolved.
    gatherer: Option<Gatherer>,
    /// When the check began.
    started: Instant,
    /// The finding.
    pub(crate) summary: Option<NatSummary>,
}

impl SelfCheck {
    /// Starts looking.
    pub(crate) fn new(inner: &Inner) -> Option<SelfCheck> {
        let socket = net::bind_dual_stack(0).ok()?;
        let locals = net::local_addrs(&socket, inner.config.local_addresses.as_deref());
        Some(SelfCheck {
            socket,
            locals,
            gatherer: None,
            started: Instant::now(),
            summary: None,
        })
    }

    /// Moves the look on.
    pub(crate) fn poll(&mut self, inner: &Inner) {
        if self.summary.is_some() {
            return;
        }
        let now = Instant::now();
        if self.gatherer.is_none() {
            let Some(servers) = inner.worker.stun_servers() else {
                return;
            };
            let timeout = inner.config.gather_timeout;
            self.gatherer = Some(Gatherer::for_socket(&self.socket, servers, now, timeout));
        }
        let Some(g) = &mut self.gatherer else { return };
        let mut buf = [0u8; 1500];
        while let Ok((n, _)) = self.socket.recv_from(&mut buf) {
            if stun::is_stun(&buf[..n]) {
                g.handle(now, &buf[..n]);
            }
        }
        g.send_due(now, &self.socket);
        if g.is_done(now) || now - self.started > inner.config.gather_timeout * 4 {
            let observed = g.observed();
            let port = self.socket.local_addr().map_or(0, |a| a.port());
            let mapping = nat::classify(&observed, port, &self.locals);
            self.summary = Some(NatSummary {
                mapping,
                open: mapping == NatMapping::Open,
                ipv6: nat::global_ipv6(&self.locals),
                carrier_grade: nat::carrier_grade(None, &observed, &self.locals),
            });
        }
    }
}
