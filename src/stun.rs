//! STUN, as far as a game needs it: telling the library's datagrams from the game's own
//! ([`is_stun`], also at the crate root), and a STUN server for private test networks
//! ([`serve`]).
//!
//! Inside, the little of STUN (RFC 8489) needed to learn a socket's public address: Binding
//! requests to public STUN servers and their responses. ICE's own connectivity checks are STUN
//! too, but with credentials; the `is` crate handles those. A server's Binding response
//! carries no credentials, which `is` refuses, hence this.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Bytes 4 to 8 of every STUN message (RFC 8489, section 5).
const MAGIC_COOKIE: [u8; 4] = 0x2112_A442u32.to_be_bytes();
/// The message type of a Binding request.
const BINDING_REQUEST: u16 = 0x0001;
/// The message type of a Binding success response.
const BINDING_SUCCESS: u16 = 0x0101;
/// The MAPPED-ADDRESS attribute, from older servers.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// The XOR-MAPPED-ADDRESS attribute.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// A STUN transaction id.
pub(crate) type TransactionId = [u8; 12];

/// Whether `data` looks like a STUN message (of any kind): the first two bits zero and the
/// magic cookie in place. A game sharing its socket with this crate should give such datagrams
/// to [`Host::handle_datagram`](crate::Host::handle_datagram) and make sure its own packets
/// never look like this.
///
/// ```
/// assert!(!game_rendezvous::is_stun(b"a game's own packet, which starts with a letter"));
/// ```
#[must_use]
pub fn is_stun(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] & 0xc0 == 0 && data[4..8] == MAGIC_COOKIE
}

/// A Binding request with no attributes.
pub(crate) fn binding_request(id: TransactionId) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC_COOKIE);
    msg[8..20].copy_from_slice(&id);
    msg
}

/// A Binding success response telling the requester its address, `mapped`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the attribute holds at most 20 bytes"
)]
pub(crate) fn binding_success(id: TransactionId, mapped: SocketAddr) -> Vec<u8> {
    let mapped = crate::net::canonical(mapped);
    let mut value = vec![0u8];
    let port = mapped.port() ^ u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);
    match mapped.ip() {
        IpAddr::V4(ip) => {
            value.push(1);
            value.extend(port.to_be_bytes());
            value.extend(xor(&ip.octets(), &id));
        }
        IpAddr::V6(ip) => {
            value.push(2);
            value.extend(port.to_be_bytes());
            value.extend(xor(&ip.octets(), &id));
        }
    }
    let mut msg = Vec::with_capacity(20 + 4 + value.len());
    msg.extend(BINDING_SUCCESS.to_be_bytes());
    msg.extend(((4 + value.len()) as u16).to_be_bytes());
    msg.extend(MAGIC_COOKIE);
    msg.extend(id);
    msg.extend(ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend((value.len() as u16).to_be_bytes());
    msg.extend(value);
    msg
}

/// Answers a Binding request from `from` as a STUN server would; `None` for anything else.
pub(crate) fn respond(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if !is_stun(request) || u16::from_be_bytes([request[0], request[1]]) != BINDING_REQUEST {
        return None;
    }
    let id: TransactionId = request[8..20].try_into().ok()?;
    Some(binding_success(id, from))
}

/// Serves STUN Binding requests on `socket`, blocking, until it fails: a STUN server for tests
/// and private networks, as in the `test_network` example.
///
/// ```no_run
/// let socket = std::net::UdpSocket::bind("127.0.0.1:3478")?;
/// std::thread::spawn(move || game_rendezvous::stun::serve(&socket));
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// When reading the socket fails (other than for an ICMP "port unreachable").
pub fn serve(socket: &UdpSocket) -> std::io::Result<()> {
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            // Windows reports an earlier send's ICMP "port unreachable" here.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e),
        };
        if let Some(reply) = respond(&buf[..n], from) {
            let _ = socket.send_to(&reply, from);
        }
    }
}

/// The transaction id and mapped address of a Binding success response.
pub(crate) fn parse_binding_success(data: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    if !is_stun(data) || u16::from_be_bytes([data[0], data[1]]) != BINDING_SUCCESS {
        return None;
    }
    let id: TransactionId = data[8..20].try_into().ok()?;
    let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    let attrs = data.get(20..20 + len)?;
    let mut plain = None;
    let mut at = 0;
    while at + 4 <= attrs.len() {
        let kind = u16::from_be_bytes([attrs[at], attrs[at + 1]]);
        let size = usize::from(u16::from_be_bytes([attrs[at + 2], attrs[at + 3]]));
        let value = attrs.get(at + 4..at + 4 + size)?;
        match kind {
            ATTR_XOR_MAPPED_ADDRESS => return parse_address(value, Some(&id)).map(|a| (id, a)),
            ATTR_MAPPED_ADDRESS => plain = parse_address(value, None),
            _ => {}
        }
        // Attributes are padded to 4 bytes.
        at += 4 + size.div_ceil(4) * 4;
    }
    plain.map(|a| (id, a))
}

/// A (XOR-)MAPPED-ADDRESS value; `xor_id` for the XOR form.
fn parse_address(value: &[u8], xor_id: Option<&TransactionId>) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let mut port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    if xor_id.is_some() {
        port ^= u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);
    }
    let raw = value.get(4..)?;
    let ip = match (family, raw.len()) {
        (1, 4) => {
            let b: [u8; 4] = match xor_id {
                Some(id) => xor(raw, id).try_into().ok()?,
                None => raw.try_into().ok()?,
            };
            IpAddr::from(b)
        }
        (2, 16) => {
            let b: [u8; 16] = match xor_id {
                Some(id) => xor(raw, id).try_into().ok()?,
                None => raw.try_into().ok()?,
            };
            IpAddr::from(b)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// XORs an address with the magic cookie followed by the transaction id, as XOR-MAPPED-ADDRESS
/// does (an IPv4 address only uses the cookie).
fn xor(bytes: &[u8], id: &TransactionId) -> Vec<u8> {
    let key: Vec<u8> = MAGIC_COOKIE.iter().chain(id.iter()).copied().collect();
    bytes.iter().zip(key).map(|(b, k)| b ^ k).collect()
}

/// When to (re)send a Binding request, from the start of gathering. UDP may lose any of them.
const RESENDS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(300),
    Duration::from_millis(900),
];
/// Once one server has answered, how long to wait for the others.
const STRAGGLERS: Duration = Duration::from_millis(400);

/// Learns a socket's server-reflexive addresses (the address its NAT shows the internet) from
/// several STUN servers at once. Sans-IO: the owner sends what [`poll_transmit`](Self::poll_transmit)
/// returns from the socket being studied and feeds every reply to [`handle`](Self::handle).
#[derive(Debug)]
pub(crate) struct Gatherer {
    /// When gathering began: resends are timed from it.
    started: Instant,
    /// When gathering gives up on the servers that have not answered.
    deadline: Instant,
    /// Requests out, by transaction id.
    pending: HashMap<TransactionId, SocketAddr>,
    /// The servers asked.
    servers: Vec<SocketAddr>,
    /// How many of [`RESENDS`] have gone out.
    resends_done: usize,
    /// Each answering server and the address it saw.
    answers: Vec<(SocketAddr, SocketAddr)>,
    /// When the first server answered.
    first_answer: Option<Instant>,
}

impl Gatherer {
    /// Gathers from `servers` (already resolved) for at most `timeout`. Servers of a family the
    /// socket cannot reach should be left out.
    pub(crate) fn new(servers: Vec<SocketAddr>, now: Instant, timeout: Duration) -> Self {
        Gatherer {
            started: now,
            deadline: now + timeout,
            pending: HashMap::new(),
            servers,
            resends_done: 0,
            answers: Vec::new(),
            first_answer: None,
        }
    }

    /// Gathers for `socket` from those of `servers` (already resolved) it can reach, for at
    /// most `timeout`.
    pub(crate) fn for_socket(
        socket: &UdpSocket,
        servers: Vec<SocketAddr>,
        now: Instant,
        timeout: Duration,
    ) -> Self {
        let families = crate::net::Families::of(socket);
        let servers = servers
            .into_iter()
            .filter(|s| families.reaches(s.ip()))
            .collect();
        Gatherer::new(servers, now, timeout)
    }

    /// Sends the requests due by `now` from `socket`.
    pub(crate) fn send_due(&mut self, now: Instant, socket: &UdpSocket) {
        for (server, request) in self.poll_transmit(now) {
            let _ = crate::net::send_to(socket, &request, server);
        }
    }

    /// The requests due by `now`, as (server, datagram).
    pub(crate) fn poll_transmit(&mut self, now: Instant) -> Vec<(SocketAddr, [u8; 20])> {
        let mut out = Vec::new();
        if self.is_done(now) {
            return out;
        }
        while self.resends_done < RESENDS.len() && now >= self.started + RESENDS[self.resends_done]
        {
            self.resends_done += 1;
            for &server in &self.servers {
                if self.answers.iter().any(|a| a.0 == server) {
                    continue;
                }
                let id: TransactionId = rand::random();
                self.pending.insert(id, server);
                out.push((server, binding_request(id)));
            }
        }
        out
    }

    /// Takes a datagram if it answers one of this gatherer's requests.
    pub(crate) fn handle(&mut self, now: Instant, data: &[u8]) -> bool {
        let Some((id, mapped)) = parse_binding_success(data) else {
            return false;
        };
        let Some(server) = self.pending.remove(&id) else {
            return false;
        };
        if !self.answers.iter().any(|a| a.0 == server) {
            self.answers.push((server, crate::net::canonical(mapped)));
            self.first_answer.get_or_insert(now);
        }
        true
    }

    /// Every server has answered, or the time is up.
    pub(crate) fn is_done(&self, now: Instant) -> bool {
        self.answers.len() == self.servers.len()
            || now >= self.deadline
            || self.first_answer.is_some_and(|t| now >= t + STRAGGLERS)
    }

    /// The distinct addresses the servers saw.
    pub(crate) fn mapped(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for (_, a) in &self.answers {
            if !out.contains(a) {
                out.push(*a);
            }
        }
        out
    }

    /// Whether different servers saw different IPv4 ports: the NAT maps each destination to a
    /// new port ("symmetric"), which defeats hole punching unless the other side is open.
    pub(crate) fn symmetric_nat(&self) -> bool {
        let mut ports = self
            .answers
            .iter()
            .filter(|(_, a)| a.is_ipv4())
            .map(|(_, a)| a.port());
        ports.next().is_some_and(|first| ports.any(|p| p != first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trip() {
        let id = [7u8; 12];
        for addr in ["203.0.113.9:40000", "[2001:db8::5]:1234"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let reply = respond(&binding_request(id), addr).unwrap();
            assert!(is_stun(&reply));
            assert_eq!(parse_binding_success(&reply), Some((id, addr)));
        }
    }

    #[test]
    fn gatherer_resends_and_finishes() {
        let server: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let t0 = Instant::now();
        let mut g = Gatherer::new(vec![server], t0, Duration::from_secs(2));
        let first = g.poll_transmit(t0);
        assert_eq!(first.len(), 1);
        assert!(g.poll_transmit(t0 + Duration::from_millis(100)).is_empty());
        let again = g.poll_transmit(t0 + Duration::from_millis(300));
        assert_eq!(again.len(), 1);
        // A reply to the first request still counts.
        let me: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let reply = respond(&first[0].1, me).unwrap();
        assert!(g.handle(t0 + Duration::from_millis(350), &reply));
        assert!(g.is_done(t0 + Duration::from_millis(350)));
        assert_eq!(g.mapped(), vec![me]);
        assert!(!g.symmetric_nat());
    }
}
