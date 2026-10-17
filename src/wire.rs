//! STUN messages (RFC 8489) with any attributes, and TURN's `ChannelData` framing (RFC 8656):
//! what the TURN client and the hole-punching probes build and read.
//!
//! `is` reads and writes ICE's own checks; it cannot write TURN's Allocate (no
//! REQUESTED-TRANSPORT) or sign with a long-term credential's key, hence this.

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// The magic cookie, bytes 4 to 8 of every STUN message.
pub(crate) const MAGIC_COOKIE: u32 = 0x2112_A442;
/// The size of a STUN header.
const HEADER: usize = 20;

/// STUN and TURN methods.
pub(crate) mod method {
    /// Binding (STUN).
    pub(crate) const BINDING: u16 = 0x001;
    /// Allocate (TURN).
    pub(crate) const ALLOCATE: u16 = 0x003;
    /// Refresh (TURN).
    pub(crate) const REFRESH: u16 = 0x004;
    /// Send (TURN indication).
    pub(crate) const SEND: u16 = 0x006;
    /// Data (TURN indication).
    pub(crate) const DATA: u16 = 0x007;
    /// `CreatePermission` (TURN).
    pub(crate) const CREATE_PERMISSION: u16 = 0x008;
    /// `ChannelBind` (TURN).
    pub(crate) const CHANNEL_BIND: u16 = 0x009;
}

/// STUN and TURN attributes.
pub(crate) mod attr {
    /// USERNAME.
    pub(crate) const USERNAME: u16 = 0x0006;
    /// MESSAGE-INTEGRITY (HMAC-SHA1).
    pub(crate) const MESSAGE_INTEGRITY: u16 = 0x0008;
    /// ERROR-CODE.
    pub(crate) const ERROR_CODE: u16 = 0x0009;
    /// CHANNEL-NUMBER.
    pub(crate) const CHANNEL_NUMBER: u16 = 0x000C;
    /// LIFETIME, in seconds.
    pub(crate) const LIFETIME: u16 = 0x000D;
    /// XOR-PEER-ADDRESS.
    pub(crate) const XOR_PEER_ADDRESS: u16 = 0x0012;
    /// DATA.
    pub(crate) const DATA: u16 = 0x0013;
    /// REALM.
    pub(crate) const REALM: u16 = 0x0014;
    /// NONCE.
    pub(crate) const NONCE: u16 = 0x0015;
    /// XOR-RELAYED-ADDRESS.
    pub(crate) const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    /// REQUESTED-TRANSPORT.
    pub(crate) const REQUESTED_TRANSPORT: u16 = 0x0019;
    /// XOR-MAPPED-ADDRESS.
    pub(crate) const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    /// SOFTWARE.
    pub(crate) const SOFTWARE: u16 = 0x8022;
    /// FINGERPRINT.
    pub(crate) const FINGERPRINT: u16 = 0x8028;
    /// This library's hole-punching probes: the receiver's ICE username fragment, then a flag
    /// byte. In the comprehension-optional range, so other STUN agents ignore it.
    pub(crate) const PUNCH: u16 = 0xC0A7;
}

/// A STUN message's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// A request.
    Request,
    /// An indication (no answer).
    Indication,
    /// A success response.
    Success,
    /// An error response.
    Error,
}

impl Class {
    /// The class's two bits.
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0,
            Class::Indication => 1,
            Class::Success => 2,
            Class::Error => 3,
        }
    }
}

/// The message type field for `method` and `class`: the class bits sit between the method's.
fn message_type(method: u16, class: Class) -> u16 {
    let c = class.bits();
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((c & 1) << 4)
        | ((c & 2) << 7)
}

/// The method and class of a message type field.
fn split_type(t: u16) -> (u16, Class) {
    let method = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    let class = match ((t >> 4) & 1) | ((t >> 7) & 2) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    };
    (method, class)
}

/// HMAC-SHA1 of `parts` under `key`.
fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// The CRC-32 of FINGERPRINT.
fn fingerprint(data: &[u8]) -> u32 {
    crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(data) ^ 0x5354_554E
}

/// Builds a STUN message, attribute by attribute.
pub(crate) struct Builder {
    /// The message so far; its length field is set by `finish`.
    buf: Vec<u8>,
    /// The transaction id, for the XOR'd addresses.
    tid: [u8; 12],
}

impl Builder {
    /// A message of `method` and `class` with transaction id `tid`.
    pub(crate) fn new(method: u16, class: Class, tid: [u8; 12]) -> Builder {
        let mut buf = Vec::with_capacity(128);
        buf.extend(message_type(method, class).to_be_bytes());
        buf.extend([0, 0]);
        buf.extend(MAGIC_COOKIE.to_be_bytes());
        buf.extend(tid);
        Builder { buf, tid }
    }

    /// Sets the length field to the attributes written so far plus `extra` bytes.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a STUN message fits a datagram"
    )]
    fn set_length(&mut self, extra: usize) {
        let len = (self.buf.len() - HEADER + extra) as u16;
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
    }

    /// Adds an attribute, padded to 4 bytes.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "attributes are small: a datagram at most"
    )]
    pub(crate) fn attr(mut self, kind: u16, value: &[u8]) -> Builder {
        self.buf.extend(kind.to_be_bytes());
        self.buf.extend((value.len() as u16).to_be_bytes());
        self.buf.extend(value);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }

    /// Adds a 32-bit attribute.
    pub(crate) fn u32(self, kind: u16, value: u32) -> Builder {
        self.attr(kind, &value.to_be_bytes())
    }

    /// Adds an XOR'd address attribute (XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, ...).
    pub(crate) fn xor_addr(self, kind: u16, addr: SocketAddr) -> Builder {
        let value = xor_address(addr, &self.tid);
        self.attr(kind, &value)
    }

    /// Adds MESSAGE-INTEGRITY, keyed with `key`: the ICE password, or a long-term credential's
    /// MD5 key.
    pub(crate) fn integrity(mut self, key: &[u8]) -> Builder {
        // The length covers the attribute itself while the HMAC is computed.
        self.set_length(24);
        let mac = hmac_sha1(key, &[&self.buf]);
        self.attr(attr::MESSAGE_INTEGRITY, &mac)
    }

    /// Adds FINGERPRINT, and finishes.
    pub(crate) fn fingerprint(mut self) -> Vec<u8> {
        self.set_length(8);
        let crc = fingerprint(&self.buf);
        self.attr(attr::FINGERPRINT, &crc.to_be_bytes()).finish()
    }

    /// The finished message.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.set_length(0);
        self.buf
    }
}

/// An address attribute's value, XOR'd with the cookie and the transaction id.
fn xor_address(addr: SocketAddr, tid: &[u8; 12]) -> Vec<u8> {
    let addr = crate::net::canonical(addr);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the top half of the cookie"
    )]
    let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let key: Vec<u8> = MAGIC_COOKIE.to_be_bytes().into_iter().chain(*tid).collect();
    let mut value = vec![0];
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(1);
            value.extend(port.to_be_bytes());
            value.extend(ip.octets().iter().zip(&key).map(|(b, k)| b ^ k));
        }
        IpAddr::V6(ip) => {
            value.push(2);
            value.extend(port.to_be_bytes());
            value.extend(ip.octets().iter().zip(&key).map(|(b, k)| b ^ k));
        }
    }
    value
}

/// A parsed STUN message, borrowing the datagram.
#[derive(Debug)]
pub(crate) struct Message<'a> {
    /// The method.
    pub(crate) method: u16,
    /// The class.
    pub(crate) class: Class,
    /// The transaction id.
    pub(crate) tid: [u8; 12],
    /// The whole message.
    raw: &'a [u8],
    /// Each attribute: its type, where its header starts, and its value.
    attrs: Vec<(u16, usize, &'a [u8])>,
}

impl<'a> Message<'a> {
    /// Parses `data` as a STUN message; `None` if it is not one.
    pub(crate) fn parse(data: &'a [u8]) -> Option<Message<'a>> {
        if !crate::stun::is_stun(data) {
            return None;
        }
        let (method, class) = split_type(u16::from_be_bytes([data[0], data[1]]));
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let raw = data.get(..HEADER + len)?;
        let tid: [u8; 12] = raw[8..20].try_into().ok()?;
        let mut attrs = Vec::new();
        let mut at = HEADER;
        while at + 4 <= raw.len() {
            let kind = u16::from_be_bytes([raw[at], raw[at + 1]]);
            let size = usize::from(u16::from_be_bytes([raw[at + 2], raw[at + 3]]));
            let value = raw.get(at + 4..at + 4 + size)?;
            attrs.push((kind, at, value));
            at += 4 + size.div_ceil(4) * 4;
        }
        Some(Message {
            method,
            class,
            tid,
            raw,
            attrs,
        })
    }

    /// The first attribute of type `kind`.
    pub(crate) fn get(&self, kind: u16) -> Option<&'a [u8]> {
        self.attrs
            .iter()
            .find(|(k, _, _)| *k == kind)
            .map(|(_, _, v)| *v)
    }

    /// A 32-bit attribute.
    pub(crate) fn u32(&self, kind: u16) -> Option<u32> {
        let v = self.get(kind)?;
        Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
    }

    /// A text attribute (REALM, NONCE, ...).
    pub(crate) fn text(&self, kind: u16) -> Option<&'a str> {
        std::str::from_utf8(self.get(kind)?).ok()
    }

    /// An XOR'd address attribute.
    pub(crate) fn xor_addr(&self, kind: u16) -> Option<SocketAddr> {
        let v = self.get(kind)?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the top half of the cookie"
        )]
        let port = u16::from_be_bytes([*v.get(2)?, *v.get(3)?]) ^ (MAGIC_COOKIE >> 16) as u16;
        let key: Vec<u8> = MAGIC_COOKIE
            .to_be_bytes()
            .into_iter()
            .chain(self.tid)
            .collect();
        let raw = v.get(4..)?;
        let ip = match (v.get(1)?, raw.len()) {
            (1, 4) => {
                let b: Vec<u8> = raw.iter().zip(&key).map(|(b, k)| b ^ k).collect();
                IpAddr::from(<[u8; 4]>::try_from(b).ok()?)
            }
            (2, 16) => {
                let b: Vec<u8> = raw.iter().zip(&key).map(|(b, k)| b ^ k).collect();
                IpAddr::from(<[u8; 16]>::try_from(b).ok()?)
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// The ERROR-CODE: its number and reason.
    pub(crate) fn error_code(&self) -> Option<(u16, &'a str)> {
        let v = self.get(attr::ERROR_CODE)?;
        let code = u16::from(*v.get(2)? & 7) * 100 + u16::from(*v.get(3)?);
        Some((code, std::str::from_utf8(v.get(4..)?).unwrap_or("")))
    }

    /// Whether MESSAGE-INTEGRITY is present and right for `key`.
    pub(crate) fn verify(&self, key: &[u8]) -> bool {
        let Some(&(_, at, value)) = self
            .attrs
            .iter()
            .find(|(k, _, _)| *k == attr::MESSAGE_INTEGRITY)
        else {
            return false;
        };
        let mut head = self.raw[..at].to_vec();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "a STUN message fits a datagram"
        )]
        let len = (at - HEADER + 24) as u16;
        head[2..4].copy_from_slice(&len.to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(&head);
        mac.verify_slice(value).is_ok()
    }
}

/// A fresh random transaction id.
pub(crate) fn transaction_id() -> [u8; 12] {
    rand::random()
}

/// Whether `data` is TURN `ChannelData`: a channel number (0x4000 to 0x7FFF) first.
pub(crate) fn is_channel_data(data: &[u8]) -> bool {
    data.len() >= 4 && (0x40..0x80).contains(&data[0])
}

/// `ChannelData` carrying `payload` on `channel`. Unpadded: over UDP the padding is optional.
#[allow(clippy::cast_possible_truncation, reason = "a payload fits a datagram")]
pub(crate) fn channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend(channel.to_be_bytes());
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend(payload);
    out
}

/// The channel and payload of `ChannelData`.
pub(crate) fn parse_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(data) {
        return None;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    Some((channel, data.get(4..4 + len)?))
}

/// The key of a TURN long-term credential: MD5 of `username:realm:password`.
pub(crate) fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(format!("{username}:{realm}:{password}").as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_round_trip() {
        for method in [method::BINDING, method::ALLOCATE, method::CHANNEL_BIND] {
            for class in [
                Class::Request,
                Class::Indication,
                Class::Success,
                Class::Error,
            ] {
                assert_eq!(split_type(message_type(method, class)), (method, class));
            }
        }
        // RFC 8489's examples: a Binding request is 0x0001, a success response 0x0101.
        assert_eq!(message_type(method::BINDING, Class::Request), 0x0001);
        assert_eq!(message_type(method::BINDING, Class::Success), 0x0101);
        assert_eq!(message_type(method::ALLOCATE, Class::Error), 0x0113);
    }

    #[test]
    fn messages_round_trip_with_integrity() {
        let tid = [9u8; 12];
        let peer: SocketAddr = "203.0.113.5:4242".parse().unwrap();
        let msg = Builder::new(method::CREATE_PERMISSION, Class::Request, tid)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::USERNAME, b"ann")
            .attr(attr::REALM, b"example.org")
            .integrity(b"key")
            .fingerprint();
        let parsed = Message::parse(&msg).unwrap();
        assert_eq!(parsed.method, method::CREATE_PERMISSION);
        assert_eq!(parsed.class, Class::Request);
        assert_eq!(parsed.xor_addr(attr::XOR_PEER_ADDRESS), Some(peer));
        assert_eq!(parsed.text(attr::REALM), Some("example.org"));
        assert!(parsed.verify(b"key"));
        assert!(!parsed.verify(b"other"));
    }

    /// `is` (str0m) checks ICE messages; a message signed here must pass its check, and the
    /// other way round.
    #[test]
    fn integrity_agrees_with_is() {
        let tid = [3u8; 12];
        let msg = Builder::new(method::BINDING, Class::Success, tid)
            .xor_addr(attr::XOR_MAPPED_ADDRESS, "198.51.100.2:9".parse().unwrap())
            .integrity(b"pass")
            .fingerprint();
        let theirs = is::stun::StunMessage::parse(&msg).unwrap();
        assert!(theirs.verify(b"pass", hmac_sha1));
    }

    #[test]
    fn channel_data_round_trips() {
        let framed = channel_data(0x4001, b"hello");
        assert!(is_channel_data(&framed));
        assert!(!crate::stun::is_stun(&framed));
        assert_eq!(parse_channel_data(&framed), Some((0x4001, &b"hello"[..])));
    }

    #[test]
    fn long_term_key_is_md5_of_user_realm_password() {
        // MD5("ann:example.org:pw"), computed independently.
        assert_eq!(
            long_term_key("ann", "example.org", "pw"),
            [
                103, 96, 114, 65, 189, 52, 132, 123, 45, 218, 122, 115, 232, 139, 237, 160
            ]
        );
    }
}
