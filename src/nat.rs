//! What a player's router does to their traffic, and what that means for connecting.
//!
//! STUN servers are asked from the game's own socket, several at once and in a fixed order.
//! The public ports they see tell how the router maps the socket:
//!
//! - one port for every destination ("endpoint-independent"): hole punching works;
//! - a new port for each destination ("endpoint-dependent", or "symmetric"): the other side
//!   cannot know which port to send to. The new ports may still be guessable: the socket's own
//!   port ("preserving") or the last one plus a step ("sequential"). Random ones are not.
//!
//! Add whether the router forwarded a port, whether the machine has a global IPv6 address, a
//! TURN relay, and whether the router sits behind the provider's own NAT (carrier-grade NAT,
//! which defeats port forwarding), and both sides can tell before connecting whether they
//! probably can ([`NatSummary::outlook`]).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use crate::net::LocalAddr;
use crate::portmap::PortMapMethod;

/// How a router maps a socket's traffic to public ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NatMapping {
    /// Not known: too few STUN servers answered, or none yet.
    Unknown,
    /// No NAT: the STUN servers saw the machine's own address.
    Open,
    /// One public port for every destination: hole punching works.
    EndpointIndependent,
    /// A new public port for each destination ("symmetric NAT").
    EndpointDependent(PortAllocation),
}

/// How an endpoint-dependent router picks the public port for a new destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PortAllocation {
    /// The socket's own port, when free.
    Preserving,
    /// The last port given out plus `step`.
    Sequential {
        /// The difference between consecutive ports, e.g. 1.
        step: i32,
    },
    /// Unpredictable ports.
    Random,
}

/// The largest step between consecutive ports still taken for sequential allocation.
const MAX_STEP: i32 = 32;

/// How easily joiners can reach a host, from its [`NatReport`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reachability {
    /// Not known yet.
    Unknown,
    /// Anyone can connect: a public address, a forwarded port, or a TURN relay.
    Open,
    /// Most players can connect, by hole punching.
    Good,
    /// Only players whose routers are lenient can connect; a relay would let the rest in.
    Limited,
    /// Hardly anyone can connect (no STUN server answered: UDP may be blocked).
    Poor,
}

impl Reachability {
    /// Whether a TURN relay would let in players who otherwise could not connect.
    #[must_use]
    pub fn suggests_relay(self) -> bool {
        matches!(self, Reachability::Limited | Reachability::Poor)
    }
}

/// What a check of this machine's network found, for a host ([`Host::nat`](crate::Host::nat))
/// or before hosting ([`NatCheck`](crate::NatCheck)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NatReport {
    /// How the router maps the socket.
    pub mapping: NatMapping,
    /// The public addresses the STUN servers saw, in the order they were asked.
    pub public_addresses: Vec<SocketAddr>,
    /// The router is behind the internet provider's own NAT ("carrier-grade" NAT): its public
    /// address is private or shared, or not the one STUN servers see. Port forwarding on the
    /// router then does not open the port to the internet.
    pub carrier_grade: bool,
    /// The port the router forwards, with the protocol that opened it, if it did (and it is
    /// not behind carrier-grade NAT, which makes the forwarding useless).
    pub port_mapping: Option<(SocketAddr, PortMapMethod)>,
    /// The machine has a global IPv6 address: players with IPv6 can connect directly.
    pub global_ipv6: bool,
    /// The TURN relay's address for this host, if one is configured and allocated.
    pub relay: Option<SocketAddr>,
}

impl Default for NatReport {
    fn default() -> Self {
        NatReport {
            mapping: NatMapping::Unknown,
            public_addresses: Vec::new(),
            carrier_grade: false,
            port_mapping: None,
            global_ipv6: false,
            relay: None,
        }
    }
}

impl NatReport {
    /// How easily joiners can reach a host with this network.
    #[must_use]
    pub fn reachability(&self) -> Reachability {
        if self.open() {
            return Reachability::Open;
        }
        match self.mapping {
            NatMapping::Open => Reachability::Open,
            NatMapping::EndpointIndependent => Reachability::Good,
            NatMapping::EndpointDependent(_) => Reachability::Limited,
            NatMapping::Unknown if self.public_addresses.is_empty() => Reachability::Poor,
            NatMapping::Unknown => Reachability::Unknown,
        }
    }

    /// Whether anyone can reach the socket whatever their router does.
    fn open(&self) -> bool {
        self.relay.is_some() || self.port_mapping.is_some() || self.mapping == NatMapping::Open
    }

    /// The summary a host advertises in its listing, and both sides swap when joining.
    #[must_use]
    pub fn summary(&self) -> NatSummary {
        NatSummary {
            mapping: self.mapping,
            open: self.open(),
            ipv6: self.global_ipv6,
            carrier_grade: self.carrier_grade,
        }
    }
}

/// A compact summary of a player's network: what a host's listing shows
/// ([`GameInfo::nat`](crate::GameInfo::nat)), and what both sides swap when joining.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NatSummary {
    /// How the router maps the socket.
    pub mapping: NatMapping,
    /// Anyone can reach it: a public address, a forwarded port, or a TURN relay.
    pub open: bool,
    /// It has a global IPv6 address.
    pub ipv6: bool,
    /// It is behind carrier-grade NAT.
    pub carrier_grade: bool,
}

/// How likely a join is to connect, judged from both sides' networks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outlook {
    /// It will very probably connect.
    Likely,
    /// It may connect: one side's router is strict, and the library will try guessing its
    /// ports.
    Possible,
    /// Both routers are strict: it will connect only if the host sets up a relay.
    NeedsRelay,
    /// One side's network is not known (yet).
    Unknown,
}

/// How lenient a router is, for judging a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strictness {
    /// Unknown.
    Unknown,
    /// No NAT, or endpoint-independent mapping.
    Lenient,
    /// Endpoint-dependent, but its ports can be guessed.
    Predictable,
    /// Endpoint-dependent with random ports.
    Random,
}

impl NatSummary {
    /// The summary for a network nothing is known about.
    #[must_use]
    pub fn unknown() -> NatSummary {
        NatSummary {
            mapping: NatMapping::Unknown,
            open: false,
            ipv6: false,
            carrier_grade: false,
        }
    }

    /// How lenient the router is.
    fn strictness(self) -> Strictness {
        match self.mapping {
            NatMapping::Unknown => Strictness::Unknown,
            NatMapping::Open | NatMapping::EndpointIndependent => Strictness::Lenient,
            NatMapping::EndpointDependent(PortAllocation::Random) => Strictness::Random,
            NatMapping::EndpointDependent(_) => Strictness::Predictable,
        }
    }

    /// How likely a joiner with this network is to connect to a host with `host`'s.
    #[must_use]
    pub fn outlook(&self, host: &NatSummary) -> Outlook {
        use Strictness::{Lenient, Predictable, Random, Unknown};
        if host.open || (self.ipv6 && host.ipv6) {
            return Outlook::Likely;
        }
        match (self.strictness(), host.strictness()) {
            (Unknown, _) | (_, Unknown) => Outlook::Unknown,
            (Lenient, Lenient) => Outlook::Likely,
            (Lenient, Predictable | Random) | (Predictable | Random, Lenient) => Outlook::Possible,
            _ => Outlook::NeedsRelay,
        }
    }
}

impl fmt::Display for NatSummary {
    /// A compact form, as listings carry it: the mapping (`?`, `open`, `eim`, `pp`, `seq+N`,
    /// `rand`), then `;o` (open), `;6` (IPv6) and `;cg` (carrier-grade) when they apply.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.mapping {
            NatMapping::Unknown => f.write_str("?")?,
            NatMapping::Open => f.write_str("open")?,
            NatMapping::EndpointIndependent => f.write_str("eim")?,
            NatMapping::EndpointDependent(PortAllocation::Preserving) => f.write_str("pp")?,
            NatMapping::EndpointDependent(PortAllocation::Sequential { step }) => {
                write!(f, "seq{step:+}")?;
            }
            NatMapping::EndpointDependent(PortAllocation::Random) => f.write_str("rand")?,
        }
        for (on, flag) in [
            (self.open, ";o"),
            (self.ipv6, ";6"),
            (self.carrier_grade, ";cg"),
        ] {
            if on {
                f.write_str(flag)?;
            }
        }
        Ok(())
    }
}

impl FromStr for NatSummary {
    type Err = ();

    /// Reads the compact form; unknown flags are ignored, for later versions' sake.
    fn from_str(s: &str) -> Result<Self, ()> {
        if s.len() > 64 {
            return Err(());
        }
        let mut parts = s.split(';');
        let mapping = match parts.next().ok_or(())? {
            "?" => NatMapping::Unknown,
            "open" => NatMapping::Open,
            "eim" => NatMapping::EndpointIndependent,
            "pp" => NatMapping::EndpointDependent(PortAllocation::Preserving),
            "rand" => NatMapping::EndpointDependent(PortAllocation::Random),
            m => {
                let step: i32 = m.strip_prefix("seq").ok_or(())?.parse().map_err(|_| ())?;
                if step == 0 || step.abs() > MAX_STEP {
                    return Err(());
                }
                NatMapping::EndpointDependent(PortAllocation::Sequential { step })
            }
        };
        let mut summary = NatSummary {
            mapping,
            ..NatSummary::unknown()
        };
        for flag in parts {
            match flag {
                "o" => summary.open = true,
                "6" => summary.ipv6 = true,
                "cg" => summary.carrier_grade = true,
                _ => {}
            }
        }
        Ok(summary)
    }
}

/// Reads a summary a stranger sent; anything unreadable is unknown.
pub(crate) fn parse_summary(s: Option<&str>) -> Option<NatSummary> {
    s.and_then(|s| s.parse().ok())
}

/// How a router maps a socket on `port`, from the public addresses STUN servers saw (in the
/// order the servers were first asked, which is the order the router made the mappings), and
/// the machine's addresses.
pub(crate) fn classify(observed: &[SocketAddr], port: u16, locals: &[LocalAddr]) -> NatMapping {
    let v4: Vec<SocketAddr> = observed
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect();
    if v4
        .iter()
        .any(|a| locals.iter().any(|l| l.ip == a.ip()) && a.port() == port)
    {
        return NatMapping::Open;
    }
    if v4.len() < 2 {
        // With IPv6 alone the machine is unNATed (but maybe firewalled); one IPv4 answer
        // cannot tell mappings apart.
        return NatMapping::Unknown;
    }
    let ports: Vec<i32> = v4.iter().map(|a| i32::from(a.port())).collect();
    if ports.iter().all(|&p| p == ports[0]) {
        return NatMapping::EndpointIndependent;
    }
    let steps: Vec<i32> = ports.windows(2).map(|w| w[1] - w[0]).collect();
    let same_sign = steps.iter().all(|&d| d > 0) || steps.iter().all(|&d| d < 0);
    if same_sign && steps.iter().all(|d| d.abs() <= MAX_STEP) {
        let smallest = steps.iter().map(|d| d.abs()).min().unwrap_or(1);
        let step = if steps[0] > 0 { smallest } else { -smallest };
        return NatMapping::EndpointDependent(PortAllocation::Sequential { step });
    }
    if ports[0] == i32::from(port) {
        return NatMapping::EndpointDependent(PortAllocation::Preserving);
    }
    NatMapping::EndpointDependent(PortAllocation::Random)
}

/// Whether `ip` is not on the public internet: private, shared (carrier-grade NAT's
/// 100.64.0.0/10), loopback or link-local.
fn not_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_shared(v4)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Whether `ip` is in 100.64.0.0/10, the space carrier-grade NATs use inside.
fn is_shared(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

/// Whether the router sits behind carrier-grade NAT: the public address its port-mapping
/// protocol reported is private or shared, or differs from what STUN servers saw; or this
/// machine's own default address is in the shared space.
pub(crate) fn carrier_grade(
    mapped_ip: Option<IpAddr>,
    observed: &[SocketAddr],
    locals: &[LocalAddr],
) -> bool {
    let stun_v4 = observed.iter().find(|a| a.is_ipv4()).map(SocketAddr::ip);
    let mapped = mapped_ip
        .is_some_and(|ip| not_public(ip) || stun_v4.is_some_and(|s| ip.is_ipv4() && s != ip));
    let shared_local = locals
        .iter()
        .any(|l| matches!(l.ip, IpAddr::V4(v4) if is_shared(v4)));
    mapped || shared_local
}

/// Whether any of `locals` is a global IPv6 address (`2000::/3`).
pub(crate) fn global_ipv6(locals: &[LocalAddr]) -> bool {
    locals
        .iter()
        .any(|l| matches!(l.ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xe000) == 0x2000))
}

/// The public ports an endpoint-dependent router will probably give the socket for its next
/// destinations: what the other side should try sending to, beyond the ports seen.
///
/// `window` bounds how many: the socket contacts a few destinations of its own (the peer's
/// other addresses) before the one that counts.
pub(crate) fn predicted_ports(
    mapping: NatMapping,
    observed: &[SocketAddr],
    port: u16,
    window: usize,
) -> Vec<u16> {
    let last = observed
        .iter()
        .rev()
        .find(|a| a.is_ipv4())
        .map(SocketAddr::port);
    match (mapping, last) {
        (NatMapping::EndpointDependent(PortAllocation::Preserving), _) => vec![port],
        (NatMapping::EndpointDependent(PortAllocation::Sequential { step }), Some(last)) => (1
            ..=i32::try_from(window).unwrap_or(i32::MAX))
            .filter_map(|i| u16::try_from(i32::from(last) + step * i).ok())
            .filter(|&p| p >= 1024)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(ports: &[u16]) -> Vec<SocketAddr> {
        ports
            .iter()
            .map(|&p| SocketAddr::from(([203, 0, 113, 7], p)))
            .collect()
    }

    fn lan() -> Vec<LocalAddr> {
        vec![LocalAddr {
            ip: "192.168.1.20".parse().unwrap(),
            prefix: 24,
            default: true,
        }]
    }

    #[test]
    fn mappings_are_classified() {
        let c = |ports: &[u16]| classify(&addrs(ports), 7777, &lan());
        assert_eq!(c(&[]), NatMapping::Unknown);
        assert_eq!(c(&[40000]), NatMapping::Unknown);
        assert_eq!(c(&[40000, 40000, 40000]), NatMapping::EndpointIndependent);
        assert_eq!(
            c(&[40000, 40001, 40002]),
            NatMapping::EndpointDependent(PortAllocation::Sequential { step: 1 })
        );
        // Another machine's mapping in between: the smallest step.
        assert_eq!(
            c(&[40000, 40002, 40003]),
            NatMapping::EndpointDependent(PortAllocation::Sequential { step: 1 })
        );
        assert_eq!(
            c(&[7777, 51234]),
            NatMapping::EndpointDependent(PortAllocation::Preserving)
        );
        assert_eq!(
            c(&[23456, 51234, 1111]),
            NatMapping::EndpointDependent(PortAllocation::Random)
        );
        let public = vec![LocalAddr {
            ip: "203.0.113.7".parse().unwrap(),
            prefix: 24,
            default: true,
        }];
        assert_eq!(classify(&addrs(&[7777]), 7777, &public), NatMapping::Open);
    }

    #[test]
    fn carrier_grade_nat_is_spotted() {
        let seen = addrs(&[40000]);
        assert!(!carrier_grade(
            Some("203.0.113.7".parse().unwrap()),
            &seen,
            &lan()
        ));
        assert!(carrier_grade(
            Some("100.72.1.2".parse().unwrap()),
            &seen,
            &lan()
        ));
        assert!(carrier_grade(
            Some("10.0.0.1".parse().unwrap()),
            &seen,
            &lan()
        ));
        assert!(carrier_grade(
            Some("198.51.100.1".parse().unwrap()),
            &seen,
            &lan()
        ));
        let shared = vec![LocalAddr {
            ip: "100.100.1.2".parse().unwrap(),
            prefix: 10,
            default: true,
        }];
        assert!(carrier_grade(None, &seen, &shared));
    }

    #[test]
    fn summaries_round_trip() {
        let all = [
            NatMapping::Unknown,
            NatMapping::Open,
            NatMapping::EndpointIndependent,
            NatMapping::EndpointDependent(PortAllocation::Preserving),
            NatMapping::EndpointDependent(PortAllocation::Sequential { step: -2 }),
            NatMapping::EndpointDependent(PortAllocation::Random),
        ];
        for mapping in all {
            let s = NatSummary {
                mapping,
                open: true,
                ipv6: false,
                carrier_grade: true,
            };
            assert_eq!(s.to_string().parse::<NatSummary>(), Ok(s), "{s}");
        }
        assert_eq!(parse_summary(Some("seq+99")), None);
        assert_eq!(
            parse_summary(Some("eim;future-flag")).map(|s| s.mapping),
            Some(NatMapping::EndpointIndependent)
        );
    }

    #[test]
    fn outlooks() {
        let s = |m: &str| m.parse::<NatSummary>().unwrap();
        assert_eq!(s("eim").outlook(&s("eim")), Outlook::Likely);
        assert_eq!(s("rand").outlook(&s("eim")), Outlook::Possible);
        assert_eq!(s("eim").outlook(&s("seq+1")), Outlook::Possible);
        assert_eq!(s("rand").outlook(&s("seq+1")), Outlook::NeedsRelay);
        assert_eq!(s("rand").outlook(&s("rand;o")), Outlook::Likely);
        assert_eq!(s("rand;6").outlook(&s("rand;6")), Outlook::Likely);
        assert_eq!(s("?").outlook(&s("eim")), Outlook::Unknown);
    }

    #[test]
    fn predictions() {
        let seq = NatMapping::EndpointDependent(PortAllocation::Sequential { step: 2 });
        assert_eq!(
            predicted_ports(seq, &addrs(&[40000, 40002]), 7777, 3),
            [40004, 40006, 40008]
        );
        let pp = NatMapping::EndpointDependent(PortAllocation::Preserving);
        assert_eq!(predicted_ports(pp, &addrs(&[7777, 9999]), 7777, 3), [7777]);
        assert!(predicted_ports(NatMapping::EndpointIndependent, &addrs(&[1]), 1, 3).is_empty());
    }

    #[test]
    fn reachability() {
        let mut r = NatReport::default();
        assert_eq!(r.reachability(), Reachability::Poor);
        r.public_addresses = addrs(&[1, 2]);
        r.mapping = NatMapping::EndpointIndependent;
        assert_eq!(r.reachability(), Reachability::Good);
        r.mapping = NatMapping::EndpointDependent(PortAllocation::Random);
        assert_eq!(r.reachability(), Reachability::Limited);
        assert!(r.reachability().suggests_relay());
        r.relay = Some("198.51.100.1:50000".parse().unwrap());
        assert_eq!(r.reachability(), Reachability::Open);
        assert!(r.summary().open);
    }
}
