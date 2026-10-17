//! Socket helpers: dual-stack sockets, address normalisation, and this machine's addresses.
//!
//! A game reaches IPv6 peers and IPv4 peers on one socket by binding `[::]` with `IPV6_V6ONLY`
//! off. Such a socket reports IPv4 peers as IPv4-mapped IPv6 addresses (`[::ffff:a.b.c.d]`) and
//! cannot send to a plain IPv4 `SocketAddr`; [`canonical`] and [`send_to`] hide both.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

/// Binds a non-blocking UDP socket on `port` (0 for any) that reaches both IPv4 and IPv6 peers.
///
/// Falls back to an IPv4-only socket where IPv6 is unavailable. Broadcast is enabled, so the
/// socket can also do LAN discovery (send to `255.255.255.255` through [`send_to`]).
pub fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    let socket = match dual_stack_socket(port) {
        Ok(s) => s,
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
            s
        }
    };
    socket.set_nonblocking(true)?;
    let _ = socket.set_broadcast(true);
    Ok(socket.into())
}

fn dual_stack_socket(port: u16) -> io::Result<Socket> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(false)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(s)
}

/// `addr` with an IPv4-mapped IPv6 address turned back into IPv4, so that a peer has one
/// address whichever kind of socket heard it.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => addr,
        },
        v4 => v4,
    }
}

/// `addr` in the form `socket` can send to: IPv4-mapped on an IPv6 socket.
pub fn for_socket(socket: &UdpSocket, addr: SocketAddr) -> SocketAddr {
    match (socket.local_addr(), addr) {
        (Ok(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

/// Sends `data` to `to`, whether `to` is IPv4 or IPv6 and whether the socket is dual-stack.
pub fn send_to(socket: &UdpSocket, data: &[u8], to: SocketAddr) -> io::Result<usize> {
    socket.send_to(data, for_socket(socket, to))
}

/// The address families a socket can reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Families {
    pub v4: bool,
    pub v6: bool,
}

impl Families {
    /// What `socket` reaches: IPv4 for an IPv4 socket; IPv6 for an IPv6 one, and IPv4 too
    /// unless `IPV6_V6ONLY` is on (as it is by default on Windows for std's `[::]` sockets).
    pub fn of(socket: &UdpSocket) -> Families {
        match socket.local_addr() {
            Ok(SocketAddr::V4(_)) => Families { v4: true, v6: false },
            Ok(SocketAddr::V6(_)) => {
                let only_v6 = SockRef::from(socket).only_v6().unwrap_or(false);
                Families {
                    v4: !only_v6,
                    v6: true,
                }
            }
            Err(_) => Families {
                v4: false,
                v6: false,
            },
        }
    }

    /// Whether the socket reaches `ip`.
    pub fn reaches(self, ip: IpAddr) -> bool {
        if ip.is_ipv4() { self.v4 } else { self.v6 }
    }
}

/// One of this machine's addresses, with its network's prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalAddr {
    pub ip: IpAddr,
    pub prefix: u8,
    /// On the interface that holds the default route.
    pub default: bool,
}

/// The addresses a socket can be reached on directly: its LAN addresses and global IPv6
/// addresses (not loopback or link-local, which need a scope or reach nobody else).
///
/// A socket bound to one address has only that one. `only`, when given, replaces the machine's
/// addresses (tests use `127.0.0.1`).
pub(crate) fn local_addrs(socket: &UdpSocket, only: Option<&[IpAddr]>) -> Vec<LocalAddr> {
    let Ok(bound) = socket.local_addr() else {
        return Vec::new();
    };
    let bound_ip = canonical(bound).ip();
    if !bound_ip.is_unspecified() {
        return vec![LocalAddr {
            ip: bound_ip,
            prefix: if bound_ip.is_ipv4() { 32 } else { 128 },
            default: true,
        }];
    }
    let families = Families::of(socket);
    let usable = |ip: &IpAddr| families.reaches(*ip);
    if let Some(only) = only {
        return only
            .iter()
            .filter(|ip| usable(ip))
            .map(|&ip| LocalAddr {
                ip,
                prefix: if ip.is_ipv4() { 24 } else { 64 },
                default: true,
            })
            .collect();
    }
    let default_index = netdev::get_default_interface().ok().map(|i| i.index);
    let mut addrs = Vec::new();
    for iface in netdev::get_interfaces() {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        let default = Some(iface.index) == default_index;
        for net in iface.ipv4.iter().filter(|_| families.v4) {
            let ip = net.addr();
            if !ip.is_link_local() && !ip.is_unspecified() {
                addrs.push(LocalAddr {
                    ip: ip.into(),
                    prefix: net.prefix_len(),
                    default,
                });
            }
        }
        if !families.v6 {
            continue;
        }
        for (i, net) in iface.ipv6.iter().enumerate() {
            let ip = net.addr();
            let deprecated = iface.ipv6_addr_flags.get(i).is_some_and(|f| f.deprecated);
            // Global unicast and unique local (fc00::/7); not link-local (fe80::/10).
            let routable = !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && (ip.segments()[0] & 0xffc0) != 0xfe80;
            if routable && !deprecated {
                addrs.push(LocalAddr {
                    ip: ip.into(),
                    prefix: net.prefix_len(),
                    default,
                });
            }
        }
    }
    // The default interface's addresses first: they are the likeliest to work.
    addrs.sort_by_key(|a| !a.default);
    addrs
}

/// Which of `locals` a datagram from `from` most likely arrived on: the same family, preferring
/// loopback for loopback, then the same network, then the default interface.
///
/// The socket is bound to the wildcard address, so the real destination is unknown. The ICE agent
/// only needs a local candidate to pair the sender with, and every candidate shares the one
/// socket, so a wrong guess still answers from the right socket.
pub(crate) fn guess_destination(locals: &[LocalAddr], from: IpAddr) -> Option<IpAddr> {
    let same_family = || locals.iter().filter(|l| l.ip.is_ipv4() == from.is_ipv4());
    if from.is_loopback()
        && let Some(l) = same_family().find(|l| l.ip.is_loopback())
    {
        return Some(l.ip);
    }
    same_family()
        .find(|l| same_network(l.ip, from, l.prefix))
        .or_else(|| same_family().find(|l| l.default))
        .or_else(|| same_family().next())
        .map(|l| l.ip)
}

fn same_network(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix.min(32)))
                .unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_become_ipv4() {
        let mapped: SocketAddr = "[::ffff:192.168.1.5]:7777".parse().unwrap();
        assert_eq!(canonical(mapped), "192.168.1.5:7777".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:7777".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }

    #[test]
    fn dual_stack_socket_reaches_ipv4() {
        let a = bind_dual_stack(0).unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        send_to(&a, b"hi", b.local_addr().unwrap()).unwrap();
        let mut buf = [0; 8];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(from.port(), a.local_addr().unwrap().port());
    }

    #[test]
    fn families_follow_the_v6_only_option() {
        let dual = bind_dual_stack(0).unwrap();
        if matches!(dual.local_addr().unwrap(), SocketAddr::V6(_)) {
            assert_eq!(Families::of(&dual), Families { v4: true, v6: true });
            let v6_only = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            v6_only.set_only_v6(true).unwrap();
            v6_only
                .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
                .unwrap();
            let v6_only: UdpSocket = v6_only.into();
            assert_eq!(Families::of(&v6_only), Families { v4: false, v6: true });
        }
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(Families::of(&v4), Families { v4: true, v6: false });
    }

    #[test]
    fn destination_prefers_the_same_network() {
        let locals = [
            LocalAddr {
                ip: "10.0.0.2".parse().unwrap(),
                prefix: 8,
                default: false,
            },
            LocalAddr {
                ip: "192.168.1.20".parse().unwrap(),
                prefix: 24,
                default: true,
            },
        ];
        let guess = |s: &str| guess_destination(&locals, s.parse().unwrap()).unwrap();
        assert_eq!(guess("10.1.2.3"), "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(guess("8.8.8.8"), "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!(
            guess_destination(&locals, "2001:db8::1".parse().unwrap()),
            None
        );
    }
}
