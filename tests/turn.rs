//! A player joins through the host's TURN relay, against a real TURN server on this machine.
//! Ignored by default: it needs one running, e.g. coturn or webrtc-rs's `turn` server, named
//! as `server,username,password`:
//!
//! ```text
//! GR_TEST_TURN=127.0.0.1:3479,user,pass cargo test --test turn -- --ignored
//! ```

mod common;

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use common::{HostGame, TestNet, listing, wait_for};
use game_rendezvous::{HostEvent, PeerPath, Rendezvous, TurnConfig};

const WAIT: Duration = Duration::from_secs(20);

fn turn_config() -> TurnConfig {
    let spec = std::env::var("GR_TEST_TURN").expect("GR_TEST_TURN=server,username,password");
    let mut parts = spec.splitn(3, ',');
    let (Some(server), Some(user), Some(pass)) = (parts.next(), parts.next(), parts.next()) else {
        panic!("GR_TEST_TURN=server,username,password");
    };
    TurnConfig::new(server, user, pass)
}

/// A STUN server that tells every client a port one above its own.
fn lying_stun() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let SocketAddr::V4(from) = from else { continue };
            if n < 20 || buf[..2] != [0, 1] {
                continue;
            }
            // A Binding success with XOR-MAPPED-ADDRESS (RFC 8489), the port off by one.
            let mut reply = vec![0x01, 0x01, 0, 12];
            reply.extend_from_slice(&buf[4..20]);
            reply.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
            reply.extend_from_slice(&((from.port() + 1) ^ 0x2112).to_be_bytes());
            reply.extend_from_slice(&(u32::from(*from.ip()) ^ 0x2112_A442).to_be_bytes());
            let _ = socket.send_to(&reply, from);
        }
    });
    addr
}

#[test]
#[ignore = "needs a TURN server: set GR_TEST_TURN"]
fn a_player_joins_through_the_relay() {
    let net = TestNet::start();
    // The host offers only an address nobody can reach, and no STUN server finds another: the
    // relay is the only way in. A relay that fails first is skipped.
    let mut config = net.config("1.0");
    config.local_addresses = Some(vec!["192.0.2.1".parse().unwrap()]);
    config.stun_servers.clear();
    config.connect_timeout = Duration::from_secs(8);
    let config = config
        .with_turn(TurnConfig::new("127.0.0.1:9", "nobody", "nothing"))
        .with_turn(turn_config());
    let host_rv = Rendezvous::new(config).unwrap();
    // The joiner, likewise, offers an address nobody can reach, and its STUN server sends it
    // the wrong port: the host cannot reach it directly either (on one machine, it otherwise
    // would), only answer it through the relay.
    let mut config = net.config("1.0");
    config.local_addresses = Some(vec!["192.0.2.2".parse().unwrap()]);
    config.stun_servers = vec![lying_stun().to_string()];
    let client_rv = Rendezvous::new(config).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Relayed"));

    let relayed = wait_for(WAIT, "the relay", || {
        host.frame();
        host.events.iter().find_map(|e| match e {
            HostEvent::Relay(Ok(addr)) => Some(*addr),
            HostEvent::Relay(Err(why)) => panic!("no relay: {why}"),
            _ => None,
        })
    });
    assert_eq!(host.host.status().nat.relay, Some(relayed));

    let mut browser = client_rv.browse();
    let game = wait_for(WAIT, "the listing", || {
        host.frame();
        browser.poll();
        browser.games().first().cloned()
    });
    // The listing says the host can be reached whatever the joiner's router.
    assert!(game.nat.is_some_and(|n| n.open), "{:?}", game.nat);
    let mut join = client_rv.join(&game, "Bob").unwrap();
    let conn = wait_for(Duration::from_secs(40), "the join", || {
        host.frame();
        join.poll()
    })
    .expect("a connection through the relay");
    assert_eq!(conn.peer, relayed);

    // Game traffic both ways, through the relay.
    game_rendezvous::send_to(&conn.socket, b"hello host", conn.peer).unwrap();
    let from = wait_for(WAIT, "the joiner's datagram", || {
        host.frame();
        host.received
            .iter()
            .find(|(_, d)| d == b"hello host")
            .map(|(a, _)| *a)
    });
    let path = wait_for(WAIT, "PeerConnected", || {
        host.frame();
        host.events.iter().find_map(|e| match e {
            HostEvent::PeerConnected { addr, path, .. } if *addr == from => Some(*path),
            _ => None,
        })
    });
    assert_eq!(path, PeerPath::Relay);
    let mut buf = [0u8; 64];
    for i in 0..20 {
        // Several, so both the first (a Send indication) and later ones (on a channel) go.
        host.socket
            .send_to(format!("reply {i}").as_bytes(), from)
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        host.frame();
    }
    let mut got = Vec::new();
    wait_for(WAIT, "the host's datagrams", || {
        host.frame();
        while let Ok((n, _)) = conn.socket.recv_from(&mut buf) {
            if !game_rendezvous::is_stun(&buf[..n]) {
                got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
        (got.len() >= 20).then_some(())
    });
    assert!(got.iter().any(|d| d == "reply 19"), "{got:?}");
}
