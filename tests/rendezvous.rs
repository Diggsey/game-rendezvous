//! End-to-end tests on a private network: a local relay and STUN server, localhost sockets.

mod common;

use std::time::Duration;

use common::{HostGame, TestNet, listing, wait_for};
use game_rendezvous::{Connection, GameInfo, HostEvent, JoinError, RefuseReason, Rendezvous};

const WAIT: Duration = Duration::from_secs(10);

/// Waits until `browser` lists a game named `name`.
fn find_game(browser: &mut game_rendezvous::Browser, host: &mut HostGame, name: &str) -> GameInfo {
    wait_for(WAIT, "the listing", || {
        host.frame();
        browser.poll();
        browser.games().iter().find(|g| g.name == name).cloned()
    })
}

/// Runs `join` and the host's frames until the join finishes.
fn finish_join(
    join: &mut game_rendezvous::Join,
    host: &mut HostGame,
) -> Result<Connection, JoinError> {
    wait_for(Duration::from_secs(30), "the join to finish", || {
        host.frame();
        join.poll()
    })
}

#[test]
fn listing_appears_updates_and_closes() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let browse_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Ann's game"));
    let mut browser = browse_rv.browse();

    let game = find_game(&mut browser, &mut host, "Ann's game");
    assert!(game.compatible);
    assert_eq!(game.version, "1.0");
    assert_eq!((game.players, game.max_players), (1, 4));
    assert_eq!(game.metadata["mode"], "deathmatch");

    let mut changed = listing("Ann's game");
    changed.players = 3;
    host.host.set_listing(changed);
    wait_for(WAIT, "the update", || {
        host.frame();
        browser.poll();
        browser.games().iter().find(|g| g.players == 3).map(|_| ())
    });
    assert!(
        host.events
            .iter()
            .any(|e| matches!(e, HostEvent::Listed { relays: 1 }))
    );

    // A closing host replaces its listing with a tombstone: the game leaves the list at once.
    drop(host);
    wait_for(WAIT, "the game to leave the list", || {
        browser.poll();
        browser.games().is_empty().then_some(())
    });
}

#[test]
fn listing_expires_without_refresh() {
    let net = TestNet::start();
    let mut config = net.config("1.0");
    config.listing_ttl = Duration::from_secs(2);
    config.listing_refresh = Duration::from_secs(3600);
    let host_rv = Rendezvous::new(config).unwrap();
    let browse_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Short-lived"));
    let mut browser = browse_rv.browse();
    find_game(&mut browser, &mut host, "Short-lived");
    // The host lives on but stops refreshing (as if hung): the listing expires.
    wait_for(Duration::from_secs(5), "the listing to expire", || {
        browser.poll();
        browser.games().is_empty().then_some(())
    });
    // A new browser does not get the expired listing from the relay either.
    let mut late = browse_rv.browse();
    std::thread::sleep(Duration::from_millis(500));
    late.poll();
    assert!(late.games().is_empty());
}

#[test]
fn other_versions_are_listed_but_not_joinable() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("2.0")).unwrap();
    let old_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("New version"));
    let mut browser = old_rv.browse();

    let game = find_game(&mut browser, &mut host, "New version");
    assert!(!game.compatible);
    assert_eq!(game.version, "2.0");
    match old_rv.join(&game, "Old client") {
        Err(JoinError::IncompatibleVersion { ours, theirs }) => {
            assert_eq!((ours.as_str(), theirs.as_str()), ("1.0", "2.0"));
        }
        other => panic!("expected a local refusal, got {:?}", other.err()),
    }

    // A client whose own rule accepts anything is still refused by the host's rule.
    let lax_rv = Rendezvous::new(net.config("1.0").with_compatibility(|_, _| true)).unwrap();
    let mut lax_browser = lax_rv.browse();
    let game = find_game(&mut lax_browser, &mut host, "New version");
    assert!(game.compatible);
    let mut join = lax_rv.join(&game, "Lax client").unwrap();
    match finish_join(&mut join, &mut host) {
        Err(JoinError::Refused(RefuseReason::IncompatibleVersion { host_version })) => {
            assert_eq!(host_version, "2.0");
        }
        other => panic!("expected the host to refuse, got {other:?}"),
    }
    assert!(host.events.iter().any(|e| matches!(
        e,
        HostEvent::JoinRefused { name, .. } if name == "Lax client"
    )));
}

#[test]
fn join_connects_on_localhost() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Connect"));
    let mut browser = client_rv.browse();
    let game = find_game(&mut browser, &mut host, "Connect");

    let mut join = client_rv.join(&game, "Bob").unwrap();
    let conn = finish_join(&mut join, &mut host).expect("a connection");
    assert_eq!(
        conn.peer,
        format!("127.0.0.1:{}", host.port()).parse().unwrap()
    );

    // The host learned its public address from the STUN server (localhost, here).
    let status = host.host.status();
    assert_eq!(
        status.public_addresses,
        vec![format!("127.0.0.1:{}", host.port()).parse().unwrap()]
    );

    // Game traffic flows both ways on the connected sockets.
    game_rendezvous::send_to(&conn.socket, b"hello host", conn.peer).unwrap();
    let client_addr = wait_for(WAIT, "the client's datagram", || {
        host.frame();
        host.received
            .iter()
            .find(|(_, d)| d == b"hello host")
            .map(|(a, _)| *a)
    });
    let connected = wait_for(WAIT, "PeerConnected", || {
        host.frame();
        host.events.iter().find_map(|e| match e {
            HostEvent::PeerConnected { addr, name } => Some((*addr, name.clone())),
            _ => None,
        })
    });
    assert_eq!(connected, (client_addr, "Bob".to_string()));
    game_rendezvous::send_to(&host.socket, b"hello client", client_addr).unwrap();
    let mut buf = [0u8; 64];
    let reply = wait_for(WAIT, "the host's datagram", || {
        // The host's last checks may still arrive; skip them.
        match conn.socket.recv_from(&mut buf) {
            Ok((n, _)) if !game_rendezvous::stun::is_stun(&buf[..n]) => Some(buf[..n].to_vec()),
            _ => None,
        }
    });
    assert_eq!(reply, b"hello client");
}

#[test]
fn unreachable_host_is_reported() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Unreachable"));
    // The host answers on the relays but never reads its socket, so no check gets through.
    host.pump_socket = false;
    let mut browser = client_rv.browse();
    let game = find_game(&mut browser, &mut host, "Unreachable");
    let mut join = client_rv.join(&game, "Bob").unwrap();
    match finish_join(&mut join, &mut host) {
        Err(e @ JoinError::NoRoute { tried, .. }) => {
            assert!(tried >= 1);
            assert!(e.to_string().contains("UPnP"), "{e}");
        }
        other => panic!("expected NoRoute, got {other:?}"),
    }
}

#[test]
fn silent_host_is_reported() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut config = net.config("1.0");
    config.handshake_timeout = Duration::from_secs(2);
    let client_rv = Rendezvous::new(config).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Silent"));
    let mut browser = client_rv.browse();
    let game = find_game(&mut browser, &mut host, "Silent");
    // The host stops running (hung, or its game loop stopped) with its listing still up.
    let mut join = client_rv.join(&game, "Bob").unwrap();
    let result = wait_for(Duration::from_secs(10), "the join to fail", || join.poll());
    assert!(
        matches!(result, Err(JoinError::HostNotResponding)),
        "{result:?}"
    );
}

#[test]
fn unreachable_relays_are_reported() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Elsewhere"));
    let mut browser = host_rv.browse();
    let game = find_game(&mut browser, &mut host, "Elsewhere");
    // A player whose relays are all down cannot send the join request.
    let offline_rv = Rendezvous::new(net.config("1.0").with_relays(["ws://127.0.0.1:9"])).unwrap();
    let mut join = offline_rv.join(&game, "Bob").unwrap();
    let result = wait_for(Duration::from_secs(20), "the join to fail", || join.poll());
    assert!(
        matches!(result, Err(JoinError::RelaysUnavailable(_))),
        "{result:?}"
    );
}
