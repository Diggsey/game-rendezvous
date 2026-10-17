//! End-to-end tests on a private network: a local relay and STUN server, localhost sockets.

mod common;

use std::time::Duration;

use common::{HANDSHAKE_KIND, HostGame, TestNet, forged_request, listing, wait_for};
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
    assert!(conn.received.is_empty(), "the host's game has sent nothing yet");
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
    // A finished join stops asking, though the game still holds it (to show the error).
    let client = net.client();
    let host_key = net.host_key(&client);
    let repeats = net.count_handshakes(&client, host_key, Duration::from_secs(5));
    assert_eq!(repeats, 0, "the finished join kept sending its request");
    assert!(join.poll().is_none());
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

#[test]
fn games_not_taking_players_are_listed_but_not_joinable() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Busy"));
    let mut browser = client_rv.browse();
    let before = find_game(&mut browser, &mut host, "Busy");
    assert!(before.joinable);

    // A match starts: the game stays listed, as not joinable.
    let mut playing = listing("Busy");
    playing.joinable = false;
    host.host.set_listing(playing);
    let during = wait_for(WAIT, "the game to show as not joinable", || {
        host.frame();
        browser.poll();
        browser.games().iter().find(|g| !g.joinable).cloned()
    });
    assert!(during.compatible);
    assert!(matches!(
        client_rv.join(&during, "Bob"),
        Err(JoinError::NotJoinable)
    ));
    // A player whose list is out of date is refused by the host.
    let mut join = client_rv.join(&before, "Late").unwrap();
    match finish_join(&mut join, &mut host) {
        Err(JoinError::Refused(RefuseReason::NotAccepting)) => {}
        other => panic!("expected the host to refuse, got {other:?}"),
    }

    // Back in the lobby: joinable again.
    host.host.set_listing(listing("Busy"));
    wait_for(WAIT, "the game to be joinable again", || {
        host.frame();
        browser.poll();
        browser.games().iter().find(|g| g.joinable).map(|_| ())
    });
}

#[test]
fn joinable_games_are_listed_first() {
    let net = TestNet::start();
    let rv = Rendezvous::new(net.config("1.0")).unwrap();
    let old_rv = Rendezvous::new(net.config("0.9")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut busy = listing("A busy game");
    busy.joinable = false;
    let mut hosts = [
        HostGame::new(&old_rv, listing("A different version")),
        HostGame::new(&rv, busy),
        HostGame::new(&rv, listing("Z open game")),
    ];
    let mut browser = client_rv.browse();
    let names = wait_for(WAIT, "all three games", || {
        hosts.iter_mut().for_each(HostGame::frame);
        browser.poll();
        let names: Vec<String> = browser.games().iter().map(|g| g.name.clone()).collect();
        (names.len() == 3).then_some(names)
    });
    assert_eq!(names, ["Z open game", "A busy game", "A different version"]);
}

/// Anyone can send a host handshake messages. A flood of them, unreadable or for another
/// game, is read (or dropped unread) on the worker: none of it reaches the game, and a real
/// player still gets in.
#[test]
fn a_flood_of_junk_requests_does_not_reach_the_game() {
    use nostr_sdk::prelude::*;

    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Flooded"));
    let mut browser = client_rv.browse();
    let game = find_game(&mut browser, &mut host, "Flooded");

    // The host's key, from its listing on the relay.
    let client = net.client();
    let host_key = net.host_key(&client);

    // 300 unreadable messages, and 50 readable requests for another game.
    let mut flood = Vec::new();
    for i in 0..300 {
        let keys = Keys::generate();
        let event = EventBuilder::new(HANDSHAKE_KIND, format!("not a NIP-44 payload {i}"))
            .tag(Tag::public_key(host_key))
            .finalize(&keys)
            .unwrap();
        flood.push(event);
    }
    for i in 0..50 {
        flood.push(forged_request(&host_key, "another-game", "1.0", &format!("Spam {i}")));
    }
    net.send(&client, &flood);

    // A real player joins straight after the flood.
    let mut join = client_rv.join(&game, "Bob").unwrap();
    finish_join(&mut join, &mut host).expect("the real player gets in");
    let connected = wait_for(WAIT, "PeerConnected", || {
        host.frame();
        host.events.iter().find_map(|e| match e {
            HostEvent::PeerConnected { name, .. } => Some(name.clone()),
            _ => None,
        })
    });
    assert_eq!(connected, "Bob");
    // The game heard of nobody else: no refusals, no other players.
    assert!(
        host.events.iter().all(|e| matches!(
            e,
            HostEvent::Listed { .. } | HostEvent::PeerConnected { .. }
        )),
        "{:?}",
        host.events
    );
}

/// The host's game may greet a player the moment it connects, while the joiner's checks are
/// still settling: the greeting reaches the joiner's game all the same.
#[test]
fn the_hosts_first_datagram_reaches_the_joiner() {
    let net = TestNet::start();
    let host_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let client_rv = Rendezvous::new(net.config("1.0")).unwrap();
    let mut host = HostGame::new(&host_rv, listing("Greeter"));
    let mut browser = client_rv.browse();
    let game = find_game(&mut browser, &mut host, "Greeter");

    let mut join = client_rv.join(&game, "Bob").unwrap();
    let mut greeted = false;
    let conn = wait_for(Duration::from_secs(30), "the join to finish", || {
        host.frame();
        greet(&mut host, &mut greeted);
        join.poll()
    })
    .expect("a connection");
    let mut got = conn.received.clone();
    let mut buf = [0u8; 64];
    wait_for(WAIT, "the greeting", || {
        host.frame();
        greet(&mut host, &mut greeted);
        while let Ok((n, _)) = conn.socket.recv_from(&mut buf) {
            if !game_rendezvous::stun::is_stun(&buf[..n]) {
                got.push(buf[..n].to_vec());
            }
        }
        got.iter().any(|d| d == b"welcome").then_some(())
    });
}

/// Sends the joiner a greeting once the host has seen it connect.
fn greet(host: &mut HostGame, greeted: &mut bool) {
    if *greeted {
        return;
    }
    let connected = host.events.iter().find_map(|e| match e {
        HostEvent::PeerConnected { addr, .. } => Some(*addr),
        _ => None,
    });
    if let Some(addr) = connected {
        game_rendezvous::send_to(&host.socket, b"welcome", addr).unwrap();
        *greeted = true;
    }
}
