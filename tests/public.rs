//! Smoke tests against the real public relays and STUN servers. Ignored by default: they need
//! the internet and publish a short-lived listing. Run with `cargo test --test public -- --ignored`.

mod common;

use std::time::Duration;

use common::{HostGame, listing, wait_for};
use game_rendezvous::{Config, HostEvent, Rendezvous};

fn public_config() -> Config {
    let mut c = Config::new("game-rendezvous-smoke-test", "1");
    // Keep the test's listing short-lived and leave the router alone.
    c.listing_ttl = Duration::from_secs(60);
    c.port_mapping = false;
    c
}

/// A listing reaches the public relays and comes back to a browser; then a player on this
/// machine joins through them (the handshake crosses the relays, the connection stays local).
#[test]
#[ignore = "uses public relays and STUN servers"]
fn public_relays_list_and_join() {
    common::init_logging();
    let host_rv = Rendezvous::new(public_config()).unwrap();
    let client_rv = Rendezvous::new(public_config()).unwrap();
    let mut host = HostGame::new(&host_rv, listing("smoke test"));
    let mut browser = client_rv.browse();
    let game = wait_for(Duration::from_secs(30), "the listing", || {
        host.frame();
        browser.poll();
        browser
            .games()
            .iter()
            .find(|g| g.name == "smoke test")
            .cloned()
    });
    let listed = wait_for(
        Duration::from_secs(15),
        "the relays' acknowledgements",
        || {
            host.frame();
            host.events.iter().find_map(|e| match e {
                HostEvent::Listed { relays } => Some(*relays),
                _ => None,
            })
        },
    );
    let status = host.host.status();
    println!(
        "listed on {listed} relays; relays connected {:?}; public addresses {:?}",
        status.relays, status.public_addresses
    );
    assert!(
        !status.public_addresses.is_empty(),
        "no STUN server answered"
    );

    let mut join = client_rv.join(&game, "smoke").unwrap();
    let conn = wait_for(Duration::from_secs(40), "the join", || {
        host.frame();
        join.poll()
    })
    .expect("a connection");
    println!("connected to {}", conn.peer);
}
