//! Checks what this machine can do for hosting: the router's behaviour and whether players
//! could probably reach a game hosted here, then which relays connect and whether the router
//! opens a port (UPnP, NAT-PMP or PCP). It advertises a listing under the game id
//! `game-rendezvous-probe` for a few seconds, then closes it and removes the port mapping.
//!
//! ```text
//! cargo run --example probe [-- TURN_SERVER USERNAME PASSWORD]
//! ```
//!
//! With a TURN server (`host:port`), it also checks that a relay can be allocated there.

use std::time::{Duration, Instant};

use game_rendezvous::{Config, GameSocket, HostEvent, Listing, Rendezvous, TurnConfig};

fn main() {
    let mut config = Config::new("game-rendezvous-probe", "0");
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [server, user, pass] = args.as_slice() {
        config = config.with_turn(TurnConfig::new(server, user, pass));
    }
    let rv = Rendezvous::new(config).expect("the worker starts");

    let mut check = rv.check_nat().expect("a socket");
    let report = loop {
        if let Some(r) = check.poll() {
            break r.clone();
        }
        std::thread::sleep(Duration::from_millis(16));
    };
    println!("router: {:?}", report.mapping);
    println!("public addresses (STUN): {:?}", report.public_addresses);
    println!("carrier-grade NAT: {}", report.carrier_grade);
    println!("port mapping: {:?}", report.port_mapping);
    println!("global IPv6: {}", report.global_ipv6);
    match (report.relay, check.relay_error()) {
        (Some(relay), _) => println!("TURN relay: {relay}"),
        (None, Some(why)) => println!("TURN relay failed: {why}"),
        (None, None) => {}
    }
    println!(
        "reachability: {:?} (listed as {})",
        report.reachability(),
        report.summary()
    );
    drop(check);

    let socket = GameSocket::bind(0).expect("a socket");
    let listing = Listing {
        name: "probe".into(),
        ..Default::default()
    };
    let mut host = rv.host(&socket, listing).expect("hosting starts");
    let start = Instant::now();
    let mut buf = [0u8; 1500];
    while start.elapsed() < Duration::from_secs(12) {
        while socket.recv_from(&mut buf).is_ok() {}
        while let Some(event) = host.poll() {
            match event {
                HostEvent::Listed { relays } => println!("listing accepted by {relays} relays"),
                HostEvent::ListingFailed(why) => println!("listing failed: {why}"),
                HostEvent::PortMapping(m) => println!("port mapping: {m:?}"),
                HostEvent::Network(_) => {}
                other => println!("{other:?}"),
            }
        }
        std::thread::sleep(Duration::from_millis(16));
    }
    let status = host.status();
    println!(
        "relays connected: {} of {}",
        status.relays.connected, status.relays.total
    );
    println!("local port: {}", socket.local_addr().unwrap().port());
}
