//! Checks what this machine can do for hosting: which relays connect, the public address the
//! STUN servers see, and whether the router opens a port (UPnP, NAT-PMP or PCP). It advertises
//! a listing under the game id `game-rendezvous-probe` for a few seconds, then closes it and
//! removes the port mapping.
//!
//! ```text
//! cargo run --example probe
//! ```

use std::time::{Duration, Instant};

use game_rendezvous::{Config, HostEvent, Listing, Rendezvous, bind_dual_stack};

fn main() {
    let rv = Rendezvous::new(Config::new("game-rendezvous-probe", "0")).expect("the worker starts");
    let socket = bind_dual_stack(0).expect("a socket");
    let listing = Listing {
        name: "probe".into(),
        ..Default::default()
    };
    let mut host = rv.host(&socket, listing).expect("hosting starts");
    let start = Instant::now();
    let mut buf = [0u8; 1500];
    while start.elapsed() < Duration::from_secs(12) {
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            host.handle_datagram(game_rendezvous::canonical(from), &buf[..n]);
        }
        while let Some(event) = host.poll() {
            match event {
                HostEvent::Listed { relays } => println!("listing accepted by {relays} relays"),
                HostEvent::ListingFailed(why) => println!("listing failed: {why}"),
                HostEvent::PortMapping(m) => println!("port mapping: {m:?}"),
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
    println!("public addresses (STUN): {:?}", status.public_addresses);
    println!("router port mapping: {:?}", status.port_mapping);
    println!("local port: {}", socket.local_addr().unwrap().port());
}
