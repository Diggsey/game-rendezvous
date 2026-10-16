//! A private matchmaking network on this machine, for trying games without the public relays:
//! a Nostr relay and a STUN server on localhost, until stopped (Ctrl+C).
//!
//! ```text
//! cargo run --example test_network -- [RELAY_PORT [STUN_PORT]]
//! ```
//!
//! Point the game at `ws://127.0.0.1:RELAY_PORT` and `127.0.0.1:STUN_PORT`.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use nostr_sdk::prelude::{LocalRelay, RateLimit};

#[tokio::main]
async fn main() {
    let mut args = std::env::args()
        .skip(1)
        .map(|a| a.parse::<u16>().expect("a port"));
    let relay_port = args.next().unwrap_or(7000);
    let stun_port = args.next().unwrap_or(3478);

    let relay = LocalRelay::builder()
        .addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .port(relay_port)
        // Several games on one machine publish more than a public relay's per-client limit.
        .rate_limit(RateLimit {
            max_reqs: 500,
            notes_per_minute: u32::MAX,
        })
        .messages_per_minute(u32::MAX)
        .build();
    relay.run().await.expect("the relay starts");
    let stun = UdpSocket::bind((Ipv4Addr::LOCALHOST, stun_port)).expect("the STUN port is free");
    std::thread::spawn(move || game_rendezvous::stun::serve(&stun));

    println!("relay {}", relay.url().await);
    println!("stun 127.0.0.1:{stun_port}");
    tokio::signal::ctrl_c().await.expect("Ctrl+C");
    relay.shutdown();
}
