# game_rendezvous

Internet game discovery and peer-to-peer UDP connections, without servers of your own.

A game gives its id and version; the library lists hosted games on public
[Nostr](https://nostr.com) relays, swaps the players' addresses through them, encrypted, and
punches a UDP path through both sides' NATs. The game gets back a plain non-blocking
`UdpSocket` and the peer's address, and keeps its own protocol.

- **Discovery.** Hosts advertise on several public relays at once; players see every game with
  the same id, other versions included and marked incompatible. Listings expire unless
  refreshed, and hold no addresses.
- **Handshake.** A joiner and the host swap ICE credentials and address candidates through the
  relays, encrypted to each other ([NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)),
  in ephemeral events that relays pass on but do not store.
- **Connection.** Candidates come from the machine's LAN and IPv6 addresses, public STUN servers
  (asked from the game's own socket), a port the host's router was asked to open (UPnP,
  NAT-PMP or PCP), predicted ports for routers that hand them out in sequence, and the host's
  TURN relay if it has one. Both sides run ICE connectivity checks over the game's socket, and
  the best path that works wins. When one router hands out random ports and the other does
  not, the strict side opens 256 sockets and the other probes random ports until two meet.
- **Reachability.** A host can check before hosting whether players could probably reach it,
  and hears when a player could not. Listings carry a summary of the host's router, so a
  player's list can mark games it probably cannot join.
- **Relays.** A host can add a TURN relay, which lets in every player at the cost of a detour.
  The crate lists TURN providers with a free tier (`DEFAULT_RELAY_PROVIDERS`), each with a
  sign-up link and the credentials to enter, and fetches short-lived credentials from the
  providers that issue them over an API. Only the host needs an account.

Everything is poll-based and never blocks, for calling from a game loop. The relay work runs on
one background thread with its own Tokio runtime, so the game needs no async runtime.

## Hosting

The host plays on a `GameSocket`, shared with the library: the game sends and receives through
it, and it keeps the library's datagrams for the host and carries relayed players' traffic.

```rust,no_run
use game_rendezvous::{Config, GameSocket, HostEvent, Listing, Rendezvous};

let rv = Rendezvous::new(Config::new("my-game", "1.2.0"))?;
let socket = GameSocket::bind(7777)?;
let listing = Listing { name: "Ann's game".into(), max_players: 4, ..Default::default() };
let mut host = rv.host(&socket, listing)?;
let mut buf = [0u8; 65_536];
loop {
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        // The game's own packet.
    }
    while let Some(event) = host.poll() {
        if let HostEvent::PeerConnected { addr, name, .. } = event {
            println!("{name} is in, from {addr}");
        }
    }
}
```

## Relays

```rust,no_run
use std::collections::BTreeMap;
use game_rendezvous::{Config, DEFAULT_RELAY_PROVIDERS};

// The game's relay settings list the providers, with their sign-up links and fields...
for p in DEFAULT_RELAY_PROVIDERS {
    println!("{}: {} ({})", p.name, p.signup_url, p.notes);
}
// ...and turn what the player entered into the host's relay.
let values = BTreeMap::from([
    ("username".to_string(), "ann".to_string()),
    ("password".to_string(), "secret".to_string()),
]);
let relay = DEFAULT_RELAY_PROVIDERS[0].config(&values)?;
let config = Config::new("my-game", "1.2.0").with_turn(relay);
```

## Joining

```rust,no_run
let mut browser = rv.browse();
browser.poll(); // every frame while the list is shown
let game = browser.games()[0].clone();
let mut join = rv.join(&game, "Bob")?;
loop {
    match join.poll() {
        Some(Ok(connection)) => { /* connection.socket, connection.peer */ break }
        Some(Err(e)) => { println!("Could not join: {e}"); break }
        None => { /* show join.stage() */ }
    }
}
```

See the [crate documentation](https://docs.rs/game_rendezvous) for the details: shutting down,
what a host bounds against strangers, and the `port-mapping` and `relay-api` features.

## Trying it locally

The `test_network` example runs a Nostr relay and a STUN server on localhost, for playing
without the public relays:

```text
cargo run --example test_network -- 7000 3478
```

Point the game at them with `Config::with_relays(["ws://127.0.0.1:7000"])` and
`Config::with_stun_servers(["127.0.0.1:3478"])`. The `probe` example checks what this machine
can do for hosting: its router's behaviour, whether players could reach it, which relays
connect, whether its router opens a port, and optionally a TURN relay.

`cargo test` runs the end-to-end tests on a private network on localhost, and the NAT traversal
tests on a simulated internet of routers of every kind. The tests against the public relays are
ignored by default: `cargo test --test public -- --ignored`. So is the test against a real TURN
server: `GR_TEST_TURN=host:port,user,pass cargo test --test turn -- --ignored`.

## Minimum Rust version

1.88.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
