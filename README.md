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
  (asked from the game's own socket) and a port the host's router was asked to open (UPnP,
  NAT-PMP or PCP). Both sides run ICE connectivity checks over the game's socket, and the best
  path that works wins.

Everything is poll-based and never blocks, for calling from a game loop. The relay work runs on
one background thread with its own Tokio runtime, so the game needs no async runtime.

## Hosting

```rust,no_run
use game_rendezvous::{Config, HostEvent, Listing, Rendezvous, bind_dual_stack, canonical};

let rv = Rendezvous::new(Config::new("my-game", "1.2.0"))?;
let socket = bind_dual_stack(7777)?;
let listing = Listing { name: "Ann's game".into(), max_players: 4, ..Default::default() };
let mut host = rv.host(&socket, listing)?;
let mut buf = [0u8; 65_536];
loop {
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let from = canonical(from);
        if !host.handle_datagram(from, &buf[..n]) {
            // The game's own packet.
        }
    }
    while let Some(event) = host.poll() {
        if let HostEvent::PeerConnected { addr, name, .. } = event {
            println!("{name} is in, from {addr}");
        }
    }
}
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
what a host bounds against strangers, and the `port-mapping` feature.

## Trying it locally

The `test_network` example runs a Nostr relay and a STUN server on localhost, for playing
without the public relays:

```text
cargo run --example test_network -- 7000 3478
```

Point the game at them with `Config::with_relays(["ws://127.0.0.1:7000"])` and
`Config::with_stun_servers(["127.0.0.1:3478"])`. The `probe` example checks what this machine
can do for hosting: which relays connect, its public address, and whether its router opens a
port.

`cargo test` runs the end-to-end tests on a private network on localhost. The tests against the
public relays are ignored by default: `cargo test --test public -- --ignored`.

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
