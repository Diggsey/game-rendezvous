//! A private network for tests: a local Nostr relay and a local STUN server, and a stand-in
//! game loop for a host.

#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use game_rendezvous::{Config, Host, HostEvent, Listing, Rendezvous, bind_dual_stack};
use nostr_sdk::prelude::{
    Client, Event, EventBuilder, FinalizeEvent, Filter, Keys, Kind, LocalRelay, PublicKey,
    RateLimit, Tag, nip44,
};

/// The handshake's event kind.
pub const HANDSHAKE_KIND: Kind = Kind::Custom(21_059);

pub struct TestNet {
    pub relay_url: String,
    pub stun: SocketAddr,
    _relay: LocalRelay,
    /// Runs the relay, and anything a test does on the relays directly.
    pub runtime: tokio::runtime::Runtime,
}

impl TestNet {
    pub fn start() -> TestNet {
        init_logging();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // No rate limits: tests send floods on purpose.
        let relay = LocalRelay::builder()
            .rate_limit(RateLimit {
                max_reqs: 500,
                notes_per_minute: u32::MAX,
            })
            .messages_per_minute(u32::MAX)
            .build();
        runtime.block_on(relay.run()).unwrap();
        let relay_url = runtime.block_on(relay.url()).to_string();
        let stun_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let stun = stun_socket.local_addr().unwrap();
        std::thread::spawn(move || game_rendezvous::stun::serve(&stun_socket));
        TestNet {
            relay_url,
            stun,
            _relay: relay,
            runtime,
        }
    }

    /// A configuration on this network, offering only localhost addresses.
    pub fn config(&self, version: &str) -> Config {
        let mut c = Config::new("game-rendezvous-test", version)
            .with_relays([self.relay_url.clone()])
            .with_stun_servers([self.stun.to_string()]);
        c.port_mapping = false;
        c.local_addresses = Some(vec!["127.0.0.1".parse().unwrap()]);
        c.gather_timeout = Duration::from_millis(500);
        c.handshake_timeout = Duration::from_secs(5);
        c.connect_timeout = Duration::from_secs(4);
        c
    }

    /// A Nostr client of the test's own on the relay, for sending and watching events.
    pub fn client(&self) -> Client {
        let client = Client::default();
        self.runtime.block_on(async {
            client.add_relay(self.relay_url.as_str()).await.unwrap();
            client.connect().await;
        });
        client
    }

    /// The key a host signs its listing with (the only listing on the relay).
    pub fn host_key(&self, client: &Client) -> PublicKey {
        self.runtime.block_on(async {
            let filter = Filter::new()
                .kind(Kind::Custom(30078))
                .identifier("game-rendezvous/game-rendezvous-test");
            let events = client
                .fetch_events(filter)
                .timeout(Duration::from_secs(5))
                .await
                .unwrap();
            events.iter().next().expect("the listing").pubkey
        })
    }

    /// Sends `events` through `client`.
    pub fn send(&self, client: &Client, events: &[Event]) {
        self.runtime.block_on(async {
            for event in events {
                client.send_event(event).await.unwrap();
            }
        });
    }

    /// How many handshake events reach `to` over `period`.
    pub fn count_handshakes(&self, client: &Client, to: PublicKey, period: Duration) -> usize {
        use nostr_sdk::prelude::{ClientNotification, RelayMessage, StreamExt};
        self.runtime.block_on(async {
            let mut notifications = client.notifications();
            let filter = Filter::new().kind(HANDSHAKE_KIND).pubkey(to);
            let id = client.subscribe(filter).await.unwrap().value;
            let mut seen = std::collections::HashSet::new();
            let deadline = tokio::time::Instant::now() + period;
            while let Ok(Some(n)) = tokio::time::timeout_at(deadline, notifications.next()).await {
                if let ClientNotification::Message { message, .. } = n
                    && let RelayMessage::Event { subscription_id, event } = *message
                    && *subscription_id == id
                {
                    seen.insert(event.id);
                }
            }
            let _ = client.unsubscribe(&id).await;
            seen.len()
        })
    }
}

/// A join request to the host at `to`, signed by a key of its own, as a stranger could send.
pub fn forged_request(to: &PublicKey, game_id: &str, version: &str, name: &str) -> Event {
    let keys = Keys::generate();
    let request = serde_json::json!({
        "type": "request", "attempt": name, "game_id": game_id,
        "version": version, "protocol": 1, "player_name": name,
        "ice": { "ufrag": "abcd", "pwd": "abcdefghijklmnopqrstuv", "candidates": [] },
    });
    let content = nip44::encrypt(
        keys.secret_key(),
        to,
        request.to_string(),
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(HANDSHAKE_KIND, content)
        .tag(Tag::public_key(*to))
        .finalize(&keys)
        .unwrap()
}

/// Logs to the test's output (shown for failures, or with `--nocapture`).
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "game_rendezvous=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Polls `f` until it gives a value, panicking after `timeout`.
pub fn wait_for<T>(timeout: Duration, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(t) = f() {
            return t;
        }
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A host as a game runs it: its socket, read every frame, with the library's datagrams
/// passed on.
pub struct HostGame {
    pub socket: UdpSocket,
    pub host: Host,
    pub events: Vec<HostEvent>,
    /// The game's own datagrams.
    pub received: Vec<(SocketAddr, Vec<u8>)>,
    /// When false, the game does not read its socket (a broken host).
    pub pump_socket: bool,
}

impl HostGame {
    pub fn new(rv: &Rendezvous, listing: Listing) -> HostGame {
        let socket = bind_dual_stack(0).unwrap();
        let host = rv.host(&socket, listing).unwrap();
        HostGame {
            socket,
            host,
            events: Vec::new(),
            received: Vec::new(),
            pump_socket: true,
        }
    }

    /// One frame.
    pub fn frame(&mut self) {
        let mut buf = [0u8; 1500];
        while self.pump_socket {
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let from = game_rendezvous::canonical(from);
                    if !self.host.handle_datagram(from, &buf[..n]) {
                        self.received.push((from, buf[..n].to_vec()));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            }
        }
        while let Some(e) = self.host.poll() {
            self.events.push(e);
        }
    }

    pub fn port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }
}

pub fn listing(name: &str) -> Listing {
    Listing {
        name: name.into(),
        players: 1,
        max_players: 4,
        joinable: true,
        metadata: [("mode".to_string(), "deathmatch".to_string())].into(),
    }
}
