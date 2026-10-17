//! The background worker: a thread with its own tokio runtime that keeps the relay connections,
//! publishes and subscribes on behalf of hosts, browsers and joiners, resolves the STUN servers
//! and runs port mappings.
//!
//! The game-facing types never block: they send [`Command`]s here and read answers from
//! channels ([`Inbox`]) when they are polled. Work that involves the players' keys (signing,
//! encrypting and decrypting) runs here too, in tasks a host or a join starts with
//! [`Worker::spawn`], so that nothing a stranger sends costs the game's frame time.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use nostr_sdk::prelude::StreamExt;
use nostr_sdk::prelude::{Client, ClientNotification, RelayStatus};
use nostr_sdk::prelude::{Event, EventId, Filter, Keys, PublicKey, RelayMessage, SubscriptionId};
use tokio::sync::{mpsc as tmpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::handshake::{self, Message};
use crate::portmap::{self, PortMapEvent};

/// How long shutting down waits for last messages (closing listings, removing port mappings).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// How long shutting down waits for port mappings in progress: long enough to finish a
/// gateway search and mapping, then remove it, so that none is left open on the router.
const PORT_MAP_GRACE: Duration = Duration::from_secs(8);
/// How long to wait before looking the STUN servers up again when none resolved.
const STUN_RETRY: Duration = Duration::from_secs(15);
/// How long a publish waits for a first relay connection.
const CONNECT_WAIT: Duration = Duration::from_secs(6);

/// The worker's end of a channel to the game side.
pub(crate) type Sink<T> = tmpsc::UnboundedSender<T>;
/// The game side's end: read with `try_recv` when polled. Unlike `std::sync::mpsc`'s, it is
/// `Sync`, so the types holding one can live in an engine's shared resources.
pub(crate) type Inbox<T> = tmpsc::UnboundedReceiver<T>;

/// A channel between the worker and the game side.
pub(crate) fn channel<T>() -> (Sink<T>, Inbox<T>) {
    tmpsc::unbounded_channel()
}

/// The outcome of a publish.
#[derive(Debug, Clone, Default)]
pub(crate) struct Published {
    /// Relays that accepted the event.
    pub(crate) accepted: usize,
    /// Why the others did not.
    pub(crate) errors: Vec<String>,
}

/// What the game side asks the worker to do.
pub(crate) enum Command {
    /// Subscribes to `filter` on every relay, sending the events to `events`.
    Subscribe {
        /// The subscription's id, to close it with.
        id: SubscriptionId,
        /// What to subscribe to.
        filter: Filter,
        /// Where the events go, once each.
        events: Sink<Event>,
    },
    /// Closes a subscription.
    Unsubscribe(SubscriptionId),
    /// Asks the router to forward `port`, until `stop` fires or is dropped.
    MapPort {
        /// The host's port.
        port: u16,
        /// What the router said.
        events: Sink<PortMapEvent>,
        /// Fires (or is dropped) when the host stops.
        stop: oneshot::Receiver<()>,
    },
    /// Runs a task on the worker. Shutting down waits for it (briefly), so a task can still
    /// publish a last event once its owner has gone.
    Spawn(Box<dyn FnOnce(TaskContext) -> TaskFuture + Send>),
    /// Stops the worker: the last handle has gone.
    Shutdown,
}

/// A task run on the worker.
pub(crate) type TaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What a task on the worker can use: the relay client, directly (the worker's command loop
/// stops at shutdown, while its tasks get a moment to finish).
#[derive(Clone)]
pub(crate) struct TaskContext {
    /// The relay client.
    client: Client,
    /// What the worker shares with the game side.
    shared: Arc<Shared>,
}

impl TaskContext {
    /// Publishes `event`, waiting for the relays' answers.
    pub(crate) async fn publish(&self, event: &Event) -> Published {
        publish(&self.client, &self.shared, event).await
    }

    /// Seals `message` from `keys` to `to` and publishes it in the background; the outcome goes
    /// to `done`, if given. Returns whether it could be sealed.
    ///
    /// Each call seals afresh, so a repeat is a new event: relays (and subscribers) drop one
    /// they have already seen.
    pub(crate) fn send_sealed(
        &self,
        keys: &Keys,
        to: &PublicKey,
        message: &Message,
        done: Option<Sink<Published>>,
    ) -> bool {
        let Some(event) = handshake::seal(keys, to, message) else {
            return false;
        };
        self.publish_in_background(event, done);
        true
    }

    /// Publishes `event` in the background; its outcome goes to `done`, if given.
    pub(crate) fn publish_in_background(&self, event: Event, done: Option<Sink<Published>>) {
        let ctx = self.clone();
        tokio::spawn(async move {
            let outcome = ctx.publish(&event).await;
            if let Some(done) = done {
                let _ = done.send(outcome);
            }
        });
    }
}

/// State the worker shares with the game side.
#[derive(Default)]
pub(crate) struct Shared {
    /// Relays connected, as of the last status tick.
    pub(crate) relays_connected: AtomicUsize,
    /// The STUN servers' addresses, once resolved.
    pub(crate) stun_servers: Mutex<Option<Vec<SocketAddr>>>,
}

/// A handle on the worker; cheap to clone. The worker shuts down when the last handle goes,
/// after sending what is already queued.
#[derive(Clone)]
pub(crate) struct Worker {
    /// Commands to the worker.
    commands: tmpsc::UnboundedSender<Command>,
    /// What the worker shares with the game side.
    shared: Arc<Shared>,
    /// Stops the thread when the last handle goes.
    _thread: Arc<WorkerThread>,
}

/// The worker's thread, which it stops when dropped.
struct WorkerThread {
    /// Commands to the worker, for the last one: `Shutdown`.
    commands: tmpsc::UnboundedSender<Command>,
    /// The thread, to join.
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Told when the worker has finished.
    finished: Mutex<mpsc::Receiver<()>>,
}

impl Drop for WorkerThread {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        // Wait (briefly) so that a game exiting right after closing its listing still gets the
        // tombstone and the port mapping removal out.
        let finished = self.finished.get_mut().unwrap();
        if finished
            .recv_timeout(PORT_MAP_GRACE + Duration::from_secs(1))
            .is_ok()
            && let Some(t) = self.thread.get_mut().unwrap().take()
        {
            let _ = t.join();
        }
    }
}

impl Worker {
    /// Starts the worker, connecting to `relays` and resolving `stun_servers`.
    pub(crate) fn start(relays: Vec<String>, stun_servers: Vec<String>) -> std::io::Result<Worker> {
        let (tx, rx) = tmpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let (finished_tx, finished) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let worker_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("game_rendezvous".into())
            .spawn(move || {
                runtime.block_on(run(relays, stun_servers, rx, worker_shared));
                // Dropping the runtime would wait for blocking calls that cannot be cancelled
                // (a name lookup, the interface list); leave them to finish on their own.
                runtime.shutdown_background();
                let _ = finished_tx.send(());
            })?;
        Ok(Worker {
            commands: tx.clone(),
            shared,
            _thread: Arc::new(WorkerThread {
                commands: tx,
                thread: Mutex::new(Some(thread)),
                finished: Mutex::new(finished),
            }),
        })
    }

    /// Sends the worker a command (nothing happens if it has stopped).
    pub(crate) fn send(&self, c: Command) {
        let _ = self.commands.send(c);
    }

    /// Runs `task` on the worker.
    pub(crate) fn spawn<F, Fut>(&self, task: F)
    where
        F: FnOnce(TaskContext) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.send(Command::Spawn(Box::new(move |ctx| Box::pin(task(ctx)))));
    }

    /// Events matching `filter` from now on (and stored ones), until `Unsubscribe(id)`.
    pub(crate) fn subscribe(&self, filter: Filter) -> (SubscriptionId, Inbox<Event>) {
        let id = SubscriptionId::generate();
        let (tx, rx) = channel();
        self.send(Command::Subscribe {
            id: id.clone(),
            filter,
            events: tx,
        });
        (id, rx)
    }

    /// Relays connected now.
    pub(crate) fn relays_connected(&self) -> usize {
        self.shared.relays_connected.load(Ordering::Relaxed)
    }

    /// The resolved STUN servers; `None` while still resolving.
    pub(crate) fn stun_servers(&self) -> Option<Vec<SocketAddr>> {
        self.shared.stun_servers.lock().unwrap().clone()
    }
}

/// The worker: connects to `relays`, looks `stun_servers` up, and carries out `commands`
/// until told to stop.
async fn run(
    relays: Vec<String>,
    stun_servers: Vec<String>,
    mut commands: tmpsc::UnboundedReceiver<Command>,
    shared: Arc<Shared>,
) {
    let client = Client::default();
    for url in &relays {
        if let Err(e) = client.add_relay(url.as_str()).await {
            warn!("relay {url}: {e}");
        }
    }
    client.connect().await;
    let mut notifications = client.notifications();
    let mut tasks = JoinSet::new();
    // Port mappings: shutting down waits longer for them (`PORT_MAP_GRACE`).
    let mut port_maps = JoinSet::new();
    // It may wait to try again, so shutting down stops it rather than waiting for it.
    let resolving = tasks.spawn(resolve_stun(stun_servers, shared.clone()));
    let mut sinks: HashMap<SubscriptionId, Sink<Event>> = HashMap::new();
    // Subscriptions still being sent to the relays. Each runs in a task of its own, so an
    // unsubscribe waits for its subscribe: run first, it would close nothing, and the
    // subscription would then stay open on the relays.
    let mut subscribing: HashMap<SubscriptionId, oneshot::Receiver<()>> = HashMap::new();
    // Each relay sends its own copy of an event; subscribers get one.
    let mut seen = Seen::default();
    let mut status_tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None | Some(Command::Shutdown) => break,
                Some(Command::Subscribe { id, filter, events }) => {
                    sinks.insert(id.clone(), events);
                    let (subscribed, done) = oneshot::channel();
                    subscribing.insert(id.clone(), done);
                    let client = client.clone();
                    tasks.spawn(async move {
                        if let Err(e) = client.subscribe(filter).with_id(id).await {
                            warn!("subscribe: {e}");
                        }
                        let _ = subscribed.send(());
                    });
                }
                Some(Command::Unsubscribe(id)) => {
                    sinks.remove(&id);
                    let subscribed = subscribing.remove(&id);
                    let client = client.clone();
                    tasks.spawn(async move {
                        if let Some(subscribed) = subscribed {
                            let _ = subscribed.await;
                        }
                        let _ = client.unsubscribe(&id).await;
                    });
                }
                Some(Command::MapPort { port, events, stop }) => {
                    port_maps.spawn(portmap::run(port, events, stop));
                }
                Some(Command::Spawn(task)) => {
                    tasks.spawn(task(TaskContext {
                        client: client.clone(),
                        shared: shared.clone(),
                    }));
                }
            },
            Some(n) = notifications.next() => {
                // Every relay's copy comes as a message (`ClientNotification::Event` would skip
                // events this client published itself, such as a host's own listing when the
                // same game also browses); the relay client has checked the signature.
                let ClientNotification::Message { message, .. } = n else { continue };
                let RelayMessage::Event { subscription_id, event } = *message else { continue };
                if !seen.insert((subscription_id.as_ref().clone(), event.id)) {
                    continue;
                }
                if let Some(sink) = sinks.get(subscription_id.as_ref())
                    && sink.send(event.into_owned()).is_err()
                {
                    // Its reader is gone; it will unsubscribe.
                    sinks.remove(subscription_id.as_ref());
                }
            }
            _ = status_tick.tick() => {
                let connected = count_connected(&client).await;
                shared.relays_connected.store(connected, Ordering::Relaxed);
            }
            // Reap finished tasks so the set does not grow.
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            Some(_) = port_maps.join_next(), if !port_maps.is_empty() => {}
        }
    }
    resolving.abort();
    // Let the tasks finish (a closing host publishes its tombstone), and the port mappings be
    // removed, but not forever. Publishes in the background, such as answers to joiners, are
    // not waited for.
    let _ = tokio::join!(
        tokio::time::timeout(SHUTDOWN_GRACE, async {
            while tasks.join_next().await.is_some() {}
        }),
        tokio::time::timeout(PORT_MAP_GRACE, async {
            while port_maps.join_next().await.is_some() {}
        }),
    );
    client.shutdown().await;
}

/// The events delivered lately, by subscription, so that other relays' copies are dropped.
///
/// Two generations of [`SEEN_GENERATION`] each: when the newer fills up, the older is
/// forgotten. Memory stays bounded, and an event is forgotten only once that many others
/// have arrived since, never at once with every recent one (which a relay could otherwise
/// force by sending junk).
#[derive(Default)]
struct Seen {
    /// The newer generation, filling up.
    current: HashSet<(SubscriptionId, EventId)>,
    /// The older generation, forgotten when the newer is full.
    previous: HashSet<(SubscriptionId, EventId)>,
}

/// How many events a generation of [`Seen`] holds.
const SEEN_GENERATION: usize = 5_000;

impl Seen {
    /// Whether `key` is new; it is remembered either way.
    fn insert(&mut self, key: (SubscriptionId, EventId)) -> bool {
        if self.previous.contains(&key) || !self.current.insert(key) {
            return false;
        }
        if self.current.len() >= SEEN_GENERATION {
            self.previous = std::mem::take(&mut self.current);
        }
        true
    }
}

/// How many relays `client` is connected to.
async fn count_connected(client: &Client) -> usize {
    client
        .relays()
        .await
        .values()
        .filter(|r| r.status() == RelayStatus::Connected)
        .count()
}

/// Publishes `event` to every relay, waiting (a little) for a first connection and for the
/// relays' answers.
async fn publish(client: &Client, shared: &Shared, event: &Event) -> Published {
    // Right after start no relay is connected yet; give them a moment. The worker's status
    // tick keeps the count current.
    let start = tokio::time::Instant::now();
    while shared.relays_connected.load(Ordering::Relaxed) == 0 && start.elapsed() < CONNECT_WAIT {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A relay that never acknowledges must not hold up the report of the others.
    match client
        .send_event(event)
        .ok_timeout(Duration::from_secs(5))
        .await
    {
        Ok(output) => {
            let errors: Vec<String> = output
                .failed
                .iter()
                .map(|(url, e)| format!("{url}: {e}"))
                .collect();
            if !errors.is_empty() {
                debug!("publish {}: {}", event.kind, errors.join("; "));
            }
            Published {
                accepted: output.success.len(),
                errors,
            }
        }
        Err(e) => Published {
            accepted: 0,
            errors: vec![e.to_string()],
        },
    }
}

/// Looks the STUN servers up and shares the addresses found. While none resolve (the machine
/// may not be online yet), it shares that and tries again every [`STUN_RETRY`].
async fn resolve_stun(servers: Vec<String>, shared: Arc<Shared>) {
    loop {
        let found = lookup_stun(&servers).await;
        let done = !found.is_empty() || servers.is_empty();
        *shared.stun_servers.lock().unwrap() = Some(found);
        if done {
            return;
        }
        tokio::time::sleep(STUN_RETRY).await;
    }
}

/// Looks the STUN servers up, all at once.
async fn lookup_stun(servers: &[String]) -> Vec<SocketAddr> {
    let mut lookups = JoinSet::new();
    for server in servers {
        let server = server.clone();
        lookups.spawn(async move {
            let lookup = tokio::net::lookup_host(server.as_str());
            match tokio::time::timeout(Duration::from_secs(5), lookup).await {
                Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
                Ok(Err(e)) => {
                    debug!("STUN server {server}: {e}");
                    Vec::new()
                }
                Err(_) => {
                    debug!("STUN server {server}: lookup timed out");
                    Vec::new()
                }
            }
        });
    }
    let mut found: Vec<SocketAddr> = Vec::new();
    while let Some(addrs) = lookups.join_next().await {
        let addrs = addrs.unwrap_or_default();
        // One address per family and server is plenty.
        let v4 = addrs.iter().find(|a| a.is_ipv4());
        let v6 = addrs.iter().find(|a| a.is_ipv6());
        found.extend(v4.into_iter().chain(v6).copied());
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(sub: &SubscriptionId, n: usize) -> (SubscriptionId, EventId) {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
        (sub.clone(), EventId::from_byte_array(bytes))
    }

    #[test]
    fn recent_events_stay_seen_through_a_flood() {
        let sub = SubscriptionId::new("s");
        let mut seen = Seen::default();
        assert!(seen.insert(key(&sub, 0)));
        assert!(!seen.insert(key(&sub, 0)));
        // A flood fills a generation: the event just before it is still known.
        for n in 1..SEEN_GENERATION {
            assert!(seen.insert(key(&sub, n)));
        }
        assert!(!seen.insert(key(&sub, SEEN_GENERATION - 1)));
        assert!(!seen.insert(key(&sub, 0)));
        // Only after another full generation is it forgotten.
        for n in SEEN_GENERATION..2 * SEEN_GENERATION {
            seen.insert(key(&sub, n));
        }
        assert!(seen.insert(key(&sub, 0)));
    }
}
