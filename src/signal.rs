//! The background worker: a thread with its own tokio runtime that keeps the relay connections,
//! publishes and subscribes on behalf of hosts, browsers and joiners, resolves the STUN servers
//! and runs port mappings.
//!
//! The game-facing types never block: they send [`Command`]s here and read answers from
//! channels ([`Inbox`]) when they are polled. Work that involves the players' keys (signing,
//! encrypting and decrypting) runs here too, in tasks a host or a join starts with
//! [`Signal::spawn`], so that nothing a stranger sends costs the game's frame time.

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
use nostr_sdk::prelude::{Event, EventId, Filter, RelayMessage, SubscriptionId};
use tokio::sync::{mpsc as tmpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::portmap::{self, PortMapEvent};

/// How long shutting down waits for last messages (closing listings, removing port mappings).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// How long a publish waits for a first relay connection.
const CONNECT_WAIT: Duration = Duration::from_secs(6);

/// The worker's end of a channel to the game side.
pub(crate) type Sink<T> = tmpsc::UnboundedSender<T>;
/// The game side's end: read with `try_recv` when polled. Unlike `std::sync::mpsc`'s, it is
/// `Sync`, so the types holding one can live in an engine's shared resources.
pub(crate) type Inbox<T> = tmpsc::UnboundedReceiver<T>;

pub(crate) fn channel<T>() -> (Sink<T>, Inbox<T>) {
    tmpsc::unbounded_channel()
}

/// The outcome of a publish.
#[derive(Debug, Clone, Default)]
pub(crate) struct Published {
    /// Relays that accepted the event.
    pub accepted: usize,
    /// Why the others did not.
    pub errors: Vec<String>,
}

pub(crate) enum Command {
    Subscribe {
        id: SubscriptionId,
        filter: Filter,
        events: Sink<Event>,
    },
    Unsubscribe(SubscriptionId),
    MapPort {
        port: u16,
        events: Sink<PortMapEvent>,
        stop: oneshot::Receiver<()>,
    },
    /// Runs a task on the worker. Shutting down waits for it (briefly), so a task can still
    /// publish a last event once its owner has gone.
    Spawn(Box<dyn FnOnce(TaskContext) -> TaskFuture + Send>),
    Shutdown,
}

pub(crate) type TaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What a task on the worker can use: the relay client, directly (the worker's command loop
/// stops at shutdown, while its tasks get a moment to finish).
#[derive(Clone)]
pub(crate) struct TaskContext {
    client: Client,
    shared: Arc<Shared>,
}

impl TaskContext {
    /// Publishes `event`, waiting for the relays' answers.
    pub async fn publish(&self, event: &Event) -> Published {
        publish(&self.client, &self.shared, event).await
    }

    /// Publishes `event` in the background; its outcome goes to `done`, if given.
    pub fn publish_in_background(&self, event: Event, done: Option<Sink<Published>>) {
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
    pub relays_connected: AtomicUsize,
    pub relays_total: AtomicUsize,
    /// The STUN servers' addresses, once resolved.
    pub stun_servers: Mutex<Option<Vec<SocketAddr>>>,
}

/// A handle on the worker; cheap to clone. The worker shuts down when the last handle goes,
/// after sending what is already queued.
#[derive(Clone)]
pub(crate) struct Signal {
    commands: tmpsc::UnboundedSender<Command>,
    pub shared: Arc<Shared>,
    _worker: Arc<Worker>,
}

struct Worker {
    commands: tmpsc::UnboundedSender<Command>,
    thread: Mutex<Option<JoinHandle<()>>>,
    finished: Mutex<mpsc::Receiver<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        // Wait (briefly) so that a game exiting right after closing its listing still gets the
        // tombstone and the port mapping removal out.
        let finished = self.finished.get_mut().unwrap();
        if finished
            .recv_timeout(SHUTDOWN_GRACE + Duration::from_secs(1))
            .is_ok()
            && let Some(t) = self.thread.get_mut().unwrap().take()
        {
            let _ = t.join();
        }
    }
}

impl Signal {
    /// Starts the worker, connecting to `relays` and resolving `stun_servers`.
    pub fn start(relays: Vec<String>, stun_servers: Vec<String>) -> std::io::Result<Signal> {
        let (tx, rx) = tmpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        shared.relays_total.store(relays.len(), Ordering::Relaxed);
        let (finished_tx, finished) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let worker_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("game_rendezvous".into())
            .spawn(move || {
                runtime.block_on(run(relays, stun_servers, rx, worker_shared));
                let _ = finished_tx.send(());
            })?;
        Ok(Signal {
            commands: tx.clone(),
            shared,
            _worker: Arc::new(Worker {
                commands: tx,
                thread: Mutex::new(Some(thread)),
                finished: Mutex::new(finished),
            }),
        })
    }

    pub fn send(&self, c: Command) {
        let _ = self.commands.send(c);
    }

    /// Runs `task` on the worker.
    pub fn spawn<F, Fut>(&self, task: F)
    where
        F: FnOnce(TaskContext) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.send(Command::Spawn(Box::new(move |ctx| Box::pin(task(ctx)))));
    }

    /// Events matching `filter` from now on (and stored ones), until `Unsubscribe(id)`.
    pub fn subscribe(&self, filter: Filter) -> (SubscriptionId, Inbox<Event>) {
        let id = SubscriptionId::generate();
        let (tx, rx) = channel();
        self.send(Command::Subscribe {
            id: id.clone(),
            filter,
            events: tx,
        });
        (id, rx)
    }

    pub fn relays_connected(&self) -> usize {
        self.shared.relays_connected.load(Ordering::Relaxed)
    }

    /// The resolved STUN servers; `None` while still resolving.
    pub fn stun_servers(&self) -> Option<Vec<SocketAddr>> {
        self.shared.stun_servers.lock().unwrap().clone()
    }
}

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
    tasks.spawn(resolve_stun(stun_servers, shared.clone()));
    let mut sinks: HashMap<SubscriptionId, Sink<Event>> = HashMap::new();
    // Each relay sends its own copy of an event; subscribers get one.
    let mut seen: HashSet<(SubscriptionId, EventId)> = HashSet::new();
    let mut status_tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                None | Some(Command::Shutdown) => break,
                Some(Command::Subscribe { id, filter, events }) => {
                    sinks.insert(id.clone(), events);
                    let client = client.clone();
                    tasks.spawn(async move {
                        if let Err(e) = client.subscribe(filter).with_id(id).await {
                            warn!("subscribe: {e}");
                        }
                    });
                }
                Some(Command::Unsubscribe(id)) => {
                    sinks.remove(&id);
                    let client = client.clone();
                    tasks.spawn(async move {
                        let _ = client.unsubscribe(&id).await;
                    });
                }
                Some(Command::MapPort { port, events, stop }) => {
                    tasks.spawn(portmap::run(port, events, stop));
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
                if seen.len() > 10_000 {
                    seen.clear();
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
        }
    }
    // Let queued publishes and port mapping removals finish, but not forever.
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    client.shutdown().await;
}

async fn count_connected(client: &Client) -> usize {
    client
        .relays()
        .await
        .values()
        .filter(|r| r.status() == RelayStatus::Connected)
        .count()
}

async fn publish(client: &Client, shared: &Shared, event: &Event) -> Published {
    // Right after start no relay is connected yet; give them a moment.
    let start = tokio::time::Instant::now();
    while shared.relays_connected.load(Ordering::Relaxed) == 0
        && count_connected(client).await == 0
        && start.elapsed() < CONNECT_WAIT
    {
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

/// Looks the STUN servers up, all at once, and shares the addresses found.
async fn resolve_stun(servers: Vec<String>, shared: Arc<Shared>) {
    let mut lookups = JoinSet::new();
    for server in servers {
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
    *shared.stun_servers.lock().unwrap() = Some(found);
}
