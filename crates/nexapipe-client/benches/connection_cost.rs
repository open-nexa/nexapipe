//! What one connection costs.
//!
//! The client keeps a pool of connections to each backend, and a flow
//! **borrows** one of them: the pool keeps the connection, and the flow holds
//! a handle to it until the flow ends. So the number of connections a client
//! opens is a number a deployment pays for — each one is a handshake, and each
//! one is a connection the far side holds state for.
//!
//! Two numbers, because the question this bench answers needs both:
//!
//! - **`open_connection`** — a QUIC handshake and nothing else. This is what
//!   choosing the protocol with ALPN would add: the protocol would be chosen
//!   at the handshake, so a client that speaks both HTTP and L4 would open
//!   **two** connections to the same endpoint where it opens one today, and
//!   the second one costs a handshake.
//! - **`open_flow`** — a flow on a connection that is already open. This is
//!   the number that does not change: the second protocol's first flow costs
//!   a connection *as well as* a flow, and the flow itself costs the same
//!   either way.
//!
//! The far side is an iroh endpoint on this host, bound to the loopback
//! interface, so the bench needs no network and no relay.
//!
//! ## What these numbers are, and what they are not
//!
//! They are the cost **on this machine, over the loopback interface**. A
//! handshake over a real path costs more, and how much more is a property of
//! the path rather than of the code.
//!
//! **The two numbers are not commensurable, and their difference is not a
//! result.** A handshake is CPU work — the key exchange and the packet
//! protection — and it is what a second connection would cost. A flow on an
//! open connection is a *wait*: for the far side to answer the preface, and
//! for this task to be woken up. That wait belongs to the machine's scheduler
//! rather than to the protocol, so it moves with the machine's load: the same
//! code comes out several times larger in its median iteration than in its
//! best one, while the handshake's number stays in the same band.
//!
//! So the pair says what each of the two costs on its own. It does **not**
//! say that one is "a round trip more" than the other, and the difference
//! between the two must not be read as what splitting the protocol would
//! cost. What a second connection costs is **a handshake**, paid once per
//! endpoint and protocol.
//!
//! The counts are not measured here — `flow_connections` measures how many
//! connections a hundred flows open, and it measures them on the far side's
//! own count rather than on anything the client reports.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::IrohConnectionPool;
use nexapipe_client::endpoint_group::EndpointGroup;
use nexapipe_client::l4::open_tcp;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The ALPN the tunnel speaks. The same bytes the client uses.
const ALPN: &[u8] = b"\x05nexapipe";

/// The host the flows ask for.
const HOST: &str = "db.test";

/// The port they ask for.
const PORT: u16 = 5432;

/// The far side of the tunnel: a server that speaks the L4 framing, and
/// counts the connections it is given.
///
/// The count is not a measurement here — `flow_connections` measures that —
/// but it is what the flow measure below **checks itself against**: a flow
/// that opened a connection would be a handshake wearing a flow's clothes,
/// and the number would say so.
async fn serve(endpoint: Endpoint, connections: Arc<AtomicUsize>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(accepting) = incoming.accept() else {
            continue;
        };
        let Ok(connection) = accepting.await else {
            continue;
        };
        connections.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                tokio::spawn(async move {
                    // The preface: magic, version, proto, host length, the host,
                    // and the port — so its length is known once the fourth
                    // byte has been read.
                    let mut header = [0u8; 4];
                    if recv.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; usize::from(header[3]) + 2];
                    if recv.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    // `Ok` — the flow is open. The client waits for this byte
                    // before it sends anything, so it has to come first.
                    if send.write_all(&[0x00]).await.is_err() {
                        return;
                    }
                    // Hold the flow open for as long as the client keeps it:
                    // a flow that ended here would not be a flow.
                    let mut sink = [0u8; 1];
                    let _ = recv.read(&mut sink).await;
                });
            }
        });
    }
}

/// The two ends of the bench.
struct Harness {
    /// This side's endpoint.
    client: Endpoint,
    /// The far side's endpoint.
    ///
    /// Kept here so that the harness can close it: the accept loop below owns
    /// a copy of it, and an endpoint that is only released when a task that
    /// never ends is dropped stays open — with its socket — for the life of
    /// the process.
    server: Endpoint,
    /// The far side's accept task, stopped when the harness is stopped.
    server_task: tokio::task::JoinHandle<()>,
    /// Where the far side is.
    server_addr: iroh::EndpointAddr,
    /// How many connections the far side has been given.
    connections: Arc<AtomicUsize>,
}

impl Harness {
    async fn start() -> Self {
        // The far side.
        let server = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("the far side binds");
        let server_addr = server.addr();
        let connections = Arc::new(AtomicUsize::new(0));
        let server_task = tokio::spawn(serve(server.clone(), connections.clone()));

        // This side.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");

        Self {
            client,
            server,
            server_task,
            server_addr,
            connections,
        }
    }

    /// Stops the far side: the accept task ends and the endpoint closes.
    async fn stop(self) {
        self.server_task.abort();
        self.server.close().await;
    }

    /// One connection, opened and timed.
    ///
    /// The handshake and nothing else: no preface, no flow, no bytes. The
    /// connection is dropped at the end of it, so the next iteration pays for
    /// its own — which is the point, because the question is what one
    /// connection costs.
    ///
    /// The work is CPU — the key exchange and the packet protection — so the
    /// number stays in the same band whether the machine is busy or quiet.
    async fn open_connection(&self) -> Duration {
        let start = Instant::now();
        let connection = self
            .client
            .connect(self.server_addr.clone(), ALPN)
            .await
            .expect("the connection opens");
        let elapsed = start.elapsed();
        black_box(&connection);
        elapsed
    }

    /// One flow, on a connection that is already open.
    ///
    /// The first flow pays for the connection as well; the second one does
    /// not, because the pool keeps it and the flow borrows it. So the second
    /// flow is the one this measures, and what it costs is the preface and
    /// the status byte — one round trip, and no handshake. Most of what it
    /// costs is the **wait** for that round trip, so the number moves with
    /// the machine's load; the module's header says what follows from that.
    ///
    /// The far side counts the connections it is given, and the count is
    /// checked: **a flow that opened a connection would be a handshake
    /// wearing a flow's clothes**, and the number would be wrong in a way
    /// nothing else in this bench would notice.
    async fn open_flow(&self) -> Duration {
        let pool =
            IrohConnectionPool::new_with_endpoint(self.client.clone(), self.server_addr.clone());
        let group = Arc::new(EndpointGroup::new_with_single_pool(pool).await);

        // The first flow opens the connection.
        let _first = open_tcp(&group, HOST, PORT)
            .await
            .expect("the first flow opens");
        let after_first = self.connections.load(Ordering::Relaxed);

        let start = Instant::now();
        let second = open_tcp(&group, HOST, PORT).await.expect("the flow opens");
        let elapsed = start.elapsed();
        black_box(&second);

        let after_second = self.connections.load(Ordering::Relaxed);
        assert_eq!(
            after_second, after_first,
            "the second flow opened a connection of its own, so what was measured was a \
             handshake and not a flow"
        );

        elapsed
    }
}

fn connection_cost(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("connection_cost");

    // A handshake is a millisecond and every sample builds a fresh iroh
    // endpoint, so criterion's default of a hundred samples does not fit in
    // its five-second window: it warns on every run, and the mean it reports
    // is an average over a very noisy population. Ten samples is what
    // `flow_connections` uses, and it is enough here — the point of this bench
    // is what each of the two numbers is, not a difference between them.
    group.sample_size(10);

    group.bench_function("open_connection", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += harness.open_connection().await;
                }
                black_box(&harness);

                // The far side is stopped here, not left to the end of the
                // process: criterion calls this once per sample, and every
                // one of them would otherwise leave an endpoint and an accept
                // task behind.
                harness.stop().await;

                total
            })
        })
    });

    group.bench_function("open_flow", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += harness.open_flow().await;
                }
                black_box(&harness);

                harness.stop().await;

                total
            })
        })
    });

    group.finish();
}

criterion_group!(benches, connection_cost);
criterion_main!(benches);
