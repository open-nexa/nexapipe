//! The client's local proxy on a plain HTTP request.
//!
//! `forwarding_path` measures the CONNECT tunnel: the bytes cross the proxy's
//! accept loop, the L4 handshake, the tunnel and the copy loop, and what comes
//! back is the same bytes. This bench measures the **other** path a request
//! takes through the same proxy — the one a browser takes when it is told to
//! use the proxy for ordinary HTTP rather than for a tunnel.
//!
//! On that path the proxy parses the request head, finds the `Host` header,
//! checks it against the domains it proxies, rewrites the headers it forwards,
//! opens a bi-stream, writes the request, and copies the response back. None of
//! that is in `forwarding_path`'s numbers, and all of it happens on every
//! request.
//!
//! The far side is an HTTP server over an iroh bi-stream on this host, bound to
//! the loopback interface, so the bench needs no network and no relay.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::IrohConnectionPool;
use nexapipe_client::local_proxy::LocalProxy;
use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// The ALPN the tunnel speaks. The same bytes the client uses.
const ALPN: &[u8] = b"nexapipe";

/// The host the application asks for.
const HOST: &str = "app.test";

/// The path it asks for.
const PATH: &str = "/resource";

/// The body the far side answers with.
const RESPONSE_BODY: &str = "the body the backend answered with";

/// How long one request may take before the bench calls it a failure.
///
/// A bound, not a politeness: a request that hangs would otherwise hang the
/// bench, and a bench that hangs on CI is a bench nobody runs.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The far side of the tunnel: an HTTP server over an iroh bi-stream.
///
/// Reads the request head, answers with one response, and finishes the stream
/// so the client sees a clean end of stream rather than a reset — the client's
/// copy loop runs until the stream ends, so a far side that never finished it
/// would leave the request waiting.
async fn serve_http(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            // One bi-stream per request: the client opens a new one for every
            // request it makes, so the far side has to take them one at a time.
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                tokio::spawn(async move {
                    // The head, up to the blank line that ends it.
                    let mut buf = vec![0u8; 8192];
                    let mut head = Vec::new();
                    loop {
                        let n = match recv.read(&mut buf).await {
                            Ok(Some(n)) => n,
                            Ok(None) | Err(_) => return,
                        };
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                        RESPONSE_BODY.len(),
                        RESPONSE_BODY
                    );
                    if send.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    // The clean end of stream the client's copy loop waits for.
                    let _ = send.finish();
                });
            }
        });
    }
}

/// The proxy, its address, and the task that runs it.
struct Harness {
    proxy: LocalProxy,
    proxy_addr: SocketAddr,
    runner: tokio::task::JoinHandle<Result<(), nexapipe_client::error::ClientError>>,
}

impl Harness {
    /// Brings the whole path up: the far side, this side, the pool over it and
    /// the proxy in front.
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
        tokio::spawn(serve_http(server));

        // This side: an endpoint, a pool over it, and the proxy.
        let client = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .bind()
            .await
            .expect("this side binds");
        let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);
        let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
            .await
            .expect("the proxy binds");
        let proxy_addr = proxy.local_addr().expect("the proxy's address");
        let runner = tokio::spawn({
            let proxy = proxy.clone();
            async move { proxy.run().await }
        });

        Self {
            proxy,
            proxy_addr,
            runner,
        }
    }

    /// One request, from the application to the response it gets back.
    ///
    /// The application opens a connection, sends the request and reads until
    /// the proxy closes it — which it does once the response has been relayed,
    /// so the read ends there.
    ///
    /// The clock starts before the connection is opened, so the number is the
    /// whole cost of one request as the application pays it: the socket, the
    /// write, and the response coming back.
    async fn request_response(&self) -> Duration {
        let start = std::time::Instant::now();
        let mut stream = self.connect().await;
        let request = format!("GET http://{HOST}{PATH} HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("the request goes out");

        let mut answer = Vec::new();
        tokio::time::timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut answer))
            .await
            .expect("the response arrives")
            .expect("the response reads");
        assert!(
            answer.starts_with(b"HTTP/1.1 200"),
            "the far side should have answered: {:?}",
            String::from_utf8_lossy(&answer)
        );
        start.elapsed()
    }

    /// The application's connection to the proxy.
    ///
    /// Two socket options, and both of them are about the bench's speed rather
    /// than about the proxy.
    ///
    /// `SO_REUSEADDR` lets a local port be bound again while it is still the
    /// remote end of a socket in `TIME_WAIT`, which BSD otherwise refuses.
    /// `SO_LINGER` with a zero timeout makes the close send a reset instead of
    /// a FIN, so the connection never enters `TIME_WAIT` at all.
    ///
    /// Without them the bench fails partway through a run with
    /// `EADDRNOTAVAIL`: the proxy closes the connection after every response,
    /// so a bench that makes thousands of requests per second leaves tens of
    /// thousands of sockets in `TIME_WAIT`, and the operating system's
    /// ephemeral ports run out. This is the operating system's limit and the
    /// bench's pace, not the proxy's behaviour — a real client does not open
    /// thousands of connections per second.
    async fn connect(&self) -> TcpStream {
        let socket = TcpSocket::new_v4().expect("a socket");
        socket.set_reuseaddr(true).expect("the socket allows reuse");
        socket
            .set_zero_linger()
            .expect("the socket allows a zero linger");
        socket
            .connect(self.proxy_addr)
            .await
            .expect("the proxy accepts")
    }

    /// One request, timed only up to the response head.
    ///
    /// This is the time the application waits before it can start rendering,
    /// which is the part of the request a user feels. The rest of the body
    /// arrives after it.
    ///
    /// The head is read into a buffer and scanned, **not** read one byte at a
    /// time: a byte-at-a-time read is a syscall per byte, so it would measure
    /// the bench's own syscall count rather than the proxy's latency.
    ///
    /// The clock stops at the head, but the connection is read to the end
    /// anyway. Dropping it at the head would close the socket while the proxy
    /// is still writing the rest of the response, which changes what the proxy
    /// does — and a bench that changes the thing it measures measures
    /// something else.
    async fn first_byte(&self) -> Duration {
        let mut stream = self.connect().await;
        let request = format!("GET http://{HOST}{PATH} HTTP/1.1\r\nHost: {HOST}\r\n\r\n");

        let start = std::time::Instant::now();
        stream
            .write_all(request.as_bytes())
            .await
            .expect("the request goes out");

        let mut head = Vec::new();
        let mut buf = vec![0u8; 4096];
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                let n = stream.read(&mut buf).await.expect("the head arrives");
                assert!(n > 0, "the proxy closed before the head was complete");
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await
        .expect("the response head arrives");
        let elapsed = start.elapsed();

        // Read the rest, so the connection ends the way it does in the other
        // bench. This is after the clock stops.
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;

        elapsed
    }

    /// Takes the proxy down and waits for it to stop.
    async fn stop(self) {
        self.proxy.stop();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.runner).await;
    }
}

fn local_request(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("local_request");

    // A shorter measurement window than criterion's default, and the reason is
    // the connection count. The proxy closes the connection after every
    // response, so every iteration opens one — and at criterion's default
    // window this bench would make tens of thousands of connections, which is
    // a lot of churn for the operating system to absorb and a lot of noise to
    // measure. Two seconds is enough iterations for criterion's statistics and
    // few enough connections to leave the machine alone.
    group.measurement_time(Duration::from_secs(2));
    group.warm_up_time(Duration::from_secs(1));

    group.bench_function("request_response", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                // One request before the clock starts: the first one pays for
                // the QUIC handshake, and what is measured here is the request
                // rather than the price of opening the connection.
                black_box(harness.request_response().await);

                // The sum of the requests, not the wall time around them: the
                // two benches measure different moments, and the wall time
                // would put the same thing into both.
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += harness.request_response().await;
                }

                harness.stop().await;
                total
            })
        })
    });

    group.bench_function("first_byte", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let harness = Harness::start().await;

                black_box(harness.first_byte().await);

                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += harness.first_byte().await;
                }

                harness.stop().await;
                total
            })
        })
    });

    group.finish();
}

criterion_group!(benches, local_request);
criterion_main!(benches);
