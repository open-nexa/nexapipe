//! The L4 forwarding path: a flow from the client through the server to a
//! backend and back.
//!
//! What is measured is the copy loop — the bytes moving between the tunnel and
//! the backend — and not the handshake around it: the flow is established
//! first, and the measurement starts when the payload does. The handshake is a
//! fixed price per flow rather than a rate, and the tests cover what it does.
//!
//! The backend is a loopback TCP echo and the client side is a
//! `tokio::io::duplex` pair, so the whole bench runs without a network and
//! without an iroh endpoint — the same arrangement the L4 tests use.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nexapipe::config::RouteMode;
use nexapipe::l4::{DEFAULT_MAX_FLOWS_PER_CONNECTION, FlowLimiter, serve_stream};
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RouteConfig};
use nexapipe_proto::{L4Proto, Preface};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How much one measured step carries, in bytes.
///
/// The size of one HTTP request body rather than of a file: the path this
/// bench measures is the one a request takes, and a payload that fits in a
/// couple of socket reads is what a request looks like.
const PAYLOAD: usize = 64 * 1024;

/// The host the flow asks for. It has to be a host the route table names,
/// because the route lookup is part of the path being measured.
const HOST: &str = "db.test";

/// A backend that echoes everything back until the client stops writing.
async fn echo_backend(listener: TcpListener) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// The route table the flow is served from: one TCP route to the echo.
fn config_with(backend: &str) -> RouteConfig {
    RouteConfig::new(vec![Route::new(
        HOST,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Tcp,
        None,
    )])
}

fn l4_forward(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("l4_forward");
    group.throughput(Throughput::Bytes(PAYLOAD as u64));

    group.bench_function("tcp_flow", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let backend = listener.local_addr().unwrap();
                tokio::spawn(echo_backend(listener));
                let config = config_with(&backend.to_string());
                let payload = vec![0x5au8; PAYLOAD];

                // The flow is established before the clock starts: what is
                // measured is the copy loop, not the price of establishing a
                // flow.
                let (client, server) = tokio::io::duplex(256 * 1024);
                let limiter = Arc::new(FlowLimiter::new(DEFAULT_MAX_FLOWS_PER_CONNECTION));
                let task = tokio::spawn(async move {
                    serve_stream(
                        server,
                        Vec::new(),
                        &config,
                        &limiter,
                        "bench",
                        None,
                        "bench-request-id",
                        None,
                    )
                    .await
                });

                let (mut reader, mut writer) = tokio::io::split(client);
                let preface = Preface::new(L4Proto::Tcp, HOST, 5432).to_bytes().unwrap();
                writer.write_all(&preface).await.unwrap();
                // The status byte: the flow has to be accepted before the
                // payload means anything, and a flow that was refused would
                // otherwise look like a very slow one.
                let mut status = [0u8; 1];
                reader.read_exact(&mut status).await.unwrap();
                assert_eq!(status[0], 0, "the flow should be accepted");

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    writer.write_all(&payload).await.unwrap();
                    let mut echoed = vec![0u8; PAYLOAD];
                    reader.read_exact(&mut echoed).await.unwrap();
                    black_box(&echoed);
                }
                let elapsed = start.elapsed();

                drop(reader);
                drop(writer);
                let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
                elapsed
            })
        })
    });

    group.finish();
}

criterion_group!(benches, l4_forward);
criterion_main!(benches);
