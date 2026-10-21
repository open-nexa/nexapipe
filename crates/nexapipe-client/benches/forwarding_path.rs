//! The forwarding path, end to end: an application connects to the local
//! proxy, asks for a tunnel, and the bytes travel over an iroh connection to
//! the far side and back.
//!
//! This is the only bench here that reflects what a user experiences: the
//! request crosses the proxy's accept loop, the tunnel handshake, the tunnel
//! itself and the copy loop on the way back.
//!
//! The far side is an iroh endpoint on this host, bound to the loopback
//! interface, and the tunnel it serves is an echo: it reads the L4 preface,
//! answers the status byte and echoes what comes after. The two endpoints talk
//! to each other over the loopback interface, so the bench needs no network
//! and no relay.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use iroh::Endpoint;
use iroh::endpoint::presets;
use nexapipe_client::IrohConnectionPool;
use nexapipe_client::local_proxy::LocalProxy;
use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The ALPN the tunnel speaks. The same bytes the client uses.
const ALPN: &[u8] = b"\x05nexapipe";

/// The host the application asks for.
const HOST: &str = "db.test";

/// The port it asks for.
const PORT: u16 = 5432;

/// How much one measured step carries, in bytes.
const PAYLOAD: usize = 64 * 1024;

/// The far side of the tunnel: an echo that speaks the L4 framing.
///
/// Reads the preface, answers with the status byte the client waits for, and
/// echoes everything after it. The preface is `magic, version, proto, host
/// length`, the host, and the port — so its length is known once the fourth
/// byte has been read.
async fn serve_tunnel(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            let mut header = [0u8; 4];
            if recv.read_exact(&mut header).await.is_err() {
                return;
            }
            let mut rest = vec![0u8; usize::from(header[3]) + 2];
            if recv.read_exact(&mut rest).await.is_err() {
                return;
            }
            // `Ok` — the tunnel is open. The client waits for this byte before
            // it sends anything, so it has to come first.
            if send.write_all(&[0x00]).await.is_err() {
                return;
            }

            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) | Err(_) => break,
                    Ok(Some(n)) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = send.finish();
            // The connection is held until the client is done with it: dropping
            // it here would close the tunnel before the last bytes were read.
            let mut sink = [0u8; 1];
            let _ = recv.read(&mut sink).await;
        });
    }
}

fn forwarding_path(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("forwarding_path");
    group.throughput(Throughput::Bytes(PAYLOAD as u64));

    group.bench_function("connect_tunnel", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                // The far side.
                let server = Endpoint::builder(presets::N0)
                    .alpns(vec![ALPN.to_vec()])
                    .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .unwrap()
                    .bind()
                    .await
                    .expect("the far side binds");
                let server_addr = server.addr();
                tokio::spawn(serve_tunnel(server));

                // This side: an endpoint, a pool over it, and the proxy.
                let client = Endpoint::builder(presets::N0)
                    .alpns(vec![ALPN.to_vec()])
                    .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .unwrap()
                    .bind()
                    .await
                    .expect("this side binds");
                let pool = IrohConnectionPool::new_with_endpoint(client, server_addr);
                let proxy =
                    LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
                        .await
                        .expect("the proxy binds");
                let proxy_addr = proxy.local_addr().expect("the proxy's address");
                let runner = tokio::spawn({
                    let proxy = proxy.clone();
                    async move { proxy.run().await }
                });

                // The tunnel is established before the clock starts: what is
                // measured is the traffic over it, not the price of opening it.
                let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
                stream
                    .write_all(format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                let mut answer = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    stream.read_exact(&mut byte).await.unwrap();
                    answer.push(byte[0]);
                    if answer.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(
                    answer.starts_with(b"HTTP/1.1 200"),
                    "the tunnel should be established: {:?}",
                    String::from_utf8_lossy(&answer)
                );

                let payload = vec![0x5au8; PAYLOAD];
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    stream.write_all(&payload).await.unwrap();
                    let mut echoed = vec![0u8; PAYLOAD];
                    stream.read_exact(&mut echoed).await.unwrap();
                    black_box(&echoed);
                }
                let elapsed = start.elapsed();

                drop(stream);
                proxy.stop();
                let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
                elapsed
            })
        })
    });

    group.finish();
}

criterion_group!(benches, forwarding_path);
criterion_main!(benches);
