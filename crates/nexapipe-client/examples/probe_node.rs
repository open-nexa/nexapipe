//! Diagnostics probe: connect to a backend node exactly the way the connection pool
//! does (node ID + N0 presets, optionally a pinned relay), and print the real outcome.
//!
//! The desktop service swallows the connect error — the pool's own warning only fires
//! after its internal timeout, and `preconnect_report` cancels it sooner — so this
//! example is the fastest way to see what iroh actually reports for a node.
//!
//! Usage:
//! ```text
//! cargo run -p nexapipe-client --example probe_node -- <node-id-hex> [pinned-relay-url]
//! ```

use iroh::endpoint::presets;
use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, RelayUrl};
use nexapipe_client::connection_pool::parse_endpoint_addr;
use std::time::Duration;

/// Same ALPN the pool negotiates with the server.
const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let node_id = args
        .next()
        .expect("usage: probe_node <node-id-hex> [pinned-relay-url]");
    let pin = args.next();

    let mut builder = Endpoint::builder(presets::N0);
    if let Some(url) = &pin {
        // Same construction as `RelayModeSpec::Pinned`: a map holding exactly one relay.
        let url: RelayUrl = url.parse()?;
        builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter([
            RelayConfig::from(url.clone()),
        ])));
        println!("relay map restricted to {url}");
    }
    let ep = builder.bind().await?;
    println!("bound as {}", ep.id());

    let addr = parse_endpoint_addr(Some(&node_id), None)?;
    println!("connecting to {node_id} with ALPN {:?} ...", ALPN_NEXAPIPE);
    let started = std::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(20), ep.connect(addr, ALPN_NEXAPIPE)).await {
        Err(_) => {
            println!(
                "TIMEOUT: no QUIC handshake within 20s ({:.1}s elapsed)",
                started.elapsed().as_secs_f32()
            );
        }
        Ok(Err(e)) => {
            println!(
                "CONNECT ERROR after {:.1}s: {e:#}",
                started.elapsed().as_secs_f32()
            );
        }
        Ok(Ok(conn)) => {
            println!(
                "CONNECTED in {:.1}s; remote_address: {:?}; paths: {:?}",
                started.elapsed().as_secs_f32(),
                conn.remote_id(),
                conn.paths()
            );
            conn.close(0u32.into(), b"probe done");
        }
    }
    ep.close().await;
    Ok(())
}
