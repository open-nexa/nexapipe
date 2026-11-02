# nexapipe-client

The client library for the [nexapipe](https://github.com/open-nexa/nexapipe)
proxy — a way for an application to reach services that live behind NAT,
without a control plane, without an account, and without the proxy ever
terminating TLS.

It ships as an `rlib` for Rust, a `cdylib` for Android (JNI), and a UniFFI
binding for Swift, Kotlin and Python.

## What it does

- **Connection pooling** over an iroh/QUIC endpoint, with the transport tuned
  (per-stream window, congestion controller, MTU) and overridable without a
  rebuild.
- **Domain-to-node routing**: a set of domains, a set of nodes, and the
  decision of which node carries which domain.
- **A local HTTP proxy**: `CONNECT` opens an L4 flow, and a TLS `ClientHello`
  opened straight at it goes down the SNI path.
- **A TUN proxy**: a smoltcp TCP/IP stack with per-domain virtual IPs, so a
  flow carries its own port — and UDP works.

## Using it

```toml
[dependencies]
nexapipe-client = "1.0"
```

```rust
use std::sync::Arc;

use nexapipe_client::{EndpointGroup, LoadBalancingStrategy, LocalProxy, NodeConfig};

let group = EndpointGroup::new_with_nodes(
    vec![NodeConfig {
        server_node_id: Some(server_node_id),
        server_ticket: None,
        domains: vec!["app.example.com".to_string()],
    }],
    None,
    LoadBalancingStrategy::RoundRobin,
)
.await?;

// An HTTP proxy on 127.0.0.1:8081, forwarding only the configured domains.
let proxy = LocalProxy::new(
    "127.0.0.1:8081",
    vec!["app.example.com".to_string()],
    Arc::new(group),
)
.await?;
proxy.run().await?;   // run() blocks; call stop() from elsewhere to end it
```

### Cargo features

| Feature | Purpose |
| --- | --- |
| `native-certs` (default) | Use the operating system's certificate store. |
| `webpki-roots` | Bundle Mozilla's roots instead. |
| `local-proxy` | The local HTTP proxy: `CONNECT` opens an L4 TCP flow, and a TLS `ClientHello` opened straight at it goes down the SNI path. |
| `tun-proxy` | A smoltcp TCP/IP stack for a TUN fd, with per-domain virtual IPs so a flow carries its own port (and UDP works). Implies `local-proxy`. |
| `jni` | JNI entry points for `com.nexa.pipe.IrohProxy`. |
| `uniffi` | UniFFI bindings for Swift, Kotlin and Python. |
| `tracing` (default) | `tracing` integration. |

### The `tun-proxy` feature needs nothing in your `Cargo.toml`

The TUN runs a TCP/IP stack — smoltcp — and this crate depends on it
directly, on a release that carries the fix for the sequence-number underflow
panic (smoltcp PR #1079, in 0.13 and later). There is no patch to apply and
no `[patch.crates-io]` to write: the stack the TUN runs is the crates.io one.

What the client does with it — the framing around the stack, the handshake, the
flows — is in `src/tun_proxy/netstack/`, and it is the client's own code.

### Documentation

The page on [docs.rs](https://docs.rs/nexapipe-client) is built with the
`tun-proxy`, `local-proxy`, `jni` and `uniffi` features on, so it carries the
whole crate — the TUN stack, the local proxy, the Android bridge and the
UniFFI bindings, not only the part the default features reach.

## Licence

MIT. See the `LICENSE` file in the package.
