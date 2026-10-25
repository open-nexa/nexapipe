# nexapipe

An iroh/QUIC reverse proxy that forwards HTTP, HTTPS, WebSocket, TCP and UDP to
services that live behind NAT — **without ever holding a certificate, without a
control plane, and without a server to rent**.

It is the server half of [nexapipe](https://github.com/open-nexa/nexapipe). The
client half is [`nexapipe-client`](https://crates.io/crates/nexapipe-client).

## How it works

```
   clients                       nexapipe server                    your LAN / host
   ───────                       ───────────────                    ───────────────
   any HTTP client  ── TLS ───►  passthrough by SNI      ── TCP ──►  Caddy :443 (certs)
   nexapipe-client  ── QUIC ──►  L7 router (Host + path) ── HTTP ──► backend A  backend B
   (local proxy / TUN)           L4 tunnel (tcp / udp)               :18080  :15432  :3478
```

One inner TCP connection maps to one QUIC bidirectional stream. What it carries
depends on who opened it: an HTTP request, a TLS session, or an L4 flow. The
**first byte** of a stream picks the handler, so the four kinds of traffic never
have to be told apart by guessing.

**TLS is terminated by your backend, never by this proxy.** A `ClientHello` is
matched by SNI and copied through as bytes, so the session runs end to end
between the visitor and your backend. The proxy holds no key material and never
sees a plaintext byte of an `https://` request.

## Using it

```toml
[dependencies]
nexapipe = "1.0"
```

The crate is a library with a thin binary beside it: `run_proxy` is what the
binary calls, and what an embedder calls too.

```rust
use nexapipe::config::ProxyConfig;
use nexapipe::proxy::{ProxyOptions, run_proxy};

let config = ProxyConfig::load("config.toml")?;
run_proxy(config.routing_table()?, "config.toml", shutdown, ProxyOptions {
    /* ... */
}).await?;
```

A server is three lines of configuration:

```toml
[[routes]]
host_pattern = "*"
backends = ["http://127.0.0.1:3000"]
```

## What is in the library

| Module | What it is |
| --- | --- |
| `proxy` | Starting the proxy: the routes, the listeners, the shutdown |
| `conn` | The iroh connection handling, and the handshake that authenticates a client |
| `http` | HTTP and WebSocket proxying towards the backends |
| `passthrough` | TLS passthrough: SNI to a route, bytes copied through |
| `l4` | The L4 tunnel: raw TCP and framed UDP |
| `routes` | The routing table: host patterns, path patterns, backend pools |
| `auth` | The credentials, and the rules about which host a client may reach |
| `log` | The access log, the metrics, and the sinks that take them |
| `config` | The configuration file and the routes it carries |

### The seams

Two things a deployment may want to change are traits, with the built-in
implementation in this crate:

- **`conn::Authenticator`** — where a credential is checked. The built-in one
  reads the client table in `config.toml`; a deployment that keeps its
  credentials in an identity provider hands its own implementation to
  `AuthState::with_authenticator()`.
- **`log::AccessSink`** — where the access records go. The built-in one writes
  the log file; a deployment that has to hand its audit to a SIEM registers its
  own and takes the records as values.

## Documentation

The full documentation, the configuration reference and the security boundary
are in the [repository](https://github.com/open-nexa/nexapipe).

## Licence

MIT. See the `LICENSE` file in the package.
