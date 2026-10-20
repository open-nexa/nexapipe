use crate::routes::{L4Options, Route};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Address of the plaintext listener. **Absent means "do not bind it at
    /// all"**, and that is the default: every client that authenticates comes
    /// in over iroh, and nothing on this listener can be gated — the 2FA
    /// handshake lives in the iroh accept loop (`crate::conn`), so a request
    /// that arrives here reaches a route without ever answering for itself.
    /// Configure it for a client on the same host (a sidecar, another
    /// container sharing the network namespace), not for the network.
    pub listen_addr: Option<String>,
    /// Allow [`Self::listen_addr`] to name something other than loopback.
    ///
    /// Opt-in because binding a non-loopback address publishes every `http`
    /// route and every `passthrough` backend to whoever can reach the port,
    /// with no authentication step in between. Set it only when something
    /// downstream does the gating (a reverse proxy, a firewall, a private
    /// network you control).
    pub expose: Option<bool>,

    // ---- Removed keys, still accepted so an existing config.toml keeps parsing ----
    //
    // This process no longer terminates TLS: the backend does (Caddy &co). The
    // fields below are kept only so `ProxyConfig::from_file` does not fail on a
    // config written for the old layout; `warn_removed_tls_keys` logs them at
    // startup and they can be deleted from the file.
    pub tls_enabled: Option<bool>,
    pub tls_listen_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// The `[admin]` section: the auxiliary listener for liveness and metrics.
///
/// Separate from `[server]` on purpose. `[server] listen_addr` serves routes,
/// so a request arriving there is matched against the routing table before
/// anything else can look at it; this listener answers questions about the
/// proxy itself, and has to keep answering them when routing is the thing that
/// is broken.
///
/// **Loopback only, with no `expose`.** Nothing here should be reachable from
/// the network: it names the routes, the clients and the backends, and the
/// unauthenticated paths carry no credential check.
///
/// **There is deliberately no `token` key.** The token that guards `/v1/*` is
/// generated on first start into a file next to this one; a key here would put
/// a credential into the file operators copy around and commit, and writing it
/// back would trip the watcher that reloads on the config's mtime. See
/// [`crate::admin::token`].
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminConfig {
    /// Address of the auxiliary listener. **Absent means "do not bind it"**,
    /// and that is the default: an instance that is not being scraped or
    /// supervised should not hold a port open for it.
    pub listen_addr: Option<String>,
}

/// The `[metrics]` section: whether `/metrics` is served at all.
///
/// A config gate rather than a cargo feature because it is a runtime choice:
/// the same binary is deployed with and without a scraper, and a feature would
/// mean a second build-and-test combination in CI and in every release for a
/// decision a deployment makes per host.
#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub struct MetricsConfig {
    /// Serve `/metrics` on the `[admin]` listener. Default: `false`.
    ///
    /// Off by default because the listener it hangs off is unauthenticated:
    /// nothing is exposed until someone asks for it *and* binds the address.
    pub enabled: bool,
}

/// `Default` because the startup path builds one from scratch when a config
/// has no `[iroh]` section at all but still needs somewhere to put the secret
/// key it just generated. Every field is optional, so "all of them absent" is
/// exactly what an empty `[iroh]` means.
#[derive(Deserialize, Clone, Default)]
pub struct IrohConfig {
    pub relay_url: Option<String>,
    pub relay_mode: Option<String>,
    /// Bearer token sent to the relay. Only meaningful with `relay_mode = "custom"`;
    /// a relay that requires one has to be configured on both sides, because the
    /// client's relay map is the only place its token is read from.
    pub relay_auth_token: Option<String>,
    pub bind_port: Option<u16>,
    /// Also bind the IPv6 wildcard (`[::]`) on the same port.
    ///
    /// Off unless asked for, so a config written before this existed keeps
    /// binding exactly what it binds today.
    ///
    /// It is "also", not "instead": the IPv4 socket stays. An endpoint that
    /// could only be reached over IPv6 would be a regression for every client
    /// that has no IPv6 route, and the two sockets are independent here, so
    /// there is nothing to trade off — turning this on adds a socket, it does
    /// not move one.
    ///
    /// Only meaningful together with `bind_port`: without a fixed port there is
    /// nothing to keep the two families on the same one.
    pub bind_ipv6: Option<bool>,
    /// Secret key for stable endpoint identity.
    ///
    /// Optional in the config because the server generates one on first start
    /// when this is absent, and writes it here — so a config that never
    /// mentions it still ends up with a Node ID that survives a restart. Set it
    /// by hand only to move an identity between hosts, or to keep one when the
    /// file is not writable (see `NEXAPIPE_NO_PERSIST_IDENTITY`).
    ///
    /// A value that is present but does not parse refuses the start.
    pub secret_key: Option<String>,
    /// Path to a file holding `secret_key`, for a config that must not carry
    /// the key itself.
    ///
    /// The point is the permission gate: a config whose only credential is a
    /// pointer holds nothing worth reading, so it can stay `0644` — a Docker
    /// bind mount, a file an operator edits — while the key file it names is
    /// held to the `0600` rule in its place. See [`CredentialSource`].
    pub secret_key_file: Option<String>,
    /// Path to a file holding `relay_auth_token`, same idea as
    /// [`Self::secret_key_file`] for the relay bearer token.
    pub relay_auth_token_file: Option<String>,
    /// Where `secret_key` was resolved from. Filled by
    /// [`ProxyConfig::resolve_external_credentials`] during the load; not
    /// spelled in the file, so `serde` skips it.
    #[serde(skip)]
    pub secret_key_source: CredentialSource,
    /// Where `relay_auth_token` was resolved from. See
    /// [`Self::secret_key_source`].
    #[serde(skip)]
    pub relay_auth_token_source: CredentialSource,
}

/// Where a `[iroh]` credential was resolved from.
///
/// [`ProxyConfig::holds_credentials`] asks this: the permission gate is about
/// what an account that reads *the config file* would obtain, and a credential
/// that came from the environment or from a pointed-to file is not in the
/// config for anyone to read. Only the inline literal makes the file itself a
/// credential holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialSource {
    /// The literal value written in config.toml.
    #[default]
    Inline,
    /// `NEXAPIPE_IROH_SECRET_KEY` / `NEXAPIPE_RELAY_AUTH_TOKEN`.
    Env,
    /// The file `secret_key_file` / `relay_auth_token_file` names.
    File,
}

/// `Some(_)` becomes `Some("<redacted>")` for a `Debug` view.
///
/// Keeping the `Option` shape is the point: whether a credential is configured
/// at all is something an operator needs to see in a log, and it is not the
/// credential.
pub(crate) fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

/// Handwritten so the endpoint's credentials never reach a log line.
///
/// `ProxyConfig` is logged at debug level whenever it is parsed — including on
/// every hot reload, where the logger is already installed — and a derived
/// `Debug` would put the ed25519 private key and the relay bearer token on that
/// line. Reading the log would then be enough to own this endpoint's identity
/// permanently, which is worse than losing one client's TOTP seed.
impl std::fmt::Debug for IrohConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohConfig")
            .field("relay_url", &self.relay_url)
            .field("relay_mode", &self.relay_mode)
            .field("relay_auth_token", &redacted(&self.relay_auth_token))
            .field("bind_port", &self.bind_port)
            .field("bind_ipv6", &self.bind_ipv6)
            .field("secret_key", &redacted(&self.secret_key))
            .field("secret_key_file", &self.secret_key_file)
            .field("secret_key_source", &self.secret_key_source)
            .field("relay_auth_token_file", &self.relay_auth_token_file)
            .field("relay_auth_token_source", &self.relay_auth_token_source)
            .finish()
    }
}

/// How a route talks to its backends.
///
/// * `Http` (default) — the proxy parses the request, applies the path rules
///   below and re-issues it with the shared HTTP client. Plaintext `http://`
///   backends only; TLS is not spoken to backends.
/// * `Passthrough` — the proxy copies raw bytes. Used for TLS, which is
///   terminated by the backend (Caddy &co): the route is selected by SNI and
///   `path_pattern` / `path_rewrite` do not apply.
/// * `Tcp` / `Udp` — the L4 tunnel (`crate::l4`). One inner connection is one
///   QUIC bi-stream carrying a preface that names the route and the port; the
///   backend address comes from this route's `backends`. Nothing here parses
///   HTTP, and `path_pattern` / `path_rewrite` do not apply.
///
/// The four modes never see each other's traffic: which one applies is decided
/// before any matching happens, by the first byte of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteMode {
    #[default]
    Http,
    Passthrough,
    Tcp,
    Udp,
}

impl RouteMode {
    /// The spelling used in the config file and in `GET /v1/routes`.
    ///
    /// Deliberately not `Display` for now: the only two callers want a
    /// `&'static str` — one to write JSON, one to log — and a `Display` impl
    /// would invite formatting a mode into prose before anyone has decided how
    /// it should read there.
    pub fn name(self) -> &'static str {
        match self {
            RouteMode::Http => "http",
            RouteMode::Passthrough => "passthrough",
            RouteMode::Tcp => "tcp",
            RouteMode::Udp => "udp",
        }
    }

    /// True for the two modes the L4 tunnel serves.
    pub fn is_l4(self) -> bool {
        matches!(self, RouteMode::Tcp | RouteMode::Udp)
    }

    /// Which mode carries a given L4 preface protocol.
    pub fn from_l4_proto(proto: nexapipe_proto::L4Proto) -> Self {
        match proto {
            nexapipe_proto::L4Proto::Tcp => RouteMode::Tcp,
            nexapipe_proto::L4Proto::Udp => RouteMode::Udp,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub host_pattern: String,
    /// Defaults to `/`. Ignored when `mode = "passthrough"`.
    #[serde(default = "default_path_pattern")]
    pub path_pattern: String,
    pub path_is_prefix: Option<bool>,
    pub strategy: Option<String>,
    pub backends: Vec<String>,
    /// `"http"` (default), `"passthrough"`, `"tcp"` or `"udp"`. See [`RouteMode`].
    pub mode: Option<String>,
    /// Several modes at once, sharing this route's `backends` — the ordinary way
    /// to write a host that answers both a request and a tunnel.
    ///
    /// `mode` and `modes` may be combined; the union is what the route serves.
    /// Two entries instead of one is still the way to give the modes different
    /// `backends`, since a route has exactly one pool.
    pub modes: Option<Vec<String>>,
    pub path_rewrite: Option<String>,
    /// `tcp` / `udp` routes: the client ports this route accepts.
    ///
    /// Only a selector — it decides whether the route matches, never where the
    /// connection goes. Leaving it out accepts every port, which is what you want
    /// when the backend port is the same one the client asked for.
    pub client_ports: Option<Vec<u16>>,
    /// `udp` routes: seconds of silence before a flow is closed. The server
    /// default (`[timeouts] l4_idle_secs`, itself 60) applies when this is
    /// absent.
    pub idle_timeout_secs: Option<u64>,
    /// `tcp` / `udp` routes: seconds one flow may run before it is closed. The
    /// server default (`deadline::DEFAULT_L4_FLOW_SECS`) applies when absent.
    ///
    /// Distinct from `idle_timeout_secs` on purpose: that one bounds the gap
    /// between packets and re-arms on each, while this bounds the flow. Raise it
    /// for a long-lived session — an interactive SSH connection or a database
    /// session over the tunnel is meant to outlive any default.
    pub flow_timeout_secs: Option<u64>,

    // ---- Removed keys, see `ServerConfig` ----
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub redirect_to_https: Option<bool>,
}

fn default_path_pattern() -> String {
    "/".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyNode {
    pub server_node_id: Option<String>,
    pub server_ticket: Option<String>,
    pub domains: Vec<String>,
}

/// Client-side 2FA credentials used by local-proxy mode.
#[derive(Deserialize, Clone)]
pub struct LocalProxyTwoFactorConfig {
    pub enabled: Option<bool>,
    pub client_id: String,
    pub secret: String,
    pub algorithm: Option<String>,
}

/// Handwritten for the same reason as [`IrohConfig`]'s: this is the client side
/// of a TOTP secret, and the whole config is logged when it is parsed.
impl std::fmt::Debug for LocalProxyTwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalProxyTwoFactorConfig")
            .field("enabled", &self.enabled)
            .field("client_id", &self.client_id)
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub proxy_domains: Vec<String>,
    pub nodes: Option<Vec<LocalProxyNode>>,
    pub strategy: Option<String>,
    /// Full server ticket (contains Node ID + addresses)
    /// Ticket changes when addresses change, but connection info is complete
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_ticket: Option<String>,
    /// Server Node ID only (stable across restarts when using secret_key)
    /// When set, uses discovery service to find server addresses
    /// Preferred for long-term configurations
    /// Deprecated: use `nodes` for multi-endpoint support
    pub server_node_id: Option<String>,
    /// 2FA credentials used to authenticate with the server.
    /// Example:
    ///   [local_proxy.two_factor]
    ///   enabled = true
    ///   client_id = "client-001"
    ///   secret = "JBSWY3DPEHPK3PXP"
    ///   algorithm = "sha1"
    pub two_factor: Option<LocalProxyTwoFactorConfig>,
}

/// Logging configuration (`[log]` section).
///
/// Every field is optional; the defaults (see `log::init`) keep the previous
/// behaviour of logging to stdout and add rotating files under `./logs`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LogConfig {
    /// Write the log to files. Default: `true`.
    pub file: Option<bool>,
    /// Directory holding the log files. Default: `./logs`.
    /// Can be overridden with the `NEXAPIPE_LOG_DIR` environment variable.
    pub dir: Option<String>,
    /// Name of the active log file. Default: `nexapipe.log`.
    /// Rotated copies are written next to it as `nexapipe.<timestamp>.log`.
    pub file_name: Option<String>,
    /// Emit one line per proxied request. Default: `true`.
    pub access_log: Option<bool>,
    /// Name of the access log file. Default: `access.log`.
    pub access_log_file_name: Option<String>,
    /// Rotation interval: `daily` (default), `hourly` or `never`.
    pub rotation: Option<String>,
    /// Also rotate once the active file is bigger than this (MiB, 0 = off). Default: 0.
    pub max_size_mb: Option<u64>,
    /// Rotated files to keep per log file (0 = keep all). Default: 14.
    pub max_files: Option<usize>,
    /// Keep logging to stdout as well. Default: `true`.
    pub console: Option<bool>,
    /// Replace query parameter values with `<redacted>` in the access log.
    /// Default: `true`.
    ///
    /// Parameter names are kept, because they are what makes an access log
    /// useful when you read it back; values are not, because that is where
    /// tokens and signatures travel. Set it to `false` to log request URIs
    /// verbatim — only do that on a log file nobody else can read.
    pub redact_query: Option<bool>,
}

/// The `[timeouts]` section: how long one round trip to a backend may take,
/// and how long each phase of a proxied exchange may hold its slot.
///
/// Two families of wait live here, and keeping them in one section is the point:
/// they are all "a bound that expires as a diagnostic, not a quota", and a
/// deployment that needs one of them raised usually needs to reason about the
/// others beside it.
///
/// The first family covers one step of talking to a backend — dialing it, or
/// waiting for its answer — and deliberately not the request as a whole: once
/// a response head arrives, streaming its body may run for as long as it needs
/// to, on purpose, because "slow backend" is not the same failure as "silent
/// backend".
///
/// The second family bounds the phases of the exchange itself: how long a
/// client may take to send its head and body, how long a streamed response may
/// stay silent between chunks, how long an L4 flow may run and how idle a UDP
/// flow may go, how long a TLS hello may take. See
/// [`crate::deadline`] for which of these are phase deadlines — taken once and
/// never renewed, which is what stops a one-byte trickle from holding a slot
/// forever — and which are idle timeouts, correct only where the phase is
/// meant to stay open.
///
/// Every key is optional, and every default is the constant the server used
/// before this section existed, so writing `[timeouts]` and nothing under it
/// changes nothing.
///
/// Read once at startup, not live: these are handed to the HTTP client builder
/// and to the stream handlers when they start, so an edit takes a restart.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(default)]
pub struct TimeoutsConfig {
    /// Seconds allowed for dialing a backend. Default: 10.
    ///
    /// One value because it is one thing: the HTTP path (including WebSocket
    /// upgrades), TLS passthrough and the L4 tunnel all dial exactly one TCP
    /// connection toward exactly one backend, and before this existed they each
    /// carried their own copy of ten seconds.
    ///
    /// Dialing ends when the connection is up, so this has to cover the network
    /// and nothing the backend says afterwards — raise it for a backend across
    /// a slow or lossy link, where a too-short one turns every request into a
    /// failure that looks like the backend being down.
    pub connect_secs: Option<u64>,
    /// Seconds a backend may take to answer with a status line. Default: 30.
    ///
    /// This is the wait for the response head, not for the response: the moment
    /// the head arrives the deadline is over, and a one-hour stream can follow
    /// it. It is the number to raise for an API that computes before it
    /// answers, and what stops a backend that accepts the connection and then
    /// says nothing from holding the request slot until the client gives up.
    pub response_secs: Option<u64>,
    /// Seconds a client may take to send its request head. Default: 30.
    ///
    /// A **phase deadline**, taken once when the head starts arriving: a client
    /// that trickles one byte of `Host:` every few seconds holds a slot, a task
    /// and a connection slot, and a per-read timeout is exactly what it wants.
    /// This is the number that closes that. See [`crate::deadline`].
    ///
    /// It bounds the head, not the stream: the first byte says which protocol
    /// the stream carries, and until it arrives the protocol is unknown, so the
    /// wait for it is the longer of this and [`Self::tls_hello_secs`]. A short
    /// `header_secs` therefore never cuts off a TLS session or an L4 tunnel —
    /// neither of them sends a request head at all.
    pub header_secs: Option<u64>,
    /// Seconds a client may take to send a request body once the head is in.
    /// Default: 300.
    ///
    /// A **phase deadline**, separate from the head because a large upload
    /// legitimately takes longer than a header does; one budget for both would
    /// be too short for uploads or too loose against a stalled one.
    pub body_secs: Option<u64>,
    /// Seconds a backend response body may stay silent before it is treated as
    /// dead. Default: 120.
    ///
    /// **Idle, not a phase deadline**, and deliberately so: a streamed response
    /// or a server-sent-events stream is supposed to be open for as long as the
    /// two ends want. What must not be possible is a backend that sent the head
    /// and then said nothing at all, so the bound is on the gap between chunks
    /// and re-arms on every chunk by design.
    ///
    /// It applies to every path that proxies a response, the plaintext
    /// listener included: there the body is handed to the client as it arrives,
    /// and a backend that stalls mid-body fails the response rather than
    /// truncating it quietly.
    pub response_idle_secs: Option<u64>,
    /// Seconds an L4 tunnel may run before it is closed. Default: 3600.
    ///
    /// A **phase deadline**, because an L4 flow has no protocol-level end: a
    /// backend connection that never closes and never sends is indistinguishable
    /// from one being used, and bounding the whole flow is what stops a peer
    /// from renewing it indefinitely. Raise it for long-lived SSH or a database
    /// session over the tunnel; a per-route [`crate::routes`] `flow_timeout_secs`
    /// overrides it for one route alone.
    pub l4_flow_secs: Option<u64>,
    /// Seconds between two UDP datagrams in either direction before an L4 flow
    /// is considered idle. Default: 60.
    ///
    /// **Idle**, because a UDP flow has no "complete" to wait for; this bounds
    /// the gap, not the flow, and re-arming on every datagram is the correct
    /// shape here.
    pub l4_idle_secs: Option<u64>,
    /// Seconds a TLS ClientHello may take to arrive. Default: 10.
    ///
    /// A **phase deadline**. The client sends the record header and then the
    /// body of it; a peer that sends the five header bytes and nothing else
    /// would otherwise hold the connection open indefinitely with no read
    /// deadline at all.
    ///
    /// It also covers the wait for the session's first byte, on both
    /// listeners: that byte is what says a TLS session is starting, so it
    /// belongs to the hello rather than to the head.
    pub tls_hello_secs: Option<u64>,
}

/// The `[timeouts]` section with every default filled in.
///
/// The file answers "was this key written?"; this answers "how long do I wait?",
/// which is the question the rest of the server actually asks. Reading either
/// field of the config directly would put `.unwrap_or(TEN_SECONDS)` in every
/// call site — three of them today — and one of them would eventually disagree
/// with the others.
///
/// `deadlines` carries the per-phase budgets ([`crate::deadline::Deadlines`])
/// resolved from the same section, so a handler that needs "how long may the
/// client take to send its head" reads it off the `Timeouts` it was already
/// handed rather than reaching the config itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: std::time::Duration,
    pub response: std::time::Duration,
    pub deadlines: crate::deadline::Deadlines,
}

impl Timeouts {
    /// The deadlines a server without a `[timeouts]` section runs with, i.e. the
    /// constants this section replaced.
    const DEFAULT_CONNECT: std::time::Duration = std::time::Duration::from_secs(10);
    const DEFAULT_RESPONSE: std::time::Duration = std::time::Duration::from_secs(30);

    /// The longest wait either dial key accepts: an hour spent dialing, or
    /// waiting for a status line, is not a slow backend but one that will never
    /// answer.
    const MAX_SECS: u64 = 3600;

    pub fn resolve(config: TimeoutsConfig) -> Self {
        let deadlines = crate::deadline::Deadlines::resolve(&crate::deadline::Overrides {
            header_secs: config.header_secs,
            body_secs: config.body_secs,
            response_idle_secs: config.response_idle_secs,
            l4_flow_secs: config.l4_flow_secs,
            l4_idle_secs: config.l4_idle_secs,
            tls_hello_secs: config.tls_hello_secs,
        });
        Timeouts {
            connect: config
                .connect_secs
                .map_or(Self::DEFAULT_CONNECT, std::time::Duration::from_secs),
            response: config
                .response_secs
                .map_or(Self::DEFAULT_RESPONSE, std::time::Duration::from_secs),
            deadlines,
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::resolve(TimeoutsConfig::default())
    }
}

/// The `[health_check]` section: periodic `GET {path}` probing of `http` route
/// backends.
///
/// A switch rather than a behaviour everyone gets, because a probe is only
/// meaningful if the backend answers it. Plenty of backends — a device's web UI
/// that answers 5xx on an unknown path, or one that does not speak HTTP and so
/// times out — cannot answer a probe at all, and before this section existed a
/// single failed probe was enough to take such a backend out of rotation for
/// good. Set `enabled = false` for those: every backend stays in the pool and
/// traffic is simply forwarded, which is what the proxy did before health checks
/// existed. A backend that 404s, or answers any 2xx, is already counted healthy,
/// so having no dedicated health endpoint is not on its own a reason to opt out.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// `false` disables probing entirely. Default: `true`.
    pub enabled: bool,
    /// Seconds between two rounds of checks. Default: 10.
    pub interval: u64,
    /// Seconds before a single check is abandoned. Default: 5.
    pub timeout: u64,
    /// Consecutive failed checks before a backend leaves the pool. One failure
    /// is never enough: a probe lost to a restart or a GC pause must not empty
    /// the pool. Default: 3.
    pub threshold: usize,
    /// Path appended to the backend URL. Default: `/health`.
    pub path: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            enabled: true,
            interval: 10,
            timeout: 5,
            threshold: 3,
            path: "/health".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    /// **Removed.** Kept in the struct for exactly one reason: serde drops keys
    /// it does not know, so deleting this field would let a config that still
    /// names a `default_backend` keep running — and quietly start answering 404
    /// for hosts it used to forward somewhere. Parsed as an opaque value so its
    /// presence is detected, and refused by [`Self::build_routes`].
    ///
    /// What it did is spelled as a route now: `host_pattern = "*"`.
    #[serde(default)]
    pub default_backend: Option<toml::Value>,
    pub debug: Option<bool>,
    pub routes: Option<Vec<RouteConfig>>,
    pub server: Option<ServerConfig>,
    pub iroh: Option<IrohConfig>,
    pub local_proxy: Option<LocalProxyConfig>,
    /// Which client Node IDs may hold a connection at all. Optional, and
    /// different in kind from `[auth]`: this is not a second factor, so it is
    /// what a server without 2FA uses to stop being reachable by anyone who
    /// learns the Node ID. See [`crate::conn::allow_list`].
    pub peers: Option<PeersConfig>,
    /// Removed: certificates are managed by the backend now. Parsed as an opaque
    /// value so `[acme]` is detected and reported, not silently swallowed.
    pub acme: Option<toml::Value>,
    pub log: Option<LogConfig>,
    /// Probing of `http` backends. Absent means the defaults, i.e. enabled.
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    /// How long to wait on a backend, and how long each phase of a proxied
    /// exchange may hold its slot. Absent means the deadlines this section
    /// replaced, unchanged.
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    /// The auxiliary listener for `/healthz` and `/metrics`. Absent means it is
    /// not bound at all.
    pub admin: Option<AdminConfig>,
    /// Whether `/metrics` is served. Absent means it is not.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// The `[peers]` section: a server-side allow-list of client public keys.
///
/// Deliberately not a key under `[auth]`. It is the knob for exactly the server
/// the "no allow-list" gap describes — one running with 2FA off — so tying it to
/// a section that server may not even have would bury it, and its semantics do
/// not depend on `[auth] enabled` either way. `[peers]` is checked on every
/// inbound connection, before the accept loop sees it.
///
/// Unknown keys are refused here, for the reason they are refused under
/// `[auth]`: the only key this section has is `allow`, and `allow` absent means
/// unrestricted, so `allowed = [...]` instead of `allow = [...]` would leave a
/// server that looks restricted and is not, with nothing in the log to say so.
/// A typo here is a security change rather than a lost setting.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PeersConfig {
    /// Node IDs allowed to connect. `None` (the section present but the key
    /// absent) means unrestricted, like every build before this existed.
    ///
    /// A present-but-*empty* list is refused at load time rather than read as
    /// "refuse everybody": "restrict to nobody" is a plausible typo, and the
    /// cost of guessing wrong is an operator locked out of their own server. An
    /// empty list is spelled by naming one Node ID that is not yours.
    pub allow: Option<Vec<String>>,
}

impl PeersConfig {
    /// Parses the configured Node IDs into the set the hook checks against.
    ///
    /// Fails on anything that is not a valid Node ID rather than skipping it: a
    /// typo in one entry of a list whose whole job is to refuse strangers would
    /// otherwise silently narrow the allow-list, and a silent narrowing here is
    /// worse than a refusal to start.
    pub fn parse_allow_list(
        &self,
    ) -> anyhow::Result<Option<std::collections::HashSet<iroh::EndpointId>>> {
        let Some(entries) = &self.allow else {
            return Ok(None);
        };

        if entries.is_empty() {
            anyhow::bail!(
                "[peers] allow = [] refuses every peer, including the operator's own clients. \
                 Remove the key to leave the listener unrestricted, or list the Node IDs that \
                 may connect"
            );
        }

        let mut allowed = std::collections::HashSet::with_capacity(entries.len());
        for entry in entries {
            let id: iroh::EndpointId = entry
                .parse()
                .map_err(|e| anyhow::anyhow!("[peers] allow: {entry:?} is not a Node ID ({e})"))?;
            allowed.insert(id);
        }
        Ok(Some(allowed))
    }
}

impl ProxyConfig {
    /// Logs configuration that no longer has any effect.
    ///
    /// TLS moved to the backend, so a config.toml written for the old layout
    /// parses but does nothing useful. Reporting it beats a silent failure.
    pub fn warn_removed_tls_keys(&self) {
        const HINT: &str =
            "TLS is terminated by the backend now (see README, `mode = \"passthrough\"`)";

        if self.acme.is_some() {
            tracing::warn!("[acme] is ignored and can be removed from config.toml: {HINT}");
        }

        if let Some(server) = &self.server {
            if server.tls_enabled.unwrap_or(false) {
                tracing::warn!("[server] tls_enabled is ignored and can be removed: {HINT}");
            }
            if server.tls_listen_addr.is_some() {
                tracing::warn!("[server] tls_listen_addr is ignored and can be removed: {HINT}");
            }
            if server.cert_path.is_some() || server.key_path.is_some() {
                tracing::warn!(
                    "[server] cert_path/key_path are ignored and can be removed: {HINT}"
                );
            }
        }

        for route in self.routes.iter().flatten() {
            if route.cert_path.is_some() || route.key_path.is_some() {
                tracing::warn!(
                    "[[routes]] cert_path/key_path for host_pattern={} are ignored and can be removed: {HINT}",
                    route.host_pattern
                );
            }
            if route.redirect_to_https.unwrap_or(false) {
                tracing::warn!(
                    "[[routes]] redirect_to_https for host_pattern={} is ignored: let the backend redirect instead",
                    route.host_pattern
                );
            }
        }
    }
}

impl ProxyConfig {
    /// Whether this config puts a credential in the file it was read from.
    ///
    /// The 2FA seeds are the obvious one and live in `[auth]`, but this file also
    /// carries `[iroh] secret_key` — the endpoint's private key, which is what
    /// makes a Node ID yours — and `relay_auth_token`, a bearer token. Either one
    /// is worth refusing a permissive mode over, on a server with `[auth]` off.
    /// Refuses the `[health_check]` numbers that would otherwise be rewritten
    /// on the way in.
    ///
    /// Each of them was clamped with `max(1)`, which turns a typo into
    /// behaviour nobody asked for: `interval = 0` is one round of probes per
    /// second, per route; `timeout = 0` is a probe that can never succeed, so
    /// every backend is taken out of rotation; and `threshold = 0` means a
    /// single lost probe empties the pool, the opposite of what the knob is
    /// for. All three are seconds nobody would write on purpose.
    fn validate_health_check(&self) -> anyhow::Result<()> {
        let health = &self.health_check;

        if health.interval == 0 {
            anyhow::bail!(
                "[health_check] interval is 0: it is the number of seconds between two \
                 rounds of checks, so it has to be at least 1"
            );
        }
        if health.timeout == 0 {
            anyhow::bail!(
                "[health_check] timeout is 0: no probe could ever finish, so every backend \
                 would be marked unhealthy and taken out of rotation"
            );
        }
        if health.threshold == 0 {
            anyhow::bail!(
                "[health_check] threshold is 0: one failed probe would empty the pool. \
                 It is the number of consecutive failures that takes a backend out, so it \
                 has to be at least 1"
            );
        }

        Ok(())
    }

    /// Every `[timeouts]` value is a wait for one step of talking to a backend,
    /// and neither end of the range is a number anyone would dial: zero is a
    /// deadline that expires before the round trip it is meant to bound, so
    /// every request to every backend fails; anything past the ceiling is not a
    /// longer wait but a missing one, and the symptom is a request slot held
    /// until the client gives up. Refused at load, where the operator is
    /// looking, rather than discovered as "all requests fail 502".
    fn validate_timeouts(&self) -> anyhow::Result<()> {
        for (key, secs) in [
            ("connect_secs", self.timeouts.connect_secs),
            ("response_secs", self.timeouts.response_secs),
        ] {
            let Some(secs) = secs else {
                continue;
            };
            if secs == 0 {
                anyhow::bail!(
                    "[timeouts] {key} is 0: no backend could answer that fast, so every request \
                     would fail. It is a whole number of seconds, and the shortest wait anyone \
                     asks for is 1"
                );
            }
            if secs > Timeouts::MAX_SECS {
                anyhow::bail!(
                    "[timeouts] {key} is {secs}s, past the {max}s ceiling: a wait that long is a \
                     request slot held until the client gives up, which is the failure a timeout \
                     exists to prevent",
                    max = Timeouts::MAX_SECS
                );
            }
        }

        // The per-phase budgets take the ceiling from `crate::deadline`, not
        // `Timeouts::MAX_SECS`: `l4_flow_secs` defaults to an hour and a
        // long-lived tunnel is exactly the case an operator raises it for, so
        // its ceiling is a day, not an hour. Zero is refused for the same reason
        // as above, with a different reading — here zero does not fail every
        // request, it closes every flow the instant it opens, which looks like a
        // working server that transfers nothing.
        for (key, secs) in [
            ("header_secs", self.timeouts.header_secs),
            ("body_secs", self.timeouts.body_secs),
            ("response_idle_secs", self.timeouts.response_idle_secs),
            ("l4_flow_secs", self.timeouts.l4_flow_secs),
            ("l4_idle_secs", self.timeouts.l4_idle_secs),
            ("tls_hello_secs", self.timeouts.tls_hello_secs),
        ] {
            let Some(secs) = secs else {
                continue;
            };
            if secs == 0 {
                anyhow::bail!(
                    "[timeouts] {key} is 0: the phase it bounds would close the moment it \
                     opens, and nothing would ever get through. It is a whole number of \
                     seconds, and the shortest wait anyone asks for is 1"
                );
            }
            if secs > crate::deadline::MAX_SECS {
                anyhow::bail!(
                    "[timeouts] {key} is {secs}s, past the {max}s ceiling: a bound that long \
                     never fires within a process lifetime, which is the failure a timeout \
                     exists to prevent",
                    max = crate::deadline::MAX_SECS
                );
            }
        }

        Ok(())
    }

    /// The `[timeouts]` deadlines this config resolves to.
    pub fn timeouts(&self) -> Timeouts {
        Timeouts::resolve(self.timeouts)
    }

    /// Whether the config file this was read from holds a credential.
    ///
    /// Asked about the *file*, not about what the process is running with: the
    /// permission check it feeds is "can another account on this host read the
    /// secrets in that file". So a key generated at startup and never written —
    /// because the config was read-only, or because
    /// `NEXAPIPE_NO_PERSIST_IDENTITY` said not to — must not make this true.
    /// Folding an ephemeral identity in here would make exactly the deployments
    /// that need one refuse to start over a key that is not on disk.
    ///
    /// The same logic covers a credential that lives outside the file: a key
    /// resolved from the environment or from a `secret_key_file` pointer is
    /// not in *this* file for anyone to read, so it does not make the config a
    /// credential holder — the pointed-to file is held to the `0600` rule in
    /// the config's place, where it is read (see `read_credential_file`).
    pub fn holds_credentials(&self) -> bool {
        self.iroh.as_ref().is_some_and(|iroh| {
            (iroh.secret_key.is_some() && iroh.secret_key_source == CredentialSource::Inline)
                || (iroh.relay_auth_token.is_some()
                    && iroh.relay_auth_token_source == CredentialSource::Inline)
        })
    }

    /// Turns the `[[routes]]` table into the objects the proxy actually routes
    /// with, rejecting anything that cannot work.
    ///
    /// Shared by the startup path and the config watcher: a reload has to build
    /// routes exactly the way a cold start does, or an edit would behave
    /// differently depending on when it was made. An error here is not fatal for
    /// a reload — the caller keeps the routes it already has.
    pub fn build_routes(&self) -> anyhow::Result<Vec<Route>> {
        // Both a cold start and a reload come through this function, so the
        // health check is validated here rather than only at startup: an edit
        // that sets `interval = 0` is as wrong as one written by hand.
        self.validate_health_check()?;
        self.validate_timeouts()?;

        // Refused rather than ignored: silently dropping the key would turn
        // every host it used to forward into a 404, which is a routing change
        // nobody asked for. A reload keeps the routes it already has, so a
        // config that fails here is the one that was never serving anyway.
        if self.default_backend.is_some() {
            anyhow::bail!(
                "default_backend has been removed: a host with no `http` route is answered 404. \
                 Replace it with the catch-all route it always meant — \
                 [[routes]] host_pattern = \"*\", mode = \"http\", backends = [\"<backend>\"]"
            );
        }

        let mut routes = Vec::new();

        for route_config in self.routes.iter().flatten() {
            let strategy = get_strategy(&route_config.strategy);
            let modes = get_route_modes(&route_config.mode, &route_config.modes);
            let path_is_prefix = route_config.path_is_prefix.unwrap_or(true);
            let backends_count = route_config.backends.len();
            let host_pattern = route_config.host_pattern.clone();
            let path_pattern = route_config.path_pattern.clone();
            let label = format!("route {host_pattern}");

            // Refused rather than matched loosely: a wildcard without its dot
            // silently covers hosts that merely end in the same letters, so a
            // config using one is a config that routes more than it says.
            if let Some(why) = crate::routes::host_pattern_error(&host_pattern) {
                anyhow::bail!("{label}: host_pattern {why}");
            }

            // A route with no backends matches and then has nothing to send
            // the request to: `select_backend` answers with an empty string and
            // the client gets a 502 that looks like a backend being down.
            if route_config.backends.is_empty() {
                anyhow::bail!("{label}: has no backends; a route needs at least one to forward to");
            }

            // A port no flow can arrive on, or an empty list that says "every
            // port" by accident: either one is a route that never matches, and
            // the operator has no way to notice — the client just gets refused.
            if let Some(ports) = &route_config.client_ports {
                if ports.is_empty() {
                    anyhow::bail!(
                        "{label}: client_ports is empty; leave it out to match every port"
                    );
                }
                if ports.contains(&0) {
                    anyhow::bail!(
                        "{label}: client_ports contains port 0; no flow ever arrives from \
                         port 0, so that entry can never match"
                    );
                }
            }

            // A UDP flow with a zero idle timeout is closed as soon as it is
            // opened: the tunnel is set up and torn down before the first
            // datagram crosses it. Leave it out for the server default.
            if route_config.idle_timeout_secs == Some(0) {
                anyhow::bail!(
                    "{label}: idle_timeout_secs is 0, which closes a UDP flow the moment it \
                     is opened; leave it out for the default"
                );
            }

            // Same reasoning for the whole-flow bound: zero would close every flow
            // the instant it opened, which is never what a zero here means.
            if route_config.flow_timeout_secs == Some(0) {
                anyhow::bail!(
                    "{label}: flow_timeout_secs is 0, which closes a flow the moment it is \
                     opened; leave it out for the default"
                );
            }

            // Every declared mode has to be able to dial these backends, so each
            // one is checked: the `http` rules and the L4 rules disagree (a URL
            // to fetch versus an address to dial, and only the L4 one insists on
            // a port), and a route serving both has to satisfy both.
            for backend in &route_config.backends {
                for mode in &modes {
                    let label = format!("{label} (mode {mode:?})");
                    validate_backend(&label, *mode, backend)?;
                }
            }

            // Only meaningful for `tcp` / `udp`, where they are harmless defaults
            // otherwise; the other modes never read them.
            let l4_options = L4Options {
                client_ports: route_config.client_ports.clone(),
                idle_timeout: route_config
                    .idle_timeout_secs
                    .map(std::time::Duration::from_secs),
                flow_timeout: route_config
                    .flow_timeout_secs
                    .map(std::time::Duration::from_secs),
            };
            let client_ports = route_config.client_ports.clone();
            let idle_timeout_secs = route_config.idle_timeout_secs;

            routes.push(
                Route::new(
                    &host_pattern,
                    &path_pattern,
                    path_is_prefix,
                    route_config.backends.clone(),
                    strategy,
                    // The first mode only seeds the constructor; `with_modes`
                    // then puts the whole set on the route.
                    modes[0],
                    route_config.path_rewrite.clone(),
                )
                .with_l4_options(l4_options)
                .with_modes(modes.clone()),
            );

            tracing::info!(
                "Loaded route: host={}, path={} (prefix={}), modes={:?}, backends={}, strategy={:?}",
                host_pattern,
                path_pattern,
                path_is_prefix,
                modes,
                backends_count,
                strategy
            );

            if modes.iter().any(|mode| mode.is_l4()) {
                // Worth spelling out: `client_ports` changes which flows match, and a
                // reader who assumed "the port is what gets dialled" would be wrong.
                tracing::info!(
                    "  L4 route {}: client_ports={:?} (absent = every port matches; the port never \
                     decides where the connection goes), idle_timeout_secs={:?}",
                    host_pattern,
                    client_ports,
                    idle_timeout_secs
                );
            }
        }

        Ok(routes)
    }
}

impl ProxyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path);
        tracing::debug!("Loading config from: {}", path.display());

        if !path.exists() {
            return Err(anyhow::anyhow!("Config file not found: {}", path.display()));
        }

        tracing::debug!("Config file exists, reading content");
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;

        tracing::debug!("Config content read successfully, parsing TOML");
        let mut config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
        config.resolve_external_credentials(path.parent())?;

        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }
}

/// The config written when there is none: 2FA on, nothing else.
///
/// Deliberately small, and deliberately **not** a working proxy: it carries no
/// `[[routes]]`, so every host is answered 404 until one is added. A generated
/// backend address would be a guess — `127.0.0.1:3000` is only right by
/// coincidence — and a wrong one fails every request while looking configured.
/// The commented route below is the shape to uncomment.
///
/// `[auth] enabled = true` is the one setting that is not the operator's to
/// infer: a config with no `[auth.clients]` refuses every connection, which is
/// the correct state for a file nobody has written yet. With 2FA on, the
/// startup permission check refuses to start over a world-readable config —
/// `run_server_mode` keys the refusal off `auth_cfg.enabled ||
/// proxy_config.holds_credentials()` — so the file has to be `0600` on Unix,
/// which is why this goes out through [`write_config_file`] rather than
/// `fs::write`.
///
/// No `[iroh] secret_key`: the endpoint identity is generated and written back
/// on first start (see `ensure_iroh_secret_key`), so writing one here would be
/// a second answer to the same question.
const FIRST_RUN_CONFIG: &str = include_str!("../templates/first-run-config.toml");

/// Writes a minimal config at `path` when there is none, and reports whether it
/// did.
///
/// Only `NotFound` leads to a write. A file that exists but cannot be read or
/// parsed is somebody's typo to fix, and generating over it would replace a
/// config they wrote — or, worse, a half-written one — with a default that
/// looks deliberate. So the read still happens in [`ProxyConfig::from_file`],
/// and its error still reaches the operator.
///
/// The create is atomic via `OpenOptions::create_new(true)` (the "create and
/// must-not-exist" check is a single syscall). That matters because the check
/// above and the write below are two steps: an external writer that does not
/// take the config lock — an operator saving in their editor, a sibling tool
/// — could otherwise slip a file in between, and `write_config_file` would
/// rename its temp file over that destination, discarding the operator's
/// routes and credentials. `create_new` makes the second step safe by failing
/// rather than overwriting.
///
/// `create_new` only succeeds when the parent directory already exists, so
/// the parent is created with `fs::create_dir_all` first. That is what
/// makes the docker default path (`<NEXAPIPE_CONFIG_DIR>/config.toml`)
/// work for a fresh start: `docker-compose.yaml` binds the directory the
/// env var names into the container, but a first start that runs before
/// any config has been written would otherwise fail with "no such file or
/// directory" on the lock file `with_config_lock` opens.
///
/// Under the config lock, on principle: the lock no longer *needs* to be
/// taken, because `create_new` is already atomic. Kept for symmetry with the
/// rest of the config writers — it serialises a `ensure_config_file` call
/// with an in-progress 2FA writeback so the new template never lands between
/// the 2FA reader and the 2FA writer.
///
/// Not for every command. `status` reads the config of a process that is
/// already running and `--generate-2fa` works without one, so neither should
/// leave a file behind; this is called from the server start path only.
pub fn ensure_config_file(path: &str) -> anyhow::Result<bool> {
    if Path::new(path).exists() {
        return Ok(false);
    }

    // `with_config_lock` opens `<path>.lock` and that fails when the parent
    // directory does not yet exist, so the directory is created before the
    // lock is taken. The lock file is otherwise useless: every write of this
    // path goes through this function and through the other writers in this
    // crate, all of which take the same lock. Idempotent — running it on a
    // directory that already exists is a no-op.
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", parent.display()))?;
    }

    with_config_lock(path, || {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(path) {
            Ok(mut file) => {
                file.write_all(FIRST_RUN_CONFIG.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path))?;
                file.sync_all()
                    .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", path))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A non-locking writer (operator with an editor, a sibling
                // tool) created the file between our existence check and
                // our create. Preserve whatever they wrote.
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!("cannot create {}: {e}", path)),
        }
    })
}

pub fn get_strategy(strategy: &Option<String>) -> crate::lb::LoadBalancingStrategy {
    match strategy.as_deref() {
        Some("random") | Some("Random") => crate::lb::LoadBalancingStrategy::Random,
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => {
            crate::lb::LoadBalancingStrategy::RoundRobin
        }
        Some("least_conn") | Some("LeastConn") | Some("leastconn") => {
            crate::lb::LoadBalancingStrategy::LeastConn
        }
        // Unrecognised values keep meaning round-robin rather than failing to
        // load, and they say so: a mistyped strategy is otherwise invisible —
        // traffic still flows, just not the way the config claims — and there
        // is nowhere else this could be reported.
        None => crate::lb::LoadBalancingStrategy::RoundRobin,
        Some(other) => {
            tracing::warn!(
                "Unknown load balancing strategy {other:?}; falling back to round_robin \
                 (accepted: \"round_robin\", \"random\", \"least_conn\")"
            );
            crate::lb::LoadBalancingStrategy::RoundRobin
        }
    }
}

pub fn get_route_mode(mode: &Option<String>) -> RouteMode {
    match mode.as_deref() {
        None => RouteMode::Http,
        Some(name) => parse_route_mode(name),
    }
}

/// One mode name, as written in `mode` or in one entry of `modes`.
pub fn parse_route_mode(mode: &str) -> RouteMode {
    match mode {
        "http" | "Http" | "HTTP" => RouteMode::Http,
        "passthrough" | "Passthrough" => RouteMode::Passthrough,
        "tcp" | "Tcp" | "TCP" => RouteMode::Tcp,
        "udp" | "Udp" | "UDP" => RouteMode::Udp,
        other => {
            tracing::warn!("Unknown route mode {:?}, falling back to \"http\"", other);
            RouteMode::Http
        }
    }
}

/// Every mode a route serves: the union of `mode` and `modes`, deduplicated.
///
/// Two keys exist so that the common case stays one line — `modes = ["http", "tcp"]`
/// — while `mode = "tcp"` keeps working. An empty `modes` list is not "serve
/// nothing": it leaves `mode` (or the `http` default) in place, because a route
/// that serves no mode is a silent hole in the table rather than a meaningful
/// configuration.
pub fn get_route_modes(mode: &Option<String>, modes: &Option<Vec<String>>) -> Vec<RouteMode> {
    let mut resolved: Vec<RouteMode> = Vec::new();

    if let Some(single) = mode {
        push_mode(&mut resolved, parse_route_mode(single));
    }
    for name in modes.iter().flatten() {
        push_mode(&mut resolved, parse_route_mode(name));
    }

    if resolved.is_empty() {
        vec![RouteMode::Http]
    } else {
        resolved
    }
}

fn push_mode(resolved: &mut Vec<RouteMode>, mode: RouteMode) {
    if !resolved.contains(&mode) {
        resolved.push(mode);
    }
}

/// Rejects a backend URL that cannot work.
///
/// TLS is terminated by the backend now, so an `https://` backend can only
/// fail: this process would speak plaintext at a TLS port. Saying so at startup
/// beats serving 502s, and either fix is a one-line config change.
pub fn validate_backend(label: &str, mode: RouteMode, backend: &str) -> anyhow::Result<()> {
    // Passthrough only needs a host and a port — the scheme carries no meaning
    // because those bytes are never interpreted — but it still has to name one.
    // Checked with the function the route will dial it with, so what starts is
    // what runs: an address that only fails at connect time turns every
    // connection into a 502 with nothing at startup to explain it.
    if mode == RouteMode::Passthrough {
        return match crate::passthrough::parse_backend_addr(backend) {
            Some((host, port)) if !host.is_empty() && port != 0 => Ok(()),
            _ => anyhow::bail!(
                "{label}: backend \"{backend}\" is not an address a passthrough route can dial; \
                 expected host:port, for example \"10.0.0.5:443\" or \"[::1]:443\""
            ),
        };
    }

    // An L4 backend is an address to dial, not a URL to fetch, so it is checked
    // against different rules than an HTTP one.
    if mode.is_l4() {
        return validate_l4_backend(label, backend);
    }

    let url = url::Url::parse(backend).map_err(|e| {
        anyhow::anyhow!(
            "{label}: backend \"{backend}\" is not a URL ({e}); expected http://host:port"
        )
    })?;

    match url.scheme() {
        "http" => Ok(()),
        scheme => anyhow::bail!(
            "{label}: backend \"{backend}\" uses {scheme}://, but TLS is terminated by the backend \
             now. Point the route at its http:// listener, or set mode = \"passthrough\" to forward \
             the TLS session to it untouched."
        ),
    }
}

/// Rejects an L4 backend that does not name exactly one address.
///
/// Both `host:port` and `scheme://host:port` are accepted — the scheme is ignored,
/// because these bytes are never interpreted as HTTP — but the port is mandatory and a
/// path is refused. An L4 route dials its backend directly, so there is nothing to
/// guess: a bare host would have to default to some port, and every such default is
/// wrong for somebody. Failing at startup beats a tunnel that connects to the wrong
/// service.
fn validate_l4_backend(label: &str, backend: &str) -> anyhow::Result<()> {
    let trimmed = backend.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{label}: backend is empty; expected host:port");
    }

    let (host, port) = if trimmed.contains("://") {
        let url = url::Url::parse(trimmed).map_err(|e| {
            anyhow::anyhow!("{label}: backend \"{backend}\" is not a URL ({e}); expected host:port")
        })?;
        let host = url.host_str().unwrap_or_default().to_string();
        if host.is_empty() {
            anyhow::bail!("{label}: backend \"{backend}\" names no host; expected host:port");
        }
        // A special scheme (`http://`) fills in "/" for an empty path; a non-special one
        // (`tcp://`, `udp://`) leaves it empty. Both mean "no path".
        if !matches!(url.path(), "" | "/") {
            anyhow::bail!(
                "{label}: backend \"{backend}\" has a path, but an L4 route dials an address \
                 rather than fetching a URL; expected {host}:<port>"
            );
        }
        (host, url.port())
    } else {
        match trimmed.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (
                host.to_string(),
                port.parse::<u16>().ok().filter(|port| *port != 0),
            ),
            // A bare host, an IPv6 literal without brackets, or something that is not
            // a port at all.
            _ => (trimmed.to_string(), None),
        }
    };

    match port {
        Some(port) => {
            tracing::debug!("L4 route {label}: dials {host}:{port}");
            Ok(())
        }
        None => anyhow::bail!(
            "{label}: backend \"{backend}\" does not name a port. An L4 route dials its backend \
             directly, so the port cannot be defaulted; write it as {host}:5432"
        ),
    }
}

// ===== 2FA authentication config =====

/// Refuses TOTP parameters the validator cannot honour as written.
///
/// `window` is the one that was quietly wrong: it is handed to the TOTP library
/// as a `u8`, so anything above 255 was truncated by the cast — `window = 300`
/// became 44, which widens a code's validity from ±5 minutes to ±22 minutes,
/// and `window = 256` became 0. The other two only failed later, inside the
/// library, at the first login and with nothing to say which knob was wrong.
fn validate_totp_parameters(time_step: u32, digits: u32, window: u32) -> anyhow::Result<()> {
    if time_step == 0 {
        anyhow::bail!(
            "[auth] time_step is 0: a code would cover no time at all, and the step is what \
             the counter is divided by"
        );
    }
    if !(6..=8).contains(&digits) {
        anyhow::bail!("[auth] digits is {digits}: a code is 6, 7 or 8 digits long");
    }
    if window > u8::MAX as u32 {
        anyhow::bail!(
            "[auth] window is {window}, above the {max} the TOTP library's field holds: larger \
             values were silently truncated, so 300 came out as 44",
            max = u8::MAX
        );
    }
    if window > 10 {
        // Legal, but wide enough to be worth saying out loud: `window` counts
        // steps in *both* directions, so 10 already means a code stays valid
        // for ten minutes either side of now.
        tracing::warn!(
            "[auth] window is {window}: a code stays valid for {} minutes either side of now",
            window * time_step / 60
        );
    }
    Ok(())
}

/// Authentication config in TOML format.
///
/// Unknown keys are refused here, and only here. This is the one section where
/// a typo is a security change rather than a lost setting: `enable = true`
/// instead of `enabled` left 2FA off with nothing in the log to say so, since
/// serde drops what it does not recognise and the default for `enabled` is
/// false. Every other section stays lenient, the way a config that has carried
/// a stray key for years expects.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthTomlConfig {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub algorithm: Option<String>,
    pub time_step: Option<u32>,
    pub digits: Option<u32>,
    pub window: Option<u32>,
    pub max_attempts: Option<u32>,
    pub lockout_duration: Option<u64>,
    pub clients: Option<HashMap<String, ClientAuthToml>>,
}

/// One `[auth.clients.<id>]` entry.
///
/// Unknown keys are refused for the same reason as in [`AuthTomlConfig`]: a
/// misspelled `allow_host` is not "no restriction", but that is what it
/// quietly became.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthToml {
    pub secret: String,
    pub created_at: Option<String>,
    /// Host patterns this client may reach; `None` means every route. Folded
    /// into the client's [`crate::auth::ClientAcl`] when a connection
    /// authenticates.
    pub allow_hosts: Option<Vec<String>>,
    /// A one-time enrollment token outstanding for this client, written by
    /// `--generate-invite --registration` and cleared by whoever spends it. Not
    /// written back by `save_auth_state`: it belongs to the operator, not to
    /// the runtime.
    pub pending_enrollment: Option<String>,
    /// `[auth.clients.<id>.devices.<name>]` — credentials issued to individual
    /// devices, each with a secret of its own so one can be dropped without
    /// rotating the others. Absent means this client has never issued one, and
    /// every device then shares the `secret` above.
    pub devices: Option<HashMap<String, DeviceAuthToml>>,
    /// Whether a peer that names no device may still answer with the `secret`
    /// above. Defaults to `true`, which is the only spelling a client that
    /// predates the device table can authenticate under.
    pub unnamed_device_allowed: Option<bool>,
    /// Runtime counters written back by the server (see
    /// `config_watcher::save_auth_state`); read here so a lockout survives a
    /// restart.
    pub failed_attempts: Option<u32>,
    pub locked_until: Option<u64>,
    pub last_used: Option<u64>,
}

/// One `[auth.clients.<id>.devices.<name>]` entry.
///
/// Unknown keys are refused for the same reason as in [`ClientAuthToml`]. There
/// is no `allow_hosts` here on purpose: what a client may reach is answered by
/// the client's entry alone, and a second place to say it is a second place for
/// it to disagree.
///
/// One of `secret` and `public_key` has to be set and the other has to not be,
/// which the loader enforces where the operator can see which entry it is
/// about; both fields are `Option` so that either spelling parses far enough to
/// be told what is wrong with it.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthToml {
    pub secret: Option<String>,
    /// The device's Ed25519 public key, hex: the credential of a device that
    /// signs its handshake instead of answering with a TOTP code.
    pub public_key: Option<String>,
    pub created_at: Option<String>,
    /// Written back by the server, read here, so "when did this device last
    /// connect" survives a restart.
    pub last_used: Option<u64>,
}

/// Checks a credential sidecar file's permissions before its secret becomes
/// live.
///
/// These files hold one secret and nothing else — the endpoint key a
/// `secret_key_file` / `NEXAPIPE_IROH_SECRET_KEY_FILE` points at, a relay
/// token file, or the admin IPC token — so there is no "nothing live in it
/// yet" half-way case, as the old config-file gate had: a file another
/// account can read or write is refused outright. `config.toml` itself is deliberately no
/// longer checked: operator-edited bind mounts are commonly 0644, and the
/// credentials now belong in a sidecar like this one or in the environment.
/// A file that cannot be stat'ed is not this function's problem: the caller
/// has already read it to get here.
#[cfg(unix)]
pub fn check_credential_file_permissions(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{path} is readable or writable by other accounts (mode {mode:o}) and holds a \
             credential; run `chmod 600 {path}`"
        );
    }
    Ok(())
}

/// No file modes to inspect outside Unix, so there is nothing to refuse.
#[cfg(not(unix))]
pub fn check_credential_file_permissions(_path: &str) -> anyhow::Result<()> {
    Ok(())
}

impl ProxyConfig {
    /// Load config and extract auth settings from TOML
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<crate::auth::AuthConfig>)> {
        let content = std::fs::read_to_string(path)?;

        // Parse the base config
        let mut base: Self = toml::from_str(&content)?;
        base.resolve_external_credentials(Path::new(path).parent())?;

        // Try to parse auth section separately
        // Note `toml::from_str`, not `str::parse`: `Value::from_str` reads a
        // single TOML *value*, so it rejects a whole document with "unexpected
        // content, expected nothing" and silently leaves 2FA disabled.
        let auth_config = match toml::from_str::<toml::Value>(&content) {
            Ok(toml_value) => {
                if let Some(auth_section) = toml_value.get("auth") {
                    let auth_toml: AuthTomlConfig = auth_section
                        .clone()
                        .try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to parse auth config: {}", e))?;

                    let mut clients = HashMap::new();
                    if let Some(clients_toml) = auth_toml.clients {
                        for (id, client_toml) in clients_toml {
                            // An empty token compares equal to an empty
                            // ENROLL_START — see `conn::enroll_client` — so
                            // `pending_enrollment = ""` would hand a fresh
                            // secret to anybody who asks. Refused at load time
                            // rather than read as "no enrollment outstanding":
                            // the way to close an enrollment is to delete the
                            // key, and a blank one is a typo with a wide door
                            // behind it.
                            if client_toml.pending_enrollment.as_deref() == Some("") {
                                anyhow::bail!(
                                    "[auth.clients.{id}]: pending_enrollment is empty; delete the \
                                     key instead of setting it to \"\""
                                );
                            }
                            // An allow-hosts entry is a host pattern, and a
                            // loose one authorizes more than it names: the same
                            // refusal a route's `host_pattern` gets.
                            for host in client_toml.allow_hosts.iter().flatten() {
                                if let Some(why) = crate::routes::host_pattern_error(host) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}]: allow_hosts entry {host:?} {why}"
                                    );
                                }
                            }
                            // A name in this table is a credential's whole
                            // identity: it is what the device sends, what the
                            // log line for every outcome carries, and what an
                            // operator names when revoking one. An empty one
                            // is not a name — the unnamed device is what the
                            // client's own `secret` is for.
                            //
                            // The two fields that follow are one credential
                            // spelled two ways — a TOTP seed the device shares
                            // with the server, or the public half of a key pair
                            // it keeps the other half of — and a device answers
                            // with exactly one of them. Both, or neither, is a
                            // config that does not say how the device proves
                            // itself, refused here where the operator can see
                            // which entry it is.
                            let mut devices = HashMap::new();
                            for (device_id, device_toml) in client_toml.devices.unwrap_or_default()
                            {
                                if device_id.is_empty() {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices]: a device needs a name; a \
                                         client's own `secret` is the credential of the device \
                                         that has none"
                                    );
                                }
                                if !crate::auth::is_presentable_device_id(&device_id) {
                                    anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: a device name is \
                                         printable ASCII of at most {} characters — it is written \
                                         into the log line for everything that happens to it",
                                        crate::auth::MAX_DEVICE_ID_LEN
                                    );
                                }
                                // `secret = ""` is read as no secret at all:
                                // an empty one is not a credential, and an
                                // entry left holding only that is refused
                                // below like one that has nothing.
                                let secret = device_toml.secret.filter(|s| !s.is_empty());
                                match (&secret, &device_toml.public_key) {
                                    (None, None) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: no `secret` and \
                                         no `public_key`; a device answers with one of the two, \
                                         and an empty secret is not one"
                                    ),
                                    (Some(_), Some(_)) => anyhow::bail!(
                                        "[auth.clients.{id}.devices.{device_id}]: both a `secret` \
                                         and a `public_key`; a device answers with one \
                                         credential, and two are two answers to disagree about"
                                    ),
                                    (None, Some(public_key)) => {
                                        // Checked where the key would otherwise
                                        // first be used: at a handshake, where
                                        // a bad key and a wrong one are the
                                        // same refusal.
                                        if let Err(why) = crate::auth::parse_public_key(public_key)
                                        {
                                            anyhow::bail!(
                                                "[auth.clients.{id}.devices.{device_id}]: {why}"
                                            );
                                        }
                                    }
                                    (Some(_), None) => {}
                                }
                                devices.insert(
                                    device_id,
                                    crate::auth::DeviceAuth {
                                        secret: secret.unwrap_or_default(),
                                        public_key: device_toml.public_key,
                                        created_at: device_toml.created_at.unwrap_or_else(
                                            crate::auth::config::default_created_at,
                                        ),
                                        last_used: device_toml.last_used,
                                    },
                                );
                            }
                            clients.insert(
                                id,
                                crate::auth::ClientAuth {
                                    secret: client_toml.secret,
                                    created_at: client_toml
                                        .created_at
                                        .unwrap_or_else(crate::auth::config::default_created_at),
                                    allow_hosts: client_toml.allow_hosts,
                                    pending_enrollment: client_toml.pending_enrollment,
                                    devices,
                                    unnamed_device_allowed: client_toml
                                        .unnamed_device_allowed
                                        .unwrap_or(true),
                                    last_used: client_toml.last_used,
                                    failed_attempts: client_toml.failed_attempts.unwrap_or(0),
                                    locked_until: client_toml.locked_until,
                                },
                            );
                        }
                    }

                    let algorithm = match auth_toml.algorithm.as_deref() {
                        Some("sha256") | Some("SHA256") => crate::auth::TotpAlgorithm::SHA256,
                        Some("sha512") | Some("SHA512") => crate::auth::TotpAlgorithm::SHA512,
                        _ => crate::auth::TotpAlgorithm::SHA1,
                    };

                    let time_step = auth_toml.time_step.unwrap_or(30);
                    let digits = auth_toml.digits.unwrap_or(6);
                    let window = auth_toml.window.unwrap_or(1);
                    validate_totp_parameters(time_step, digits, window)?;

                    Some(crate::auth::AuthConfig {
                        enabled: auth_toml.enabled.unwrap_or(false),
                        issuer: auth_toml
                            .issuer
                            .unwrap_or_else(|| crate::auth::DEFAULT_ISSUER.to_string()),
                        algorithm,
                        time_step,
                        digits,
                        window,
                        clients,
                        max_attempts: auth_toml.max_attempts.unwrap_or(5),
                        lockout_duration: auth_toml.lockout_duration.unwrap_or(300),
                    })
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        Ok((base, auth_config))
    }

    /// Writes `secret` under `[auth.clients.<client_id>]` of the config file at
    /// `path`, creating `[auth]` and `[auth.clients]` when they are missing.
    ///
    /// The document is edited as TOML instead of being re-serialized from a
    /// `ProxyConfig`, so comments, key order and the layout of every other
    /// section survive — which is the whole point, this edits the file a human
    /// wrote. `force` is what allows an existing secret to be replaced: a device
    /// that already imported the old one stops authenticating the instant it
    /// changes, so callers keep the existing secret unless told otherwise.
    ///
    /// `[auth] enabled` is deliberately left alone: flipping it on would turn
    /// 2FA on for every client, not just the one being enrolled.
    pub fn write_client_secret(
        path: &str,
        client_id: &str,
        secret: &str,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        with_config_lock(path, || {
            Self::write_client_secret_unlocked(path, client_id, secret, force)
        })
    }

    fn write_client_secret_unlocked(
        path: &str,
        client_id: &str,
        secret: &str,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, secret not written ({e})"))?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        let replaced = client.contains_key("secret");
        if replaced && !force {
            anyhow::bail!("client \"{client_id}\" already has a secret in {path}");
        }
        client.insert("secret", toml_edit::value(secret));

        write_config_file(path, &doc.to_string())?;

        Ok(if replaced {
            ClientSecretWrite::Replaced
        } else {
            ClientSecretWrite::Added
        })
    }

    /// Records a one-time enrollment token for `client_id`.
    ///
    /// Any token already outstanding is replaced, which is how an invitation
    /// that never arrived gets revoked: generate another one and the old link
    /// stops working. The client's secret is left alone — enrollment does not
    /// touch it until a token is actually spent.
    ///
    /// The client has to exist: a `[auth.clients.<id>]` section with a token and
    /// no secret would fail to load.
    pub fn write_pending_enrollment(
        path: &str,
        client_id: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::write_pending_enrollment_unlocked(path, client_id, token)
        })
    }

    fn write_pending_enrollment_unlocked(
        path: &str,
        client_id: &str,
        token: &str,
    ) -> anyhow::Result<()> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, token not written ({e})"))?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;
        if !client.contains_key("secret") {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {path}; \
                 run --generate-2fa {client_id} first"
            );
        }

        client.insert("pending_enrollment", toml_edit::value(token));

        write_config_file(path, &doc.to_string())
    }

    /// Spends the token: writes the issued `secret` and drops
    /// `pending_enrollment`, so the same link cannot enroll twice.
    ///
    /// Both keys are written in one pass on purpose. A secret on disk with the
    /// token still beside it would leave the window open for a second device to
    /// trade the same link for the same credential.
    pub fn complete_enrollment(path: &str, client_id: &str, secret: &str) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::complete_enrollment_unlocked(path, client_id, secret)
        })
    }

    fn complete_enrollment_unlocked(
        path: &str,
        client_id: &str,
        secret: &str,
    ) -> anyhow::Result<()> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, enrollment not saved ({e})"))?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        client.insert("secret", toml_edit::value(secret));
        client.remove("pending_enrollment");

        write_config_file(path, &doc.to_string())
    }

    /// Spends the token for one named device: writes that device's own
    /// credential into `[auth.clients.<id>.devices.<name>]` and drops
    /// `pending_enrollment`, leaving the client's `secret` as it was.
    ///
    /// The material is whichever the enrollment turned on: a secret the server
    /// generated, or the public key the device offered in ENROLL_START.
    ///
    /// The client's secret is deliberately untouched. It is the credential of
    /// the device that has no name — every device that enrolled before this
    /// table existed — so rotating it is what re-enrolls all of them at once,
    /// and an enrollment that names a device is the one case where that is
    /// known not to be what was asked for. [`Self::complete_enrollment`] is
    /// still the answer for an enrollment that names none, and still rotates it.
    ///
    /// Both keys move in one pass, for the reason given there: a secret on disk
    /// with the token still beside it would leave the window open for a second
    /// device to trade the same link for the same credential.
    ///
    /// The entry lands where [`Self::write_device_credential`] puts one: both
    /// writers go through [`device_table`] and [`device_entry`], so a device
    /// that spent a token and one an operator wrote by hand are the same shape
    /// on disk.
    pub fn complete_device_enrollment(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
    ) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::complete_device_enrollment_unlocked(path, client_id, device, material)
        })
    }

    fn complete_device_enrollment_unlocked(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
    ) -> anyhow::Result<()> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, enrollment not saved ({e})"))?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;

        let devices = device_table(client, client_id, path)?;
        devices.insert(device, device_entry(material, path)?);

        client.remove("pending_enrollment");

        write_config_file(path, &doc.to_string())
    }

    /// Writes one device's credential — a TOTP secret or a public key — under
    /// `[auth.clients.<client_id>.devices.<device>]`, which is what gives one
    /// device of a client a credential of its own.
    ///
    /// The client's own `secret` is deliberately left alone: it is the
    /// credential of the device that names none, so rotating it re-enrolls
    /// every unnamed device at once, and issuing one device a credential of its
    /// own is exactly the case where that is known not to be what was asked
    /// for.
    ///
    /// `force` is what allows an existing device to be issued another one, for
    /// the reason [`Self::write_client_secret`] needs it: a device already
    /// using the old credential stops authenticating the moment it changes.
    /// Replacing one kind with the other has to go through `force` the same
    /// way — a device that answered with a code and now answers with a
    /// signature is as enrolled-out as one whose secret changed.
    ///
    /// What it writes is the entry [`Self::complete_device_enrollment`] writes
    /// when a device spends a token — one shape on disk, reached the same way.
    /// The two differ only in what has to be true first: an enrollment has a
    /// token to spend, and this has an operator, who has to say `--force`
    /// before an existing credential is replaced.
    ///
    /// The client has to be there first — a device table under a client with no
    /// secret of its own is a config that will not load.
    pub fn write_device_credential(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        with_config_lock(path, || {
            Self::write_device_credential_unlocked(path, client_id, device, material, force)
        })
    }

    fn write_device_credential_unlocked(
        path: &str,
        client_id: &str,
        device: &str,
        material: crate::auth::DeviceMaterial<'_>,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        // The name becomes a key in this file and the subject of every log line
        // about the device, so it is checked here rather than on its way into
        // either. An empty one is not a name: the unnamed device is what the
        // client's own `secret` is for.
        if !crate::auth::is_presentable_device_id(device) {
            anyhow::bail!(
                "device name {device:?} is printable ASCII of at most {} characters — it is a key \
                 in {path} and the subject of every log line about it",
                crate::auth::MAX_DEVICE_ID_LEN
            );
        }

        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, secret not written ({e})"))?;

        let auth = sub_table(doc.as_table_mut(), "auth", path)?;
        let clients = sub_table(auth, "clients", path)?;
        let client = sub_table(clients, client_id, path)?;
        if !client.contains_key("secret") {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {path}; \
                 run --generate-2fa {client_id} first"
            );
        }

        let devices = device_table(client, client_id, path)?;
        let replaced = devices.contains_key(device);
        if replaced && !force {
            anyhow::bail!(
                "device \"{device}\" of client \"{client_id}\" already has a credential in {path}"
            );
        }

        devices.insert(device, device_entry(material, path)?);

        write_config_file(path, &doc.to_string())?;

        Ok(if replaced {
            ClientSecretWrite::Replaced
        } else {
            ClientSecretWrite::Added
        })
    }
    /// Drops one device's credential: `[auth.clients.<client_id>.devices.<device>]`.
    ///
    /// Revoking is a delete and not a rotation, because a deleted entry is the
    /// one thing the handshake reads as "this device has no credential" — the
    /// same answer a device that never enrolled gets, so what happened cannot be
    /// told apart from outside. The client's own `secret` is left alone: it
    /// belongs to the device that names none, and a client with one is not
    /// revoked by dropping a device that named itself.
    pub fn remove_device(path: &str, client_id: &str, device: &str) -> anyhow::Result<()> {
        with_config_lock(path, || {
            Self::remove_device_unlocked(path, client_id, device)
        })
    }

    fn remove_device_unlocked(path: &str, client_id: &str, device: &str) -> anyhow::Result<()> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, nothing revoked ({e})"))?;

        // Not `sub_table`: revoking must never create the thing it is about to
        // delete, and an absent section is the operator naming something that
        // is not there, which is worth saying.
        let clients = auth_clients(doc.as_table_mut());
        let Some(clients) = clients else {
            anyhow::bail!("{path} has no [auth.clients] table, nothing revoked");
        };
        let Some(client) = clients
            .get_mut(client_id)
            .and_then(|item| item.as_table_like_mut())
        else {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] section in {path}, \
                 nothing revoked"
            );
        };
        let Some(devices) = client
            .get_mut("devices")
            .and_then(|item| item.as_table_like_mut())
        else {
            anyhow::bail!("client \"{client_id}\" has no devices in {path}, nothing revoked");
        };
        if devices.remove(device).is_none() {
            anyhow::bail!(
                "client \"{client_id}\" has no device \"{device}\" in {path}; its devices are {}",
                device_names(devices)
            );
        }

        write_config_file(path, &doc.to_string())
    }

    /// Drops a client and every device under it: all of
    /// `[auth.clients.<client_id>]`.
    pub fn remove_client(path: &str, client_id: &str) -> anyhow::Result<()> {
        with_config_lock(path, || Self::remove_client_unlocked(path, client_id))
    }

    fn remove_client_unlocked(path: &str, client_id: &str) -> anyhow::Result<()> {
        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, nothing revoked ({e})"))?;

        let clients = auth_clients(doc.as_table_mut());
        let Some(clients) = clients else {
            anyhow::bail!("{path} has no [auth.clients] table, nothing revoked");
        };
        if clients.remove(client_id).is_none() {
            anyhow::bail!(
                "client \"{client_id}\" has no [auth.clients.{client_id}] section in {path}, \
                 nothing revoked"
            );
        }

        write_config_file(path, &doc.to_string())
    }
}

/// The `[auth.clients]` table of `doc`, when the document has one.
///
/// Shared by the two revoking writers, which must find the table without ever
/// creating it: a revoke that invented an empty `[auth.clients]` to delete from
/// would leave the file changed while reporting that nothing was revoked.
fn auth_clients(doc: &mut toml_edit::Table) -> Option<&mut dyn toml_edit::TableLike> {
    doc.get_mut("auth")
        .and_then(|item| item.as_table_like_mut())
        .and_then(|auth| auth.get_mut("clients"))
        .and_then(|item| item.as_table_like_mut())
}

/// The names of the devices in `devices`, for the message a revoke leaves
/// behind when it is asked for one that is not there.
fn device_names(devices: &dyn toml_edit::TableLike) -> String {
    let mut names: Vec<&str> = devices.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    if names.is_empty() {
        return "none".to_string();
    }
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `[auth.clients.<client_id>.devices]` as a table, created when it is missing.
///
/// Where a device's credential goes, for both of the writers that put one
/// there: the enrollment that spends a token, and the operator CLI behind
/// [`ProxyConfig::write_device_credential`]. One table either way, so a device
/// that enrolled and one that was handed a credential by hand are the same
/// shape on disk, and the handshake does not have to know which of the two it
/// is.
///
/// Not `sub_table`, which makes an implicit table: a device added under one
/// would be written as `devices.laptop = { … }` on a line of the client's own
/// section, and a table that says what it holds reads better than a dotted key
/// that does not.
fn device_table<'a>(
    client: &'a mut dyn toml_edit::TableLike,
    client_id: &str,
    path: &str,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match client.entry("devices") {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            entry.insert(toml_edit::Item::Table(toml_edit::Table::new()))
        }
    };
    item.as_table_like_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "{path}: [auth.clients.{client_id}.devices] is not a table, the device secret was \
             not written"
        )
    })
}

/// The entry a device's credential is stored as: whichever of the two it is —
/// `secret` or `public_key` — and when it was issued, which is the one thing
/// the file says about a device besides its name.
///
/// Inline rather than a sub-table of its own, because the table it goes into
/// may itself be an inline one an operator wrote, and a sub-table cannot be
/// put inside one.
///
/// The material is checked here rather than written as handed over: the loader
/// refuses an empty secret (it would key this device's HMAC with nothing) and a
/// public key that is not a key, so an unchecked write would hand back success
/// while leaving a config that cannot be read again. A key is written in the
/// canonical spelling — lowercase hex — whatever case it arrived in.
fn device_entry(
    material: crate::auth::DeviceMaterial<'_>,
    path: &str,
) -> anyhow::Result<toml_edit::Item> {
    let mut entry = toml_edit::InlineTable::new();
    match material {
        crate::auth::DeviceMaterial::Secret(secret) => {
            if secret.is_empty() {
                anyhow::bail!(
                    "{path}: a device secret cannot be empty; an empty one keys this device's \
                     HMAC with nothing and leaves a config that cannot be loaded"
                );
            }
            entry.insert("secret", toml_edit::Value::from(secret));
        }
        crate::auth::DeviceMaterial::PublicKey(public_key) => {
            let key = crate::auth::parse_public_key(public_key)
                .map_err(|why| anyhow::anyhow!("{path}: {why}"))?;
            entry.insert(
                "public_key",
                toml_edit::Value::from(crate::auth::public_key_hex(&key)),
            );
        }
    }
    entry.insert(
        "created_at",
        toml_edit::Value::from(crate::auth::config::default_created_at()),
    );
    Ok(toml_edit::value(entry))
}

/// Runs `work` while holding an exclusive lock on the config file at `path`.
///
/// Every read-modify-write of the config goes through this. `write_config_file`
/// makes a single write atomic, but it says nothing about two writers that both
/// read first: the second one's write is built from the contents it read before
/// the first one landed, so one of the two edits is lost. The three callers are
/// in this binary — a CLI command, the enrollment flow and the 2FA counter
/// writeback — and any two of them can coincide.
///
/// The lock is advisory: a writer that does not take it still races. That is
/// acceptable, because every writer of this file is this program.
pub fn with_config_lock<T>(
    path: &str,
    work: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = ConfigLock::acquire(path)?;
    work()
}

/// The lock file sits *beside* the config rather than being the config itself.
///
/// Writes go through [`write_config_file`], which is a temp file and a rename,
/// and a rename swaps the directory entry for a different inode — so a lock
/// taken on the config path would stay behind on a file that was replaced
/// underneath it, and every writer would hold a different lock. A separate file
/// is never renamed, so it stays the one thing everybody contends for.
struct ConfigLock {
    file: fs::File,
}

impl ConfigLock {
    fn acquire(path: &str) -> anyhow::Result<Self> {
        let lock_path = format!("{path}.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            // The lock file is a lock, not a document: whatever it already
            // holds is nobody's data, and truncating a file another process may
            // be about to open buys nothing.
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("cannot open {lock_path}: {e}"))?;

        // Beside a file that holds TOTP secrets, so it is created the way the
        // config itself is checked for: private to its owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("cannot set the mode of {lock_path}: {e}"))?;
        }

        // `File::lock`, standard since 1.89: `flock(2)` on Unix and
        // `LockFileEx` on Windows, which is the pair writing by hand would have
        // meant two `unsafe` blocks to reach.
        file.lock()
            .map_err(|e| anyhow::anyhow!("cannot lock {lock_path}: {e}"))?;
        Ok(Self { file })
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Released on close regardless; unlocking explicitly keeps the pairing
        // visible, and the error has nowhere to go from a `Drop`.
        let _ = self.file.unlock();
    }
}

/// Replaces the file at `path` with `contents` in one step.
///
/// Written next to the target and renamed over it, rather than truncated in
/// place: a process killed in the middle of `fs::write` leaves a short file,
/// and a short config is one the proxy cannot start from again. A rename is a
/// single directory entry swap, so anything reading the file sees either the
/// old contents or the new ones.
///
/// The replacement is created `0600`, because what it holds is TOTP secrets and
/// enrollment tokens: a new file takes the umask, and the file it replaces was
/// checked at startup for being private.
///
/// The mode is part of the call that creates the file, not a `chmod` after the
/// write. Tightening it afterwards leaves the secrets on disk at `0644` for as
/// long as the write takes, and `write_all` plus `sync_all` make sure they
/// really are on disk in that window — the server refuses to *start* on a
/// world-readable config, so handing one to every local account for the length
/// of a write contradicts the check that exists to prevent it.
pub fn write_config_file(path: &str, contents: &str) -> anyhow::Result<()> {
    let target = Path::new(path);
    let directory = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    // The pid alone was not enough to keep two writers apart: pids are reused,
    // and a pid that comes back while an older temp file of the same name is
    // still there would have the new write truncate a file it did not create.
    // The random half makes the name this process's own regardless.
    let temp = directory.join(format!(
        ".{name}.{}.{:x}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));

    let write = || -> anyhow::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", temp.display()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", temp.display()))?;
        Ok(())
    };

    if let Err(e) = write() {
        let _ = fs::remove_file(&temp);
        return Err(e);
    }

    // Renaming over a symlink puts a regular file where the link was: the
    // indirection an operator set up is gone, the file the link pointed at keeps
    // its old contents, and every command involved still reports success. A
    // config reached through a link is a normal way to keep one file in version
    // control or out of a container image, so the rename is aimed at what the
    // link resolves to instead — the real file is replaced and the link stays.
    //
    // `Path::join` with an absolute path yields that path, so a link pointing
    // outside this directory needs no special case; a relative one resolves
    // against the directory holding the link, which is what the shell does.
    let destination = match fs::read_link(target) {
        Ok(resolved) => directory.join(resolved),
        Err(_) => target.to_path_buf(),
    };

    // A rename cannot replace a file that is itself a mount point, which is
    // what a bind-mounted single config file is. Falling back to writing in
    // place is the lesser evil: it loses the atomicity, not the write.
    if let Err(rename) = fs::rename(&temp, &destination) {
        let _ = fs::remove_file(&temp);

        // Writing in place keeps whatever mode the target already has, so the
        // mode is tightened *before* anything is written: a target that is
        // world-readable would otherwise hold the secrets that way for as long
        // as the write leaves it. A mode that cannot be set is an error rather
        // than something to log past — a config of secrets at 0644 is worse
        // than one that was not written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if target.exists() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("cannot set the mode of {path}: {e}"))?;
            }
        }

        let written = fs::write(target, contents)
            .map_err(|e| anyhow::anyhow!("cannot write {path}: {e} (rename failed: {rename})"));

        // Covers a target that did not exist: the write above creates it under
        // the process umask, which is not what a file of secrets should inherit.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if written.is_ok() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("cannot set the mode of {path}: {e}"))?;
            }
        }

        return written;
    }

    Ok(())
}

/// What [`ProxyConfig::ensure_iroh_secret_key`] resolved the endpoint's
/// identity to.
#[derive(Clone, PartialEq, Eq)]
pub enum EndpointIdentity {
    /// `[iroh] secret_key` was already set and parses. Nothing was written.
    Configured(String),
    /// No `secret_key` was configured and one was generated and written to the
    /// config file. The Node ID is stable from this restart on.
    Generated(String),
    /// No `secret_key` was configured, and persisting one was either turned off
    /// by `NEXAPIPE_NO_PERSIST_IDENTITY` or not possible (a read-only mount, a
    /// config owned by another user). The server runs on the returned key, and
    /// the Node ID will be different after the next restart.
    Ephemeral(String),
}

/// Handwritten, and never `derive(Debug)`, for the reason
/// [`IrohConfig`]'s is: every variant here *is* the ed25519 private key.
///
/// The derive is a loaded gun. This enum reaches a `{:?}` on the failure path
/// of a test, where CI collects the output and keeps it — and a real key
/// printed there is the endpoint's identity in a log anyone with read access to
/// the build can lift. A failure would hand over exactly the thing the caller
/// was told is private. The variant is enough to debug with: which of the three
/// paths produced this is the question a reader actually has.
impl std::fmt::Debug for EndpointIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (variant, key) = match self {
            Self::Configured(key) => ("Configured", key),
            Self::Generated(key) => ("Generated", key),
            Self::Ephemeral(key) => ("Ephemeral", key),
        };
        f.debug_struct("EndpointIdentity")
            .field("variant", &variant)
            .field("key", &redacted(&Some(key.clone())))
            .finish()
    }
}

impl EndpointIdentity {
    /// The hex key the endpoint should run on, whichever way it was arrived at.
    pub fn key(&self) -> &str {
        match self {
            Self::Configured(key) | Self::Generated(key) | Self::Ephemeral(key) => key,
        }
    }
}

/// Set to any value other than empty, `0` or `false` (for example `1`) to keep
/// `[iroh] secret_key` out of the config file.
///
/// Empty does **not** disable persistence: a compose file that lists a variable
/// without a value (`- NEXAPIPE_NO_PERSIST_IDENTITY`) is asking for the default,
/// not for the behaviour. `persistence_disabled` is where that rule lives.
///
/// The one deployment this exists for: a throwaway container or a test harness
/// that wants a clean identity on every run, and would rather not have the file
/// silently gain a private key. Everywhere else it is the wrong setting — the
/// Node ID changing on every restart is what makes clients lose track of the
/// server.
const NO_PERSIST_ENV: &str = "NEXAPIPE_NO_PERSIST_IDENTITY";

/// Whether the operator asked for the identity *not* to be written to disk.
///
/// Read from the environment rather than from the config on purpose: the
/// decision is about whether this process may touch that file, so it has to be
/// answerable when the file cannot be read at all, and an env var is what a
/// systemd unit or a compose file can set without editing a config the server
/// may not even have permission to write.
fn persist_identity_disabled() -> bool {
    persistence_disabled(std::env::var(NO_PERSIST_ENV).ok().as_deref())
}

/// The rule [`persist_identity_disabled`] applies, as a function of the value.
///
/// `unset`, empty and `0` all mean "no": a compose file that lists a variable
/// without a value (`- NEXAPIPE_NO_PERSIST_IDENTITY`) is asking for the default,
/// not for the behaviour being switched on. Everything else means yes, so an
/// operator who writes `NEXAPIPE_NO_PERSIST_IDENTITY=yes` gets what they meant.
///
/// Split out from the `env::var` call because `set_var` is `unsafe` in Rust
/// 2024 and the parsing is the part worth testing.
fn persistence_disabled(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(value) => {
            let value = value.trim();
            !(value.is_empty() || value == "0" || value.eq_ignore_ascii_case("false"))
        }
    }
}

impl ProxyConfig {
    /// Resolves the endpoint's identity for this run, generating and persisting
    /// one when the config has none.
    ///
    /// Refuses a `secret_key` that does not parse. The old behaviour was a
    /// warning and a throwaway key, which left the endpoint on a different
    /// Node ID after every restart while looking like a config problem rather
    /// than one — a typo is a typo, and the fix is to delete the line (which
    /// brings this function back) or paste a real `--generate-secret` output.
    ///
    /// A write that fails is *not* fatal. A config on a read-only mount, or one
    /// the server's user cannot write, is a normal deployment: refusing to
    /// start there would be strictly worse than the fresh-Node-ID behaviour
    /// this replaced. The key is generated either way, the warning says the
    /// Node ID will not survive a restart, and the server comes up.
    ///
    /// A `secret_key_file` the load found missing is generated into, rather
    /// than written around: the key belongs in the pointed-to file — writing it
    /// back into the config would undo the deployment's whole reason for the
    /// pointer. The same not-fatal rule covers it.
    ///
    /// Takes the already-parsed `config` rather than re-reading `path`: the
    /// caller is about to run on exactly that value, and a second read could
    /// disagree with it if the file changed in between.
    pub fn ensure_iroh_secret_key(
        path: &str,
        config: &ProxyConfig,
    ) -> anyhow::Result<EndpointIdentity> {
        let configured = config
            .iroh
            .as_ref()
            .and_then(|iroh| iroh.secret_key.clone());

        if let Some(configured) = configured {
            configured.parse::<iroh::SecretKey>().map_err(|e| {
                anyhow::anyhow!(
                    "[iroh] secret_key in {path} is not a valid key ({e}): the Node ID would \
                     change on every restart and every client would lose the server. Delete the \
                     line to have a working one generated, or run --generate-secret and paste its \
                     output"
                )
            })?;
            return Ok(EndpointIdentity::Configured(configured));
        }

        // A pointed-to key file that does not exist yet. Reached only when the
        // load resolved no key from it, which is exactly the first-start case:
        // a file that exists but is broken was refused during the load.
        if let Some(file) = config
            .iroh
            .as_ref()
            .and_then(|iroh| iroh.secret_key_file.as_deref())
        {
            let full = credential_file_path(Path::new(path).parent(), file);
            if persist_identity_disabled() {
                tracing::warn!(
                    "{NO_PERSIST_ENV} is set: no secret key is written to {}, so the Node ID \
                     will be different after every restart",
                    full.display()
                );
                return Ok(EndpointIdentity::Ephemeral(generate_secret_key_hex()));
            }
            return match write_key_file(&full) {
                Ok(hex) => {
                    tracing::info!(
                        "Generated an endpoint identity and saved it to {}; the Node ID is now \
                         stable across restarts",
                        full.display()
                    );
                    Ok(EndpointIdentity::Generated(hex))
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not write an endpoint identity to {} ({e:#}); starting on a \
                         throwaway one, so the Node ID will be different after the next restart",
                        full.display()
                    );
                    Ok(EndpointIdentity::Ephemeral(generate_secret_key_hex()))
                }
            };
        }

        if persist_identity_disabled() {
            tracing::warn!(
                "{NO_PERSIST_ENV} is set: [iroh] secret_key is not written to {path}, so the Node \
                 ID will be different after every restart"
            );
            return Ok(EndpointIdentity::Ephemeral(generate_secret_key_hex()));
        }

        match ProxyConfig::write_iroh_secret_key(path) {
            Ok(hex) => {
                tracing::info!(
                    "Generated an endpoint identity and saved it to {path} as [iroh] secret_key; \
                     the Node ID is now stable across restarts"
                );
                Ok(EndpointIdentity::Generated(hex))
            }
            Err(e) => {
                tracing::warn!(
                    "Could not write an endpoint identity to {path} ({e:#}); starting on a \
                     throwaway one, so the Node ID will be different after the next restart"
                );
                Ok(EndpointIdentity::Ephemeral(generate_secret_key_hex()))
            }
        }
    }
}

/// A fresh ed25519 key as the hex `config.toml` stores it in.
///
/// Shared by `--generate-secret` and the startup path so both spell a key the
/// same way: a hex string that round-trips through `SecretKey::from_str` is the
/// only thing either of them promises.
pub fn generate_secret_key_hex() -> String {
    hex::encode(iroh::SecretKey::generate().to_bytes())
}

/// The environment variable carrying `[iroh] secret_key` directly.
///
/// For a deployment that keeps credentials out of the config file entirely. It
/// outranks a pointed-to file and the inline literal — and a config that names
/// more than one source is refused rather than ranked (see
/// `refuse_ambiguous_credential_sources`), because a silently-picked winner is
/// how an endpoint ends up on a Node ID nobody expected.
const IROH_SECRET_KEY_ENV: &str = "NEXAPIPE_IROH_SECRET_KEY";

/// The environment variable carrying the *path* of the file holding
/// `[iroh] secret_key`.
///
/// The file-pointing twin of [`IROH_SECRET_KEY_ENV`], for a deployment (the
/// docker compose setup is one) that keeps the key in a file of its own
/// choosing — a mounted secrets directory — rather than next to the config.
/// Unlike a relative `secret_key_file` in the config, this path is taken
/// literally (anchored on the working directory if relative), because
/// environment wiring speaks in process paths, not config-relative ones.
const IROH_SECRET_KEY_FILE_ENV: &str = "NEXAPIPE_IROH_SECRET_KEY_FILE";

/// The environment variable carrying `[iroh] relay_auth_token` directly.
const RELAY_AUTH_TOKEN_ENV: &str = "NEXAPIPE_RELAY_AUTH_TOKEN";

/// The raw value of an environment credential, when the variable is set.
///
/// Whether the value counts — a blank or whitespace-only one means "not
/// named", the same rule `NEXAPIPE_NO_PERSIST_IDENTITY` follows — is decided
/// where the sources are ranked, in [`resolve_secret_key_source`] and
/// [`resolve_relay_auth_token_source`], so the ranking is testable without
/// touching process state.
fn credential_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Whether any environment variable names an `[iroh]` credential.
///
/// Blank or whitespace-only values count as unset, the same rule the value
/// variables follow in the resolver. Used to decide whether a config that has
/// no `[iroh]` table at all needs one materialised in memory before the
/// external sources can be resolved.
fn environment_names_iroh_credential() -> bool {
    let named = |name: &str| {
        credential_env(name)
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    };
    named(IROH_SECRET_KEY_ENV) || named(IROH_SECRET_KEY_FILE_ENV) || named(RELAY_AUTH_TOKEN_ENV)
}

/// Refuses a `[iroh]` credential that more than one source names.
///
/// One credential, one answer. Any ranking would leave the deployment's
/// behaviour turning on which of the two the operator last touched — for the
/// endpoint key that is a Node ID rotating underneath every client that stored
/// it — so a config that says two things is refused instead of adjudicated.
fn refuse_ambiguous_credential_sources(what: &str, sources: &[Option<&str>]) -> anyhow::Result<()> {
    let named: Vec<&str> = sources.iter().flatten().copied().collect();
    if named.len() > 1 {
        anyhow::bail!(
            "[iroh] {what} is named by {} — one credential, one source; keep exactly one of them",
            named.join(", ")
        );
    }
    Ok(())
}

/// Turns an environment-named file path into an absolute one.
///
/// A config `secret_key_file` is read against the config's directory (see
/// [`credential_file_path`]); an environment path is deployment wiring, so it
/// is taken literally and only a relative one gets anchored, on the process's
/// working directory.
fn absolute_env_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

/// The path a `*_file` key names, relative paths against the config file's
/// directory.
///
/// Anchoring on the config rather than the working directory is what makes a
/// sibling file (`secret_key_file = "iroh.key"`) mean the same thing no matter
/// where the server is started from — the same reading
/// `config.toml.admin-token` gets.
fn credential_file_path(config_dir: Option<&Path>, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    config_dir.unwrap_or(Path::new(".")).join(path)
}

/// Reads the file a `*_file` credential names.
///
/// `None` when the file does not exist — the caller decides whether that is a
/// first start (a secret key is generated into the file) or a broken config (a
/// relay token cannot be invented). An empty file is refused rather than read
/// as "no credential": the pointer was spelled, and pointing it at a blank file
/// is a typo to see, not a mode.
///
/// Held to the credential-file permission rule
/// (`check_credential_file_permissions`): this file *is* the credential now,
/// so one another account can read or write refuses the load.
fn read_credential_file(full: &Path, what: &str) -> anyhow::Result<Option<String>> {
    let content = match fs::read_to_string(full) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!("cannot read the {what} file {}: {e}", full.display()),
    };
    let content = content.trim();
    if content.is_empty() {
        anyhow::bail!(
            "{}: the {what} file holds nothing; write the credential into it and nothing else",
            full.display()
        );
    }
    check_credential_file_permissions(&full.to_string_lossy())?;
    Ok(Some(content.to_string()))
}

/// Resolves `[iroh] secret_key` from its candidate sources: the environment
/// value, the environment-named file, the file `secret_key_file` names, then
/// the literal.
///
/// `env_raw` and `env_file` are passed in rather than read here so the ranking
/// is testable without touching process state; the caller hands them over from
/// [`credential_env`], with `env_file` already made absolute by
/// [`absolute_env_path`]. `Ok(None)` means nothing named a key — including a
/// pointed-to file that does not exist yet, which is the first-start case
/// [`ProxyConfig::ensure_iroh_secret_key`] generates into. The caller folds an
/// environment-named missing path onto the `secret_key_file` field so the
/// generation lands in the file the environment named, not back in the config.
fn resolve_secret_key_source(
    config_dir: Option<&Path>,
    env_raw: Option<String>,
    env_file: Option<&Path>,
    iroh: &IrohConfig,
) -> anyhow::Result<Option<(String, CredentialSource)>> {
    // A trailing newline from `printf`, or a compose file that lists the
    // variable without a value, must neither become key bytes nor count as a
    // source: trim, and a leftover blank means the environment named nothing.
    let env = env_raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    refuse_ambiguous_credential_sources(
        "secret_key",
        &[
            env.map(|_| IROH_SECRET_KEY_ENV),
            env_file.map(|_| IROH_SECRET_KEY_FILE_ENV),
            iroh.secret_key_file.as_deref().map(|_| "secret_key_file"),
            iroh.secret_key.as_deref().map(|_| "secret_key"),
        ],
    )?;

    if let Some(key) = env {
        return Ok(Some((key.to_string(), CredentialSource::Env)));
    }
    // An environment-named file outranks the config's pointer: both are files,
    // but deployment wiring wins over what the file on disk says.
    if let Some(full) = env_file.map(Path::to_path_buf).or_else(|| {
        iroh.secret_key_file
            .as_ref()
            .map(|file| credential_file_path(config_dir, file))
    }) {
        return match read_credential_file(&full, "secret_key")? {
            Some(key) => Ok(Some((key, CredentialSource::File))),
            None => Ok(None),
        };
    }
    Ok(iroh
        .secret_key
        .clone()
        .map(|key| (key, CredentialSource::Inline)))
}

/// Resolves `[iroh] relay_auth_token` from its candidate sources, in the same
/// order [`resolve_secret_key_source`] ranks them.
///
/// Unlike a secret key, a pointed-to token file that does not exist is refused
/// rather than deferred: the server cannot invent a relay token, and a missing
/// one would otherwise surface later as a vaguer relay-configuration error.
fn resolve_relay_auth_token_source(
    config_dir: Option<&Path>,
    env_raw: Option<String>,
    iroh: &IrohConfig,
) -> anyhow::Result<Option<(String, CredentialSource)>> {
    // The same blank-means-nothing reading the secret key gives the
    // environment.
    let env = env_raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    refuse_ambiguous_credential_sources(
        "relay_auth_token",
        &[
            env.map(|_| RELAY_AUTH_TOKEN_ENV),
            iroh.relay_auth_token_file
                .as_deref()
                .map(|_| "relay_auth_token_file"),
            iroh.relay_auth_token.as_deref().map(|_| "relay_auth_token"),
        ],
    )?;

    if let Some(token) = env {
        return Ok(Some((token.to_string(), CredentialSource::Env)));
    }
    if let Some(file) = &iroh.relay_auth_token_file {
        let full = credential_file_path(config_dir, file);
        return match read_credential_file(&full, "relay_auth_token")? {
            Some(token) => Ok(Some((token, CredentialSource::File))),
            None => anyhow::bail!(
                "[iroh] relay_auth_token_file {} does not exist; unlike a secret key, a relay \
                 token cannot be generated, so write the token into the file first",
                full.display()
            ),
        };
    }
    Ok(iroh
        .relay_auth_token
        .clone()
        .map(|token| (token, CredentialSource::Inline)))
}

impl ProxyConfig {
    /// Resolves the `[iroh]` credentials that name a source outside this file.
    ///
    /// Both parse paths come through here — `from_file` for the server and the
    /// config watcher, `load_with_auth` for the 2FA-facing commands and the
    /// auth reload — so a credential is resolved the same way however the
    /// config was read. The resolved value replaces the field, and the
    /// [`CredentialSource`] it came from is recorded next to it: what
    /// [`ProxyConfig::holds_credentials`] then asks is not "is there a key"
    /// but "is the key in *this file*", which is what the permission gate is
    /// about.
    fn resolve_external_credentials(&mut self, config_dir: Option<&Path>) -> anyhow::Result<()> {
        // A config with no `[iroh]` table at all still has to honour
        // credentials wired through the environment: the docker compose setup
        // points NEXAPIPE_IROH_SECRET_KEY_FILE at a secrets directory against
        // exactly such a file — the generated first-run template has no
        // `[iroh]` table. Skipping resolution here used to let the key fall
        // through to the inline write-back into config.toml, and the watcher's
        // next reload then refused it as two sources naming one key.
        // Materialise an empty table in memory only — resolution never writes
        // the config — and resolve as usual.
        if self.iroh.is_none() && environment_names_iroh_credential() {
            self.iroh = Some(IrohConfig::default());
        }

        let Some(iroh) = self.iroh.as_mut() else {
            return Ok(());
        };

        // Blank means unset, the same rule the value env vars get; made
        // absolute here because environment paths are not config-relative.
        let env_key_file = credential_env(IROH_SECRET_KEY_FILE_ENV)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| absolute_env_path(Path::new(&value)));

        match resolve_secret_key_source(
            config_dir,
            credential_env(IROH_SECRET_KEY_ENV),
            env_key_file.as_deref(),
            iroh,
        )? {
            Some((key, source)) => {
                iroh.secret_key = Some(key);
                iroh.secret_key_source = source;
            }
            None => {
                // Nothing resolved. If the environment named a file that does
                // not exist yet, fold its path onto the pointer field: the
                // first-start generation in ensure_iroh_secret_key then writes
                // the key there rather than inline back into this config.
                if let Some(env_file) = env_key_file {
                    iroh.secret_key_file = Some(env_file.to_string_lossy().into_owned());
                }
            }
        }
        if let Some((token, source)) =
            resolve_relay_auth_token_source(config_dir, credential_env(RELAY_AUTH_TOKEN_ENV), iroh)?
        {
            iroh.relay_auth_token = Some(token);
            iroh.relay_auth_token_source = source;
        }
        Ok(())
    }
}

/// Writes a freshly generated key to the file `secret_key_file` names, or
/// reads back the one that is already there.
///
/// `create_new` first rather than checking then writing: the load saw no file,
/// and one appearing in between holds the credential now — replacing it would
/// rotate the identity underneath whoever read it in that window. The same
/// read-back on a lost race `config.toml.admin-token` does.
fn write_key_file(path: &Path) -> anyhow::Result<String> {
    let key = iroh::SecretKey::generate();
    let hex = hex::encode(key.to_bytes());
    match create_private_file(path) {
        Ok(mut file) => {
            // sync_all, not flush: for a regular file flush is nearly a no-op,
            // and a crash between write and durability could leave a truncated
            // key on disk that the next start refuses with "holds nothing".
            // A failed write removes the file too — otherwise this one failure
            // would leave an empty file behind that makes every later start
            // refuse instead of regenerating. The handle must be dropped first
            // so the remove works on Windows as well.
            if let Err(e) = file.write_all(hex.as_bytes()).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(path);
                anyhow::bail!("cannot write {}: {e}", path.display());
            }
            Ok(hex)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!(
                    "{} appeared while the key was being generated, and reading it back \
                     failed: {e}",
                    path.display()
                )
            })?;
            let existing = existing.trim();
            if existing.is_empty() {
                anyhow::bail!("{} appeared and holds nothing", path.display());
            }
            // The winner of the race wrote the file, not us, so hold it to the
            // same permission rule a normal load applies: a 0644 key a sibling
            // account dropped in is refused the same way it would be on reload.
            check_credential_file_permissions(&path.to_string_lossy())?;
            Ok(existing.to_string())
        }
        Err(e) => Err(e).map_err(|e| anyhow::anyhow!("cannot create {}: {e}", path.display())),
    }
}

/// Creates a new file only this account can read.
///
/// The mode is set at creation rather than chmod'ed after: between the two the
/// file exists with the default mode, and a credential is worth less than a
/// second of that. `mode` is applied against the umask, so the bits are set
/// again and confirmed — the same care `admin::token::create_private` takes.
#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// No file modes to set outside Unix, so the file is created as it comes.
#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

impl ProxyConfig {
    /// Writes a freshly generated `secret_key` into `[iroh]` of the config file
    /// at `path`, and returns the hex key now in it.
    ///
    /// The whole point of this function is that a Node ID nobody had to write
    /// down is still stable: an operator who skipped `--generate-secret` used
    /// to get a fresh one on every restart, and every client that had stored it
    /// lost the server. Generating the key here rather than in the endpoint
    /// builder is what makes it survive, because the builder's key is never
    /// written anywhere.
    ///
    /// Only ever called when `[iroh] secret_key` is *absent*. A key that is
    /// present but does not parse is refused at startup rather than replaced
    /// here: it is a typo the operator has to see, and silently replacing it
    /// would swap the endpoint's identity underneath whatever the typo was
    /// supposed to be — including a key that was merely truncated past the
    /// end of the line.
    ///
    /// Comments, key order and every other section survive: the document is
    /// edited as TOML rather than re-serialized from a `ProxyConfig`, which
    /// would drop the operator's prose along with the config.
    pub fn write_iroh_secret_key(path: &str) -> anyhow::Result<String> {
        with_config_lock(path, || Self::write_iroh_secret_key_unlocked(path))
    }

    fn write_iroh_secret_key_unlocked(path: &str) -> anyhow::Result<String> {
        let key = iroh::SecretKey::generate();
        let hex = hex::encode(key.to_bytes());

        let content =
            fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut doc: toml_edit::DocumentMut = content.parse().map_err(|e| {
            anyhow::anyhow!("{path} is not valid TOML, secret_key not written ({e})")
        })?;

        // `sub_table` rather than `entry("iroh")`: a config with no `[iroh]` at
        // all should gain the one key, not a header and a key.
        let iroh_table = sub_table(doc.as_table_mut(), "iroh", path).map_err(|_| {
            anyhow::anyhow!("{path}: [iroh] is not a table, secret_key not written")
        })?;
        iroh_table.insert("secret_key", toml_edit::value(hex.as_str()));

        write_config_file(path, &doc.to_string())?;

        Ok(hex)
    }
}

/// What [`ProxyConfig::write_client_secret`] did to the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSecretWrite {
    /// A `[auth.clients.<id>]` section was added, creating `[auth]` if needed.
    Added,
    /// The client already had a secret, and it was replaced.
    Replaced,
}

/// `parent[key]` as a table, creating it when it is missing.
///
/// A table created here is implicit: it is left out of the output while it holds
/// nothing of its own, so a config with no `[auth]` at all gains the one leaf
/// section instead of two empty headers above it.
fn sub_table<'a>(
    parent: &'a mut dyn toml_edit::TableLike,
    key: &str,
    path: &str,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match parent.entry(key) {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            entry.insert(toml_edit::Item::Table(table))
        }
    };
    item.as_table_like_mut()
        .ok_or_else(|| anyhow::anyhow!("{path}: [{key}] is not a table, secret not written"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DeviceMaterial;

    fn parse(source: &str) -> ProxyConfig {
        toml::from_str(source).expect("config should parse")
    }

    /// Writes `source` to a throwaway file and loads it the way a start does.
    ///
    /// `load_with_auth` takes a path rather than a string — it is also what
    /// checks the file's permissions — so parsing a snippet needs a real file.
    fn load_from(source: &str) -> anyhow::Result<(ProxyConfig, Option<crate::auth::AuthConfig>)> {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, source).expect("write the config");
        ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
    }

    /// `build_routes` is what both a cold start and a config reload use, so a
    /// route that would work after a restart must also work without one — and a
    /// broken one must be *reported*, not silently dropped.
    #[test]
    fn build_routes_is_what_a_restart_would_have_built() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "passthrough"
backends = ["host.docker.internal:8443"]

[[routes]]
host_pattern = "fn.iakl.top"
mode = "tcp"
backends = ["host.docker.internal:8443"]
client_ports = [443]

[[routes]]
host_pattern = "mt.iroh.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let routes = config.build_routes().expect("the config is valid");
        assert_eq!(routes.len(), 3);

        // The two entries for one host do not collapse into each other: same
        // host, different mode, and the L4 one kept its port selector.
        assert_eq!(routes[0].modes(), &[RouteMode::Passthrough][..]);
        assert_eq!(routes[1].modes(), &[RouteMode::Tcp][..]);
        assert!(routes[1].matches_l4("fn.iakl.top", 443));
        assert!(!routes[1].matches_l4("fn.iakl.top", 8443));
        assert_eq!(routes[2].modes(), &[RouteMode::Http][..]);

        // No `default_backend` at all: the key is gone, and building routes
        // must not require one.
        assert!(config.default_backend.is_none());
    }

    /// A config that still names `default_backend` is refused, not ignored.
    ///
    /// The key is still parsed, because serde drops what the struct does not
    /// name: without this the config would keep starting and every host the
    /// fallback used to serve would quietly become a 404.
    #[test]
    fn build_routes_refuses_the_removed_default_backend() {
        let config = parse(
            r#"
default_backend = "http://10.0.0.5:8080"

[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let error = config.build_routes().unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("default_backend has been removed"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("host_pattern = \"*\""),
            "the error must say what to write instead: {message}"
        );
    }

    #[test]
    fn build_routes_rejects_a_backend_that_cannot_work() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["https://caddy:443"]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("https://"),
            "the message has to name the offending backend, got: {error}"
        );
    }

    /// `0` was clamped with `max(1)` on the way in, which is how a typo turned
    /// into a probe storm, or into every backend being taken out of rotation.
    #[test]
    fn build_routes_refuses_a_zero_health_check_number() {
        for (key, why) in [
            ("interval", "interval is 0"),
            ("timeout", "timeout is 0"),
            ("threshold", "threshold is 0"),
        ] {
            let config = parse(&format!(
                r#"
[health_check]
{key} = 0

[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#
            ));

            let error = config.build_routes().unwrap_err().to_string();
            assert!(error.contains(why), "{key}: unexpected error: {error}");
        }
    }

    #[test]
    fn build_routes_accepts_the_health_check_defaults() {
        // Nothing in the file: the defaults have to pass the same check.
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
        );
        assert!(config.build_routes().is_ok());
    }

    /// Port 0 is not a port a flow arrives from, so a route naming it is dead
    /// the moment it loads — and nothing would ever say so.
    #[test]
    fn build_routes_refuses_a_client_port_no_flow_can_arrive_on() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "db.iakl.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
client_ports = [0]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(error.contains("port 0"), "unexpected error: {error}");
    }

    #[test]
    fn build_routes_refuses_an_empty_client_ports_list() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "db.iakl.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
client_ports = []
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("client_ports is empty"),
            "unexpected error: {error}"
        );
    }

    /// A zero idle timeout closes a UDP flow as soon as it is opened.
    #[test]
    fn build_routes_refuses_a_zero_idle_timeout() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "turn.iakl.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
idle_timeout_secs = 0
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("idle_timeout_secs"),
            "unexpected error: {error}"
        );
    }

    /// A zero flow timeout closes a flow as soon as it is opened, which is what
    /// a zero here would actually do — so it is refused rather than accepted.
    #[test]
    fn build_routes_refuses_a_zero_flow_timeout() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "tcp"
backends = ["10.0.0.5:5432"]
flow_timeout_secs = 0
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("flow_timeout_secs"),
            "unexpected error: {error}"
        );
    }

    /// The two bounds are independent: naming one does not disturb the other,
    /// and leaving both out is what a config written before either existed does.
    #[test]
    fn the_flow_and_idle_timeouts_are_carried_separately() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
idle_timeout_secs = 120
flow_timeout_secs = 7200
"#,
        );
        let routes = config.build_routes().unwrap();
        assert_eq!(
            routes[0].idle_timeout(),
            Some(std::time::Duration::from_secs(120))
        );
        assert_eq!(
            routes[0].flow_timeout(),
            Some(std::time::Duration::from_secs(7200))
        );

        let bare = parse(
            r#"
[[routes]]
host_pattern = "db.nekblab.top"
mode = "udp"
backends = ["10.0.0.5:3478"]
"#,
        );
        let routes = bare.build_routes().unwrap();
        assert!(routes[0].idle_timeout().is_none());
        assert!(
            routes[0].flow_timeout().is_none(),
            "an absent key means the server default, not zero"
        );
    }

    #[test]
    fn build_routes_rejects_a_passthrough_backend_with_no_address() {
        // Passthrough copies bytes, so its backend was never checked at all:
        // this one dials nothing and only failed once a connection arrived.
        let config = parse(
            r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "passthrough"
backends = [""]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("passthrough"),
            "the message has to say which route cannot dial it, got: {error}"
        );
    }

    #[test]
    fn build_routes_accepts_an_ipv6_passthrough_backend() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "passthrough"
backends = ["[::1]:443"]
"#,
        );

        config
            .build_routes()
            .expect("an IPv6 literal is an address a passthrough route can dial");
    }

    #[test]
    fn build_routes_rejects_a_route_with_no_backends() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "app.iakl.top"
mode = "http"
backends = []
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("no backends"),
            "the message has to say what is missing, got: {error}"
        );
    }

    /// The point of the whole section: writing nothing under it has to mean "the
    /// deadlines this server already had", not "wait forever" and not any other
    /// number.
    #[test]
    fn no_timeouts_section_keeps_the_deadlines_it_replaced() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let timeouts = config.timeouts();
        assert_eq!(timeouts.connect, std::time::Duration::from_secs(10));
        assert_eq!(timeouts.response, std::time::Duration::from_secs(30));
    }

    #[test]
    fn a_partial_timeouts_section_leaves_the_rest_alone() {
        let config = parse(
            r#"
[timeouts]
response_secs = 120

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        config
            .build_routes()
            .expect("configuring one deadline is not an error");
        let timeouts = config.timeouts();
        assert_eq!(
            timeouts.response,
            std::time::Duration::from_secs(120),
            "the one that was written"
        );
        assert_eq!(
            timeouts.connect,
            std::time::Duration::from_secs(10),
            "the one that was not"
        );
    }

    /// A zero timeout is not a stricter timeout: it is one no backend can meet,
    /// so every request fails — and it fails looking like every backend is down.
    #[test]
    fn build_routes_rejects_a_zero_timeout() {
        let config = parse(
            r#"
[timeouts]
connect_secs = 0

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("connect_secs is 0"),
            "the message has to name the key nobody can meet, got: {error}"
        );
    }

    /// Past the ceiling a timeout stops describing a slow backend and starts
    /// describing a request that never finishes, which is what it exists to
    /// prevent.
    #[test]
    fn build_routes_rejects_a_timeout_that_never_expires() {
        let config = parse(
            r#"
[timeouts]
response_secs = 86400

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("86400s"),
            "the message has to quote the number it refused, got: {error}"
        );
    }

    /// The per-phase budgets resolve into `Timeouts::deadlines` beside the dial
    /// deadlines, each key answering for its own phase and the rest staying at
    /// their defaults.
    #[test]
    fn a_phase_deadline_override_reaches_the_deadlines() {
        let config = parse(
            r#"
[timeouts]
body_secs = 60
l4_flow_secs = 7200

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        config
            .build_routes()
            .expect("raising a phase deadline is not an error");
        let deadlines = config.timeouts().deadlines;
        assert_eq!(
            deadlines.body,
            std::time::Duration::from_secs(60),
            "the one that was written"
        );
        assert_eq!(
            deadlines.l4_flow,
            std::time::Duration::from_secs(7200),
            "raising an L4 flow past its one-hour default is the documented reason the key exists"
        );
        assert_eq!(
            deadlines.header,
            std::time::Duration::from_secs(crate::deadline::DEFAULT_HEADER_SECS),
            "the one that was not written"
        );
        assert_eq!(
            deadlines.response_idle,
            std::time::Duration::from_secs(crate::deadline::DEFAULT_RESPONSE_IDLE_SECS)
        );
    }

    /// Zero is refused on the phase budgets for the reason it is refused on the
    /// dial ones, with a different reading: here it does not fail every request,
    /// it closes every flow the instant it opens.
    #[test]
    fn build_routes_rejects_a_zero_phase_deadline() {
        let config = parse(
            r#"
[timeouts]
header_secs = 0

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );

        let error = config.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("header_secs is 0"),
            "the message has to name the key nobody can meet, got: {error}"
        );
    }

    /// The phase budgets take their ceiling from `crate::deadline` (a day), not
    /// from the dial keys (an hour): a long-lived tunnel is exactly the case
    /// `l4_flow_secs` exists to be raised for, so a day must be accepted here
    /// where `response_secs = 86400` is refused.
    #[test]
    fn a_phase_deadline_may_reach_a_day_but_no_further() {
        let ok = parse(
            r#"
[timeouts]
l4_flow_secs = 86400

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );
        ok.build_routes()
            .expect("a day is the ceiling the deadline module itself enforces");

        let over = parse(
            r#"
[timeouts]
l4_flow_secs = 86401

[[routes]]
host_pattern = "app.iakl.top"
backends = ["http://10.0.0.5:8080"]
"#,
        );
        let error = over.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("86401s"),
            "the message has to quote the number it refused, got: {error}"
        );
    }

    #[test]
    fn least_conn_is_a_strategy_a_config_can_ask_for() {
        assert!(matches!(
            get_strategy(&Some("least_conn".to_string())),
            crate::lb::LoadBalancingStrategy::LeastConn
        ));
        assert!(matches!(
            get_strategy(&Some("LeastConn".to_string())),
            crate::lb::LoadBalancingStrategy::LeastConn
        ));
        // A typo is not one of them, and it must not silently become a strategy
        // that ignores load either.
        assert!(matches!(
            get_strategy(&Some("least_conns".to_string())),
            crate::lb::LoadBalancingStrategy::RoundRobin
        ));
    }

    #[test]
    fn route_mode_defaults_to_http() {
        assert_eq!(get_route_mode(&None), RouteMode::Http);
        assert_eq!(get_route_mode(&Some("http".to_string())), RouteMode::Http);
        assert_eq!(
            get_route_mode(&Some("passthrough".to_string())),
            RouteMode::Passthrough
        );
        // A typo warns and stays on http: better a plain route than one that
        // silently accepts bytes it cannot serve.
        assert_eq!(
            get_route_mode(&Some("pass-through".to_string())),
            RouteMode::Http
        );
    }

    #[test]
    fn l4_route_modes_are_recognised() {
        assert_eq!(get_route_mode(&Some("tcp".to_string())), RouteMode::Tcp);
        assert_eq!(get_route_mode(&Some("UDP".to_string())), RouteMode::Udp);
        assert!(RouteMode::Tcp.is_l4());
        assert!(RouteMode::Udp.is_l4());
        assert!(!RouteMode::Http.is_l4());
        assert!(!RouteMode::Passthrough.is_l4());

        // The preface protocol is the only thing that picks between the two.
        assert_eq!(
            RouteMode::from_l4_proto(nexapipe_proto::L4Proto::Tcp),
            RouteMode::Tcp
        );
        assert_eq!(
            RouteMode::from_l4_proto(nexapipe_proto::L4Proto::Udp),
            RouteMode::Udp
        );
    }

    /// One route, several modes: the whole reason `modes` exists is that a host
    /// which answers a request and a tunnel with the same backend used to need
    /// two entries, and forgetting the second one failed at runtime instead of
    /// at startup.
    #[test]
    fn one_route_may_serve_several_modes() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
"#,
        );

        let routes = config.build_routes().expect("the config is valid");
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].modes(),
            &[RouteMode::Http, RouteMode::Tcp][..],
            "one entry, both modes, in the order they were written"
        );
        // `client_ports` and `path_pattern` are mode-specific knobs living on the
        // same entry; only the L4 lookups read the former.
        assert!(routes[0].matches_l4("fn.iroh.iakl.top", 80));
        assert!(routes[0].matches("fn.iroh.iakl.top", "/anything"));
    }

    /// `mode` and `modes` together are the union, and duplicates collapse.
    #[test]
    fn mode_and_modes_are_merged_and_deduplicated() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "http"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal:15666"]
"#,
        );

        let routes = config.build_routes().expect("the config is valid");
        assert_eq!(routes[0].modes(), &[RouteMode::Http, RouteMode::Tcp][..]);

        // An empty list means "no extra modes", not "no modes at all".
        let config = parse(
            r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = []
backends = ["http://host.docker.internal:15666"]
"#,
        );
        let routes = config.build_routes().expect("the config is valid");
        assert_eq!(routes[0].modes(), &[RouteMode::Http][..]);
    }

    /// The price of sharing one `backends` list: an address has to satisfy every
    /// mode, and the L4 rules are the stricter ones.
    #[test]
    fn a_route_serving_tcp_needs_a_port_on_its_backend() {
        // `http://host` is a perfectly good HTTP backend — 80 is implied — but an
        // L4 route dials an address and has no port to fall back on.
        let valid = parse(
            r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "http"
backends = ["http://host.docker.internal"]
"#,
        );
        assert!(valid.build_routes().is_ok(), "http alone may omit the port");

        let merged = parse(
            r#"
[[routes]]
host_pattern = "fn.iroh.iakl.top"
modes = ["http", "tcp"]
backends = ["http://host.docker.internal"]
"#,
        );
        let error = merged.build_routes().unwrap_err().to_string();
        assert!(
            error.contains("does not name a port"),
            "adding tcp has to be rejected at startup, got: {error}"
        );
    }

    #[test]
    fn parses_a_tcp_route_with_its_l4_keys() {
        let config = parse(
            r#"

[[routes]]
host_pattern = "db.iroh.iakl.top"
mode = "tcp"
backends = ["10.0.0.50:5432"]
client_ports = [5432, 6432]
idle_timeout_secs = 120
"#,
        );

        let routes = config.routes.as_ref().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(get_route_mode(&routes[0].mode), RouteMode::Tcp);
        assert_eq!(routes[0].path_pattern, "/");
        assert_eq!(
            routes[0].client_ports.as_deref(),
            Some(&[5432u16, 6432][..])
        );
        assert_eq!(routes[0].idle_timeout_secs, Some(120));

        // A udp route without the optional keys still parses, with the defaults.
        let config = parse(
            r#"

[[routes]]
host_pattern = "turn.iroh.iakl.top"
mode = "udp"
backends = ["udp://10.0.0.60:3478"]
"#,
        );
        let routes = config.routes.as_ref().unwrap();
        assert_eq!(get_route_mode(&routes[0].mode), RouteMode::Udp);
        assert!(routes[0].client_ports.is_none());
        assert!(routes[0].idle_timeout_secs.is_none());
        assert!(validate_backend("route turn", RouteMode::Udp, &routes[0].backends[0]).is_ok());
    }

    #[test]
    fn l4_backends_must_name_exactly_one_address() {
        // Both spellings are fine: the scheme is ignored, because an L4 route dials an
        // address rather than fetching a URL.
        for backend in [
            "10.0.0.50:5432",
            "tcp://10.0.0.50:5432",
            "udp://turn.internal:3478",
            "[::1]:5432",
        ] {
            assert!(
                validate_backend("route l4", RouteMode::Tcp, backend).is_ok(),
                "{backend} should be accepted"
            );
        }

        // No port: there is no correct default to fall back on.
        for backend in [
            "10.0.0.50",
            "db.internal",
            "http://10.0.0.50",
            "tcp://10.0.0.50",
            ":5432",
            "10.0.0.50:0",
            "10.0.0.50:notaport",
            "",
        ] {
            assert!(
                validate_backend("route l4", RouteMode::Tcp, backend).is_err(),
                "{backend} should be refused"
            );
        }

        // A path is meaningless: L4 copies bytes, it does not fetch anything.
        assert!(validate_backend("route l4", RouteMode::Tcp, "http://10.0.0.50:5432/x").is_err());
    }

    #[test]
    fn parses_a_passthrough_route_without_a_path() {
        let config = parse(
            r#"

[[routes]]
host_pattern = "fn.iroh.iakl.top"
mode = "passthrough"
backends = ["caddy:443"]
"#,
        );

        let routes = config.routes.as_ref().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(get_route_mode(&routes[0].mode), RouteMode::Passthrough);
        // `path_pattern` is required by the struct but meaningless here, so it
        // defaults rather than having to be written out.
        assert_eq!(routes[0].path_pattern, "/");
        assert_eq!(routes[0].backends, vec!["caddy:443".to_string()]);
    }

    #[test]
    fn accepts_a_config_written_for_the_old_tls_layout() {
        // These keys were removed when TLS moved to the backend. An existing
        // config.toml must still load — `warn_removed_tls_keys` is what tells
        // the operator — rather than failing to start.
        let config = parse(
            r#"

[server]
listen_addr = "0.0.0.0:8080"
tls_enabled = true
cert_path = "/certs/a.crt"
key_path = "/certs/a.key"

[[routes]]
host_pattern = "fn.iroh.iakl.top"
path_pattern = "/"
backends = ["https://backend.example.com"]
cert_path = "/certs/a.crt"
redirect_to_https = true

[acme]
enabled = true
domains = ["fn.iroh.iakl.top"]
"#,
        );

        assert!(config.acme.is_some());
        assert!(config.server.as_ref().unwrap().tls_enabled.unwrap_or(false));
        let route = &config.routes.as_ref().unwrap()[0];
        assert!(route.redirect_to_https.unwrap_or(false));
        assert!(route.cert_path.is_some());
        // Parsing it is not the same as honouring it: the https backend is
        // refused, with a message that says what to do instead.
        assert!(validate_backend("route fn", RouteMode::Http, &route.backends[0]).is_err());
    }

    #[test]
    fn http_backends_must_be_plain_http() {
        assert!(validate_backend("route a", RouteMode::Http, "http://10.0.0.5:8080").is_ok());
        assert!(validate_backend("route a", RouteMode::Http, "https://example.com").is_err());
        assert!(validate_backend("route a", RouteMode::Http, "10.0.0.5:8080").is_err());

        // Passthrough never interprets the bytes, so the scheme is not its
        // business — a TLS target is conventionally written either way.
        assert!(validate_backend("route b", RouteMode::Passthrough, "caddy:443").is_ok());
        assert!(validate_backend("route b", RouteMode::Passthrough, "https://caddy:443").is_ok());
    }

    /// A config file in a scratch directory, for the functions that write.
    fn scratch_config(source: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, source).expect("write scratch config");
        (dir, path.to_string_lossy().into_owned())
    }

    /// A client with a secret of its own and a token outstanding, which is the
    /// state an enrollment invitation leaves behind.
    fn scratch_client_with_token() -> (tempfile::TempDir, String) {
        scratch_config(
            r#"
[auth]
enabled = true

[auth.clients.alice]
secret = "CLIENTSECRET"
pending_enrollment = "TOKEN"
"#,
        )
    }

    /// Enrolling a device writes that device's own entry and leaves the
    /// client's `secret` alone: the two are different credentials, and
    /// rotating the shared one is what re-enrolls every device at once.
    ///
    /// Read back through the loader rather than by looking at the text, because
    /// what matters is not where the entry lands in the file but that a restart
    /// sees the device and verifies it against its own secret.
    #[test]
    fn enrolling_a_device_writes_its_entry_and_leaves_the_clients_secret() {
        let (_dir, path) = scratch_client_with_token();

        ProxyConfig::complete_device_enrollment(
            &path,
            "alice",
            "laptop",
            DeviceMaterial::Secret("LAPTOPSECRET"),
        )
        .expect("the device enrollment is saved");

        let on_disk = fs::read_to_string(&path).expect("read the config back");
        assert!(
            !on_disk.contains("pending_enrollment"),
            "the token was left spendable: {on_disk}"
        );

        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config still loads");
        let auth = auth.expect("auth is enabled");
        let alice = &auth.clients["alice"];
        assert_eq!(alice.secret, "CLIENTSECRET", "the shared secret rotated");
        assert_eq!(alice.devices["laptop"].secret, "LAPTOPSECRET");
        assert!(
            !alice.devices["laptop"].created_at.is_empty(),
            "a device with no issued-at looks never issued"
        );
    }

    /// Revoking a device strikes one entry out of `devices` and leaves the
    /// client's own `secret` standing, so while that secret is still a
    /// credential, a peer that simply omits the device name goes on
    /// authenticating with it. `unnamed_device_allowed = false` is what takes
    /// it away, and it has to survive the loader — a flag the file carries but
    /// the server ignores would be worse than none at all.
    #[test]
    fn a_client_can_stop_answering_devices_that_name_themselves_not_at_all() {
        let source = |flag: Option<&str>| {
            format!(
                "[auth]\n\
                 enabled = true\n\
                 \n\
                 [auth.clients.alice]\n\
                 secret = \"CLIENTSECRET\"\n\
                 {}\
                 \n\
                 [auth.clients.alice.devices.laptop]\n\
                 secret = \"LAPTOPSECRET\"\n",
                flag.unwrap_or_default()
            )
        };

        let (_dir, path) = scratch_config(&source(None));
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
        assert!(
            auth.expect("auth is enabled").clients["alice"].unnamed_device_allowed,
            "the default has to stay permissive: every client issued before 0.6.0 has no \
             device table, and the shared secret is its only credential"
        );

        let (_dir, path) = scratch_config(&source(Some("unnamed_device_allowed = false\n")));
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config parses");
        assert!(
            !auth.expect("auth is enabled").clients["alice"].unnamed_device_allowed,
            "a flag the operator set must reach the running server"
        );
    }

    /// A second device enrolling alongside the first leaves the first one's
    /// credential where it is — which is the whole of what the table is for.
    #[test]
    fn a_second_device_enrolling_leaves_the_first_one_alone() {
        let (_dir, path) = scratch_client_with_token();

        ProxyConfig::complete_device_enrollment(
            &path,
            "alice",
            "laptop",
            DeviceMaterial::Secret("LAPTOPSECRET"),
        )
        .expect("the first device enrolls");
        ProxyConfig::complete_device_enrollment(
            &path,
            "alice",
            "phone",
            DeviceMaterial::Secret("PHONESECRET"),
        )
        .expect("the second device enrolls");

        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("the config still loads");
        let auth = auth.expect("auth is enabled");
        let devices = &auth.clients["alice"].devices;
        assert_eq!(devices.len(), 2, "{devices:?}");
        assert_eq!(devices["laptop"].secret, "LAPTOPSECRET");
        assert_eq!(devices["phone"].secret, "PHONESECRET");
    }

    /// Neither writer may hand a device an empty secret.
    ///
    /// The loader refuses one, so writing it is not "a device that cannot
    /// authenticate" but "a config that no longer loads at all" — and both
    /// writers would have reported success while doing it. Neither may touch
    /// the file first: the token has to stay spendable for a real enrollment.
    #[test]
    fn an_empty_device_secret_is_refused_by_both_writers() {
        let (_dir, path) = scratch_client_with_token();
        let before = fs::read_to_string(&path).expect("read the config first");

        let enrollment = ProxyConfig::complete_device_enrollment(
            &path,
            "alice",
            "laptop",
            DeviceMaterial::Secret(""),
        )
        .expect_err(
            "an empty secret is not a credential, it is a config that cannot be read again",
        );
        assert!(enrollment.to_string().contains("empty"), "{enrollment:#}");

        let operator = ProxyConfig::write_device_credential(
            &path,
            "alice",
            "laptop",
            DeviceMaterial::Secret(""),
            true,
        )
        .expect_err("the same for the operator CLI");
        assert!(operator.to_string().contains("empty"), "{operator:#}");

        assert_eq!(
            fs::read_to_string(&path).expect("read the config back"),
            before,
            "a refused write still changed the file"
        );
        assert!(
            ProxyConfig::load_with_auth(&path).is_ok(),
            "the config was left in a state that cannot be loaded"
        );
    }

    /// Two writers that both read before either writes lose one of the two
    /// edits: the second one's document is built from contents the first one has
    /// already replaced. The lock is what sequences them — and it has to be a
    /// lock *on the file*, because a process-wide mutex would serialize these
    /// two threads while doing nothing for the CLI and the server, which are
    /// different processes.
    #[test]
    fn a_second_writer_sees_the_first_one_s_edit() {
        let (_dir, path) = scratch_config("counter = 0\n");

        let first = {
            let path = path.clone();
            std::thread::spawn(move || {
                with_config_lock(&path, || {
                    // Reads, then sits on the lock long enough that an unlocked
                    // second writer would have read the old value too.
                    let content = fs::read_to_string(&path)?;
                    assert_eq!(content.trim(), "counter = 0");
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    write_config_file(&path, "counter = 1\n")
                })
                .expect("the first writer succeeds")
            })
        };

        // Let the first one take the lock before the second asks for it.
        std::thread::sleep(std::time::Duration::from_millis(25));

        let seen = with_config_lock(&path, || {
            let content = fs::read_to_string(&path)?;
            write_config_file(&path, "counter = 2\n")?;
            Ok(content)
        })
        .expect("the second writer succeeds");

        first.join().expect("the first writer ends");

        assert!(
            seen.contains("counter = 1"),
            "the second writer must read the first one's edit, got {seen:?}"
        );
        assert_eq!(
            fs::read_to_string(&path)
                .expect("the config is still there")
                .trim(),
            "counter = 2"
        );
    }

    /// A config of TOTP secrets must not be readable by another account, and
    /// not only once the write has finished: `write_config_file` used to create
    /// the replacement under the umask and chmod it to 0600 *after* flushing the
    /// secrets to disk, so a local user reading it in that window got every
    /// TOTP seed in the file. The mode now goes into the call that creates it.
    #[cfg(unix)]
    #[test]
    fn a_written_config_is_private_to_its_owner() {
        let (_dir, path) = scratch_config("counter = 0\n");
        write_config_file(&path, "counter = 1\n").expect("the write succeeds");

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path)
            .expect("the config is there")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a config holding TOTP secrets must be private, got {mode:o}"
        );
    }

    /// A config reached through a symlink is a normal way to keep one file in
    /// version control or out of a container image. Renaming a temp file over
    /// the link replaces the link with a regular file: the indirection is gone
    /// and the file it pointed at keeps the old contents, while every command
    /// involved still reports success.
    #[cfg(unix)]
    #[test]
    fn a_config_reached_through_a_symlink_is_the_one_that_changes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let real = dir.path().join("real.toml");
        let link = dir.path().join("config.toml");
        fs::write(&real, "counter = 0\n").expect("write the real file");
        std::os::unix::fs::symlink(&real, &link).expect("create the link");

        let path = link.to_str().expect("utf-8 path").to_string();
        write_config_file(&path, "counter = 1\n").expect("the write succeeds");

        assert!(
            fs::symlink_metadata(&link)
                .expect("the path is still there")
                .file_type()
                .is_symlink(),
            "the link must survive the write"
        );
        assert_eq!(
            fs::read_to_string(&real)
                .expect("read the real file")
                .trim(),
            "counter = 1",
            "the edit has to land in the file the link points at"
        );
    }

    /// The client the server would see after a write, read back through the
    /// very loader `--generate-2fa` and the server share.
    fn secret_of(path: &str, client_id: &str) -> Option<String> {
        let (_, auth) = ProxyConfig::load_with_auth(path).expect("config still parses");
        auth.and_then(|auth| auth.clients.get(client_id).map(|c| c.secret.clone()))
    }

    #[test]
    fn client_secret_is_appended_without_rewriting_the_file() {
        // `--generate-2fa` edits a file a human wrote, so the comment, the key
        // order and the layout of everything outside `[auth]` have to survive.
        let (_dir, path) = scratch_config(
            "# my proxy\n\
             default_backend = \"http://127.0.0.1:15666\"\n\
             \n\
             [[routes]]\n\
             host_pattern = \"a.example\"\n\
             backends = [\"http://127.0.0.1:8080\"]\n",
        );

        let outcome =
            ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", false)
                .expect("secret should be written");
        assert_eq!(outcome, ClientSecretWrite::Added);

        let written = fs::read_to_string(&path).expect("read back");
        assert!(written.starts_with("# my proxy\n"));
        assert!(written.contains("default_backend = \"http://127.0.0.1:15666\""));
        assert!(written.contains("[[routes]]"));
        assert!(written.contains("[auth.clients.client-001]"));
        assert_eq!(
            secret_of(&path, "client-001").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn client_secret_joins_an_existing_auth_section() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.other]\n\
             secret = \"AAAAAAAAAAAAAAAA\"\n",
        );

        let outcome =
            ProxyConfig::write_client_secret(&path, "client-002", "JBSWY3DPEHPK3PXP", false)
                .expect("secret should be written");
        assert_eq!(outcome, ClientSecretWrite::Added);

        let written = fs::read_to_string(&path).expect("read back");
        assert!(written.contains("[auth.clients.other]"));
        assert_eq!(
            secret_of(&path, "other").as_deref(),
            Some("AAAAAAAAAAAAAAAA"),
            "the neighbouring client must not be touched"
        );
        assert_eq!(
            secret_of(&path, "client-002").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        // 2FA was already on and stays on; enabling it is the operator's call.
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config parses");
        assert!(auth.expect("[auth] exists").enabled);
    }

    #[test]
    fn client_secret_needs_force_to_replace_one() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.client-001]\n\
             secret = \"OLDOLDOLDOLDOLD\"\n",
        );

        let err = ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", false)
            .expect_err("an enrolled client must not lose its secret by accident");
        assert!(err.to_string().contains("already has a secret"));
        assert_eq!(
            secret_of(&path, "client-001").as_deref(),
            Some("OLDOLDOLDOLDOLD")
        );

        let outcome =
            ProxyConfig::write_client_secret(&path, "client-001", "JBSWY3DPEHPK3PXP", true)
                .expect("force replaces it");
        assert_eq!(outcome, ClientSecretWrite::Replaced);
        assert_eq!(
            secret_of(&path, "client-001").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn client_ids_that_are_not_bare_keys_are_quoted() {
        // `[auth.clients.client.001]` would nest three tables; the id has to be
        // quoted so it stays one key.
        let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");

        ProxyConfig::write_client_secret(&path, "client.001", "JBSWY3DPEHPK3PXP", false)
            .expect("secret should be written");

        let written = fs::read_to_string(&path).expect("read back");
        assert!(
            written.contains("[auth.clients.\"client.001\"]"),
            "{written}"
        );
        assert_eq!(
            secret_of(&path, "client.001").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    /// The endpoint key and the relay token are credentials whether or not
    /// `[auth]` is on; this is what marks an inline value as a credential that
    /// belongs in a sidecar file or the environment rather than the config.
    #[test]
    fn a_key_or_a_relay_token_makes_the_config_hold_credentials() {
        assert!(parse("[iroh]\nsecret_key = \"00\"\n").holds_credentials());
        assert!(parse("[iroh]\nrelay_auth_token = \"t\"\n").holds_credentials());
        assert!(!parse("").holds_credentials());
    }

    /// Restricts a credential file the test creates to the owner, the way a
    /// real deployment has to for the load to succeed — a `fs::write` file is
    /// 0644 under the default umask, and `read_credential_file` rightly refuses
    /// that on Unix. Outside Unix there are no modes to set.
    #[cfg(unix)]
    fn chmod_owner_only(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }

    #[cfg(not(unix))]
    fn chmod_owner_only(_path: &std::path::Path) {}

    /// A key in a pointed-to file reaches the config resolved, and — the point
    /// of the pointer — does not make the config a credential holder.
    #[test]
    fn a_key_file_resolves_and_leaves_the_config_credential_free() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = generate_secret_key_hex();
        let key_path = dir.path().join("iroh.key");
        fs::write(&key_path, &key).expect("write the key file");
        chmod_owner_only(&key_path);
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

        let (config, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect("a config whose key lives in a file loads");

        let iroh = config.iroh.as_ref().expect("the [iroh] section parsed");
        assert_eq!(
            iroh.secret_key.as_deref(),
            Some(key.as_str()),
            "the key from the file is what the config runs on"
        );
        assert_eq!(iroh.secret_key_source, CredentialSource::File);
        assert!(
            !config.holds_credentials(),
            "the config holds a pointer, not a key, so the permission gate keeps warning \
             instead of refusing"
        );
    }

    /// A config naming the key twice refuses to load rather than ranking the
    /// candidates: which source wins must not turn on precedence rules the
    /// operator has to look up.
    #[test]
    fn naming_the_key_twice_refuses_to_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("iroh.key"), generate_secret_key_hex())
            .expect("write the key file");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            format!(
                "[iroh]\nsecret_key = \"{}\"\nsecret_key_file = \"iroh.key\"\n",
                generate_secret_key_hex()
            ),
        )
        .expect("write the config");

        let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect_err("two answers to one question are refused");
        assert!(err.to_string().contains("named by"), "{err}");
        assert!(err.to_string().contains("secret_key_file"), "{err}");
    }

    /// The environment outranks nothing when the config also names the key:
    /// refused, not silently adjudicated.
    ///
    /// Driven through `resolve_secret_key_source`'s parameter rather than the
    /// process environment — `set_var` is `unsafe` in Rust 2024, and the
    /// end-to-end env coverage lives in `tests/first_run_identity.rs`, where a
    /// child process takes the variable.
    #[test]
    fn an_env_key_alongside_an_inline_one_is_refused() {
        // IrohConfig *is* the [iroh] table, so its TOML carries the fields
        // without the header — a header here would be an unknown field the
        // parser silently drops.
        let iroh: IrohConfig = toml::from_str("secret_key = \"00\"\n").expect("parse");

        let err = resolve_secret_key_source(None, Some("env-key".to_string()), None, &iroh)
            .expect_err("a credential named twice is refused");
        assert!(
            err.to_string().contains(IROH_SECRET_KEY_ENV),
            "the refusal names both sources: {err}"
        );
    }

    /// An environment credential resolves with the env source, and the value
    /// is trimmed: a trailing newline from `printf` must not become key bytes.
    #[test]
    fn an_env_key_resolves_as_env() {
        let iroh: IrohConfig = toml::from_str("").expect("parse");

        let (key, source) =
            resolve_secret_key_source(None, Some("  abc  ".to_string()), None, &iroh)
                .expect("one source resolves")
                .expect("the environment names a key");
        assert_eq!(key, "abc");
        assert_eq!(source, CredentialSource::Env);
    }

    /// An empty environment variable is "not named", not an empty key — the
    /// same reading `NEXAPIPE_NO_PERSIST_IDENTITY` gets — so the literal the
    /// config carries stays the one answer.
    #[test]
    fn an_empty_env_value_names_nothing() {
        let iroh: IrohConfig = toml::from_str("secret_key = \"00\"\n").expect("parse");

        let (key, source) = resolve_secret_key_source(None, Some("   ".to_string()), None, &iroh)
            .expect("a blank env value is not a source")
            .expect("the inline literal is the only source left");
        assert_eq!(key, "00");
        assert_eq!(source, CredentialSource::Inline);
    }

    /// An environment-named file path is a file source, taken literally even
    /// when it is not next to the config.
    #[test]
    fn an_env_named_key_file_resolves_as_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key_path = dir.path().join("elsewhere").join("iroh.key");
        fs::create_dir_all(key_path.parent().expect("parent")).expect("mkdir");
        let key = generate_secret_key_hex();
        fs::write(&key_path, &key).expect("write the key file");
        chmod_owner_only(&key_path);
        let iroh: IrohConfig = toml::from_str("").expect("parse");

        let (resolved, source) =
            resolve_secret_key_source(Some(dir.path()), None, Some(&key_path), &iroh)
                .expect("the env-named file resolves")
                .expect("it names a key");
        assert_eq!(resolved, key);
        assert_eq!(source, CredentialSource::File);
    }

    /// The two environment variables naming the same key two ways are refused,
    /// not ranked.
    #[test]
    fn an_env_value_and_an_env_file_refuse() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key_path = dir.path().join("iroh.key");
        fs::write(&key_path, generate_secret_key_hex()).expect("write the key file");
        chmod_owner_only(&key_path);
        let iroh: IrohConfig = toml::from_str("").expect("parse");

        let err =
            resolve_secret_key_source(None, Some("env-key".to_string()), Some(&key_path), &iroh)
                .expect_err("two environment answers are refused");
        let text = err.to_string();
        assert!(text.contains(IROH_SECRET_KEY_ENV), "{text}");
        assert!(text.contains(IROH_SECRET_KEY_FILE_ENV), "{text}");
    }

    /// The environment file outranks nothing when the config also points at a
    /// file: refused, same one-source rule.
    #[test]
    fn an_env_file_and_a_config_pointer_refuse() {
        let dir = tempfile::tempdir().expect("temp dir");
        let env_path = dir.path().join("env.key");
        fs::write(&env_path, generate_secret_key_hex()).expect("write env key");
        chmod_owner_only(&env_path);
        let cfg_path = dir.path().join("cfg.key");
        fs::write(&cfg_path, generate_secret_key_hex()).expect("write config key");
        chmod_owner_only(&cfg_path);
        let iroh: IrohConfig = toml::from_str("secret_key_file = \"cfg.key\"\n").expect("parse");

        let err = resolve_secret_key_source(Some(dir.path()), None, Some(&env_path), &iroh)
            .expect_err("a pointer in the env and one in the config are refused");
        assert!(err.to_string().contains("secret_key_file"), "{err}");
    }

    /// An environment-named file that does not exist yet defers to first-start
    /// generation rather than failing — the caller folds the path onto the
    /// pointer field so the key is generated where the env says.
    #[test]
    fn a_missing_env_named_file_defers_to_generation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key_path = dir.path().join("secrets").join("iroh.key");
        let iroh: IrohConfig = toml::from_str("").expect("parse");

        let resolved = resolve_secret_key_source(None, None, Some(&key_path), &iroh)
            .expect("a missing pointed-to file is not an error");
        assert!(resolved.is_none(), "nothing is resolved until generation");
    }

    /// A relay token file resolves like a key file, trimmed.
    #[test]
    fn a_relay_token_file_resolves() {
        let dir = tempfile::tempdir().expect("temp dir");
        let token_path = dir.path().join("relay.token");
        fs::write(&token_path, "  bearer-token  \n").expect("write the token file");
        chmod_owner_only(&token_path);
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nrelay_auth_token_file = \"relay.token\"\n")
            .expect("write the config");

        let (config, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect("a config whose token lives in a file loads");

        let iroh = config.iroh.as_ref().expect("the [iroh] section parsed");
        assert_eq!(iroh.relay_auth_token.as_deref(), Some("bearer-token"));
        assert_eq!(iroh.relay_auth_token_source, CredentialSource::File);
        assert!(!config.holds_credentials());
    }

    /// A token file that does not exist is refused rather than deferred: the
    /// server cannot invent a relay token, and a missing one must not surface
    /// later as a vaguer relay-configuration error.
    #[test]
    fn a_missing_relay_token_file_refuses_to_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nrelay_auth_token_file = \"relay.token\"\n")
            .expect("write the config");

        let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect_err("a token cannot be generated into a missing file");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    /// A key file that holds nothing is a typo to see, not a mode: the pointer
    /// was spelled, so a blank file refuses the load.
    #[test]
    fn an_empty_key_file_refuses_to_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("iroh.key"), "  \n").expect("write a blank key file");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

        let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect_err("a blank credential file is refused");
        assert!(err.to_string().contains("holds nothing"), "{err}");
    }

    /// A first start with a `secret_key_file` writes the key into that file —
    /// never back into the config — and a reload resolves from the file
    /// without turning the config into a credential holder.
    #[test]
    fn a_missing_key_file_is_generated_into() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

        let config =
            ProxyConfig::from_file(path.to_str().expect("utf-8 path")).expect("the config loads");
        let identity =
            ProxyConfig::ensure_iroh_secret_key(path.to_str().expect("utf-8 path"), &config)
                .expect("the identity resolves");
        assert!(
            matches!(identity, EndpointIdentity::Generated(_)),
            "a first start generates into the pointed-to file, got {identity:?}"
        );

        // Compare and measure without formatting the key: a failing
        // assert_eq! would render both values, putting the private key in the
        // CI log the same way EndpointIdentity's Debug refuses to.
        let file_key =
            fs::read_to_string(dir.path().join("iroh.key")).expect("the key file was written");
        let file_key = file_key.trim();
        assert_eq!(
            file_key.len(),
            64,
            "the file holds a full ed25519 key (64 hex chars)"
        );
        assert!(
            identity.key() == file_key,
            "the running identity is the key in the file"
        );

        let content = fs::read_to_string(&path).expect("read the config back");
        assert!(
            !content.contains("secret_key ="),
            "the key must not be written back into the config: that would undo the whole \
             point of the pointer"
        );

        let (reloaded, _) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect("the config reloads from the key file");
        assert_eq!(
            reloaded.iroh.as_ref().expect("[iroh]").secret_key_source,
            CredentialSource::File,
            "the reload resolves from the file the first start wrote"
        );
        assert!(!reloaded.holds_credentials());
    }

    /// A key file another account can read is the credential in the open: the
    /// same refusal the config gets for holding one inline.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_refuses_to_load() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let key_path = dir.path().join("iroh.key");
        fs::write(&key_path, generate_secret_key_hex()).expect("write the key file");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 644");
        let path = dir.path().join("config.toml");
        fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n").expect("write the config");

        let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect_err("a world-readable credential file is refused");
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    /// A key file that appears between the load and the generation — the lost
    /// race `write_key_file` reads back — is held to the same 0600 rule as a
    /// file a normal load points at: a nonempty 0644 winner is refused rather
    /// than adopted.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_race_winner_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let key_path = dir.path().join("iroh.key");
        fs::write(&key_path, generate_secret_key_hex())
            .expect("a sibling process drops a nonempty 0644 key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 644");

        let err = write_key_file(&key_path)
            .expect_err("the lost-race read-back applies the same permission refusal");
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    /// A credential sidecar file is private or refused; there is no
    /// "credentials not live yet" half-way case for these.
    #[cfg(unix)]
    #[test]
    fn a_credential_file_is_private_or_refused() {
        use std::os::unix::fs::PermissionsExt;
        let set_mode = |path: &str, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
        };

        let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");

        set_mode(&path, 0o600);
        check_credential_file_permissions(&path).expect("0600 is accepted");

        set_mode(&path, 0o644);
        let err = check_credential_file_permissions(&path)
            .expect_err("0644 is fatal for a credential file");
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    /// A file the caller could not even stat has already failed to be read; the
    /// permission check is not the place to report that.
    #[cfg(unix)]
    #[test]
    fn credential_file_check_passes_a_file_it_cannot_stat() {
        check_credential_file_permissions("/nonexistent/iroh.key")
            .expect("a missing file is reported by the loader, not here");
    }

    /// An enrollment is two writes to the same file: a token that an invitation
    /// carries, and the secret that replaces it when the token is spent. Both
    /// have to survive a reload, because the server that writes the token is
    /// usually a different process from the one that spends it.
    #[test]
    fn an_enrollment_token_is_recorded_then_spent() {
        let (_dir, path) = scratch_config(
            "# my proxy\n\
             default_backend = \"http://127.0.0.1:15666\"\n\
             \n\
             [auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.client-001]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );

        ProxyConfig::write_pending_enrollment(&path, "client-001", "deadbeef")
            .expect("token should be written");
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
        let auth = auth.expect("auth section");
        assert_eq!(
            auth.clients["client-001"].pending_enrollment.as_deref(),
            Some("deadbeef")
        );
        assert_eq!(auth.clients["client-001"].secret, "JBSWY3DPEHPK3PXP");

        // Issuing a second token replaces the first: that is how a link that
        // never arrived gets revoked.
        ProxyConfig::write_pending_enrollment(&path, "client-001", "cafebabe")
            .expect("token should be replaced");
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
        assert_eq!(
            auth.unwrap().clients["client-001"]
                .pending_enrollment
                .as_deref(),
            Some("cafebabe")
        );

        ProxyConfig::complete_enrollment(&path, "client-001", "NEWSECRETVALUE")
            .expect("enrollment should be saved");
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
        let client = &auth.unwrap().clients["client-001"];
        assert_eq!(client.secret, "NEWSECRETVALUE");
        // The token has to go with it, or the same link enrolls a second device.
        assert_eq!(client.pending_enrollment, None);
    }

    /// A blank enrollment token is refused instead of read as "no enrollment
    /// outstanding".
    ///
    /// `constant_time_eq` calls two empty slices equal, so a config carrying
    /// `pending_enrollment = ""` would accept any stranger's empty ENROLL_START
    /// and hand them a freshly generated secret, locking out every device that
    /// was using the client id. Blanking the key is the natural way to "clear"
    /// it, so it has to fail loudly rather than quietly mean "closed".
    #[test]
    fn a_blank_enrollment_token_is_refused() {
        let (_dir, path) = scratch_config(
            "default_backend = \"http://127.0.0.1:15666\"\n\
             \n\
             [auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.client-001]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             pending_enrollment = \"\"\n",
        );

        let err = ProxyConfig::load_with_auth(&path).expect_err("a blank token must not load");
        assert!(err.to_string().contains("pending_enrollment"), "{err}");
    }

    /// The endpoint credentials have to stay out of `Debug`, because the whole
    /// config is logged at debug level whenever it is parsed — including on
    /// every hot reload, where the logger is already installed.
    #[test]
    fn a_parsed_iroh_config_prints_no_credentials() {
        let iroh = IrohConfig {
            relay_url: Some("https://relay.example".to_string()),
            relay_mode: Some("custom".to_string()),
            relay_auth_token: Some("bearer-secret".to_string()),
            bind_port: Some(1234),
            bind_ipv6: Some(true),
            secret_key: Some("ed25519-private-key".to_string()),
            secret_key_file: Some("iroh.key".to_string()),
            secret_key_source: CredentialSource::Inline,
            relay_auth_token_file: Some("relay.token".to_string()),
            relay_auth_token_source: CredentialSource::Inline,
        };

        let rendered = format!("{iroh:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("bearer-secret"), "{rendered}");
        assert!(!rendered.contains("ed25519-private-key"), "{rendered}");
        // Whether a key is configured is still worth knowing.
        assert!(rendered.contains("relay_mode"), "{rendered}");
    }

    /// A token for a client that does not exist would leave a section with no
    /// secret behind, which stops the config loading at all.
    #[test]
    fn an_enrollment_token_needs_a_client() {
        let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");
        let err = ProxyConfig::write_pending_enrollment(&path, "ghost", "deadbeef")
            .expect_err("a missing client must not be silently created");
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    /// The devices of a client, as the server would read them back.
    fn devices_of(path: &str, client_id: &str) -> HashMap<String, crate::auth::DeviceAuth> {
        let (_, auth) = ProxyConfig::load_with_auth(path).expect("config still parses");
        auth.and_then(|auth| auth.clients.get(client_id).map(|c| c.devices.clone()))
            .unwrap_or_default()
    }

    /// A device credential goes under the client's own `devices` table, and the
    /// client's `secret` — the credential of the device that names none — stays
    /// exactly as it was.
    #[test]
    fn a_device_secret_lands_under_the_clients_devices_table() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );

        let outcome = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "laptop",
            DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
            false,
        )
        .expect("the device secret should be written");
        assert_eq!(outcome, ClientSecretWrite::Added);

        let written = fs::read_to_string(&path).expect("read back");
        assert!(
            written.contains("[auth.clients.acme.devices]"),
            "the devices table has to say what it holds: {written}"
        );
        assert_eq!(
            secret_of(&path, "acme").as_deref(),
            Some("JBSWY3DPEHPK3PXP"),
            "the unnamed device keeps the credential it had"
        );
        let devices = devices_of(&path, "acme");
        assert_eq!(
            devices.get("laptop").map(|d| d.secret.as_str()),
            Some("MFRGGZDFMZTWQ2LK")
        );
    }

    /// Issuing a device a second secret would lock the one already using it out,
    /// so it takes `--force` — the same refusal replacing a client's secret does.
    #[test]
    fn a_device_secret_needs_force_to_replace_one() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             \n\
             [auth.clients.acme.devices.laptop]\n\
             secret = \"OLDOLDOLDOLDOLD\"\n",
        );

        let err = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "laptop",
            DeviceMaterial::Secret("NEWNEWNEWNEWNEW"),
            false,
        )
        .expect_err("a device must not lose its credential by accident");
        assert!(
            err.to_string().contains("already has a credential"),
            "{err}"
        );
        assert_eq!(
            devices_of(&path, "acme")
                .get("laptop")
                .map(|d| d.secret.as_str()),
            Some("OLDOLDOLDOLDOLD")
        );

        let outcome = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "laptop",
            DeviceMaterial::Secret("NEWNEWNEWNEWNEW"),
            true,
        )
        .expect("with force the secret is replaced");
        assert_eq!(outcome, ClientSecretWrite::Replaced);
        assert_eq!(
            devices_of(&path, "acme")
                .get("laptop")
                .map(|d| d.secret.as_str()),
            Some("NEWNEWNEWNEWNEW")
        );
    }

    /// A device under a client with no secret of its own is a config that cannot
    /// be loaded, so the write is refused rather than creating one.
    #[test]
    fn a_device_secret_needs_a_client_with_a_secret() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.other]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );

        let err = ProxyConfig::write_device_credential(
            &path,
            "ghost",
            "laptop",
            DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
            false,
        )
        .expect_err("a device of a client that is not there must not be created");
        assert!(err.to_string().contains("ghost"), "{err}");
        assert!(
            devices_of(&path, "ghost").is_empty(),
            "nothing was written for it"
        );
    }

    /// The name becomes a key here and the subject of every log line about the
    /// device, so one that is not printable ASCII is refused rather than read as
    /// "no name".
    #[test]
    fn an_unprintable_device_name_is_refused() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );

        for name in ["", "lap top", "laptop\nsecret = \"x\""] {
            let err = ProxyConfig::write_device_credential(
                &path,
                "acme",
                name,
                DeviceMaterial::Secret("MFRGGZDFMZTWQ2LK"),
                false,
            )
            .expect_err("an unusable device name must not be written");
            assert!(err.to_string().contains("printable ASCII"), "{err}");
        }
        assert!(devices_of(&path, "acme").is_empty());
    }

    /// The other half of the writer: a key an operator registers lands under
    /// the same table as a secret, spelled canonically — lowercase hex, so the
    /// file says one thing however the key was pasted — and reads back as a
    /// key device.
    #[test]
    fn a_device_key_lands_under_the_clients_devices_table() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );
        let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

        let outcome = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "server",
            DeviceMaterial::PublicKey(&key.to_uppercase()),
            false,
        )
        .expect("the device key should be written");
        assert_eq!(outcome, ClientSecretWrite::Added);

        let written = fs::read_to_string(&path).expect("read back");
        assert!(
            written.contains(&format!("public_key = \"{key}\"")),
            "the key is spelled canonically whatever case it arrived in: {written}"
        );
        let devices = devices_of(&path, "acme");
        let server = &devices["server"];
        assert_eq!(server.public_key.as_deref(), Some(key.as_str()));
        assert!(server.secret.is_empty(), "{server:?}");
        assert_eq!(
            secret_of(&path, "acme").as_deref(),
            Some("JBSWY3DPEHPK3PXP"),
            "the unnamed device keeps the credential it had"
        );
    }

    /// A key that is not a key is refused before the file is touched, the same
    /// way an empty secret is: what the writer must never do is report success
    /// while leaving a config the loader will refuse on the next start.
    #[test]
    fn a_public_key_that_is_not_a_key_is_refused_by_the_writer() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n",
        );
        let before = fs::read_to_string(&path).expect("read the config first");

        let err = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "server",
            DeviceMaterial::PublicKey("not a key"),
            false,
        )
        .expect_err("a value that is not a key must not be written");
        assert!(err.to_string().contains("not hex"), "{err}");

        assert_eq!(
            fs::read_to_string(&path).expect("read the config back"),
            before,
            "a refused write still changed the file"
        );
        assert!(
            ProxyConfig::load_with_auth(&path).is_ok(),
            "the config was left in a state that cannot be loaded"
        );
    }

    /// Switching a device from one credential to the other is a replace like
    /// any other: it takes `--force`, because a device answering with a code
    /// stops the moment its entry says key. The secret is gone rather than
    /// kept beside the key — one credential, which is the shape the loader
    /// insists on.
    #[test]
    fn a_key_replaces_a_secret_only_with_force() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             \n\
             [auth.clients.acme.devices.server]\n\
             secret = \"OLDOLDOLDOLDOLD\"\n",
        );
        let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

        let err = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "server",
            DeviceMaterial::PublicKey(&key),
            false,
        )
        .expect_err("a device must not lose its credential by accident");
        assert!(
            err.to_string().contains("already has a credential"),
            "{err}"
        );

        let outcome = ProxyConfig::write_device_credential(
            &path,
            "acme",
            "server",
            DeviceMaterial::PublicKey(&key),
            true,
        )
        .expect("with force the key is written");
        assert_eq!(outcome, ClientSecretWrite::Replaced);

        let devices = devices_of(&path, "acme");
        let server = &devices["server"];
        assert_eq!(server.public_key.as_deref(), Some(key.as_str()));
        assert!(
            server.secret.is_empty(),
            "the old secret is gone, not kept beside the key: {server:?}"
        );
    }

    /// Revoking one device leaves the client and every other device alone —
    /// which is the whole point of the table.
    #[test]
    fn revoking_a_device_leaves_the_others_alone() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             \n\
             [auth.clients.acme.devices.laptop]\n\
             secret = \"AAAAAAAAAAAAAAAA\"\n\
             \n\
             [auth.clients.acme.devices.phone]\n\
             secret = \"BBBBBBBBBBBBBBBB\"\n",
        );

        ProxyConfig::remove_device(&path, "acme", "laptop").expect("the device should be revoked");

        let devices = devices_of(&path, "acme");
        assert_eq!(devices.len(), 1, "one device went, {devices:?}");
        assert_eq!(
            devices.get("phone").map(|d| d.secret.as_str()),
            Some("BBBBBBBBBBBBBBBB")
        );
        assert_eq!(
            secret_of(&path, "acme").as_deref(),
            Some("JBSWY3DPEHPK3PXP"),
            "the client's own credential is not a device's to revoke"
        );
        let written = fs::read_to_string(&path).expect("read back");
        assert!(!written.contains("AAAAAAAAAAAAAAAA"), "{written}");
    }

    /// Naming a device that is not there says which ones are, so a typo does not
    /// look like a successful revocation.
    #[test]
    fn revoking_a_device_that_is_not_there_says_which_ones_are() {
        let (_dir, path) = scratch_config(
            "[auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.acme]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n\
             \n\
             [auth.clients.acme.devices.laptop]\n\
             secret = \"AAAAAAAAAAAAAAAA\"\n",
        );

        let err = ProxyConfig::remove_device(&path, "acme", "tablet")
            .expect_err("a missing device must not be reported as revoked");
        assert!(err.to_string().contains("tablet"), "{err}");
        assert!(err.to_string().contains("laptop"), "{err}");
        assert_eq!(devices_of(&path, "acme").len(), 1);
    }

    /// Revoking a client drops its devices with it: a device credential left
    /// behind under a client that is gone is a credential nobody can revoke,
    /// because `client list` no longer has a client to list it under.
    #[test]
    fn revoking_a_client_takes_its_devices_with_it() {
        let source = "[auth]\n\
                      enabled = true\n\
                      \n\
                      [auth.clients.acme]\n\
                      secret = \"JBSWY3DPEHPK3PXP\"\n\
                      \n\
                      [auth.clients.acme.devices.laptop]\n\
                      secret = \"AAAAAAAAAAAAAAAA\"\n\
                      \n\
                      [auth.clients.other]\n\
                      secret = \"CCCCCCCCCCCCCCCC\"\n";
        let (_dir, path) = scratch_config(source);

        ProxyConfig::remove_client(&path, "acme").expect("the client should be revoked");

        let written = fs::read_to_string(&path).expect("read back");
        assert!(!written.contains("acme"), "{written}");
        assert!(!written.contains("AAAAAAAAAAAAAAAA"), "{written}");
        assert_eq!(
            secret_of(&path, "other").as_deref(),
            Some("CCCCCCCCCCCCCCCC"),
            "the neighbouring client is untouched"
        );
        let (_, auth) = ProxyConfig::load_with_auth(&path).expect("config still parses");
        assert_eq!(auth.expect("[auth] exists").clients.len(), 1);
    }

    /// A revoke that names something absent changes nothing, which is also why
    /// it cannot create the section it is about to delete.
    #[test]
    fn revoking_something_absent_leaves_the_file_alone() {
        let source = "default_backend = \"http://127.0.0.1:15666\"\n\
                      \n\
                      [auth.clients.acme]\n\
                      secret = \"JBSWY3DPEHPK3PXP\"\n";
        let (_dir, path) = scratch_config(source);

        let err = ProxyConfig::remove_client(&path, "ghost")
            .expect_err("a missing client must not be reported as revoked");
        assert!(err.to_string().contains("ghost"), "{err}");
        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            source,
            "the file is byte for byte what it was"
        );

        // No [auth.clients] at all, and the same answer.
        let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");
        assert!(ProxyConfig::remove_client(&path, "acme").is_err());
        assert!(ProxyConfig::remove_device(&path, "acme", "laptop").is_err());
        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            "default_backend = \"http://127.0.0.1:15666\"\n"
        );
    }

    /// A Node ID to write into `[peers] allow`.
    fn node_id(seed: u8) -> String {
        iroh::SecretKey::from_bytes(&[seed; 32])
            .public()
            .to_string()
    }

    /// The default has to stay permissive: every deployment that predates
    /// `[peers]` has no section at all, and none of them may start refusing
    /// connections after an upgrade.
    #[test]
    fn no_peers_section_means_no_restriction() {
        assert!(parse("").peers.is_none());

        // The section present but the key absent is the same thing.
        let config = parse("[peers]\n");
        assert!(
            config
                .peers
                .as_ref()
                .unwrap()
                .parse_allow_list()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_peers_allow_list_parses_into_node_ids() {
        let source = format!("[peers]\nallow = [{:?}, {:?}]\n", node_id(1), node_id(2));
        let config = parse(&source);

        let allowed = config
            .peers
            .as_ref()
            .unwrap()
            .parse_allow_list()
            .unwrap()
            .expect("the list is configured");

        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&node_id(1).parse::<iroh::EndpointId>().unwrap()));
        assert!(allowed.contains(&node_id(2).parse::<iroh::EndpointId>().unwrap()));
    }

    /// A typo in one entry would otherwise silently narrow a list whose whole
    /// job is to refuse strangers — so it is fatal, not skipped.
    #[test]
    fn a_malformed_node_id_is_refused_not_dropped() {
        let source = format!("[peers]\nallow = [{:?}, \"not-a-node-id\"]\n", node_id(1));
        let err = parse(&source)
            .peers
            .as_ref()
            .unwrap()
            .parse_allow_list()
            .expect_err("a malformed entry must be reported");

        assert!(err.to_string().contains("not-a-node-id"), "{err}");
    }

    /// `allow = []` is refused rather than read as "refuse everybody": it is a
    /// plausible typo, and guessing wrong locks the operator out of their own
    /// server.
    #[test]
    fn an_empty_allow_list_is_refused() {
        let config = parse("[peers]\nallow = []\n");
        let err = config
            .peers
            .as_ref()
            .unwrap()
            .parse_allow_list()
            .expect_err("an empty list must not be read as either case");

        assert!(err.to_string().contains("[peers] allow = []"), "{err}");
    }

    /// A wildcard with no dot after it is a bare `ends_with`, so it covers any
    /// host ending in the same letters — `eviliakl.top` for `*iakl.top`. The
    /// only useful thing to do with one is refuse to start.
    #[test]
    fn a_route_wildcard_without_a_label_boundary_is_refused() {
        let config = parse(
            r#"
[[routes]]
host_pattern = "*iakl.top"
mode = "http"
backends = ["http://10.0.0.5:8080"]
"#,
        );
        let err = config
            .build_routes()
            .expect_err("the pattern has to be refused");
        assert!(err.to_string().contains("label boundary"), "{err}");
    }

    /// The same rule for an `allow_hosts` entry, which is a host pattern and
    /// would otherwise authorize more hosts than it names.
    #[test]
    fn an_allow_hosts_wildcard_without_a_label_boundary_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        // No `enabled = true`: with 2FA on, a 0644 file is refused for its
        // permissions before the pattern is ever looked at, and the file mode
        // is not something this test should depend on.
        std::fs::write(
            &path,
            r#"
[auth]

[auth.clients.device]
secret = "JBSWY3DPEHPK3PXP"
allow_hosts = ["*iakl.top"]
"#,
        )
        .expect("write the config");

        let err = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect_err("the pattern has to be refused");
        assert!(err.to_string().contains("label boundary"), "{err}");
    }

    /// `window` is handed to the TOTP library as a `u8`, so 300 was truncated
    /// to 44 by the cast: a code valid for ±22 minutes instead of ±30 seconds.
    #[test]
    fn a_window_that_does_not_fit_is_refused() {
        let err = load_from("[auth]\nwindow = 300\n").expect_err("300 does not fit a u8");
        assert!(err.to_string().contains("window is 300"), "{err}");

        // And a sane window still loads.
        let (_, auth) = load_from("[auth]\nwindow = 1\n").expect("a normal window loads");
        assert_eq!(auth.expect("auth section present").window, 1);
    }

    #[test]
    fn a_digit_count_no_code_has_is_refused() {
        let err = load_from("[auth]\ndigits = 4\n").expect_err("a code is not 4 digits");
        assert!(err.to_string().contains("digits is 4"), "{err}");
    }

    #[test]
    fn a_time_step_of_zero_is_refused() {
        let err = load_from("[auth]\ntime_step = 0\n").expect_err("0 covers no time at all");
        assert!(err.to_string().contains("time_step"), "{err}");
    }

    /// Why `[auth]` is the one section that refuses keys it does not know:
    /// `enable = true` for `enabled` used to leave 2FA off, and the log said
    /// nothing, because serde drops what it does not recognise and the default
    /// for `enabled` is false.
    #[test]
    fn an_unknown_auth_key_is_refused_rather_than_ignored() {
        let err = load_from("[auth]\nenable = true\n").expect_err("a typo must not disable 2FA");
        assert!(err.to_string().contains("enable"), "{err}");
    }

    /// The table an operator writes under a client, read back the way the
    /// server reads it — and the client's own `secret` is still there beside
    /// it, because that is the credential of the device with no name.
    #[test]
    fn a_device_table_loads_without_disturbing_the_client() {
        let (_, auth) = load_from(
            r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secret = "LAPTOPSECRET"

[auth.clients.client-001.devices.phone]
secret = "PHONESECRET"
created_at = "1700000000"
"#,
        )
        .expect("a device table loads");

        let client = &auth.expect("auth section present").clients["client-001"];
        assert_eq!(client.secret, "CLIENTSECRET");
        assert_eq!(client.devices.len(), 2);
        assert_eq!(client.devices["laptop"].secret, "LAPTOPSECRET");
        assert_eq!(client.devices["phone"].created_at, "1700000000");
        assert!(
            !client.devices["laptop"].created_at.is_empty(),
            "an undated device is dated the moment it is issued"
        );
    }

    /// A device secret keys that device's HMAC, so an empty one is a signature
    /// anybody can forge — refused at load rather than read as "a device that
    /// authenticates nobody". An empty spelling is no secret at all, so this is
    /// also the entry with no credential of any kind.
    #[test]
    fn an_empty_device_secret_is_refused() {
        let err = load_from(
            r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secret = ""
"#,
        )
        .expect_err("an empty secret must not load");

        assert!(err.to_string().contains("devices.laptop"), "{err}");
        assert!(err.to_string().contains("empty secret"), "{err}");
    }

    /// A device answers with exactly one credential, and the loader is where
    /// that is enforced. Neither field is a config that does not say how the
    /// device proves itself; both is two answers to disagree about. Refused
    /// here, where the operator can see which entry it is about, rather than at
    /// a handshake whose only reportable outcome is "refused".
    #[test]
    fn a_device_entry_needs_exactly_one_credential() {
        let client = r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"
"#;

        let neither = load_from(&format!(
            "{client}\n[auth.clients.client-001.devices.laptop]\ncreated_at = \"1700000000\"\n"
        ))
        .expect_err("a device with no credential must not load");
        assert!(neither.to_string().contains("devices.laptop"), "{neither}");
        assert!(neither.to_string().contains("no `secret`"), "{neither}");
        assert!(neither.to_string().contains("no `public_key`"), "{neither}");

        let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());
        let both = load_from(&format!(
            "{client}\n[auth.clients.client-001.devices.laptop]\nsecret = \"LAPTOPSECRET\"\n\
             public_key = \"{key}\"\n"
        ))
        .expect_err("two credentials must not load");
        assert!(both.to_string().contains("devices.laptop"), "{both}");
        assert!(both.to_string().contains("both"), "{both}");
    }

    /// A device that proves itself with a key: `public_key` is read where a
    /// `secret` would be, and the rest of the entry is what it always was.
    #[test]
    fn a_public_key_device_loads_where_a_secret_one_does() {
        let key = crate::auth::public_key_hex(&iroh::SecretKey::generate().public());

        let (_, auth) = load_from(&format!(
            "[auth.clients.client-001]\nsecret = \"CLIENTSECRET\"\n\n\
             [auth.clients.client-001.devices.server]\npublic_key = \"{key}\"\n"
        ))
        .expect("a key device loads");

        let device = &auth.expect("auth section present").clients["client-001"].devices["server"];
        assert_eq!(device.public_key.as_deref(), Some(key.as_str()));
        // Not `{device:?}`: `DeviceAuth`'s `Debug` prints `secret: "<redacted>"`,
        // so it says nothing here and reads to the scanner as logging a secret.
        assert!(
            device.secret.is_empty(),
            "a device registered with a key holds no seed"
        );
        assert!(
            !device.created_at.is_empty(),
            "an undated device is dated the moment it is issued"
        );
    }

    /// A key that is not a key is refused where it is written into the file.
    /// The handshake could only refuse the device that holds it — a bad key and
    /// a wrong one read the same from there — so the load is the last place
    /// this can be caught with something to say about why.
    #[test]
    fn a_public_key_that_is_not_a_key_is_refused_at_load() {
        let err = load_from(
            r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.server]
public_key = "not a key"
"#,
        )
        .expect_err("a public_key that is not a key must not load");

        assert!(err.to_string().contains("devices.server"), "{err}");
        assert!(err.to_string().contains("not hex"), "{err}");
    }

    /// Why a device entry refuses keys it does not know, which is the reason
    /// every `[auth]` table does: `secrets` for `secret` would leave the device
    /// with no credential at all, and nothing would say so.
    #[test]
    fn an_unknown_device_key_is_refused_rather_than_ignored() {
        let err = load_from(
            r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"

[auth.clients.client-001.devices.laptop]
secrets = "LAPTOPSECRET"
"#,
        )
        .expect_err("a typo must not leave a device without a credential");

        assert!(err.to_string().contains("secrets"), "{err}");
    }

    /// A device name is written into the log line for everything that happens
    /// to it, and it is what an operator names when revoking one — so it is
    /// held to what a client id is before it is ever accepted.
    #[test]
    fn a_device_name_is_refused_before_it_reaches_a_log_line() {
        let client = r#"
[auth.clients.client-001]
secret = "CLIENTSECRET"
"#;

        let err = load_from(&format!(
            "{client}\n[auth.clients.client-001.devices.\"\"]\nsecret = \"LAPTOPSECRET\"\n"
        ))
        .expect_err("an unnamed device is not a device");
        assert!(err.to_string().contains("needs a name"), "{err}");

        let err = load_from(&format!(
            "{client}\n[auth.clients.client-001.devices.\"laptop\\r\\nINFO: connected\"]\n\
             secret = \"LAPTOPSECRET\"\n"
        ))
        .expect_err("a name that ends its own log line must not load");
        assert!(err.to_string().contains("printable ASCII"), "{err}");
    }

    // -----------------------------------------------------------------------
    // The endpoint identity
    //
    // The property being pinned throughout: a config that never mentions
    // `[iroh] secret_key` comes out of the first start with a Node ID that is
    // still the same one after the next. Everything else here is about not
    // breaking the operator's file on the way there.
    // -----------------------------------------------------------------------

    /// A config with no `[iroh]` section at all gains one holding the key, and
    /// nothing else. This is the three-line config the README's quick start
    /// tells people to write, so it is the case that has to work.
    #[test]
    fn a_config_without_iroh_gains_the_key() {
        let (_dir, path) = scratch_config(
            "[[routes]]\n\
             host_pattern = \"*\"\n\
             backends = [\"http://127.0.0.1:18080\"]\n",
        );

        let identity =
            ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
                .expect("the identity is resolved");

        let EndpointIdentity::Generated(key) = identity else {
            panic!("a missing key has to be generated and written");
        };
        key.parse::<iroh::SecretKey>()
            .expect("the written key parses as an ed25519 secret key");

        let config = parse(&fs::read_to_string(&path).expect("the config is still there"));
        assert_eq!(
            config.iroh.and_then(|iroh| iroh.secret_key).as_deref(),
            Some(key.as_str()),
            "the key has to be on disk, not only in memory"
        );
        // And the rest of the file is untouched.
        assert!(
            config
                .routes
                .expect("the routes survived")
                .iter()
                .any(|route| route.host_pattern == "*"),
            "the generated key must not cost the operator their routes"
        );
    }

    /// An `[iroh]` section that exists for other reasons keeps them. Losing
    /// `relay_mode = "pinned"` because a key was written would silently change
    /// which relays the endpoint uses.
    #[test]
    fn an_existing_iroh_section_keeps_its_other_keys() {
        let (_dir, path) = scratch_config(
            "[iroh]\n\
             relay_mode = \"pinned\"\n\
             bind_port = 41641\n",
        );

        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the identity is resolved");

        let written = fs::read_to_string(&path).expect("the config is still there");
        let config = parse(&written);
        let iroh = config.iroh.expect("[iroh] survived");
        assert_eq!(iroh.relay_mode.as_deref(), Some("pinned"));
        assert_eq!(iroh.bind_port, Some(41641));
        assert!(
            iroh.secret_key.is_some(),
            "the key belongs in the section that was already there"
        );
    }

    /// The comments an operator wrote around the spot are the reason the file is
    /// edited as TOML instead of re-serialized. `config.toml.example` is 368
    /// lines of prose, and a first start that flattened it to three keys would
    /// be a nasty surprise.
    #[test]
    fn the_comments_around_the_key_survive() {
        let (_dir, path) = scratch_config(
            "# My edge box in the shed.\n\
             [iroh]\n\
             # Turned on after the relay migration.\n\
             relay_mode = \"pinned\"\n",
        );

        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the identity is resolved");

        let written = fs::read_to_string(&path).expect("the config is still there");
        assert!(
            written.contains("# My edge box in the shed."),
            "the header comment was lost:\n{written}"
        );
        assert!(
            written.contains("# Turned on after the relay migration."),
            "the comment on the key above was lost:\n{written}"
        );
    }

    /// A key that is already configured is used as it stands. Writing a fresh
    /// one here would rotate the endpoint's identity on every restart, which is
    /// the exact failure this whole mechanism exists to remove.
    ///
    /// The key is generated rather than written out as a literal. A hardcoded
    /// hex string sitting under a `secret_key` key is what a credential scanner
    /// is built to catch, and it is right to: once such a line is in the history
    /// nobody reviewing a diff can tell a fixture from a real key any more.
    #[test]
    fn a_configured_key_is_left_alone() {
        let key = generate_secret_key_hex();
        let (_dir, path) = scratch_config(&format!("[iroh]\nsecret_key = \"{key}\"\n"));

        let identity =
            ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
                .expect("the identity is resolved");

        assert_eq!(identity, EndpointIdentity::Configured(key.clone()));
        assert_eq!(
            fs::read_to_string(&path).expect("the config is still there"),
            format!("[iroh]\nsecret_key = \"{key}\"\n"),
            "a configured key must not be rewritten"
        );
    }

    /// A key that does not parse refuses the start. It used to be a warning and
    /// a random key, which left the endpoint on a different Node ID after every
    /// restart — every stored Node ID stale, and the log saying it had been
    /// handled.
    #[test]
    fn an_unparseable_key_refuses_rather_than_rotating() {
        let broken = "[iroh]\nsecret_key = \"not-a-key\"\n";
        let (_dir, path) = scratch_config(broken);

        let err = ProxyConfig::ensure_iroh_secret_key(&path, &parse(broken))
            .expect_err("a key that does not parse must not be papered over");

        let message = err.to_string();
        assert!(
            message.contains("not a valid key"),
            "the refusal names the problem: {message}"
        );
        assert!(
            message.contains("every restart"),
            "the refusal says what it would have cost: {message}"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("the config is still there"),
            broken,
            "the operator's typo has to survive so they can see it"
        );
    }

    /// Two starts in a row have to land on the same Node ID. Without this the
    /// mechanism could write a key on the first run and still let a later one
    /// replace it, which is the bug in a slower form.
    /// Two starts in a row land on the same key.
    ///
    /// The variants differ between the two calls — the first start generates, the
    /// second finds what the first wrote — so this compares the keys themselves.
    /// Asserting the variants would pin the wrong thing: what has to be stable is
    /// the identity, not which branch produced it.
    #[test]
    fn the_node_id_survives_a_restart() {
        let (_dir, path) = scratch_config("debug = true\n");

        let first =
            ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
                .expect("the first start resolves an identity");
        let second =
            ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
                .expect("the second start resolves an identity");

        assert_eq!(
            first.key(),
            second.key(),
            "the second start has to find the key the first one wrote"
        );
        assert_eq!(
            public_key(first.key()),
            public_key(second.key()),
            "and therefore the same Node ID"
        );
    }

    /// The public key of a hex secret key.
    fn public_key(hex_key: &str) -> String {
        iroh::SecretKey::from_bytes(
            &hex::decode(hex_key)
                .expect("the key is hex")
                .try_into()
                .expect("32 bytes"),
        )
        .public()
        .to_string()
    }

    /// The env var that turns persistence off is read as an operator would expect.
    ///
    /// A compose file that lists a variable with no value (`- NEXAPIPE_NO_PERSIST_IDENTITY`)
    /// is asking for the default, not for the behaviour — so empty means "no", like
    /// unset. The end-to-end half of this (the server really does leave the file
    /// alone) is in `tests/first_run_identity.rs`, which can set the variable on a
    /// child process without `unsafe`.
    #[test]
    fn the_no_persist_flag_reads_the_way_it_looks() {
        for off in [
            None,
            Some(""),
            Some("  "),
            Some("0"),
            Some("false"),
            Some("FALSE"),
        ] {
            assert!(
                !persistence_disabled(off),
                "{off:?} has to mean persistence stays on"
            );
        }
        for on in [Some("1"), Some("true"), Some("yes"), Some("anything else")] {
            assert!(
                persistence_disabled(on),
                "{on:?} has to turn persistence off"
            );
        }
    }

    /// An unwritable config is an ordinary deployment (a read-only bind mount, a
    /// A config that reads fine but cannot be written is an ordinary deployment (a
    /// read-only bind mount, a file owned by another user), and it has to keep
    /// working. The old code path here was "no key configured, random identity,
    /// carry on"; refusing to start would make this change a regression for exactly
    /// that case.
    ///
    /// Reachable portably by pointing at a file that is not TOML: the caller already
    /// parsed a config (that is what `config` is), and the writer re-reads the
    /// path, so the two can disagree — an operator saving over the file mid-start is
    /// the realistic version of it.
    #[test]
    fn an_unwritable_config_still_resolves_an_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "this is not TOML at all: \"\n").expect("write a file that is not TOML");
        let path = path.to_string_lossy().into_owned();

        let identity = ProxyConfig::ensure_iroh_secret_key(&path, &parse("debug = true\n")).expect(
            "a file the server cannot write must not stop it: the key is generated either way",
        );

        assert!(
            matches!(identity, EndpointIdentity::Ephemeral(_)),
            "a failed write has to degrade to a throwaway identity, got {identity:?}"
        );
        // Still a usable key, or the server would be refusing connections for a
        // reason that has nothing to do with why the write failed.
        assert_eq!(
            identity.key().len(),
            64,
            "an ephemeral key is still a full ed25519 key"
        );
        public_key(identity.key());
    }

    /// `EndpointIdentity` must not print its key.
    ///
    /// Every variant of it *is* the ed25519 private key, and this enum reaches
    /// a `{:?}` on the failure path of this very module, where the message goes
    /// to CI and stays there. A derived `Debug` — the obvious way to write this
    /// type — would put a live key on that line while the suite still reported
    /// green.
    ///
    /// Pinned rather than left to review because the mistake is invisible in the
    /// diff that adds the enum: nothing about `#[derive(Debug)]` looks wrong
    /// until you know what the type holds.
    #[test]
    fn an_identity_never_prints_its_key() {
        for identity in [
            EndpointIdentity::Configured(generate_secret_key_hex()),
            EndpointIdentity::Generated(generate_secret_key_hex()),
            EndpointIdentity::Ephemeral(generate_secret_key_hex()),
        ] {
            let rendered = format!("{identity:?}");
            assert!(
                !rendered.contains(identity.key()),
                "{rendered} leaked the private key"
            );
            assert!(
                rendered.contains("<redacted>"),
                "{rendered} should say the key was withheld"
            );
        }
    }

    /// The variant survives redaction: it is the one thing a reader of that log
    /// line needs — which of the three paths produced this identity.
    #[test]
    fn an_identity_still_says_which_path_it_came_from() {
        let rendered = |identity: EndpointIdentity| format!("{identity:?}");
        assert!(rendered(EndpointIdentity::Configured(String::new())).contains("Configured"));
        assert!(rendered(EndpointIdentity::Generated(String::new())).contains("Generated"));
        assert!(rendered(EndpointIdentity::Ephemeral(String::new())).contains("Ephemeral"));
    }

    /// The generated key is a private key, so the file it lands in must be
    /// private. This is the same rule `check_credential_file_permissions`
    /// refuses a load over, so the write has to satisfy it rather than leave
    /// the next start to find its own output and reject it.
    #[cfg(unix)]
    #[test]
    fn a_generated_key_lands_in_a_private_file() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = scratch_config("debug = true\n");
        ProxyConfig::ensure_iroh_secret_key(&path, &parse(&fs::read_to_string(&path).unwrap()))
            .expect("the identity is resolved");

        let mode = fs::metadata(&path)
            .expect("the config is there")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a file holding the endpoint's private key must be private, got {mode:o}"
        );
    }
}
