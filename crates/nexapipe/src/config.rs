use crate::routes::{L4Options, Route};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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

#[derive(Deserialize, Clone)]
pub struct IrohConfig {
    pub relay_url: Option<String>,
    pub relay_mode: Option<String>,
    /// Bearer token sent to the relay. Only meaningful with `relay_mode = "custom"`;
    /// a relay that requires one has to be configured on both sides, because the
    /// client's relay map is the only place its token is read from.
    pub relay_auth_token: Option<String>,
    pub bind_port: Option<u16>,
    /// Secret key for stable endpoint identity.
    /// If provided, the endpoint will have the same Node ID across restarts.
    /// Can be generated using `nexapipe --generate-secret` command.
    pub secret_key: Option<String>,
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
            .field("secret_key", &redacted(&self.secret_key))
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
    /// default (`l4::DEFAULT_UDP_IDLE_TIMEOUT`) applies when this is absent.
    pub idle_timeout_secs: Option<u64>,

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

/// The `[health_check]` section: periodic `GET {path}` probing of `http` route
/// backends.
///
/// A switch rather than a behaviour everyone gets, because a probe is only
/// meaningful if the backend answers it. Plenty of backends — a static file
/// server, a device's web UI, anything that 404s or hangs on an unknown path —
/// cannot answer `GET /health` at all, and before this section existed a single
/// failed probe was enough to take such a backend out of rotation for good. Set
/// `enabled = false` for those: every backend stays in the pool and traffic is
/// simply forwarded, which is what the proxy did before health checks existed.
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
}

/// The `[peers]` section: a server-side allow-list of client public keys.
///
/// Deliberately not a key under `[auth]`. It is the knob for exactly the server
/// the "no allow-list" gap describes — one running with 2FA off — so tying it to
/// a section that server may not even have would bury it, and its semantics do
/// not depend on `[auth] enabled` either way. `[peers]` is checked on every
/// inbound connection, before the accept loop sees it.
#[derive(Debug, Clone, Deserialize, Default)]
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
    /// Turns the `[[routes]]` table into the objects the proxy actually routes
    /// with, rejecting anything that cannot work.
    ///
    /// Shared by the startup path and the config watcher: a reload has to build
    /// routes exactly the way a cold start does, or an edit would behave
    /// differently depending on when it was made. An error here is not fatal for
    /// a reload — the caller keeps the routes it already has.
    pub fn build_routes(&self) -> anyhow::Result<Vec<Route>> {
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
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;

        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }
}

pub fn get_strategy(strategy: &Option<String>) -> crate::lb::LoadBalancingStrategy {
    match strategy.as_deref() {
        Some("random") | Some("Random") => crate::lb::LoadBalancingStrategy::Random,
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => {
            crate::lb::LoadBalancingStrategy::RoundRobin
        }
        None | Some(_) => crate::lb::LoadBalancingStrategy::RoundRobin,
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
    // Passthrough only needs a host and a port; the scheme carries no meaning
    // because those bytes are never interpreted.
    if mode == RouteMode::Passthrough {
        return Ok(());
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
    /// Runtime counters written back by the server (see
    /// `config_watcher::save_auth_state`); read here so a lockout survives a
    /// restart.
    pub failed_attempts: Option<u32>,
    pub locked_until: Option<u64>,
    pub last_used: Option<u64>,
}

/// Warns when the config file is reachable by accounts other than its owner.
///
/// Refusing is not always an option — the caller may be rewriting the file long
/// after startup, where failing would take a running proxy down — so this is the
/// report-only half. [`check_config_permissions`] is the one that gates a start.
#[cfg(unix)]
pub fn warn_world_readable_config(path: &str) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        tracing::error!(
            "{path} is readable or writable by other accounts (mode {mode:o}) and holds the 2FA \
             secrets; run `chmod 600 {path}`"
        );
    }
}

/// No file modes to inspect outside Unix, so there is nothing to warn about.
#[cfg(not(unix))]
pub fn warn_world_readable_config(_path: &str) {}

/// The refusal for a config file other accounts can reach, if there should be
/// one.
///
/// `[auth.clients]` holds the TOTP secrets, and those secrets are the *only*
/// credential gating the iroh listener: the HMAC in every AUTH_RESPONSE is keyed
/// with one, so anybody who can read this file can authenticate as that client
/// for as long as the secret lives — and `save_auth_state` rewrites the file on
/// every failed attempt, so a permissive mode is not a one-off leak but a
/// standing one. Where the secrets are the live credential that is worth
/// refusing a start over; the IPC token check (`reject_world_readable`) already
/// refuses for the same reason, and a warning that only turns up in a rotated
/// log is how a permissive mode survives for years.
///
/// With `[auth]` disabled none of it authenticates anybody, and a 0644 config is
/// a fixture of Docker deployments: those keep the warning.
///
/// `mode` is passed in rather than read from the file so the rule can be tested
/// everywhere, including on the platforms with no file modes to inspect.
pub(crate) fn world_readable_refusal(path: &str, mode: u32, auth_enabled: bool) -> Option<String> {
    (mode & 0o077 != 0 && auth_enabled).then(|| {
        format!(
            "{path} is readable or writable by other accounts (mode {mode:o}) and holds the 2FA \
             secrets: with [auth] enabled those secrets are the only credential gating the iroh \
             listener, so every account on this host can authenticate as every client. Run \
             `chmod 600 {path}`, or disable [auth]"
        )
    })
}

/// Checks the config file's permissions before its secrets become live.
///
/// Refuses when `[auth]` is enabled and the file is not private, warns
/// otherwise. A file that cannot be stat'ed is not this function's problem: the
/// caller has already read it to get here.
#[cfg(unix)]
pub fn check_config_permissions(path: &str, auth_enabled: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if let Some(refusal) = world_readable_refusal(path, mode, auth_enabled) {
        anyhow::bail!(refusal);
    }
    if mode & 0o077 != 0 {
        tracing::error!(
            "{path} is readable or writable by other accounts (mode {mode:o}); [auth] is not \
             enabled, so nothing in it authenticates anybody yet — run `chmod 600 {path}` before \
             enabling it"
        );
    }
    Ok(())
}

/// No file modes to inspect outside Unix, so there is nothing to refuse.
#[cfg(not(unix))]
pub fn check_config_permissions(_path: &str, _auth_enabled: bool) -> anyhow::Result<()> {
    Ok(())
}

impl ProxyConfig {
    /// Load config and extract auth settings from TOML
    pub fn load_with_auth(path: &str) -> anyhow::Result<(Self, Option<crate::auth::AuthConfig>)> {
        let content = std::fs::read_to_string(path)?;

        // Parse the base config
        let base: Self = toml::from_str(&content)?;

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
                            clients.insert(
                                id,
                                crate::auth::ClientAuth {
                                    secret: client_toml.secret,
                                    created_at: client_toml.created_at.unwrap_or_else(|| {
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_secs().to_string())
                                            .unwrap_or_else(|_| "0".to_string())
                                    }),
                                    allow_hosts: client_toml.allow_hosts,
                                    pending_enrollment: client_toml.pending_enrollment,
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

        fs::write(path, doc.to_string())
            .map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))?;

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

        fs::write(path, doc.to_string()).map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))
    }

    /// Spends the token: writes the issued `secret` and drops
    /// `pending_enrollment`, so the same link cannot enroll twice.
    ///
    /// Both keys are written in one pass on purpose. A secret on disk with the
    /// token still beside it would leave the window open for a second device to
    /// trade the same link for the same credential.
    pub fn complete_enrollment(path: &str, client_id: &str, secret: &str) -> anyhow::Result<()> {
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

        fs::write(path, doc.to_string()).map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))
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

    /// A mode only the owner can reach is never a reason to refuse; anything
    /// group- or world-reachable is, even without the read bit — one write is
    /// enough to swap a secret.
    #[test]
    fn only_a_private_config_passes_with_2fa_on() {
        assert_eq!(world_readable_refusal("config.toml", 0o600, true), None);
        assert!(world_readable_refusal("config.toml", 0o644, true).is_some());
        assert!(world_readable_refusal("config.toml", 0o640, true).is_some());
        assert!(world_readable_refusal("config.toml", 0o602, true).is_some());
    }

    /// With `[auth]` off nothing in the file authenticates anybody, and 0644 is
    /// how a Docker bind mount arrives: warn, do not refuse.
    #[test]
    fn a_permissive_config_is_only_warned_about_with_2fa_off() {
        assert_eq!(world_readable_refusal("config.toml", 0o644, false), None);
    }

    /// A refusal that does not say how to fix it is a support ticket.
    #[test]
    fn the_refusal_names_the_fix() {
        let refusal = world_readable_refusal("/etc/nexapipe/config.toml", 0o644, true)
            .expect("0644 with 2FA on is refused");
        assert!(
            refusal.contains("chmod 600 /etc/nexapipe/config.toml"),
            "{refusal}"
        );
    }

    #[cfg(unix)]
    fn chmod(path: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// The check the startup path runs, against a real file: the same mode has
    /// to be fatal once the secrets are live and survivable before they are.
    #[cfg(unix)]
    #[test]
    fn startup_check_refuses_only_while_the_secrets_are_live() {
        let (_dir, path) = scratch_config("default_backend = \"http://127.0.0.1:15666\"\n");

        chmod(&path, 0o600);
        check_config_permissions(&path, true).expect("0600 starts with 2FA on");

        chmod(&path, 0o644);
        let err = check_config_permissions(&path, true).expect_err("0644 is fatal with 2FA on");
        assert!(err.to_string().contains("chmod 600"), "{err}");
        check_config_permissions(&path, false).expect("0644 still starts with 2FA off");
    }

    /// A file the caller could not even stat has already failed to be read; the
    /// permission check is not the place to report that.
    #[cfg(unix)]
    #[test]
    fn startup_check_passes_a_file_it_cannot_stat() {
        check_config_permissions("/nonexistent/config.toml", true)
            .expect("a missing config is reported by the loader, not here");
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
            secret_key: Some("ed25519-private-key".to_string()),
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
}
