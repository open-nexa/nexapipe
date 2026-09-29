pub mod local_proxy;

use crate::admin;
use crate::auth::AuthConfig;
use crate::config::{
    AdminConfig, HealthCheckConfig, IrohConfig, LocalProxyConfig, MetricsConfig, RouteMode,
    ServerConfig,
};
use crate::config_watcher::{ConfigWatcher, PlaintextListener};
use crate::conn;
use crate::health::{HealthChecker, HealthProbes};
use crate::http;
use crate::lb::BackendPool;
use crate::log;
use crate::passthrough;
use crate::routes::RouteConfig;
use crate::shutdown::{DRAIN_TIMEOUT, InFlight, ShutdownSignal};
use anyhow::Context;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::client::legacy;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use nexapipe_client::relay::RelayModeSpec;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Shared by the startup path and the config watcher, which spawns checkers for
/// routes that appear in a reload.
pub type HttpClient =
    legacy::Client<legacy::connect::HttpConnector, http_body_util::Full<bytes::Bytes>>;

/// One background `GET /health` probe per `http` route, kept in step with the
/// routes that are live.
///
/// Called at startup and again after every reload, and it reconciles rather
/// than only adding: a probe whose route was deleted, or whose backends
/// changed, is stopped, because it is watching a pool the routing table no
/// longer hands out. What is left running is a probe whose pool is still the
/// live one — which is what keeps a reload from silently unhooking health
/// checks from the pool traffic actually uses.
pub async fn sync_health_checks(
    config: &Arc<RouteConfig>,
    http_client: &Arc<HttpClient>,
    probes: &tokio::sync::Mutex<HealthProbes>,
    health: &HealthCheckConfig,
    enabled: &Arc<std::sync::atomic::AtomicBool>,
) {
    // Which routes want a probe right now, and on which pool. Taken before the
    // lock on the probes, because none of it depends on them.
    let mut wanted: std::collections::HashMap<String, Arc<BackendPool>> =
        std::collections::HashMap::new();

    for route in config.routes().await {
        // Only an http:// backend answers `GET /health`. A passthrough backend is
        // a TLS listener and an L4 backend is whatever the route points at — a
        // database, a TURN server, an SSH daemon. Probing either would fail, mark
        // the backend down, and the pool would then quietly fall back to its first
        // entry. There is nothing to probe without speaking the protocol, so the
        // pool is left alone; a dead backend shows up as a connect error when a
        // flow arrives.
        // A route serving `http` *and* something else is still probed: the pool
        // is shared, so its health is what the other modes dial into as well.
        if !route.serves(RouteMode::Http) {
            tracing::info!(
                "Route {}: modes={:?}, skipping the HTTP health check",
                route.host_pattern(),
                route.modes()
            );
            continue;
        }

        wanted.insert(route.pool_key().await, route.backend_pool().clone());
    }

    let mut probes = probes.lock().await;

    // Before anything is started: a probe is only worth keeping if the route it
    // belongs to still wants a probe on that same pool.
    probes.stop_stale(&wanted);

    // Backends that cannot answer a probe are a supported deployment, not an
    // error, so nothing is started rather than configured around it.
    if !health.enabled {
        tracing::debug!("Health checks disabled, no probes started");
        return;
    }

    for (key, backend_pool) in wanted {
        if probes.contains(&key) {
            continue;
        }

        let health_checker = HealthChecker::new(
            backend_pool.clone(),
            http_client.clone(),
            std::time::Duration::from_secs(health.interval.max(1)),
            std::time::Duration::from_secs(health.timeout.max(1)),
            health.threshold,
            &health.path,
            enabled.clone(),
        );
        probes.spawn(key, backend_pool, health_checker);
    }
}

/// How long the plaintext listener waits for a first byte before handing the
/// connection to the HTTP server. Long enough for a TLS `ClientHello` to
/// arrive, short enough not to park the task.
const FIRST_BYTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What [`run_proxy`] needs from the parsed config file.
///
/// A struct rather than a longer argument list: these are all "a section of
/// `config.toml`", and every one of them is optional, so a positional list was
/// one more section away from being unreadable at the call site.
pub struct ProxyOptions {
    pub server: Option<ServerConfig>,
    pub iroh: Option<IrohConfig>,
    pub auth: Option<AuthConfig>,
    pub peers: Option<conn::allow_list::PeerAllowList>,
    pub health_check: HealthCheckConfig,
    /// The auxiliary listener for `/healthz` and `/metrics`. `None` means it is
    /// not bound.
    pub admin: Option<AdminConfig>,
    /// Whether `/metrics` is served on it.
    pub metrics: MetricsConfig,
}

pub async fn run_proxy(
    config: Arc<RouteConfig>,
    config_path: &str,
    shutdown_signal: Arc<ShutdownSignal>,
    options: ProxyOptions,
) -> anyhow::Result<()> {
    let ProxyOptions {
        server: server_config,
        iroh: iroh_config,
        auth: auth_config,
        peers: peer_allow_list,
        health_check,
        admin: admin_config,
        metrics: metrics_config,
    } = options;

    // Read from for `nexapipe_uptime_seconds`. Taken here rather than in
    // `main` so a `--local-proxy` run never sets it: there is one process-wide
    // start time, and the mode that does not scrape should not own it.
    crate::metrics::mark_start();

    let http_client = Arc::new(http::create_http_client());

    let health_probes = Arc::new(tokio::sync::Mutex::new(HealthProbes::new()));
    let health_enabled = Arc::new(std::sync::atomic::AtomicBool::new(health_check.enabled));
    // Shared by both accept loops: a shutdown has to wait for the work they
    // spawned, not for a fixed number of seconds.
    let in_flight = Arc::new(InFlight::new());
    sync_health_checks(
        &config,
        &http_client,
        &health_probes,
        &health_check,
        &health_enabled,
    )
    .await;

    // 2FA state: the shared config plus the file its lockout counters persist
    // to.
    //
    // Built even when the config carries no `[auth]` section. Leaving it absent
    // would give the watcher nothing to reload into, so a deployment that
    // started without 2FA could never turn it on while running — and adding the
    // section to a live server is exactly what someone enabling it for the
    // first time does. The default config is `enabled = false` with no clients,
    // so until the file says otherwise this behaves like the no-2FA case:
    // `conn::handle_connection` reads `enabled` per connection and skips the
    // handshake while it is false.
    let auth_state = Some(conn::AuthState::new(
        auth_config.unwrap_or_default(),
        config_path,
    ));

    // The watcher needs three things to apply a reload: it rebuilds the routes,
    // restarts whatever health checks the new routes need, swaps in the
    // `[auth.clients]` table the file now carries — so an invite generated while
    // the server runs works without a restart — and moves `[auth] enabled` when
    // the file turns 2FA on. `plaintext` is filled in further down, once the
    // listener has been bound; the watcher is an `Arc` by then, so the field is
    // set through `OnceLock` rather than a constructor argument.
    let config_watcher = Arc::new(ConfigWatcher::new(
        config_path.to_string(),
        config.clone(),
        http_client.clone(),
        health_probes,
        health_enabled,
        auth_state.clone(),
    ));
    tokio::spawn({
        let config_watcher_clone = config_watcher.clone();
        async move {
            config_watcher_clone.start_watch().await;
        }
    });
    tracing::info!("Config watcher started, monitoring: {}", config_path);

    // Whether 2FA gates the iroh listener *right now*. The value is live — a
    // reload can turn it on, taking effect for connections opened after it — so
    // this is a startup reading, used for the two startup warnings below and
    // nothing else. Nothing later in this function may cache it.
    let auth_enabled = match &auth_state {
        Some(state) => state.config().read().await.enabled,
        None => false,
    };

    // A connection ticket or node id is a *reachability* credential, not an
    // authentication one: without 2FA, anyone who obtains either reaches every
    // route and every backend. That is easy to miss when the config simply has
    // no `[auth]` section yet, so it is said out loud rather than left to the
    // reader of the docs. An allow-list narrows it, so the wording says which of
    // the two is actually holding the line.
    if !auth_enabled {
        match &peer_allow_list {
            Some(list) if list.is_configured() => {
                tracing::warn!(
                    "2FA is not enabled: peers are gated by the [peers] allow list ({} Node IDs) \
                     instead, so a Node ID or ticket that is not on it is refused",
                    list.len()
                );
            }
            _ => {
                tracing::warn!(
                    "2FA is not enabled: the endpoint's node id and ticket alone reach every route"
                );
                eprintln!(
                    "\n*** WARNING: 2FA authentication is NOT enabled. ***\n\
                     Anyone who obtains this endpoint's Node ID or ticket can connect and\n\
                     reach every route and every backend. Add an [auth] section with\n\
                     enabled = true (see config.toml.2fa.example) to require credentials, or\n\
                     a [peers] allow list to restrict which Node IDs may connect at all.\n"
                );
            }
        }
    }

    let mut builder = Endpoint::builder(presets::N0).alpns(vec![ALPN_NEXAPIPE.to_vec()]);

    // Which relay we use, resolved by the same code the clients use, so the two cannot drift
    // apart. `None` means nothing was configured, which is iroh's default (every N0 relay).
    // Everything else either resolves or fails startup: `relay_mode` used to be ignored
    // entirely unless `relay_url` was also set, and a `relay_url` on its own was logged and
    // then dropped — both of which let a broken configuration run unchanged.
    let relay = RelayModeSpec::parse(
        iroh_config.as_ref().and_then(|c| c.relay_mode.as_deref()),
        iroh_config.as_ref().and_then(|c| c.relay_url.as_deref()),
        iroh_config
            .as_ref()
            .and_then(|c| c.relay_auth_token.as_deref()),
    )
    .context("invalid [iroh] relay configuration")?;
    if let Some(relay) = &relay {
        tracing::info!("Relay: {}", relay.describe());
        if !relay.uses_url()
            && let Some(url) = iroh_config.as_ref().and_then(|c| c.relay_url.as_deref())
        {
            tracing::warn!(
                "[iroh] relay_url {url:?} is set but this mode does not use one; ignoring it"
            );
        }
        builder = builder.relay_mode(relay.relay_mode());
    }

    if let Some(iroh_cfg) = iroh_config {
        // Use configured secret key for stable endpoint identity
        if let Some(secret_key_str) = &iroh_cfg.secret_key {
            match secret_key_str.parse::<SecretKey>() {
                Ok(secret_key) => {
                    builder = builder.secret_key(secret_key);
                    tracing::info!("Using configured secret key for stable endpoint identity");
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse secret_key from config, generating new one: {}",
                        e
                    );
                }
            }
        }

        if let Some(port) = iroh_cfg.bind_port {
            let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))
                .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
            builder = builder.bind_addr(addr)?;
            tracing::info!("Iroh bind port: {}", port);
        }
    }

    // QUIC transport tuning: one inner TCP connection maps to one QUIC bi-stream, so the
    // per-stream receive window sets the throughput ceiling of every proxied connection.
    // See nexapipe_client::transport for the numbers and the override variables.
    let transport_tuning = nexapipe_client::transport::TransportTuning::from_env();
    tracing::info!("QUIC transport tuning: {}", transport_tuning.describe());
    let mut builder = builder.transport_config(transport_tuning.transport_config());

    // The allow-list is installed as an endpoint hook rather than checked in the
    // accept loop, which is what makes a refusal cost the peer a close frame and
    // nothing else: the hook runs inside `accept`, so a refused connection never
    // becomes an `Incoming`, never takes a per-peer slot and never gets a task.
    // Installed last, so it is the final word on whether a handshake that got
    // this far is allowed to proceed.
    if let Some(list) = peer_allow_list {
        tracing::info!(
            "Peer allow-list active: {} Node IDs; every other peer is closed right after the \
             QUIC handshake",
            list.len()
        );
        builder = builder.hooks(list);
    }

    let ep = builder.bind().await?;

    let node_id = ep.id();
    let node_addr = ep.addr();

    tracing::info!("Iroh proxy endpoint started successfully");
    tracing::info!("Node ID: {}", node_id);

    for (i, route) in config.routes().await.into_iter().enumerate() {
        tracing::info!(
            "Route {}: host={}, path={} (prefix={}), backends={}, strategy={:?}",
            i + 1,
            route.host_pattern(),
            route.path_pattern(),
            route.path_is_prefix(),
            route.backend_pool().len(),
            route.backend_pool().strategy()
        );
    }

    let ticket = EndpointTicket::new(node_addr);
    let ticket_str = ticket.encode_string();

    println!("\n========================================");
    println!("Proxy Connection Information");
    println!("========================================");
    println!("Node ID (stable, for server_node_id): {}", node_id);
    println!("Ticket (for clients): {}", ticket_str);
    println!("========================================");
    println!("To use stable connection, add to [local_proxy] in config.toml:");
    println!("server_node_id = \"{}\"", node_id);
    println!("========================================\n");

    tracing::info!("Connection ticket: {}", ticket_str);
    tracing::info!("Node ID (for server_node_id config): {}", node_id);

    // ===== Plaintext listener =====
    //
    // Only bound when `[server] listen_addr` says so. This listener is the one
    // entry point 2FA does not cover: the handshake lives in the iroh accept
    // loop above, so anything served here answers before a credential has ever
    // been asked for. It exists for a client on the same host, and a
    // non-loopback bind has to be asked for explicitly with `[server] expose`.
    let listen_addr = server_config.as_ref().and_then(|s| s.listen_addr.clone());
    let exposed = server_config
        .as_ref()
        .and_then(|s| s.expose)
        .unwrap_or(false);

    // The watcher has to reach the same verdict on a reload that turns 2FA on,
    // and its first poll is 5 s away, so the address is recorded before the
    // accept loop starts.
    let mut plaintext = None;

    let http_listener = match listen_addr {
        Some(addr) => {
            let listener = TcpListener::bind(&addr).await?;
            // Decided after the bind rather than by parsing the address: this
            // way `0.0.0.0`, `[::]` and a concrete LAN address all get judged
            // by what the socket actually became.
            let bound = listener.local_addr()?;
            if !may_bind_plaintext(bound, exposed) {
                anyhow::bail!(
                    "[server] listen_addr binds {bound}, which is reachable from the network, and \
                     the plaintext listener cannot authenticate: every request reaching it goes \
                     straight to a route. Use a loopback address, or set [server] expose = true \
                     when something else gates the port"
                );
            }
            if let Some(refusal) = plaintext_auth_conflict(bound, exposed, auth_enabled) {
                anyhow::bail!(refusal);
            }
            tracing::info!("HTTP server listening on: {}", bound);
            plaintext = Some(PlaintextListener {
                addr: bound,
                exposed,
            });
            Some(listener)
        }
        None => {
            tracing::info!(
                "No [server] listen_addr configured, the plaintext listener stays closed: \
                 traffic has to come in over iroh"
            );
            None
        }
    };

    if let Some(listener) = plaintext {
        config_watcher.set_plaintext_listener(listener);
    }

    // ===== Auxiliary listener =====
    //
    // `/healthz` and `/metrics`, and later the management endpoints. Bound here
    // and never rebound: moving a listener is a restart, which is why
    // `[admin] listen_addr` is the one setting a config reload does not apply.
    let admin_listener = match admin_config.as_ref().and_then(|a| a.listen_addr.clone()) {
        Some(addr) => {
            let listener = TcpListener::bind(&addr).await?;
            // Judged after the bind, like the plaintext listener: only the
            // address the socket actually became says whether it is reachable.
            let bound = listener.local_addr()?;
            if !admin::may_bind_admin(bound) {
                anyhow::bail!("{}", admin::non_loopback_refusal(bound));
            }
            tracing::info!("Admin listener on: {} (/healthz)", bound);
            Some(listener)
        }
        None => {
            // Only worth saying when someone asked for metrics and will now
            // find nothing there: a deployment with no scraper needs no line
            // telling it the listener it never configured is closed.
            if metrics_config.enabled {
                tracing::warn!(
                    "[metrics] enabled = true but there is no [admin] listen_addr, so /metrics is \
                     not served: add an [admin] section with a loopback address"
                );
            }
            None
        }
    };

    let mut admin_server = None;
    if let Some(listener) = admin_listener {
        if metrics_config.enabled {
            tracing::info!("Metrics enabled, serving /metrics on the admin listener");
        }
        let config_clone = config.clone();
        let shutdown_signal_clone = shutdown_signal.clone();
        let in_flight_clone = in_flight.clone();

        admin_server = Some(tokio::spawn(async move {
            if let Err(e) = admin::serve_admin(
                listener,
                config_clone,
                in_flight_clone,
                metrics_config.enabled,
                shutdown_signal_clone,
            )
            .await
            {
                tracing::error!("Admin listener failed: {}", e);
            }
        }));
    }

    // One limiter for the whole endpoint: the per-peer cap only means anything
    // if every accepted connection counts against the same map.
    let conn_limiter = conn::limits::ConnectionLimiter::from_env();
    tracing::info!(
        "At most {} concurrent connections per peer",
        conn_limiter.max()
    );

    // Kept, rather than spawned and forgotten: the drain below counts work that
    // is still running, and a listener that has not stopped accepting yet is
    // still able to add to it. Its handle is the only way to know it has
    // stopped.
    let mut http_server = None;
    if let Some(http_listener) = http_listener {
        let config_clone = config.clone();
        let http_client_clone = http_client.clone();
        let shutdown_signal_clone = shutdown_signal.clone();
        let in_flight_clone = in_flight.clone();

        http_server = Some(tokio::spawn(async move {
            if let Err(e) = start_http_server(
                http_listener,
                config_clone,
                http_client_clone,
                shutdown_signal_clone,
                in_flight_clone,
            )
            .await
            {
                tracing::error!("HTTP server failed: {}", e);
            }
        }));
    }

    loop {
        tokio::select! {
            incoming = ep.accept() => {
                match incoming {
                    Some(incoming) => {
                        let config_clone = config.clone();
                        let http_client_clone = http_client.clone();
                        let auth_state_clone = auth_state.clone();
                        let limiter_clone = conn_limiter.clone();
                        let in_flight_clone = in_flight.clone();
                        // Counted out here, not in the task's first line: a
                        // guard taken inside would leave a window in which the
                        // connection is accepted but not yet counted, and a
                        // shutdown landing in it sees zero and closes while
                        // this connection is still being set up.
                        let guard = in_flight_clone.enter();
                        tokio::spawn(async move {
                            // Handed on rather than dropped here: it stands for
                            // the connection, and the task that serves it is
                            // what decides when that is over.
                            conn::handle_incoming(
                                incoming,
                                config_clone,
                                http_client_clone,
                                auth_state_clone,
                                limiter_clone,
                                guard,
                            )
                            .await;
                        });
                    }
                    None => {
                        tracing::info!("Endpoint closed");
                        break;
                    }
                }
            }
            _ = shutdown_signal.requested() => {
                tracing::info!("Shutdown signal received, stopping proxy");
                break;
            }
        }
    }

    // The plaintext listener is its own task: it shares the shutdown signal, so
    // it leaves its accept loop on its own, but "on its own" says nothing about
    // when. Waiting for the handle is what makes the count below mean
    // something — until it returns, that loop can still accept a connection and
    // add to what is being drained.
    if let Some(handle) = http_server {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_panic() => tracing::error!("HTTP server task panicked: {e}"),
            Err(e) => tracing::error!("HTTP server task was cancelled: {e}"),
        }
    }

    // Same reason for the admin listener: it has its own shutdown branch, and
    // "it will stop" is not "it has stopped".
    if let Some(handle) = admin_server {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_panic() => tracing::error!("Admin listener task panicked: {e}"),
            Err(e) => tracing::error!("Admin listener task was cancelled: {e}"),
        }
    }

    let open = in_flight.count();
    if open > 0 {
        // Both accept loops have stopped taking new work by now, so this is a
        // countdown rather than a race.
        tracing::info!("Draining {} open connection(s)...", open);
        in_flight.wait_until_idle(DRAIN_TIMEOUT).await;
        tracing::info!("Drained, {} connection(s) left open", in_flight.count());
    } else {
        tracing::info!("No open connections, shutting down");
    }

    Ok(())
}

async fn start_http_server(
    listener: TcpListener,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    shutdown_signal: Arc<ShutdownSignal>,
    in_flight: Arc<InFlight>,
) -> anyhow::Result<()> {
    // Refusals since the last accepted connection. A listener that has run out
    // of file descriptors fails again the moment it is asked, so without a
    // pause this loop would spend the rest of the process writing log lines.
    let mut refused_in_a_row = 0u32;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, addr) = match result {
                    Ok(accepted) => {
                        refused_in_a_row = 0;
                        accepted
                    }
                    Err(e) => {
                        // One accept failure used to propagate and take the
                        // listener down for good, while the iroh side carried
                        // on serving: the port went quiet with nothing in the
                        // log to say it had. A refusal is one connection, not
                        // a verdict on the listener.
                        refused_in_a_row += 1;
                        tracing::error!("Plaintext listener failed to accept a connection: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            (refused_in_a_row.min(20) as u64) * 50,
                        ))
                        .await;
                        continue;
                    }
                };
                tracing::debug!("New connection on the plaintext listener from: {}", addr);

                let config_clone = config.clone();
                let client_clone = client.clone();
                let remote_addr_str = addr.to_string();
                let in_flight_clone = in_flight.clone();
                // Counted here rather than in the task's first line, for the
                // same reason as the iroh accept loop: an accepted connection
                // that is not counted yet is one a shutdown cannot see.
                let guard = in_flight_clone.enter();

                tokio::spawn(async move {
                    let _connection = guard;
                    // The listener speaks HTTP, but a client may also open a
                    // TLS session straight at it. One peeked byte tells the two
                    // apart — a request line can never start with 0x16 — and a
                    // TLS session goes to the passthrough path, since this
                    // process has no key material and never decrypts anything.
                    if is_tls_connection(&stream).await {
                        tracing::debug!("TLS session on the plaintext listener from: {}", remote_addr_str);
                        if let Err(e) =
                            passthrough::handle_tcp_stream(stream, Vec::new(), &config_clone).await
                        {
                            tracing::error!("TLS passthrough failed for {}: {}", remote_addr_str, e);
                        }
                        return;
                    }

                    // The timer is not on by default, and without it hyper has no
                    // header read timeout: a client that opens a socket and
                    // sends nothing holds the connection open for as long as it
                    // likes. This is the listener an operator may expose.
                    let mut http_builder = Builder::new(hyper_util::rt::TokioExecutor::new());
                    http_builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Some(crate::conn::HEAD_READ_TIMEOUT));

                    let service = service_fn(move |req: hyper::Request<Incoming>| {
                        proxy_handler(req, config_clone.clone(), client_clone.clone(), remote_addr_str.clone())
                    });

                    let io = TokioIo::new(stream);
                    if let Err(e) = http_builder.serve_connection_with_upgrades(io, service).await {
                        tracing::error!("Failed to serve connection: {}", e);
                    }
                });
            }
            _ = shutdown_signal.requested() => {
                tracing::info!("Shutdown signal received, stopping HTTP server");
                break;
            }
        }
    }
    Ok(())
}

/// Whether the plaintext listener may serve `bound` under this configuration.
///
/// Split out from [`run_proxy`] so the rule can be tested without binding
/// anything: everything the decision needs is the address the socket became and
/// whether `[server] expose` asked for it.
fn may_bind_plaintext(bound: SocketAddr, exposed: bool) -> bool {
    exposed || bound.ip().is_loopback()
}

/// The refusal for an exposed plaintext listener that 2FA cannot protect, if
/// there is one.
///
/// `expose = true` publishes every route and every passthrough backend on an
/// address where no credential is ever asked for — 2FA lives in the iroh accept
/// loop only — so enabling both is refused rather than logged: an error that
/// only turns up in a rotated log is how a firewall nobody remembers configuring
/// becomes the sole thing standing between the network and the backends.
///
/// Split out from [`run_proxy`] for the same reason as
/// [`may_bind_plaintext`]: the decision is three booleans' worth of input and
/// deserves its own tests. `pub(crate)` because the config watcher asks the same
/// question when a reload turns 2FA on — a reload must not be the way around a
/// check the startup path enforces.
pub(crate) fn plaintext_auth_conflict(
    bound: SocketAddr,
    exposed: bool,
    auth_enabled: bool,
) -> Option<String> {
    (exposed && auth_enabled).then(|| {
        format!(
            "[server] expose = true leaves {bound} unauthenticated even though [auth] is \
             enabled: 2FA only runs on the iroh listener, so this address would reach every \
             route and every passthrough backend without credentials. Gate the port with \
             something else, or disable [auth]"
        )
    })
}

/// True when the peer opened a TLS session rather than sending a request.
async fn is_tls_connection(stream: &tokio::net::TcpStream) -> bool {
    let mut first = [0u8; 1];
    match tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) => passthrough::is_tls_handshake(first[0]),
        // EOF, error, or a peer that never sends anything: hand it to the HTTP
        // server, which owns read timeouts and error responses.
        _ => false,
    }
}

async fn proxy_handler(
    req: hyper::Request<Incoming>,
    config: Arc<RouteConfig>,
    client: Arc<HttpClient>,
    remote_addr: String,
) -> Result<
    hyper::Response<http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>>,
    anyhow::Error,
> {
    let start = std::time::Instant::now();
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    if http::is_websocket_request(&req) {
        tracing::debug!("WebSocket request detected");
        return Ok(http::create_error_response(
            hyper::StatusCode::UPGRADE_REQUIRED,
            "WebSocket not supported via HTTP server",
        ));
    }

    let response = match http::proxy_request(&client, req, config.clone()).await {
        Ok(resp) => resp,
        Err(e) => {
            // The detail goes to the log, not to the client: `e` is an
            // internal one — a backend URL that would not parse, the address
            // of the backend that did not answer — and a proxy sitting in
            // front of a private network is not the place to publish those.
            tracing::error!("Proxy request failed: {}", e);
            let duration = start.elapsed();
            // Recorded where the answer is decided, not inside `log_access`:
            // the L4 path calls that too, and what it counts there is a flow,
            // not a request.
            crate::metrics::METRICS.record_request(
                hyper::StatusCode::BAD_GATEWAY.as_u16(),
                duration.as_millis() as u64,
            );
            log::log_access(
                &remote_addr,
                &method,
                &uri,
                hyper::StatusCode::BAD_GATEWAY.as_u16(),
                duration.as_millis() as u64,
                0,
            );
            return Ok(http::create_error_response(
                hyper::StatusCode::BAD_GATEWAY,
                "Bad Gateway",
            ));
        }
    };

    let duration = start.elapsed();
    let status = response.status().as_u16();
    crate::metrics::METRICS.record_request(status, duration.as_millis() as u64);
    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    log::log_access(
        &remote_addr,
        &method,
        &uri,
        status,
        duration.as_millis() as u64,
        content_length,
    );

    Ok(response)
}

pub async fn run_local_proxy(
    local_proxy_config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    local_proxy::run_local_proxy(local_proxy_config, shutdown_signal).await
}

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";

#[cfg(test)]
mod tests {
    use super::{may_bind_plaintext, plaintext_auth_conflict};
    use std::net::SocketAddr;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        let ip: std::net::IpAddr = ip.parse().expect("valid IP");
        SocketAddr::new(ip, port)
    }

    /// Loopback is the only thing the plaintext listener serves without being
    /// asked to: anything else publishes routes nobody has to authenticate to.
    #[test]
    fn loopback_binds_without_being_exposed() {
        assert!(may_bind_plaintext(addr("127.0.0.1", 8080), false));
        assert!(may_bind_plaintext(addr("::1", 8080), false));
    }

    #[test]
    fn a_network_address_needs_expose() {
        assert!(!may_bind_plaintext(addr("0.0.0.0", 8080), false));
        assert!(!may_bind_plaintext(addr("::", 8080), false));
        assert!(!may_bind_plaintext(addr("192.168.1.10", 8080), false));
        assert!(may_bind_plaintext(addr("0.0.0.0", 8080), true));
        assert!(may_bind_plaintext(addr("192.168.1.10", 8080), true));
    }

    /// An exposed listener alongside enabled 2FA is a configuration that only
    /// *looks* guarded: the iroh path asks for credentials, this one never does.
    /// It has to be refused, not served with a log entry nobody reads.
    #[test]
    fn an_exposed_listener_conflicts_with_enabled_2fa() {
        let bound = addr("0.0.0.0", 8080);
        let refusal =
            plaintext_auth_conflict(bound, true, true).expect("the combination is refused");
        assert!(
            refusal.contains("expose = true"),
            "the refusal has to name the setting: {refusal}"
        );
    }

    #[test]
    fn no_conflict_when_2fa_is_off_or_the_listener_is_not_exposed() {
        let bound = addr("0.0.0.0", 8080);
        // No 2FA at all: the iroh listener is unauthenticated too, so the
        // plaintext one adds no new exposure beyond what startup already
        // warns about.
        assert_eq!(plaintext_auth_conflict(bound, true, false), None);
        // 2FA on, but the listener is loopback-only.
        assert_eq!(
            plaintext_auth_conflict(addr("127.0.0.1", 8080), false, true),
            None
        );
    }
}
