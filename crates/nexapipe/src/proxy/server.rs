//! The two things the binary starts: the proxy itself, and the local proxy
//! beside it.

use crate::admin;
use crate::auth::AuthConfig;
use crate::config::{
    AdminConfig, BackendsConfig, HealthCheckConfig, IrohConfig, LocalProxyConfig, MetricsConfig,
    ServerConfig,
};
use crate::config_watcher::{ConfigWatcher, PlaintextListener};
use crate::conn;
use crate::conn::limits::{EnvCaps, Limits, LimitsConfig};
use crate::health::HealthProbes;
use crate::http;
use crate::routes::RoutingTable;
use crate::shutdown::{DRAIN_TIMEOUT, InFlight, ShutdownSignal};
use anyhow::Context;
use iroh::endpoint::BindOpts;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;
use nexapipe_client::discovery::DiscoveryMode;
use nexapipe_client::relay::RelayModeSpec;
use nexapipe_proto::protocol::accepted_alpns;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::health::sync_health_checks;
use super::local_proxy;
use super::plaintext::{may_bind_plaintext, plaintext_auth_conflict, start_http_server};

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
    /// How the proxy reaches the backends: the trust store an `https://`
    /// backend's certificate is checked against.
    pub backends: BackendsConfig,
    /// The ceilings the whole process runs under. Absent means the defaults.
    pub limits: LimitsConfig,
}

pub async fn run_proxy(
    config: Arc<RoutingTable>,
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
        backends,
        limits: limits_config,
    } = options;

    // The ceilings the process runs under, resolved once and here: they are
    // read at startup and not live, because a budget that changed under an
    // in-flight upload would release bytes against a ceiling it was never
    // counted against.
    //
    // The body budget's ceiling is written into the process-wide budget before
    // anything can read a body, so no request is ever counted against a
    // ceiling it did not start under.
    //
    // The error is not wrapped: `anyhow`'s `Display` shows the outermost
    // message only, and the one this returns already names the section and
    // the key that cannot work.
    let limits = Limits::resolve(&limits_config, &EnvCaps::from_environment())?;
    conn::limits::init_body_budget(limits.max_body_bytes);

    // Read from for `nexapipe_uptime_seconds`. Taken here rather than in
    // `main` so a `--local-proxy` run never sets it: there is one process-wide
    // start time, and the mode that does not scrape should not own it.
    crate::metrics::mark_start();

    // Dialling a backend is bounded by `[timeouts] connect_secs`, read once here
    // because it is a builder setting: the connector applies it to every dial,
    // including the ones made later for a pooled connection the backend closed.
    //
    // The trust store is read here too, for the same reason: a CA file that
    // cannot be read is a config that cannot work, and the operator should
    // read about it at startup rather than in the log of a request that failed
    // to verify.
    let ca_file = backends
        .ca_file
        .as_deref()
        .map(std::path::Path::new)
        .filter(|path| !path.as_os_str().is_empty());
    let clients = Arc::new(
        http::BackendClients::new(config.timeouts().connect, ca_file)
            .context("cannot prepare the clients for the backends")?,
    );

    let health_probes = Arc::new(tokio::sync::Mutex::new(HealthProbes::new()));
    let health_enabled = Arc::new(std::sync::atomic::AtomicBool::new(health_check.enabled));
    // Shared by both accept loops: a shutdown has to wait for the work they
    // spawned, not for a fixed number of seconds.
    let in_flight = Arc::new(InFlight::new());
    // Every peer with a connection being served. Cheap to keep unconditionally:
    // it is an empty map until a client connects, and `GET /v1/connections`
    // reads it rather than the proxy having to be told to start collecting.
    let peers = Arc::new(conn::peers::PeerRegistry::new());
    sync_health_checks(
        &config,
        &clients,
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
    //
    // `peers` is what lets a reload reach a connection rather than only the next
    // one: `client revoke` edits the file, and the next pass has to tell the
    // connections already authenticated as what it removed to stop.
    let config_watcher = Arc::new(ConfigWatcher::new(
        config_path.to_string(),
        config.clone(),
        clients.clone(),
        health_probes,
        health_enabled,
        auth_state.clone(),
        Arc::clone(&peers),
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

    // Every protocol a client may ask for, and the two generic names beside
    // them.
    //
    // **This list is what decides.** QUIC's negotiation picks the first of the
    // *accept side's* entries that the peer also offers — not the first of the
    // peer's offer. So the order below is the preference order: a client that
    // asks for one protocol by name gets that one, and a client that asks for
    // nothing in particular gets the generic name, which is served the way it
    // always was — by the first byte of each stream.
    //
    // The last entry is the spelling clients used before the prefix byte was
    // dropped; a client of that vintage offers only that, and it reaches a
    // server of this one.
    //
    // The list itself is written down once, in the crate the client links
    // too: a list written down twice is a list that eventually differs.
    let mut builder = Endpoint::builder(presets::N0).alpns(accepted_alpns());

    // Which relay we use, resolved by the same code the clients use, so the two cannot drift
    // apart. `None` means nothing was configured, which is iroh's default (every N0 relay).
    // Everything else either resolves or fails startup: `relay_mode` used to be ignored
    // entirely unless `relay_url` was also set, and a `relay_url` on its own was logged and
    // then dropped — both of which let a broken configuration run unchanged.
    let relay = RelayModeSpec::parse(
        iroh_config.as_ref().and_then(|c| c.relay_mode.as_deref()),
        iroh_config.as_ref().and_then(|c| c.relay_url.as_deref()),
        iroh_config.as_ref().and_then(|c| {
            c.relay_auth_token
                .as_ref()
                .map(|token| token.expose_secret().as_str())
        }),
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

    // Whether this endpoint may use n0's address lookup — the DNS and pkarr
    // queries that turn a Node ID into an address. It is the one piece of n0's
    // infrastructure a relay setting does not reach, so it gets a setting of
    // its own; `none` takes the lookup services off the endpoint, and a peer
    // then has to bring an address of its own (a ticket) to be reachable.
    //
    // A value that is present but unknown refuses the start, the rule the
    // relay modes follow for a mode they cannot read. An empty one is
    // refused as well: it is present, and it names no mode.
    let discovery = match iroh_config.as_ref().and_then(|c| c.discovery.as_deref()) {
        Some(value) => DiscoveryMode::parse(value)
            .with_context(|| format!("invalid [iroh] discovery: {value:?}"))?,
        None => DiscoveryMode::default(),
    };
    tracing::info!("Discovery: {}", discovery.describe());
    builder = discovery.apply(builder);

    if let Some(iroh_cfg) = iroh_config {
        // Use configured secret key for stable endpoint identity.
        //
        // An unparseable key is refused rather than replaced by a fresh one.
        // It used to be a warning and a random key, which put the endpoint on a
        // different Node ID after every restart while looking like a solved
        // problem — every client that had stored the Node ID lost the server,
        // and nothing in the log said why. `ProxyConfig::ensure_iroh_secret_key`
        // has already refused this at startup, so reaching the error here means
        // the two checks disagree; failing keeps that from being silent.
        if let Some(secret_key_str) = &iroh_cfg.secret_key {
            let secret_key = secret_key_str
                .expose_secret()
                .parse::<SecretKey>()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "[iroh] secret_key is not a valid key ({e}); refusing to start on a \
                     throwaway identity, because the Node ID would change on every restart"
                    )
                })?;
            builder = builder.secret_key(secret_key);
            tracing::info!("Using configured secret key for stable endpoint identity");
        }

        // IPv6 is opt-in because it is a second socket, not a change to the
        // first: `bind_addr` adds one, so the IPv4 socket stays bound either way
        // and a client with no IPv6 route keeps working. Without `bind_port`
        // there is no port to keep the two families on, so the flag is ignored
        // — and saying so beats letting an operator think IPv6 is on.
        if iroh_cfg.bind_ipv6.unwrap_or(false) && iroh_cfg.bind_port.is_none() {
            tracing::warn!(
                "iroh.bind_ipv6 is set but iroh.bind_port is not: bind_ipv6 is ignored \
                 without a fixed port; iroh keeps its default IPv4 and IPv6 bindings"
            );
        }

        if let Some(port) = iroh_cfg.bind_port {
            let addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))
                .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
            builder = builder.bind_addr(addr)?;

            if iroh_cfg.bind_ipv6.unwrap_or(false) {
                // Not required: on a host with no IPv6 at all this bind fails,
                // and a server that refuses to start because an optional socket
                // was unavailable is worse than one that logs it. Everything
                // dialling over IPv4 is unaffected.
                let v6 = SocketAddr::from_str(&format!("[::]:{}", port))
                    .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
                builder =
                    builder.bind_addr_with_opts(v6, BindOpts::default().set_is_required(false))?;
                tracing::info!("Iroh bind port: {} (IPv4 and IPv6)", port);
            } else {
                tracing::info!("Iroh bind port: {}", port);
            }
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
    // `/healthz`, `/metrics` and `/v1/*`. Bound here and never rebound: moving
    // a listener is a restart, which is why `[admin] listen_addr` is the one
    // setting a config reload does not apply.
    let admin_listener = match admin_config.as_ref().and_then(|a| a.listen_addr.clone()) {
        Some(addr) => {
            let listener = TcpListener::bind(&addr).await?;
            // Judged after the bind, like the plaintext listener: only the
            // address the socket actually became says whether it is reachable.
            let bound = listener.local_addr()?;
            if !admin::may_bind_admin(bound) {
                anyhow::bail!("{}", admin::non_loopback_refusal(bound));
            }
            tracing::info!(
                "Admin listener on: {} (/healthz, /v1/* behind a token)",
                bound
            );
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

        // Made here, and only because the listener is up: a deployment that
        // never binds it should not find a credential on disk next to its
        // config.
        let token = admin::token::load_or_create(config_path);
        let state = Arc::new(admin::AdminState::new(
            config.clone(),
            in_flight.clone(),
            peers.clone(),
            auth_state.clone(),
            metrics_config.enabled,
            token,
        ));
        let shutdown_signal_clone = shutdown_signal.clone();

        admin_server = Some(tokio::spawn(async move {
            if let Err(e) = admin::serve_admin(listener, state, shutdown_signal_clone).await {
                tracing::error!("Admin listener failed: {}", e);
            }
        }));
    }

    // One set of limiters for the whole endpoint: every cap only means anything
    // if every accepted connection and stream counts against the same state.
    // Both ceilings are here rather than only the per-peer one because an
    // `EndpointId` is a public key — see `conn::limits`.
    let limiters = conn::limits::Limiters::from_limits(&limits);
    tracing::info!("Accepting at most {}", limiters.describe());
    crate::metrics::METRICS.record_connection_limits(
        limiters.connections.max(),
        limiters.connections.max_global(),
    );

    // Kept, rather than spawned and forgotten: the drain below counts work that
    // is still running, and a listener that has not stopped accepting yet is
    // still able to add to it. Its handle is the only way to know it has
    // stopped.
    let mut http_server = None;
    if let Some(http_listener) = http_listener {
        let config_clone = config.clone();
        let clients_clone = clients.clone();
        let shutdown_signal_clone = shutdown_signal.clone();
        let in_flight_clone = in_flight.clone();
        // The same limiters the tunnel counts against: one process, one
        // ceiling, whatever the connection arrived on.
        let limiters_clone = limiters.clone();

        http_server = Some(tokio::spawn(async move {
            if let Err(e) = start_http_server(
                http_listener,
                config_clone,
                clients_clone,
                shutdown_signal_clone,
                in_flight_clone,
                limiters_clone,
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
                        let clients_clone = clients.clone();
                        let auth_state_clone = auth_state.clone();
                        let limiters_clone = limiters.clone();
                        let peers_clone = peers.clone();
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
                                clients_clone,
                                auth_state_clone,
                                limiters_clone,
                                guard,
                                peers_clone,
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

pub async fn run_local_proxy(
    local_proxy_config: LocalProxyConfig,
    shutdown_signal: Arc<ShutdownSignal>,
) -> anyhow::Result<()> {
    local_proxy::run_local_proxy(local_proxy_config, shutdown_signal).await
}
