//! The health checks the routes need.
//!
//! One background probe per `http` route, started at startup and again after
//! every reload, and kept in step with the routes that are live.

use crate::config::{HealthCheckConfig, RouteMode};
use crate::health::{HealthChecker, HealthProbes, ProbeKind, ProbeTarget};
use crate::http::BackendClients;
use crate::routes::RoutingTable;
use std::sync::Arc;

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
    config: &Arc<RoutingTable>,
    clients: &Arc<BackendClients>,
    probes: &tokio::sync::Mutex<HealthProbes>,
    health: &HealthCheckConfig,
    enabled: &Arc<std::sync::atomic::AtomicBool>,
) {
    // Which routes want a probe right now, and on which pool. Taken before the
    // lock on the probes, because none of it depends on them.
    let mut wanted: std::collections::HashMap<String, ProbeTarget> =
        std::collections::HashMap::new();

    for route in config.routes().await {
        // How a backend is asked depends on what it can answer. An http backend
        // answers `GET {health_path}`. A passthrough or L4 backend — a TLS
        // listener, a database, a TURN server, an SSH daemon — answers nothing
        // without being spoken to in the protocol it serves, so it gets a TCP
        // connect instead, which is the smallest question anybody can answer:
        // it says a port is listening, and not that what is behind it works.
        //
        // A route serving `http` *and* another mode is asked the HTTP question:
        // the pool is shared, and an answer the backend gave is worth more than
        // a connection anything would accept.
        //
        // A `udp`-only route gets no probe at all. UDP answers nothing without
        // a datagram in the protocol it serves, so the only probe available
        // would be one every backend fails — and a pool emptied by a probe that
        // could never have succeeded is worse than none.
        let kind = if route.serves(RouteMode::Http) {
            ProbeKind::Http {
                path: health.path.clone(),
                protocol: route.backend_protocol(),
            }
        } else if route.serves(RouteMode::Passthrough) || route.serves(RouteMode::Tcp) {
            ProbeKind::Tcp
        } else {
            tracing::info!(
                "Route {}: modes={:?}, no probe speaks these, so a dead backend shows up \
                 when a flow arrives",
                route.host_pattern(),
                route.modes()
            );
            continue;
        };

        wanted.insert(
            route.pool_key().await,
            ProbeTarget {
                pool: route.backend_pool().clone(),
                kind,
            },
        );
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

    for (key, target) in wanted {
        if probes.contains(&key) {
            continue;
        }

        let health_checker = HealthChecker::new(
            target.pool.clone(),
            clients.clone(),
            std::time::Duration::from_secs(health.interval.max(1)),
            std::time::Duration::from_secs(health.timeout.max(1)),
            health.threshold,
            target.kind,
            enabled.clone(),
        );
        probes.spawn(key, target.pool, health_checker);
    }
}
