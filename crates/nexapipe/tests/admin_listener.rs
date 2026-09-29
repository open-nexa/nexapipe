//! The auxiliary listener: `/healthz` and `/metrics`, over a real socket.
//!
//! The point of these is the *shape* of the answer, which is what a scraper and
//! a supervisor depend on and what no unit test of the counters can pin down:
//! `/healthz` answers without a credential, `/metrics` is **absent** while
//! `[metrics] enabled` is false rather than present and empty, and everything
//! that has not been built yet is a 404.
//!
//! The listener is driven in-process rather than through the binary: it is the
//! same `serve_admin` the startup path spawns, and this way a test does not
//! have to bind an iroh endpoint, wait for it, or guess a port that another
//! test may be between uses of.
use nexapipe::admin;
use nexapipe::config::{ProxyConfig, RouteMode};
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RouteConfig};
use nexapipe::shutdown::{InFlight, ShutdownSignal};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One answer, split the way an HTTP/1.1 response is laid out.
struct Reply {
    status: u16,
    head: String,
    body: String,
}

/// A listener serving `routes`, on a loopback port nothing else was using.
struct Admin {
    addr: SocketAddr,
    shutdown: Arc<ShutdownSignal>,
}

async fn spawn_admin(routes: Vec<Route>, metrics_enabled: bool) -> Admin {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("listener address");
    let shutdown = Arc::new(ShutdownSignal::new());

    let config = Arc::new(RouteConfig::new(routes));
    let in_flight = Arc::new(InFlight::new());
    let signal = shutdown.clone();

    tokio::spawn(async move {
        let _ = admin::serve_admin(listener, config, in_flight, metrics_enabled, signal).await;
    });

    Admin { addr, shutdown }
}

impl Admin {
    async fn get(&self, path: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .expect("connect to the admin listener");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut raw = String::new();
        stream
            .read_to_string(&mut raw)
            .await
            .expect("read response");

        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in:\n{raw}"));

        Reply {
            status,
            head: head.to_string(),
            body: body.to_string(),
        }
    }

    fn stop(&self) {
        self.shutdown.request_shutdown();
    }
}

fn http_route(host: &str, backends: Vec<String>) -> Route {
    Route::new(
        host,
        "/",
        true,
        backends,
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )
}

/// Liveness has to work without a credential — a supervisor should not need one
/// — and it has to be the only thing that does while metrics are off.
#[tokio::test]
async fn healthz_is_live_and_the_rest_is_absent_while_metrics_are_off() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        false,
    )
    .await;

    let health = admin.get("/healthz").await;
    assert_eq!(health.status, 200, "{}", health.head);
    assert_eq!(health.body, "ok");

    // Absent, not empty: a scraper pointed at a deployment that never enabled
    // metrics has to be able to tell that from "no traffic yet".
    let metrics = admin.get("/metrics").await;
    assert_eq!(metrics.status, 404, "{}", metrics.head);

    // The management endpoints are not built yet, and an unknown path must not
    // look like one that exists.
    let unknown = admin.get("/v1/status").await;
    assert_eq!(unknown.status, 404, "{}", unknown.head);

    admin.stop();
}

/// Once it is switched on, `/metrics` is the Prometheus text format and not
/// something a scraper has to be taught about: the content type is the one the
/// format specifies, and every metric declares its type before it is used.
#[tokio::test]
async fn metrics_are_served_in_the_exposition_format_when_enabled() {
    let admin = spawn_admin(
        vec![http_route("app.test", vec!["http://127.0.0.1:1".into()])],
        true,
    )
    .await;

    let metrics = admin.get("/metrics").await;
    assert_eq!(metrics.status, 200, "{}", metrics.head);
    assert!(
        metrics.head.contains("version=0.0.4"),
        "the exposition content type is missing from:\n{}",
        metrics.head
    );
    assert!(
        metrics
            .body
            .contains("# TYPE nexapipe_requests_total counter"),
        "{}",
        metrics.body
    );
    assert!(
        metrics
            .body
            .contains("nexapipe_connections_by_path{kind=\"direct\"} 0"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// Backend health is read from the pools at exposition time rather than counted
/// by the probes, so what the pools say now is what the page says — including
/// for a backend that was taken out of rotation since the last reload.
#[tokio::test]
async fn backends_are_counted_from_the_live_pools() {
    let up = "http://127.0.0.1:8080".to_string();
    let down = "http://127.0.0.1:9090".to_string();
    let route = http_route("app.test", vec![up.clone(), down.clone()]);
    route.backend_pool().set_backend_health(&down, false).await;

    let admin = spawn_admin(vec![route], true).await;
    let metrics = admin.get("/metrics").await;

    assert!(
        metrics.body.contains("nexapipe_backends_up 1"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("nexapipe_backends_down 1"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// A route that is never probed is never counted: a passthrough backend is a
/// TLS listener, so nothing would ever mark it down and counting it would
/// report backends as up that nobody has checked.
#[tokio::test]
async fn a_route_that_is_never_probed_is_not_counted_as_up() {
    let route = Route::new(
        "app.test",
        "/",
        true,
        vec!["10.0.0.5:443".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    );

    let admin = spawn_admin(vec![route], true).await;
    let metrics = admin.get("/metrics").await;

    assert!(
        metrics.body.contains("nexapipe_backends_up 0"),
        "{}",
        metrics.body
    );
    assert!(
        metrics.body.contains("nexapipe_backends_down 0"),
        "{}",
        metrics.body
    );

    admin.stop();
}

/// The two sections the listener hangs off, read back through the config file:
/// absent means the listener is not bound, and metrics stay off until someone
/// asks for both.
#[test]
fn the_admin_and_metrics_sections_round_trip_through_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    std::fs::write(
        &path,
        "[admin]\nlisten_addr = \"127.0.0.1:9090\"\n\n[metrics]\nenabled = true\n",
    )
    .unwrap();
    let config = ProxyConfig::from_file(path.to_str().unwrap()).expect("the config parses");
    let admin = config.admin.as_ref().expect("[admin] is present");
    assert_eq!(admin.listen_addr.as_deref(), Some("127.0.0.1:9090"));
    assert!(config.metrics.enabled, "[metrics] enabled = true");

    let empty = dir.path().join("empty.toml");
    std::fs::write(&empty, "[server]\n").unwrap();
    let config = ProxyConfig::from_file(empty.to_str().unwrap()).expect("the config parses");
    assert!(
        config.admin.is_none(),
        "no [admin] section means no listener"
    );
    assert!(
        !config.metrics.enabled,
        "metrics are off until they are asked for"
    );
}

/// The one address rule that has no escape hatch: unlike the plaintext
/// listener, this one cannot be asked to bind off loopback.
#[test]
fn a_non_loopback_address_is_refused() {
    let addr: SocketAddr = "192.168.1.10:9090".parse().unwrap();
    assert!(!admin::may_bind_admin(addr));

    let refusal = admin::non_loopback_refusal(addr);
    assert!(refusal.contains("192.168.1.10:9090"), "{refusal}");
}
