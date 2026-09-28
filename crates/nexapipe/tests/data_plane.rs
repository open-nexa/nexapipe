//! The HTTP data plane, driven end to end over a real iroh connection.
//!
//! The unit tests cover the pieces — routing, the legacy parsers, the body
//! limit, `copy_both_ways` — but nothing until now has put a request through
//! `conn::handle_bidi_stream` and read the answer back. That path is where the
//! first byte is dispatched, the head is collected and the body is read, and it
//! is the one every client actually uses.
//!
//! These tests run two endpoints on loopback with the relay disabled, so they
//! need a UDP socket on 127.0.0.1 and nothing else: no relay, no DNS, no
//! network. Each one pairs the proxy with a backend that is a real socket, so a
//! request that is forwarded wrongly — to the wrong backend, or not at all —
//! shows up as a backend that saw nothing.

use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use nexapipe::config::RouteMode;
use nexapipe::conn;
use nexapipe::http;
use nexapipe::l4::FlowLimiter;
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RouteConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The ALPN the proxy endpoint is built with; iroh refuses a connection whose
/// ALPN does not match, so the test client has to ask for the same one.
const ALPN: &[u8] = b"\x05nexapipe";

/// Ceiling for one reply. Far above anything these backends return, and it
/// stops a test from waiting on a stream that never ends.
const REPLY_LIMIT: usize = 1024 * 1024;

/// `conn::handle_bidi_stream` stops collecting a head at this size.
const HEAD_LIMIT: usize = 64 * 1024;

/// A deadline generous for loopback, and short enough that a hang fails the
/// test instead of the 45-minute CI timeout doing it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// An endpoint that never leaves the machine: no relay, no discovery, one
/// loopback socket. `presets::Minimal` sets only the crypto provider, which is
/// the one option iroh requires and the rest of the presets come with network
/// services this test must not depend on.
async fn bind() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .expect("loopback bind address")
        .bind()
        .await
        .expect("bind endpoint")
}

/// The address to dial: the endpoint's own id, with only its loopback address.
///
/// `addr()` also advertises whatever global addresses the host has, and a
/// client that tries those first spends the whole dial timeout on them.
fn dial_address(ep: &Endpoint) -> EndpointAddr {
    let local = *ep
        .addr()
        .ip_addrs()
        .find(|a| a.ip().is_loopback())
        .expect("an endpoint bound to loopback reports a loopback address");
    EndpointAddr::new(ep.id()).with_ip_addr(local)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// One request as a backend saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    request_line: String,
    body: Vec<u8>,
}

/// An HTTP/1.1 backend on a loopback port that answers every request with the
/// same body and remembers what it was asked for.
struct Backend {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Backend {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn spawn_backend(reply_body: &'static str) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = format!("http://{}", listener.local_addr().expect("backend address"));

    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut sock).await else {
                    return;
                };
                sink.lock().unwrap().push(request);

                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                    reply_body.len(),
                    reply_body
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    Backend { url, seen }
}

/// Reads one HTTP/1.1 request: the head, then a body if `content-length` asks
/// for one. A backend that read only the head would make every test with a body
/// look like a proxy bug.
async fn read_request(sock: &mut TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    let head_end = loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let content_length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    Some(Seen { request_line, body })
}

/// A backend that speaks nothing: it keeps the bytes it was sent and answers
/// with one byte. This is what a passthrough route's TLS backend looks like
/// from the proxy's side.
async fn spawn_raw_backend() -> (String, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw backend");
    let addr = listener
        .local_addr()
        .expect("raw backend address")
        .to_string();
    let got = Arc::new(Mutex::new(Vec::new()));

    let sink = got.clone();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = sock.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        sink.lock().unwrap().extend_from_slice(&buf);
        let _ = sock.write_all(b"\x16").await;
    });

    (addr, got)
}

// ---------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------

struct Proxy {
    addr: EndpointAddr,
}

/// Serves `routes` over a loopback endpoint, the way the binary does: accept a
/// connection, then hand every bidirectional stream to
/// `conn::handle_bidi_stream`.
async fn spawn_proxy(routes: Vec<Route>) -> Proxy {
    let ep = bind().await;
    let addr = dial_address(&ep);

    let config = Arc::new(RouteConfig::new(routes));
    let client = Arc::new(http::create_http_client());
    let limiter = Arc::new(FlowLimiter::new(64));

    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(accepting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = accepting.await else {
                continue;
            };

            let config = config.clone();
            let client = client.clone();
            let limiter = limiter.clone();
            tokio::spawn(async move {
                // Keep accepting on this connection: a task that returns after
                // one stream drops the connection with it, and the reply it
                // just wrote goes with it.
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let _ = conn::handle_bidi_stream(
                        send,
                        recv,
                        &config,
                        &client,
                        &limiter,
                        "data-plane-test",
                        None,
                    )
                    .await;
                }
            });
        }
    });

    Proxy { addr }
}

fn http_route(host: &str, backend: &str) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    )
}

fn passthrough_route(host: &str, backend: &str) -> Route {
    Route::new(
        host,
        "/",
        true,
        vec![backend.to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Passthrough,
        None,
    )
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

struct Tunnel {
    // Outlives the connection: dropping the endpoint closes everything on it.
    _endpoint: Endpoint,
    conn: iroh::endpoint::Connection,
}

impl Tunnel {
    async fn dial(addr: EndpointAddr) -> Self {
        let endpoint = bind().await;
        let conn = tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, ALPN))
            .await
            .expect("dialling the proxy timed out")
            .expect("dial the proxy");
        Tunnel {
            _endpoint: endpoint,
            conn,
        }
    }

    /// Sends `payload` and leaves the stream open, then waits out whatever the
    /// proxy does.
    ///
    /// Finishing the stream is the ordinary way to say "that was the whole
    /// request", and the head loop treats an unfinished stream that has ended
    /// as a short request — so the slowloris shape has to keep talking
    /// without ever hanging up.
    async fn send_and_keep_open(&self, payload: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");

        let reply =
            tokio::time::timeout(Duration::from_secs(45), recv.read_to_end(REPLY_LIMIT)).await;
        drop(send);

        match reply {
            Ok(Ok(reply)) => reply,
            _ => Vec::new(),
        }
    }

    /// Sends `payload` on a fresh stream and reads the reply until the peer
    /// finishes it.
    async fn exchange(&self, payload: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = self.conn.open_bi().await.expect("open_bi");
        send.write_all(payload).await.expect("write request");
        send.finish().expect("finish request");

        // A refused or abandoned stream reads back as an empty reply, which is
        // a legitimate answer for the tests that provoke one.
        recv.read_to_end(REPLY_LIMIT).await.unwrap_or_default()
    }
}

/// Polls `probe` until it yields, so a test can assert on what another task
/// recorded without sleeping for a fixed time.
///
/// The backends record what they saw as their own task gets to it, which is
/// after the exchange that caused it has already returned.
async fn eventually<T, F>(mut probe: F) -> T
where
    F: FnMut() -> Option<T>,
{
    for _ in 0..100 {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the condition was never met within 5s");
}

fn reply_body(reply: &[u8]) -> String {
    let text = String::from_utf8_lossy(reply).to_string();
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

fn status_of(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_get_reaches_the_backend_and_the_reply_comes_back() {
    let backend = spawn_backend("hello from the backend").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"GET /hello HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );
    assert_eq!(reply_body(&reply), "hello from the backend");

    let seen = backend.seen();
    assert_eq!(seen.len(), 1, "the backend should have seen one request");
    assert_eq!(seen[0].request_line, "GET /hello HTTP/1.1");
}

#[tokio::test]
async fn the_host_header_selects_which_backend_is_asked() {
    let app = spawn_backend("app").await;
    let api = spawn_backend("api").await;
    let proxy = spawn_proxy(vec![
        http_route("app.test", &app.url),
        http_route("api.test", &api.url),
    ])
    .await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let first = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await;
    let second = tunnel
        .exchange(b"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n")
        .await;

    assert_eq!(reply_body(&first), "app");
    assert_eq!(reply_body(&second), "api");

    // Each backend was asked once, and only about its own host: a request that
    // landed on both, or on neither, is a routing bug the status codes alone
    // would not show.
    assert_eq!(app.seen().len(), 1);
    assert_eq!(api.seen().len(), 1);
}

#[tokio::test]
async fn a_request_body_is_forwarded_with_the_request() {
    let backend = spawn_backend("done").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    let reply = tunnel
        .exchange(b"POST /upload HTTP/1.1\r\nHost: app.test\r\ncontent-length: 5\r\n\r\nworld")
        .await;

    assert!(
        status_of(&reply).starts_with("HTTP/1.1 200"),
        "expected a 200, got {:?}",
        status_of(&reply)
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request_line, "POST /upload HTTP/1.1");
    assert_eq!(seen[0].body, b"world");
}

#[tokio::test]
async fn a_client_hello_is_copied_to_the_passthrough_backend() {
    let (backend, got) = spawn_raw_backend().await;
    let proxy = spawn_proxy(vec![passthrough_route("app.test", &backend)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // The first byte is what dispatches: 0x16 is a TLS record, so this never
    // reaches an HTTP route even though the proxy is listening either way.
    let hello = client_hello_with_sni("app.test");
    let _ = tunnel.exchange(&hello).await;

    let seen = eventually(|| {
        let seen = got.lock().unwrap().clone();
        (!seen.is_empty()).then_some(seen)
    })
    .await;
    assert!(
        seen.starts_with(&[0x16]),
        "the backend should have received a TLS record, got {} bytes",
        seen.len()
    );
    assert!(
        seen.windows("app.test".len()).any(|w| w == b"app.test"),
        "the ClientHello should reach the backend with its SNI intact"
    );
}

#[tokio::test]
async fn a_head_past_the_limit_is_answered_without_a_backend() {
    let backend = spawn_backend("never").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A head that is still going past the limit: no blank line anywhere, and
    // no `Host` before the filler, so the only way this can be answered is by
    // stopping the read.
    let mut head = Vec::new();
    head.extend_from_slice(b"GET / HTTP/1.1\r\n");
    head.extend_from_slice(&vec![b'x'; HEAD_LIMIT * 2]);
    let reply = tunnel.exchange(&head).await;

    assert!(
        status_of(&reply).contains("404"),
        "an unusable head should be answered with 404, got {:?}",
        status_of(&reply)
    );
    assert!(
        backend.seen().is_empty(),
        "a head that was never completed must not reach a backend"
    );
}

/// The head deadline is 30 s, so this one waits that long before it can assert
/// anything. Run it explicitly: `cargo test -p nexapipe --test data_plane -- --ignored`.
#[tokio::test]
#[ignore = "waits out the 30s head deadline"]
async fn a_head_that_never_arrives_is_dropped() {
    let backend = spawn_backend("never").await;
    let proxy = spawn_proxy(vec![http_route("app.test", &backend.url)]).await;
    let tunnel = Tunnel::dial(proxy.addr).await;

    // A request line and a `Host`, never finished, and the stream is left open
    // so the head loop cannot read an end of stream instead of a head.
    let reply = tunnel
        .send_and_keep_open(b"GET / HTTP/1.1\r\nHost: app.test\r\n")
        .await;

    assert!(
        backend.seen().is_empty(),
        "a head that never finished must not reach a backend"
    );
    assert!(
        !status_of(&reply).starts_with("HTTP/1.1 200"),
        "a request that never completed should not be served"
    );
}

// ---------------------------------------------------------------------------
// A TLS ClientHello
// ---------------------------------------------------------------------------

/// The smallest ClientHello that carries `sni`, built the way
/// `passthrough::extract_sni` reads it: record, handshake, extensions.
fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    let mut extension = Vec::new();
    extension.extend_from_slice(&0u16.to_be_bytes()); // server_name
    let entry_len = 1 + 2 + sni_bytes.len();
    extension.extend_from_slice(&((2 + entry_len) as u16).to_be_bytes());
    extension.extend_from_slice(&(entry_len as u16).to_be_bytes());
    extension.push(0); // host_name
    extension.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extension.extend_from_slice(sni_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // compression methods length
    body.push(0);
    body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension);

    let mut handshake = vec![0x01]; // client_hello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
