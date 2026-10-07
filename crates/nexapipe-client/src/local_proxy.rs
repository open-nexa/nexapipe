use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::{EndpointGroup, PooledConnection};
use crate::http::{is_websocket_request_static, parse_http_request_legacy};
use iroh::EndpointId;
use iroh::endpoint::{RecvStream, SendStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

#[cfg(feature = "tracing")]
use tracing;

#[cfg(feature = "jni")]
use crate::jni_log;

/// No-op `jni_log!` for builds without the `jni` feature.
///
/// The format arguments are still *evaluated* (borrowed) inside a dead branch,
/// so the optimiser removes the call but `unused_variables` does not fire on
/// variables that only ever appear inside a log statement.
#[cfg(not(feature = "jni"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

/// Gate for the debug-only WebSocket frame dumps.
///
/// `jni_log!` already skips formatting when `Debug` logging is off, but that only helps if the
/// arguments are cheap. Building a frame preview is not: it hex-escapes up to 256 bytes with
/// one `format!` allocation per non-printable byte, and it used to run on **every** WebSocket
/// chunk in both directions regardless of the log level.
#[cfg(feature = "jni")]
#[inline]
fn debug_log_enabled() -> bool {
    crate::jni::debug_log_enabled()
}

#[cfg(not(feature = "jni"))]
#[inline]
fn debug_log_enabled() -> bool {
    false
}

/// Headers whose value is a credential, and so never belongs in a log.
const SENSITIVE_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

/// The headers of a request, with the values that carry credentials replaced.
///
/// Logging them whole put `Authorization` and `Cookie` into logcat on every
/// request. Names and non-sensitive values are still what makes a dump useful
/// when debugging, so only the values are dropped.
fn redacted_headers(headers: &::http::HeaderMap) -> String {
    let mut out = String::from("{");
    for (name, value) in headers {
        if SENSITIVE_HEADERS.contains(&name.as_str().to_lowercase().as_str()) {
            out.push_str(&format!("{}: <redacted>, ", name));
        } else {
            out.push_str(&format!("{}: {:?}, ", name, value));
        }
    }
    out.push('}');
    out
}

const STREAM_BUF_SIZE: usize = 128 * 1024;

/// Largest request header the local proxy collects, before it gives up on a
/// peer that never ends one. Same order as the server's own head limit, and
/// far above any real request: what it bounds is a client that keeps the
/// connection open and dribbles bytes into it.
const MAX_REQUEST_HEADER: usize = 64 * 1024;

/// Whether what has been read of a request is over [`MAX_REQUEST_HEADER`].
///
/// The cap is on the header, not on the request: a small header followed by a
/// body of any size is an ordinary upload, so what is measured is what precedes
/// the terminator. Until one arrives, everything read so far is header as far as
/// anyone can tell — which is the case that bounds a peer that never ends one.
fn header_over_limit(request: &[u8], header_end: Option<usize>) -> bool {
    header_end.unwrap_or(request.len()) > MAX_REQUEST_HEADER
}

/// How long the accept loop waits after an error before trying again, and how
/// many it takes before it concludes the listener is not coming back.
const ACCEPT_ERROR_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_millis(100);
const MAX_CONSECUTIVE_ACCEPT_ERRORS: usize = 10;

/// How many connections are served at once.
///
/// Each one holds a [`STREAM_BUF_SIZE`] buffer (sometimes two), so this is what
/// turns an unbounded number of connections into a bounded amount of memory.
/// The same figure the server's `accept_bi` uses, which is not a coincidence:
/// a caller is one connection either way.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// One line per this many refused connections. A refusal is the caller's
/// problem to retry, not a per-connection event worth a log line — and logging
/// every one would let a caller that opens connections in a loop write to the
/// log as fast as it can connect.
const REJECTED_LOG_EVERY: usize = 100;
const STREAM_OPERATION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Number of attempts for opening a fresh iroh bi-stream for a new request.
/// If the pooled connection is stale (already closed by the peer), `open_bi` or
/// the initial `write_all` can fail; we discard that connection and retry with a
/// fresh one instead of failing the whole request.
pub(crate) const OPEN_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct LocalProxy {
    listener: Arc<TcpListener>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    stopped: Arc<AtomicBool>,
    /// Wakes the accept loop the moment the proxy is stopped, so it does not
    /// have to give up on `accept()` every 100 ms to find out.
    stop_notify: Arc<Notify>,
    /// The per-connection tasks, so stopping the proxy ends them.
    ///
    /// A handler holds a pooled connection for as long as its peer keeps the
    /// socket open, which is not this process's decision: without this a
    /// "stopped" proxy would still be holding connections out of the pool, and
    /// a `close_all` could not return them.
    connections: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    /// How many of [`MAX_CONCURRENT_CONNECTIONS`] are still free.
    ///
    /// Held here rather than in the accept loop so both constructors get one;
    /// the permits themselves move into the connection tasks, which is what
    /// releases them.
    permits: Arc<Semaphore>,
}

impl LocalProxy {
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        #[cfg(feature = "jni")]
        jni_log!("[DEBUG:local-proxy] Binding to {}", listen_addr);
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => {
                #[cfg(feature = "jni")]
                jni_log!("[DEBUG:local-proxy] Bound successfully to {}", listen_addr);
                l
            }
            Err(e) => {
                #[cfg(feature = "jni")]
                jni_log!(
                    "[DEBUG:local-proxy] Failed to bind to {}: {}",
                    listen_addr,
                    e
                );
                return Err(e.into());
            }
        };
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", listen_addr);
        Ok(Self::shared(
            Arc::new(listener),
            endpoint_group,
            proxy_domains,
        ))
    }

    pub async fn new_with_single_pool(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        conn_pool: IrohConnectionPool,
    ) -> Result<Self, ClientError> {
        let listener = TcpListener::bind(listen_addr).await?;
        let endpoint_group = EndpointGroup::new_with_single_pool(conn_pool).await;
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", listen_addr);
        Ok(Self::shared(
            Arc::new(listener),
            Arc::new(endpoint_group),
            proxy_domains,
        ))
    }

    /// The one place the two constructors' shared fields are filled in.
    fn shared(
        listener: Arc<TcpListener>,
        endpoint_group: Arc<EndpointGroup>,
        proxy_domains: Vec<String>,
    ) -> Self {
        Self {
            listener,
            endpoint_group,
            proxy_domains: Arc::new(proxy_domains),
            stopped: Arc::new(AtomicBool::new(false)),
            stop_notify: Arc::new(Notify::new()),
            connections: Arc::new(std::sync::Mutex::new(Vec::new())),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        }
    }

    pub async fn run(&self) -> Result<(), ClientError> {
        let stopped = self.stopped.clone();
        let listener = self.listener.clone();
        let proxy_domains = self.proxy_domains.clone();
        let endpoint_group = self.endpoint_group.clone();
        let stop_notify = self.stop_notify.clone();
        let permits = self.permits.clone();

        // Refused connections are counted, but only reported every so often: a
        // line each would let a caller that loops over connect() write to the
        // log as fast as it can open sockets.
        let mut rejected = 0usize;

        // Accept errors that are not fatal: a moment with no file descriptors
        // left, say. Counting them keeps the loop from spinning on a listener
        // that is genuinely broken, which is the case the old single-error exit
        // was there for.
        let mut consecutive_accept_errors = 0usize;

        loop {
            if stopped.load(Ordering::Acquire) {
                #[cfg(feature = "tracing")]
                tracing::info!("Local proxy stopping");
                break;
            }

            // `accept()` is cancel safe: a connection it has taken is never
            // handed to another task, so losing this race only means the
            // socket stays in the backlog until the loop comes back for it.
            //
            // `notify_one` — not `notify_waiters` — because a stop that lands
            // in the gap between the flag check and the `notified()` future
            // being created must still be remembered: `notify_one` stores a
            // permit for a waiter that has not arrived yet, `notify_waiters`
            // wakes only the ones already parked and would be lost.
            let accepted = tokio::select! {
                result = listener.accept() => result,
                _ = stop_notify.notified() => {
                    #[cfg(feature = "tracing")]
                    tracing::info!("Local proxy stopping");
                    break;
                }
            };

            match accepted {
                Ok((stream, addr)) => {
                    consecutive_accept_errors = 0;

                    // Refused rather than queued. A caller made to wait would hold
                    // its socket — and the 128 KiB buffer that comes with it — for
                    // as long as the queue takes, which is the memory this cap
                    // exists to bound in the first place.
                    let permit = match permits.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            rejected = rejected.wrapping_add(1);
                            if rejected % REJECTED_LOG_EVERY == 1 {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    "Refusing a local proxy connection from {}: {} are already \
                                     being served ({} refused so far)",
                                    addr,
                                    MAX_CONCURRENT_CONNECTIONS,
                                    rejected
                                );
                            }
                            // Dropped here, which closes it: no bytes read, no
                            // buffer ever allocated for it.
                            drop(stream);
                            continue;
                        }
                    };

                    #[cfg(feature = "tracing")]
                    tracing::debug!("New connection from: {}", addr);

                    let proxy_domains_clone = proxy_domains.clone();
                    let endpoint_group_clone = endpoint_group.clone();

                    let handle = tokio::spawn(async move {
                        // Released when the task ends, however it ends: this is
                        // what makes the permit a cap on live connections rather
                        // than on connections ever accepted.
                        let _permit = permit;
                        if let Err(e) = handle_local_connection(
                            stream,
                            proxy_domains_clone,
                            endpoint_group_clone,
                        )
                        .await
                        {
                            #[cfg(feature = "tracing")]
                            tracing::error!("Failed to handle local connection: {}", e);
                        }
                    });
                    self.track_connection(handle);
                }
                Err(e) => {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    #[cfg(feature = "tracing")]
                    tracing::error!("Local proxy accept error: {}", e);

                    // Transient ones — out of file descriptors under a burst of
                    // connections — used to end the loop, leaving the listener
                    // open and nothing accepting from it. Back off and go round
                    // again instead, but not forever.
                    consecutive_accept_errors += 1;
                    if consecutive_accept_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            "Local proxy accept failed {} times in a row, giving up",
                            consecutive_accept_errors
                        );
                        break;
                    }
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                }
            }
        }
        Ok(())
    }

    /// Remember a connection task so [`Self::stop`] can end it.
    fn track_connection(&self, handle: JoinHandle<()>) {
        let Ok(mut connections) = self.connections.lock() else {
            return;
        };
        // A busy proxy would otherwise keep every handle it ever spawned:
        // finished tasks are dropped here as they are noticed, and the rest in
        // `abort_connections`.
        connections.retain(|h| !h.is_finished());
        connections.push(handle);
    }

    fn abort_connections(&self) {
        let Ok(mut connections) = self.connections.lock() else {
            return;
        };
        for handle in connections.drain(..) {
            handle.abort();
        }
    }

    pub fn stop(&self) {
        #[cfg(feature = "tracing")]
        tracing::info!("Stopping local proxy");
        self.stopped.store(true, Ordering::Release);
        self.stop_notify.notify_one();
        // The handlers outlive `run()`: each one holds a pooled connection
        // until its peer closes the socket, which is not a decision this
        // process gets to make. Aborting is what lets a `close_all()` after
        // `run()` actually return those connections.
        self.abort_connections();
    }

    pub async fn close_all(&self) {
        self.endpoint_group.close_all().await;
    }
}

// Only referenced from the `debug_log_enabled()`-gated WebSocket dumps; in non-JNI builds
// that guard is a constant `false`, so the lint sees no live caller.
#[allow(dead_code)]
fn websocket_frame_preview(data: &[u8]) -> String {
    let mut preview = String::new();
    for &b in data.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            preview.push(b as char);
        } else {
            preview.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > 256 {
        preview.push_str("...");
    }
    format!("{} bytes: {}", data.len(), preview)
}

fn parse_websocket_frames(buffer: &mut Vec<u8>, frames: &mut Vec<(u8, Vec<u8>)>) {
    let mut pos = 0usize;
    while buffer.len().saturating_sub(pos) >= 2 {
        let b0 = buffer[pos];
        let b1 = buffer[pos + 1];
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let mut payload_len = (b1 & 0x7f) as u64;
        let mut header_len = 2usize;

        if payload_len == 126 {
            if buffer.len() < pos + 4 {
                break;
            }
            payload_len = u16::from_be_bytes([buffer[pos + 2], buffer[pos + 3]]) as u64;
            header_len = 4;
        } else if payload_len == 127 {
            if buffer.len() < pos + 10 {
                break;
            }
            payload_len = u64::from_be_bytes(
                buffer[pos + 2..pos + 10]
                    .try_into()
                    .expect("slice length is 8"),
            );
            header_len = 10;
        }

        if masked {
            header_len += 4;
        }

        let payload_start = pos + header_len;
        let total = match payload_start.checked_add(payload_len as usize) {
            Some(total) => total,
            None => break,
        };
        if total > buffer.len() {
            break;
        }

        let payload = if masked {
            let mask = &buffer[payload_start - 4..payload_start];
            buffer[payload_start..total]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ mask[i % 4])
                .collect()
        } else {
            buffer[payload_start..total].to_vec()
        };

        frames.push((opcode, payload));
        pos = total;
    }

    if pos > 0 {
        buffer.drain(..pos);
    }
}

/// Open a new iroh bi-stream for `host`, optionally writing `initial_data` as
/// the first bytes of the request/tunnel payload.
///
/// Retries `open_bi` / initial-write failures up to [`OPEN_ATTEMPTS`]
/// times, discarding the stale pooled connection on each failure so the retry
/// gets a fresh connection.
///
/// "Discarding" is the whole point, and it is what the retry buys: a
/// connection whose path died still looks open to QUIC (`close_reason()` stays
/// `None` until the idle timeout expires), so handing one back to the pool
/// hands it to the next attempt — the pool is last-in-first-out — and the
/// request fails [`OPEN_ATTEMPTS`] times on the same dead connection. Dropping
/// the last handle closes it for real, and the next attempt dials again.
///
/// The cost is that a timeout is retried like any other failure, so one
/// request can now wait [`OPEN_ATTEMPTS`] × [`STREAM_OPERATION_TIMEOUT`]
/// before it gives up. Not retrying was worse: a half-open connection then
/// stayed broken for every later request too.
///
/// Shared with [`crate::l4`]: the L4 tunnel needs the same recovery, and the
/// preface it passes as `initial_data` is written by exactly this code path.
pub(crate) async fn open_stream_with_retry(
    endpoint_group: &Arc<EndpointGroup>,
    host: &str,
    initial_data: Option<&[u8]>,
) -> Result<(PooledConnection, SendStream, RecvStream), ClientError> {
    let mut last_err: Option<ClientError> = None;
    // Whose health each attempt is spent on, kept so that running out of
    // attempts can name the backend that ran out. Recording the failure as it
    // happens would condemn a backend for having been idle: see
    // [`PooledConnection::discard`].
    let mut tried: Vec<EndpointId> = Vec::new();

    for _attempt in 1..=OPEN_ATTEMPTS {
        let pooled_conn = match endpoint_group.get_connection(host).await {
            Ok(conn) => conn,
            Err(e) => {
                // Leaving the loop before every attempt is spent must not lose
                // what those attempts found out. The group that could not offer
                // another connection has itself recorded what it learned about
                // the backend it was reaching for; without this the backends
                // named in `tried` keep every later request dialling them for
                // another full round of attempts first.
                endpoint_group.record_request_failures(&tried);
                return Err(e);
            }
        };
        let tried_node = pooled_conn.node();
        let conn = pooled_conn.conn().clone();

        let (mut send, recv) = match tokio::time::timeout(STREAM_OPERATION_TIMEOUT, conn.open_bi())
            .await
        {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi failed (attempt {}/{}): {}, retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS,
                    e
                );
                last_err = Some(anyhow::anyhow!(e).into());
                tried.extend(tried_node);
                // Closed rather than dropped: another handle is held by the
                // path watcher, so dropping this one would leave the
                // connection open until that task got around to it.
                pooled_conn.discard(b"the connection could not open a stream");
                continue;
            }
            Err(_) => {
                jni_log!(
                    "[DEBUG:local-proxy] open_bi timed out (attempt {}/{}), retrying on a fresh connection",
                    _attempt,
                    OPEN_ATTEMPTS
                );
                // A stream that never opened is a connection that does not
                // work, whether or not QUIC has noticed it yet — the same
                // stale-connection case as the branch above, so it gets the
                // same treatment rather than ending the loop on the first
                // attempt.
                last_err = Some(ClientError::TimeoutError);
                tried.extend(tried_node);
                pooled_conn.discard(b"the connection never opened a stream");
                continue;
            }
        };

        if let Some(data) = initial_data
            && let Err(e) = send.write_all(data).await
        {
            jni_log!(
                "[DEBUG:local-proxy] initial write failed (attempt {}/{}): {}, retrying on a fresh connection",
                _attempt,
                OPEN_ATTEMPTS,
                e
            );
            last_err = Some(e.into());
            tried.extend(tried_node);
            // Same reasoning as the `open_bi` failures: a connection that
            // could not take the first bytes is not one to hand back.
            pooled_conn.discard(b"the connection would not take the first bytes");
            continue;
        }

        return Ok((pooled_conn, send, recv));
    }

    // Every attempt spent and not one served. "Down" is now the most generous
    // reading left, and it is the reading the next request needs: continuing to
    // hand out these backends would spend another three attempts each on
    // connections nobody asked for. The next successful probe clears it.
    //
    // Every failure exit above says the same thing before it returns, which is
    // what makes this one line the loop's only failure path rather than the
    // exit it happens to reach most often.
    endpoint_group.record_request_failures(&tried);

    Err(last_err.unwrap_or_else(|| {
        ClientError::ConnectionError(format!(
            "Failed to open stream to {} after {} attempts",
            host, OPEN_ATTEMPTS
        ))
    }))
}

/// Ends the tasks it holds when it is dropped.
///
/// Dropping a `JoinHandle` detaches its task instead of cancelling it, so a
/// handler that spawns the two halves of a tunnel and is then aborted by
/// [`LocalProxy::stop`] used to leave both halves running: still holding the
/// client socket and the pooled connection the stop was meant to release.
/// The guard dies with the aborted future, and what it does is immediate.
struct TunnelTasks(Vec<tokio::task::AbortHandle>);

impl Drop for TunnelTasks {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

pub(crate) async fn handle_local_connection<S>(
    mut stream: S,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the first chunk of data to determine protocol (HTTP vs TLS)
    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];

    let n = match tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        stream.read(&mut temp_buf),
    )
    .await
    {
        Ok(Ok(0)) => {
            jni_log!("[DEBUG:local-proxy] Empty request, closing connection");
            return Ok(());
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            jni_log!("[DEBUG:local-proxy] Read error: {}", e);
            return Ok(());
        }
        Err(_) => {
            jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
            return Ok(());
        }
    };

    request_buf.extend_from_slice(&temp_buf[..n]);

    // Check if this is a TLS connection (ClientHello starts with 0x16 = Handshake content type)
    if !request_buf.is_empty() && request_buf[0] == 0x16 {
        jni_log!("[DEBUG:local-proxy] Detected TLS ClientHello, handling as raw tunnel via SNI");
        return handle_tls_tunnel(stream, request_buf, endpoint_group, proxy_domains).await;
    }

    // Step 2: HTTP — read the complete request header (up to \r\n\r\n)
    let mut header_end: Option<usize> = None;
    if let Some(pos) = request_buf[..].windows(4).position(|w| w == b"\r\n\r\n") {
        header_end = Some(pos + 4);
    }

    // The same cap as the loop below, applied to the first read: a header that
    // arrives whole in one read never enters the loop, and would otherwise
    // escape the limit entirely.
    if header_over_limit(&request_buf, header_end) {
        jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
        return Ok(());
    }

    while header_end.is_none() {
        let n = match tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            stream.read(&mut temp_buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                jni_log!("[DEBUG:local-proxy] Read error: {}", e);
                return Ok(());
            }
            Err(_) => {
                jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
                return Ok(());
            }
        };

        let prev_len = request_buf.len();
        request_buf.extend_from_slice(&temp_buf[..n]);

        // Search for \r\n\r\n, starting a few bytes before the new data
        let search_start = prev_len.saturating_sub(3);
        if let Some(pos) = request_buf[search_start..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            header_end = Some(search_start + pos + 4);
        }

        // A peer that keeps sending without ever ending its headers grows this
        // buffer without bound — one read every 30s is enough, because each
        // read is what resets the timeout above.
        if header_over_limit(&request_buf, header_end) {
            jni_log!("[DEBUG:local-proxy] Request header over the limit, closing connection");
            return Ok(());
        }
    }

    let header_end = match header_end {
        Some(pos) => pos,
        None => {
            jni_log!("[DEBUG:local-proxy] HTTP header end not found, closing connection");
            return Ok(());
        }
    };

    let request = match parse_http_request_legacy(&request_buf[..header_end]) {
        Ok(req) => {
            jni_log!(
                "[DEBUG:local-proxy] Parsed HTTP request: {} {}",
                req.method(),
                req.uri()
            );
            req
        }
        Err(e) => {
            jni_log!("[DEBUG:local-proxy] Failed to parse HTTP request: {}", e);
            jni_log!(
                "[DEBUG:local-proxy] First 16 bytes: {:?}",
                &request_buf[..std::cmp::min(request_buf.len(), 16)]
            );
            return Ok(());
        }
    };

    if request.method().as_str() == "CONNECT" {
        // `CONNECT host:port` is authority-form (RFC 9110 9.3.6). The port used to be
        // dropped here (`uri.split(':').next()`), which is why this branch only ever
        // worked for 443/TLS: everything else reached the server as a request line with
        // no port, matched no route, and was silently forwarded to `default_backend`.
        let target = request.uri().to_string();
        let Some((host, port)) = crate::l4::parse_connect_target(&target) else {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT without a usable host:port: '{}'",
                target
            );
            return write_proxy_error(&mut stream, "400 Bad Request").await;
        };

        if !should_proxy_domain(&host, &proxy_domains) {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT '{}' is not a proxied domain, refusing",
                target
            );
            return write_proxy_error(&mut stream, "403 Forbidden").await;
        }

        // Open the tunnel *before* answering 200. `200 Connection Established` promises
        // that the far side is up, so the client has to still be able to receive an HTTP
        // error when it is not — which is why the answer comes after the L4 handshake
        // and not before it.
        let (pooled_conn, mut send, mut recv) =
            match crate::l4::open_tcp(&endpoint_group, &host, port).await {
                Ok(tunnel) => tunnel,
                Err(e) => {
                    jni_log!(
                        "[DEBUG:local-proxy] CONNECT {}:{} failed: {}",
                        host,
                        port,
                        e
                    );
                    return write_proxy_error(&mut stream, "502 Bad Gateway").await;
                }
            };

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        client_write
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Spawn bidirectional forwarding as separate tasks to keep each
        // task's async state machine small (avoids deep nesting that causes
        // stack overflow on tokio worker threads).
        let mut client_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel client_to_iroh read error: {}", e);
                        break;
                    }
                }
            }
        });

        let mut backend_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => break,
                    Ok(Some(n)) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client write error: {}", e);
                            break;
                        }
                        if let Err(e) = client_write.flush().await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client flush error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel iroh_to_client read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Lives until this handler returns, and dies with it if it is aborted
        // first — which is the only moment that matters: `stop()` cancels the
        // task running this function, and the two halves above have to go with
        // it or the tunnel outlives the proxy it belongs to.
        let _tasks = TunnelTasks(vec![
            client_task.abort_handle(),
            backend_task.abort_handle(),
        ]);

        tokio::select! {
            _ = &mut client_task => (),
            _ = &mut backend_task => (),
        }

        client_task.abort();
        backend_task.abort();

        endpoint_group.return_connection(&host, pooled_conn).await;
        return Ok(());
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            let h = h.split(':').next().unwrap_or(h);
            jni_log!("[DEBUG:local-proxy] Found Host header: '{}'", h);
            if should_proxy_domain(h, &proxy_domains) {
                target_host = Some(h.to_string());
                break;
            }
        }
    }

    if target_host.is_none() {
        jni_log!("[DEBUG:local-proxy] No matching Host header found");
        return Ok(());
    }

    let host = target_host.unwrap();
    jni_log!(
        "[DEBUG:local-proxy] Getting connection for domain: '{}'",
        host
    );

    // WebSocket upgrade: rewrite the request line to use an absolute "http://"
    // URI. When a browser connects through a normal HTTP proxy it sends
    // "GET http://host/path HTTP/1.1" (absolute-form request-target per
    // RFC 7230 §5.3.2). The backend uses this to recognize that the stream
    // should be kept alive for bidirectional data flow after the HTTP upgrade,
    // rather than treating it as a one-shot HTTP exchange.
    if is_websocket_request_static(&request) {
        jni_log!("[DEBUG:local-proxy] WebSocket request, rewriting to absolute URI");
        jni_log!(
            "[DEBUG:local-proxy] WebSocket request details: uri={}, host={}, headers={}",
            request.uri(),
            host,
            redacted_headers(request.headers())
        );

        // Find the first line (request line)
        let first_line_end = request_buf[..header_end]
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(0);

        if first_line_end > 0 {
            let request_line = &request_buf[..first_line_end];
            let line_str = String::from_utf8_lossy(request_line);
            if let Some((method_rest, version)) = line_str.rsplit_once(" HTTP/")
                && let Some(method) = method_rest.split_whitespace().next()
            {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                // Use http:// scheme (not ws://) — the backend handles
                // the WebSocket upgrade via the Upgrade header, not the URI
                let absolute_uri = format!("http://{}{}", host, path);
                let new_line = format!("{} {} HTTP/{}\r\n", method, absolute_uri, version);

                let mut request_to_send =
                    Vec::with_capacity(new_line.len() + header_end - first_line_end);
                request_to_send.extend_from_slice(new_line.as_bytes());
                // Copy the rest of headers (skip the original request line)
                let rest_start = first_line_end + 2; // skip \r\n
                if rest_start < header_end {
                    request_to_send.extend_from_slice(&request_buf[rest_start..header_end]);
                }

                jni_log!(
                    "[DEBUG:local-proxy] Rewrote WebSocket request line: {}",
                    new_line.trim()
                );

                // Open iroh bi-stream and send the modified request
                let (pooled_conn, mut send, mut recv) =
                    open_stream_with_retry(&endpoint_group, &host, Some(&request_to_send)).await?;

                let (mut client_read, mut client_write) = tokio::io::split(stream);
                jni_log!(
                    "[DEBUG:local-proxy] WebSocket request sent to iroh: {} bytes",
                    request_to_send.len()
                );

                // Bidirectional forwarding (no send.finish() — keep stream open)
                let client_to_iroh = async move {
                    let mut buf = vec![0u8; STREAM_BUF_SIZE];
                    let mut ws_buffer = Vec::new();
                    loop {
                        match client_read.read(&mut buf).await {
                            Ok(0) => {
                                jni_log!("[DEBUG:local-proxy] WS client EOF");
                                return "client_eof";
                            }
                            Ok(n) => {
                                // Payload, not metadata: it costs a preview to
                                // build and it is the user's traffic, so it is
                                // only worth it while debugging.
                                if debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS client->iroh: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                }
                                // The buffer only feeds the dumps above, and it
                                // only empties once a whole frame is in it: a
                                // client that sends a frame header and then
                                // nothing would grow it forever, logs or no
                                // logs. So the decode is part of what is
                                // switched off with them.
                                if debug_log_enabled() {
                                    ws_buffer.extend_from_slice(&buf[..n]);
                                    let mut frames = Vec::new();
                                    parse_websocket_frames(&mut ws_buffer, &mut frames);
                                    for (opcode, payload) in frames {
                                        if opcode == 1 || opcode == 8 {
                                            jni_log!(
                                                "[DEBUG:local-proxy] WS client frame decoded (opcode {}): {}",
                                                opcode,
                                                String::from_utf8_lossy(&payload)
                                            );
                                        }
                                    }
                                }
                                if let Err(e) = send.write_all(&buf[..n]).await {
                                    jni_log!("[DEBUG:local-proxy] WS client->backend err: {}", e);
                                    return "client_write_error";
                                }
                            }
                            Err(e) => {
                                jni_log!("[DEBUG:local-proxy] WS client read error: {}", e);
                                return "client_read_error";
                            }
                        }
                    }
                };

                let iroh_to_client = async move {
                    let mut buf = vec![0u8; STREAM_BUF_SIZE];
                    let mut first = true;
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(None) => {
                                jni_log!("[DEBUG:local-proxy] WS iroh EOF");
                                return "iroh_eof";
                            }
                            Ok(Some(n)) => {
                                if first {
                                    first = false;
                                    let p = &buf[..std::cmp::min(n, 200)];
                                    if debug_log_enabled() {
                                        jni_log!(
                                            "[DEBUG:local-proxy] WS first response: {}",
                                            String::from_utf8_lossy(p)
                                        );
                                    }
                                }
                                if debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS iroh->client: {}",
                                        websocket_frame_preview(&buf[..n])
                                    );
                                }
                                if n <= 1024 && debug_log_enabled() {
                                    jni_log!(
                                        "[DEBUG:local-proxy] WS iroh->client decoded: {}",
                                        String::from_utf8_lossy(&buf[..n])
                                    );
                                }
                                if client_write.write_all(&buf[..n]).await.is_err() {
                                    return "client_write_error";
                                }
                                let _ = client_write.flush().await;
                            }
                            Err(e) => {
                                jni_log!("[DEBUG:local-proxy] WS iroh read error: {}", e);
                                return "iroh_read_error";
                            }
                        }
                    }
                };

                let mut client_task = tokio::spawn(client_to_iroh);
                let mut backend_task = tokio::spawn(iroh_to_client);
                // See the CONNECT branch: this dies with the handler, and with
                // it both halves of the WebSocket tunnel.
                let _tasks = TunnelTasks(vec![
                    client_task.abort_handle(),
                    backend_task.abort_handle(),
                ]);

                let (closed_direction, close_reason) = tokio::select! {
                    result = &mut client_task => {
                        ("client_to_iroh", result.unwrap_or("client_task_panicked"))
                    }
                    result = &mut backend_task => {
                        ("iroh_to_client", result.unwrap_or("backend_task_panicked"))
                    }
                };

                if closed_direction == "client_to_iroh" {
                    backend_task.abort();
                } else {
                    client_task.abort();
                }
                jni_log!(
                    "[DEBUG:local-proxy] WebSocket tunnel closed first by {} ({})",
                    closed_direction,
                    close_reason
                );

                endpoint_group.return_connection(&host, pooled_conn).await;
                return Ok(());
            }
        }

        // Fallback: if we couldn't rewrite, just connect normally
        jni_log!("[DEBUG:local-proxy] WebSocket URI rewrite failed, falling back to regular HTTP");
    }

    // Regular HTTP path
    // Remove cache validation headers to prevent 304 responses with empty body
    let filtered_headers = remove_cache_validation_headers(&request_buf[..header_end]);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!(
        "[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}",
        request_to_send.len(),
        host
    );
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(&endpoint_group, &host, Some(&request_to_send)).await?;

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    let client_to_backend = async move {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Client to backend write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Client read error: {}", e);
                    break;
                }
            }
        }
        let _ = send.finish();
    };

    let backend_to_client = async move {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        let mut total_bytes = 0;
        let mut debug_preview = Vec::with_capacity(1500);
        let mut response_sent = false;
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    total_bytes += n;
                    if !response_sent && debug_preview.len() < 1500 {
                        debug_preview.extend_from_slice(
                            &buf[..std::cmp::min(n, 1500 - debug_preview.len())],
                        );
                    }
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client write error: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Backend to client flush error: {}", e);
                        break;
                    }
                    if !response_sent {
                        response_sent = true;
                        jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
                        if !debug_preview.is_empty() && debug_log_enabled() {
                            jni_log!(
                                "[DEBUG:local-proxy] Response preview: {}",
                                String::from_utf8_lossy(&debug_preview)
                            );
                        }
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Backend read error: {}", e);
                    break;
                }
            }
        }
        if !response_sent && total_bytes > 0 {
            jni_log!(
                "[DEBUG:local-proxy] Response sent (late): {} bytes",
                total_bytes
            );
            if !debug_preview.is_empty() && debug_log_enabled() {
                jni_log!(
                    "[DEBUG:local-proxy] Response preview: {}",
                    String::from_utf8_lossy(&debug_preview)
                );
            }
        }
    };
    // END regular HTTP closures

    // Regular HTTP request-response handling
    jni_log!("[DEBUG:local-proxy] Detected HTTP request, using request-response mode");
    jni_log!(
        "[DEBUG:local-proxy] Request headers: {}",
        redacted_headers(request.headers())
    );
    let client_task = tokio::spawn(client_to_backend);
    let mut backend_task = tokio::spawn(backend_to_client);
    // See the CONNECT branch: the client half is aborted below on the normal
    // path, and both go when the proxy is stopped mid-request.
    let _tasks = TunnelTasks(vec![
        client_task.abort_handle(),
        backend_task.abort_handle(),
    ]);

    // Wait for the backend response to be fully relayed back to the client
    // (bounded for streaming/long-lived responses). We must NOT wait for the
    // client to close its TCP connection first: HTTP clients routinely keep the
    // connection alive (keep-alive) after reading the response, so client_task
    // would block indefinitely and the iroh connection would never be returned
    // to the pool -- which defeats pre-connect/connection warm-up and leaks
    // pooled connections.
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(60), &mut backend_task).await;

    // Response has been delivered; stop the client->backend relay so the pooled
    // iroh connection is released immediately. Aborting also closes the client
    // TCP socket (HTTP/1.1 allows the server to close after the response),
    // so a keep-alive client socket can't pin this task.
    client_task.abort();

    endpoint_group.return_connection(&host, pooled_conn).await;
    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
}

/// Handle a raw TLS tunnel connection via SNI extraction.
///
/// When a client connects to the VPN's virtual proxy IP on port 443, it sends
/// a TLS ClientHello directly (since it doesn't know there's an HTTP proxy in
/// between). This function extracts the SNI hostname from the ClientHello,
/// establishes an iroh tunnel to the appropriate backend, and forwards raw TCP
/// data bidirectionally — no HTTP parsing involved.
pub(crate) async fn handle_tls_tunnel<S>(
    mut stream: S,
    initial_data: Vec<u8>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] TLS tunnel mode");

    // Ensure we have enough data for the full TLS record (ClientHello)
    // Record header is 5 bytes: content_type(1) + version(2) + length(2)
    let mut data = initial_data;
    if data.len() >= 5 {
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let total_needed = 5 + record_len;
        while data.len() < total_needed {
            let mut extra = [0u8; 4096];
            match stream.read(&mut extra).await {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&extra[..n]),
                Err(_) => break,
            }
        }
    }

    // Extract SNI from TLS ClientHello
    let sni = match extract_sni_from_client_hello(&data) {
        Some(sni) => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: extracted SNI '{}'", sni);
            sni
        }
        None => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: could not extract SNI from ClientHello");
            return Ok(());
        }
    };

    if !should_proxy_domain(&sni, &proxy_domains) {
        jni_log!(
            "[DEBUG:local-proxy] TLS tunnel: SNI '{}' not in proxy domains, closing",
            sni
        );
        return Ok(());
    }

    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: establishing iroh tunnel for '{}'",
        sni
    );

    // Open a fresh iroh bi-stream and forward the initial TLS ClientHello. If
    // the pooled connection is stale, open_bi / write fails and we retry on a
    // fresh connection.
    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: forwarding initial {} bytes",
        data.len()
    );
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(&endpoint_group, &sni, Some(&data)).await?;

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Bidirectional raw data forwarding (TCP tunnel)
    let client_to_iroh = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel client->iroh write error: {}",
                            e
                        );
                        break;
                    }
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel client read error: {}", e);
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel iroh->client write error: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        jni_log!("[DEBUG:local-proxy] TLS tunnel flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel backend read error: {}", e);
                    break;
                }
            }
        }
    };

    jni_log!("[DEBUG:local-proxy] TLS tunnel: bidirectional forwarding started");
    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
    }

    endpoint_group.return_connection(&sni, pooled_conn).await;
    jni_log!("[DEBUG:local-proxy] TLS tunnel closed");
    Ok(())
}

/// Extract the SNI (Server Name Indication) hostname from a TLS ClientHello.
///
/// The TLS 1.2/1.3 ClientHello format (simplified):
///   1 byte  content_type (0x16 = Handshake)
///   2 bytes version
///   2 bytes record length
///   --- record data ---
///   1 byte  handshake_type (0x01 = ClientHello)
///   3 bytes handshake length
///   2 bytes client version
///   32 bytes random
///   1 byte  session ID length + data
///   2 bytes cipher suites length + data
///   1 byte  compression methods length + data
///   2 bytes extensions length
///   extensions...
///
/// SNI extension type = 0x0000
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Must be TLS Handshake content type
    if data[0] != 0x16 {
        return None;
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let total_needed = 5 + record_len;
    if data.len() < total_needed {
        return None;
    }

    let mut pos = 5usize;

    // Handshake type: ClientHello (0x01)
    if pos >= data.len() || data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // Handshake length (3 bytes, big-endian)
    if pos + 3 > data.len() {
        return None;
    }
    let _hs_len =
        ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
    pos += 3;

    // Skip protocol version (2 bytes) + random (32 bytes)
    pos += 34;
    if pos > data.len() {
        return None;
    }

    // Skip session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos > data.len() {
        return None;
    }

    // Skip cipher suites
    if pos + 1 >= data.len() {
        return None;
    }
    let cipher_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_len;
    if pos > data.len() {
        return None;
    }

    // Skip compression methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos > data.len() {
        return None;
    }

    // Extensions
    if pos + 1 >= data.len() {
        return None;
    }
    let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > data.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let ext_data_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 {
            // server_name (SNI) extension
            if pos + 2 > ext_end {
                return None;
            }
            let _sni_list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            pos += 2;

            if pos + 3 <= ext_end.min(data.len()) {
                let name_type = data[pos];
                pos += 1;
                let name_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                pos += 2;

                if name_type == 0x00 && pos + name_len <= data.len() && pos + name_len <= ext_end {
                    // Read host_name (ASCII/UTF-8 encoded hostname)
                    return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_data_len;
    }

    None
}

fn remove_cache_validation_headers(header_bytes: &[u8]) -> Vec<u8> {
    // The input always ends with \r\n\r\n (the HTTP header terminator,
    // up to header_end). We iterate over each header line, strip the cache
    // validation headers, and preserve the original \r\n\r\n terminator
    // so the body (appended separately) starts at the right position.
    let mut result = Vec::with_capacity(header_bytes.len());
    let mut start = 0;

    while let Some(pos) = header_bytes[start..].windows(2).position(|w| w == b"\r\n") {
        let line_end = start + pos;
        let line = &header_bytes[start..line_end];

        let is_cache_header = line.len() >= 18 && {
            let lower = line.to_ascii_lowercase();
            lower.starts_with(b"if-modified-since:") || lower.starts_with(b"if-none-match:")
        };

        if !is_cache_header {
            result.extend_from_slice(line);
            result.extend_from_slice(b"\r\n");
        }

        start = line_end + 2;
    }

    // Loop already preserved the \r\n\r\n terminator — don't add an extra one
    result
}

/// Answer a `CONNECT` that cannot be served.
///
/// Only valid while the socket is still an HTTP one: once `200 Connection Established`
/// has gone out the socket is a byte tunnel and an HTTP status line would be payload.
/// That is why every refusal — an unusable target, a domain outside the proxy list, a
/// tunnel the server refused — has to be decided before the 200 is written.
async fn write_proxy_error<S>(stream: &mut S, status_line: &str) -> Result<(), ClientError>
where
    S: AsyncWrite + Unpin,
{
    let response =
        format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

pub(crate) fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    for domain in proxy_domains {
        let domain_lower = domain.to_lowercase();
        if let Some(suffix) = domain_lower.strip_prefix('*') {
            if host_lower.ends_with(suffix) {
                return true;
            }
        } else if host_lower == domain_lower || host_lower.ends_with(&format!(".{}", domain_lower))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoadBalancingStrategy;
    use iroh::Endpoint;
    use iroh::endpoint::presets;

    /// A proxy listening on an ephemeral port, with no backends behind it.
    ///
    /// Enough for the accept loop, which in these tests never gets as far as
    /// dialling one. Built through `shared` rather than `new` because the test
    /// needs the address `new` keeps to itself.
    async fn listening_proxy() -> (LocalProxy, std::net::SocketAddr) {
        let ep = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let group = EndpointGroup::new_with_nodes_and_endpoint(
            Vec::new(),
            None,
            LoadBalancingStrategy::RoundRobin,
            ep,
        )
        .await
        .expect("a group with no backend still builds");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback listener needs no network");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");
        (
            LocalProxy::shared(Arc::new(listener), Arc::new(group), Vec::new()),
            addr,
        )
    }

    fn spawn_run(proxy: &LocalProxy) -> JoinHandle<Result<(), ClientError>> {
        let proxy = proxy.clone();
        tokio::spawn(async move { proxy.run().await })
    }

    /// The cap is what turns memory into a bounded quantity: every connection
    /// allocates a `STREAM_BUF_SIZE` buffer, so an accept loop that takes every
    /// caller lets anything on the loopback interface spend this process's
    /// memory one connection at a time.
    ///
    /// The refused socket is closed without a byte being read — it must not be
    /// queued, because a queued caller holds the buffer while it waits.
    #[tokio::test]
    async fn connections_beyond_the_cap_are_refused() {
        use std::time::{Duration, Instant};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let (proxy, addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // Hold the whole budget open. A connection that has sent nothing sits in
        // the handler waiting for a request, which is the state being counted.
        let mut held = Vec::with_capacity(MAX_CONCURRENT_CONNECTIONS);
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(TcpStream::connect(addr).await.expect("the caller connects"));
        }

        // `track_connection` runs straight after each accept, so the number of
        // tracked handles is the number being served. Waiting for it to reach the
        // cap is what makes the next connection a refusal rather than a race.
        let deadline = Instant::now() + Duration::from_secs(10);
        while proxy.connections.lock().unwrap().len() < MAX_CONCURRENT_CONNECTIONS {
            assert!(
                Instant::now() < deadline,
                "the accept loop took only {} of {} connections",
                proxy.connections.lock().unwrap().len(),
                MAX_CONCURRENT_CONNECTIONS
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // One over the budget: closed immediately, with nothing read from it.
        let mut extra = TcpStream::connect(addr).await.expect("the caller connects");
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
            .await
            .expect("a refusal closes the socket instead of leaving it open");
        assert_eq!(
            closed.expect("a refusal is a close, not an error"),
            0,
            "a connection beyond the cap must be closed, not queued"
        );

        // And the budget is released: once a caller hangs up, its slot comes back.
        drop(held.pop());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut probe = TcpStream::connect(addr).await.expect("the caller connects");
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(200), probe.read(&mut buf)).await {
                // A timeout means the connection was accepted and is waiting for
                // a request: the slot came back.
                Err(_) => break,
                Ok(Ok(0)) => {
                    assert!(
                        Instant::now() < deadline,
                        "no slot was released after a connection ended"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(Ok(n)) => panic!("nothing is ever sent to a fresh connection, got {n} bytes"),
                Ok(Err(e)) => panic!("a fresh connection is not reset: {e}"),
            }
        }

        proxy.stop();
        runner.abort();
    }

    /// `stop()` has to reach a loop that is parked in `accept()`, not one that
    /// happens to look at a flag on the way past: with nothing to wake it, the
    /// task stays on the listener for as long as the process lives.
    #[tokio::test]
    async fn stop_wakes_a_loop_that_is_waiting_for_a_connection() {
        let (proxy, _addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // Long enough that the loop is definitely inside `accept()`.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        proxy.stop();

        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
                .await
                .is_ok(),
            "run() never returned after stop()"
        );
    }

    /// The handlers outlive `run()`, so a proxy that only stops the loop would
    /// leave them holding pooled connections. Stopping has to end them too.
    #[tokio::test]
    async fn stop_ends_the_connections_it_accepted() {
        let (proxy, addr) = listening_proxy().await;
        let runner = spawn_run(&proxy);

        // A client that connects and then says nothing: the handler parks in
        // its first read, which is the state that used to survive stop().
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the proxy is listening");

        let tracked = tokio::time::timeout(tokio::time::Duration::from_secs(2), async {
            loop {
                if proxy.connections.lock().unwrap().len() == 1 {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(tracked.is_ok(), "the accepted connection was never tracked");

        proxy.stop();
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
                .await
                .is_ok(),
            "run() never returned after stop()"
        );
        assert!(
            proxy.connections.lock().unwrap().is_empty(),
            "stop() must drop the handles it aborted"
        );

        // Aborting the handler drops its socket, so the peer sees EOF instead
        // of waiting out the handler's read timeout.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(tokio::time::Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("the client read never returned")
            .expect("the client read failed");
        assert_eq!(read, 0, "the handler kept its socket open after stop()");
    }

    /// The cap is on the header, not on the whole request: a short header
    /// followed by a body larger than the cap is an ordinary upload, and used
    /// to be refused for being one.
    #[test]
    fn the_header_limit_ignores_the_body() {
        let mut request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        request.extend(std::iter::repeat_n(b'x', MAX_REQUEST_HEADER * 4));

        let header_end = header_terminator(&request);

        assert!(!header_over_limit(&request, header_end));
    }

    /// A header that arrives whole in one read never enters the read loop, so
    /// the first read is measured as well — otherwise the cap only ever applied
    /// to a header split across two.
    #[test]
    fn an_oversized_header_is_refused_even_when_it_is_complete() {
        let mut request = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEADER));
        request.extend_from_slice(b"\r\n\r\n");

        let header_end = header_terminator(&request).expect("the terminator is written above");

        assert!(header_over_limit(&request, Some(header_end)));
    }

    /// Until a terminator arrives, everything read is header as far as anyone
    /// can tell — which is the case that bounds a peer that never ends one.
    #[test]
    fn a_header_that_never_ends_is_still_capped() {
        let request: Vec<u8> = std::iter::repeat_n(b'a', MAX_REQUEST_HEADER + 1).collect();

        assert!(header_over_limit(&request, None));
        assert!(!header_over_limit(&request[..MAX_REQUEST_HEADER], None));
    }

    /// Where the header ends in `request`, if it ends at all.
    fn header_terminator(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
    }
}
