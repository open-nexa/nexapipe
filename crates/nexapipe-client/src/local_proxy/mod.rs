use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};
use crate::http::{is_websocket_request_static, parse_http_request_legacy};
use nexapipe_proto::protocol::Protocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

use http_head::{
    HeaderOutcome, filter_request_headers, read_http_header, redacted_headers, request_line_end,
};
use tls::handle_tls_tunnel;
pub(crate) use tunnel::OPEN_ATTEMPTS;
pub(crate) use tunnel::open_stream_with_retry_until;
use tunnel::{TunnelTasks, open_stream_with_retry};
use websocket::{
    WS_FRAME_BUFFER_LIMIT, parse_websocket_frames, websocket_frame_preview, ws_frame_buffer_append,
};

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

mod http_head;
mod tls;
mod tunnel;
mod websocket;

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

/// Whether the local proxy may serve `bound`.
///
/// **Loopback only, unless the caller says otherwise.** The local proxy does
/// not authenticate the peer that connects to it: it hands out the tunnel of a
/// connection that has already authenticated, so whoever reaches the port gets
/// the tunnel without a credential. That is the same reason the server's own
/// plaintext listener is loopback-only unless it is explicitly exposed, and
/// the desktop app already refuses a non-loopback address before it reaches
/// this crate.
///
/// `exposed` is the caller's own answer to the same question: a deployment
/// that puts something else in front of the port — a firewall, a container
/// network — says so explicitly rather than by accident.
pub fn may_bind_local_proxy(bound: SocketAddr, exposed: bool) -> bool {
    exposed || bound.ip().is_loopback()
}

/// How long the accept loop waits after an error before trying again, and how
/// many it takes before it concludes the listener is not coming back.
/// The buffer one copy of a stream reads into.
///
/// **32 KiB**, which is what the server uses for the same job, and about what
/// a socket read fills anyway. The buffer does not decide how fast a stream
/// goes — the copy is a pipeline, and the size of the buffer is the size of
/// one write — but it decides what a connection costs: the local proxy holds
/// one of these while it reads a request, and a tunnel holds two, one per
/// direction.
const STREAM_BUF_SIZE: usize = 32 * 1024;
const ACCEPT_ERROR_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_millis(100);
const MAX_CONSECUTIVE_ACCEPT_ERRORS: usize = 10;

/// How many connections are served at once.
///
/// A connection holds two [`STREAM_BUF_SIZE`] buffers once it is copying in
/// both directions — one per direction of the copy loop — so this is what
/// turns an unbounded number of connections into a bounded amount of memory.
/// The same figure the server's `accept_bi` uses, which is not a coincidence:
/// a caller is one connection either way.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// One line per this many refused connections. A refusal is the caller's
/// problem to retry, not a per-connection event worth a log line — and logging
/// every one would let a caller that opens connections in a loop write to the
/// log as fast as it can connect.
const REJECTED_LOG_EVERY: usize = 100;

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
    /// A handler holds a **borrow** on a pooled connection for as long as its
    /// peer keeps the socket open, which is not this process's decision:
    /// without this a "stopped" proxy would still be holding borrows, and
    /// the connections they ride would stay open.
    connections: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    /// How many of [`MAX_CONCURRENT_CONNECTIONS`] are still free.
    ///
    /// Held here rather than in the accept loop so both constructors get one;
    /// the permits themselves move into the connection tasks, which is what
    /// releases them.
    permits: Arc<Semaphore>,
}

impl LocalProxy {
    /// Binds the local proxy on `listen_addr`.
    ///
    /// **The address has to be a loopback one.** The local proxy does not
    /// authenticate the peer that connects to it: it hands out the tunnel of a
    /// connection that has already authenticated, so whoever reaches the port
    /// gets the tunnel without a credential. A non-loopback bind publishes
    /// that to everyone who can reach the machine, so it is refused here
    /// rather than left to the caller to think about.
    ///
    /// A deployment that puts something else in front of the port — a
    /// firewall, a container network — says so with
    /// [`LocalProxy::new_exposed`], which is the only way to bind
    /// elsewhere.
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        Self::bind(listen_addr, proxy_domains, endpoint_group, false).await
    }

    /// Binds the local proxy on `listen_addr`, even when it is not a loopback
    /// address.
    ///
    /// The explicit opt-in, for a deployment that gates the port with
    /// something else. The same shape as the server's `[server] expose`: a
    /// setting that says "I know, and I have put something in front of it".
    pub async fn new_exposed(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self, ClientError> {
        Self::bind(listen_addr, proxy_domains, endpoint_group, true).await
    }

    async fn bind(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
        exposed: bool,
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
        // Judged by the address the socket actually became, so `0.0.0.0` and
        // `[::]` are caught as what they are rather than as what was asked
        // for — the same rule the server's plaintext listener follows.
        let bound = listener.local_addr()?;
        if !may_bind_local_proxy(bound, exposed) {
            return Err(ClientError::InvalidConfig(format!(
                "the local proxy would bind {bound}, which is reachable from the network, and it \
                 hands out an already-authenticated tunnel to whoever connects. Use a loopback \
                 address, or set `[local_proxy] expose = true` when something else gates the port \
                 (the library's `LocalProxy::new_exposed`)"
            )));
        }
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", bound);
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
        let bound = listener.local_addr()?;
        if !may_bind_local_proxy(bound, false) {
            return Err(ClientError::InvalidConfig(format!(
                "the local proxy would bind {bound}, which is reachable from the network, and it \
                 hands out an already-authenticated tunnel to whoever connects. Use a loopback \
                 address"
            )));
        }
        let endpoint_group = EndpointGroup::new_with_single_pool(conn_pool).await;
        #[cfg(feature = "tracing")]
        tracing::info!("Local proxy listening on: {}", bound);
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
        report_domain_patterns(&proxy_domains);
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

    /// The address the proxy is listening on.
    ///
    /// Only known once the listener is bound, which is why it is an accessor
    /// rather than a field: a caller that asked for port 0 — the usual way of
    /// asking for any free port — has to be told which one it got.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
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
                    // Named here rather than inside the handler, where it is not
                    // known: a flow listed without where it came from is a row
                    // with a hole in it, and the socket that accepted it is the
                    // only thing that ever knows.
                    let peer = Some(addr.to_string());

                    let handle = tokio::spawn(async move {
                        // Released when the task ends, however it ends: this is
                        // what makes the permit a cap on live connections rather
                        // than on connections ever accepted.
                        let _permit = permit;
                        if let Err(e) = handle_local_connection(
                            stream,
                            proxy_domains_clone,
                            endpoint_group_clone,
                            peer,
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

pub(crate) async fn handle_local_connection<S>(
    mut stream: S,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
    // Where the bytes came from, as whatever accepted the socket named it.
    // `None` when the caller has no address to give — a stream that was never
    // a socket, or a caller that never saw one.
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the first chunk of data to determine protocol (HTTP vs TLS)
    //
    // Shares the header budget with the loop below rather than having its own
    // thirty seconds: this is the first read *of* that header, so giving it a
    // separate budget would let a client spend twice the intended time before
    // the first byte of its request line was counted against anything.
    let header_budget = crate::deadline::Deadlines::default().header;
    let first_byte_deadline = tokio::time::Instant::now() + header_budget;
    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];

    let n = match tokio::time::timeout_at(first_byte_deadline, stream.read(&mut temp_buf)).await {
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

    // Check if this is a TLS connection. The predicate is the protocol
    // crate's, the same one the server asks: a hello is a hello on both
    // sides, and a client that spelled the byte out itself would be free to
    // disagree with the server about what a TLS connection is.
    if !request_buf.is_empty() && nexapipe_proto::tls::is_tls_handshake(request_buf[0]) {
        jni_log!("[DEBUG:local-proxy] Detected TLS ClientHello, handling as raw tunnel via SNI");
        let header_buf = std::mem::take(&mut temp_buf);
        return handle_tls_tunnel(
            stream,
            request_buf,
            header_buf,
            endpoint_group,
            proxy_domains,
            peer,
        )
        .await;
    }

    // Step 2: HTTP — read the complete request head (up to \r\n\r\n).
    //
    // `first_byte_deadline`, not a fresh instant: the budget was taken once,
    // before the first read above, and it covers the whole head. Taking it again
    // here would hand the caller two budgets — thirty seconds to send a first
    // byte and thirty more to finish the header — which is exactly the doubling
    // the first read's comment says this avoids.
    //
    // The per-read timeouts this replaces re-armed on each read, so a client
    // sending one byte of `Host:` before each expiry kept the connection, the
    // task and the slot for as long as it liked — the read that arrived *was*
    // the renewal.
    // The same buffer the first read used: one buffer for the whole head,
    // rather than one for the first read and another for the rest of it.
    let header_end = match read_http_header(
        &mut stream,
        &mut request_buf,
        &mut temp_buf,
        first_byte_deadline,
    )
    .await
    {
        HeaderOutcome::Complete(header_end) => header_end,
        HeaderOutcome::Closed => return Ok(()),
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

        // One tunnel is one flow for as long as this handler lives, however it
        // ends: EOF, either direction failing, or this task being cancelled
        // because the proxy stopped.
        //
        // The counters are the *flow's* rather than the connection's, which is
        // what lets a reader ask how much this connection has moved as opposed
        // to how much the backend has. Two halves of one copy loop each carry a
        // clone of the same guard, so the two directions land in one total.
        let flow = pooled_conn.enter_flow(FlowMeta {
            kind: FlowKind::Connect,
            target: Some(format!("{host}:{port}")),
            source: peer.clone(),
        });
        let count_to_backend = flow.counter();
        let count_from_backend = flow.counter();

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        client_write
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Spawn bidirectional forwarding as separate tasks to keep each
        // task's async state machine small (avoids deep nesting that causes
        // stack overflow on tokio worker threads).
        //
        // The buffer the head was read into becomes the client half's buffer:
        // a connection holds two of them — one per direction — rather than
        // three.
        let header_buf = std::mem::take(&mut temp_buf);
        let mut client_task = tokio::spawn(async move {
            let mut buf = header_buf;
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => {
                        // The client is done sending. That is a half-close, not
                        // the end of the conversation: the server may still
                        // have a reply on the way, and the reply has to reach
                        // the client.
                        //
                        // Propagated as a FIN, so the server sees what it
                        // would see from a socket whose write side the client
                        // had shut down. Dropping the stream instead would
                        // reset it, and a reset is not a half-close.
                        let _ = send.finish();
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                            break;
                        }
                        count_to_backend.record_sent(n as u64);
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
                        count_from_backend.record_received(n as u64);
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel iroh_to_client read error: {}", e);
                        break;
                    }
                }
            }
            // The server is done sending. That is a half-close, and the client
            // has to hear it: the write side towards the client is shut down,
            // so the client sees an end of stream the way it would see it
            // from a socket.
            //
            // Without this the client waits for an answer that is not coming.
            // Joining the two directions is right, but joining them is not the
            // same as leaving the client hanging: the direction that ended has
            // to be handed on to the peer. The read side stays open, so a
            // client that still has something to say can say it.
            let _ = client_write.shutdown().await;
        });

        // Lives until this handler returns, and dies with it if it is aborted
        // first — which is the only moment that matters: `stop()` cancels the
        // task running this function, and the two halves above have to go with
        // it or the tunnel outlives the proxy it belongs to.
        let _tasks = TunnelTasks(vec![
            client_task.abort_handle(),
            backend_task.abort_handle(),
        ]);

        // **Both directions, and each of them for as long as it lasts.**
        //
        // A TCP half-close is a request, not an ending: a client that writes
        // its request and then shuts down its write side is saying "I am done
        // sending", and the server's reply still has to arrive. Racing the two
        // directions and aborting the loser dropped that reply on the floor and
        // reset the connection under the client.
        //
        // The bound is the one the copy loop was always meant to have:
        // `STREAM_SECS`, an hour. It matches the server's own `l4_flow`
        // default, so the two ends of the tunnel give up at about the same
        // moment, and it is what keeps a half-closed tunnel from holding its
        // resources for the life of the process.
        let stream_budget = crate::deadline::Deadlines::default().stream;
        tokio::select! {
            _ = async {
                let _ = (&mut client_task).await;
                let _ = (&mut backend_task).await;
            } => (),
            _ = flow.cancelled() => (),
            _ = tokio::time::sleep(stream_budget) => {
                jni_log!(
                    "[DEBUG:local-proxy] CONNECT tunnel to {}:{} ran for {:?} and was abandoned",
                    host,
                    port,
                    stream_budget
                );
            }
        }

        // Both, whichever branch won: the half that is still running is the one
        // that outlived its reason to, and the `TunnelTasks` guard above aborts
        // whatever is left when this handler returns.
        client_task.abort();
        backend_task.abort();

        return Ok(());
    }

    // A request that names more than one host is refused here, the same rule
    // the server applies. The route and the access check read the first `Host`
    // header and the backend would be handed all of them, so the request that
    // is authorised and the request that is served would be two different
    // requests — and the failure showed up as the server's 400, which looks
    // like a proxy bug rather than a request that cannot be answered.
    if request.headers().get_all("host").iter().count() > 1 {
        jni_log!(
            "[local-proxy] refusing a request that names more than one host: {}",
            redacted_headers(request.headers())
        );
        return write_proxy_error(&mut stream, "400 Bad Request").await;
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            // The authority is split the way the server splits it, so
            // `[::1]:8080` keeps its address. An empty port is dropped, as the
            // server drops it: `example.com:` is `example.com`.
            let (h, _port) = nexapipe_proto::host_and_port(h);
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
        let first_line_end = request_line_end(&request_buf[..header_end]);

        if first_line_end > 0 {
            // The method and the version come from the **parsed** request, not
            // from the bytes: the request line is rebuilt here, and a raw slice
            // of it carries whatever the client put there. A bare LF ends the
            // line for a parser that accepts one, and the rest of it lands in
            // the version token — straight into the request this proxy sends.
            let method = request.method().as_str();
            // `http::Version`'s Debug is the wire spelling — "HTTP/1.1" — and
            // the request line wants exactly that.
            let version = format!("{:?}", request.version());
            {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                // Use http:// scheme (not ws://) — the backend handles
                // the WebSocket upgrade via the Upgrade header, not the URI
                let absolute_uri = format!("http://{}{}", host, path);
                let new_line = format!("{} {} {}\r\n", method, absolute_uri, version);

                let mut request_to_send =
                    Vec::with_capacity(new_line.len() + header_end - first_line_end);
                request_to_send.extend_from_slice(new_line.as_bytes());
                // Copy the rest of headers (skip the original request line),
                // minus the ones that must not be forwarded. `Upgrade` and
                // `Connection` stay: the upgrade is the point of this request.
                let rest_start = first_line_end + 1; // skip the line feed
                if rest_start < header_end {
                    request_to_send.extend_from_slice(&filter_request_headers(
                        &request_buf[rest_start..header_end],
                        true,
                    ));
                }

                jni_log!(
                    "[DEBUG:local-proxy] Rewrote WebSocket request line: {}",
                    new_line.trim()
                );

                // Open iroh bi-stream and send the modified request
                let (pooled_conn, mut send, mut recv) = open_stream_with_retry(
                    &endpoint_group,
                    &host,
                    Some(&request_to_send),
                    Protocol::Http,
                )
                .await?;

                // One tunnel is one flow, and it stays counted until the
                // handler this sits in returns — see the CONNECT branch.
                let flow = pooled_conn.enter_flow(FlowMeta {
                    kind: FlowKind::WebSocket,
                    target: Some(host.clone()),
                    source: peer.clone(),
                });
                flow.record_sent(request_to_send.len() as u64);
                let count_to_backend = flow.counter();
                let count_from_backend = flow.counter();

                let (mut client_read, mut client_write) = tokio::io::split(stream);
                jni_log!(
                    "[DEBUG:local-proxy] WebSocket request sent to iroh: {} bytes",
                    request_to_send.len()
                );

                // Bidirectional forwarding (no send.finish() — keep stream open)
                //
                // The buffer the head was read into becomes the client half's
                // buffer: a connection holds two of them — one per direction —
                // rather than three.
                let header_buf = std::mem::take(&mut temp_buf);
                let client_to_iroh = async move {
                    let mut buf = header_buf;
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
                                    if ws_frame_buffer_append(&mut ws_buffer, &buf[..n]) {
                                        let mut frames = Vec::new();
                                        parse_websocket_frames(&mut ws_buffer, &mut frames);
                                        for (opcode, payload) in frames {
                                            if opcode == 1 || opcode == 8 {
                                                jni_log!(
                                                    "[DEBUG:local-proxy] WS client frame decoded \
                                                     (opcode {}): {}",
                                                    opcode,
                                                    String::from_utf8_lossy(&payload)
                                                );
                                            }
                                        }
                                    } else {
                                        // The frame is never finished, so the
                                        // bytes are held for a frame that will
                                        // not arrive. They are dropped rather
                                        // than kept: the dump is a preview of
                                        // 256 bytes, and a peer that sends a
                                        // header and then nothing would
                                        // otherwise grow this without end.
                                        ws_buffer.clear();
                                        jni_log!(
                                            "[DEBUG:local-proxy] WS client frame over {} bytes \
                                             and never finished, dropping it",
                                            WS_FRAME_BUFFER_LIMIT
                                        );
                                    }
                                }
                                if let Err(e) = send.write_all(&buf[..n]).await {
                                    jni_log!("[DEBUG:local-proxy] WS client->backend err: {}", e);
                                    return "client_write_error";
                                }
                                count_to_backend.record_sent(n as u64);
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
                                count_from_backend.record_received(n as u64);
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
                    // Asked to end: not an error, and not one of the two
                    // directions going quiet either.
                    _ = flow.cancelled() => ("closed", "closed_by_request"),
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

                return Ok(());
            }
        }

        // Fallback: if we couldn't rewrite, just connect normally
        jni_log!("[DEBUG:local-proxy] WebSocket URI rewrite failed, falling back to regular HTTP");
    }

    // Regular HTTP path
    // The hop-by-hop headers go, and so do the cache validation headers that
    // would make the origin answer with a 304 and an empty body.
    let filtered_headers = filter_request_headers(&request_buf[..header_end], false);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!(
        "[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}",
        request_to_send.len(),
        host
    );
    let (pooled_conn, mut send, mut recv) = open_stream_with_retry(
        &endpoint_group,
        &host,
        Some(&request_to_send),
        Protocol::Http,
    )
    .await?;

    // The helper wrote the request — headers and whatever body had already
    // arrived — before this line was reached. Counting the copy loop alone
    // would therefore be counting everything except a large upload, which for
    // a POST is most of it.
    let flow = pooled_conn.enter_flow(FlowMeta {
        kind: FlowKind::Http,
        target: Some(host.clone()),
        source: peer.clone(),
    });
    flow.record_sent(request_to_send.len() as u64);
    let count_to_backend = flow.counter();
    let count_from_backend = flow.counter();

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // The buffer the head was read into becomes the client half's buffer: a
    // connection holds two of them — one per direction — rather than three.
    let header_buf = std::mem::take(&mut temp_buf);
    let client_to_backend = async move {
        let mut buf = header_buf;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Client to backend write error: {}", e);
                        break;
                    }
                    count_to_backend.record_sent(n as u64);
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
        // The preview is only ever read when the debug log is on, so it is only
        // built then: a 1.5 KiB buffer filled for every response, for a log
        // line nobody asked for.
        let mut debug_preview = debug_log_enabled().then(|| Vec::with_capacity(1500));
        let mut response_sent = false;
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    total_bytes += n;
                    if let Some(preview) = debug_preview.as_mut()
                        && !response_sent
                        && preview.len() < 1500
                    {
                        preview.extend_from_slice(&buf[..std::cmp::min(n, 1500 - preview.len())]);
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
                    count_from_backend.record_received(n as u64);
                    if !response_sent {
                        response_sent = true;
                        jni_log!("[DEBUG:local-proxy] Response sent: {} bytes", total_bytes);
                        if let Some(preview) = debug_preview.as_ref()
                            && !preview.is_empty()
                        {
                            jni_log!(
                                "[DEBUG:local-proxy] Response preview: {}",
                                String::from_utf8_lossy(preview)
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
            if let Some(preview) = debug_preview.as_ref()
                && !preview.is_empty()
            {
                jni_log!(
                    "[DEBUG:local-proxy] Response preview: {}",
                    String::from_utf8_lossy(preview)
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
    // The timer and the cancel switch, together: this is the one path here that
    // is bounded by a clock instead of by a peer going quiet, and being asked to
    // end has to be able to cut that short rather than wait out the minute.
    tokio::select! {
        _ = tokio::time::timeout(tokio::time::Duration::from_secs(60), &mut backend_task) => (),
        _ = flow.cancelled() => (),
    }

    // Response has been delivered; stop the client->backend relay so the pooled
    // iroh connection is released immediately. Aborting also closes the client
    // TCP socket (HTTP/1.1 allows the server to close after the response),
    // so a keep-alive client socket can't pin this task.
    client_task.abort();

    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
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
    crate::domains::should_proxy_domain(host, proxy_domains)
}

/// Say what a list of proxy-domain patterns is worth, once, when a client starts.
///
/// Two kinds of note, and they are not the same kind. A pattern that matches
/// **nothing** is a warning: `*example.com` — a wildcard without the dot —
/// used to be a bare `ends_with` here, so it matched `notexample.com` as well,
/// and the server has always refused the spelling. A pattern that means one
/// name where a reader may expect a whole tree is worth an information line
/// and no more: a bare `example.com` names that host, and `*.example.com`
/// names its subdomains.
pub(crate) fn report_domain_patterns(patterns: &[String]) {
    let notes = crate::domains::domain_notes(patterns);
    for (pattern, why) in &notes.unusable {
        warn(&format!(
            "the proxy-domain pattern \"{pattern}\" matches nothing: {why}"
        ));
    }
    for pattern in &notes.narrowed {
        info(&format!(
            "the proxy-domain pattern \"{pattern}\" names that host only; \"*.{pattern}\" covers \
             its subdomains"
        ));
    }
}

/// A warning the user can read.
///
/// The Android build installs the `log` logger at `Info` and no tracing
/// subscriber, so a `Debug` line never reaches the log and a `tracing` line
/// goes nowhere.
///
/// Crate-wide rather than private to this module: the TUN stack has warnings
/// of its own, and there is no reason for two of them.
#[cfg(feature = "jni")]
pub(crate) fn warn(message: &str) {
    crate::jni::warn_log(message);
}

#[cfg(all(not(feature = "jni"), feature = "tracing"))]
pub(crate) fn warn(message: &str) {
    tracing::warn!("{message}");
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
pub(crate) fn warn(_message: &str) {}

/// A line of information the user can read, on the same terms as [`warn`].
#[cfg(feature = "jni")]
fn info(message: &str) {
    crate::jni::info_log(message);
}

#[cfg(all(not(feature = "jni"), feature = "tracing"))]
fn info(message: &str) {
    tracing::info!("{message}");
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
fn info(_message: &str) {}

#[cfg(test)]
mod tests;
