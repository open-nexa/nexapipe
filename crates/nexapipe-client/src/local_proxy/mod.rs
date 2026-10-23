use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::endpoint_group::EndpointGroup;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

pub(crate) use connection::handle_local_connection;
pub(crate) use tunnel::OPEN_ATTEMPTS;
pub(crate) use tunnel::open_stream_with_retry_until;

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

mod connection;
mod http_head;
mod plaintext;
mod response;
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

/// How long a plain-HTTP response's backend may be quiet before it is cut.
///
/// **An idle window, not a total.** Every chunk that arrives re-arms it, so
/// a response that keeps arriving keeps its exchange alive however long it
/// takes — a large download, an SSE stream, a long-poll — and only a *gap*
/// of silence ends it.
///
/// The bound this replaces was a total one: sixty seconds from the moment
/// the request went out, whatever else was happening. A response that was
/// still arriving was cut at the minute, and because the socket was dropped
/// rather than an answer written, the client was left holding a truncated
/// body and no error to explain it.
///
/// The same quiet window the server gives a response — `response_idle_secs`,
/// 120 s by default — so the two ends of a tunnel give up at about the same
/// moment.
const RESPONSE_IDLE: tokio::time::Duration = tokio::time::Duration::from_secs(120);

/// How many bytes are read and thrown away when a client sends more than its
/// request.
///
/// The connection carries one request, so the bytes that came after it are
/// not part of the exchange — but they are still in the socket, and a socket
/// that is closed with unread data in it is reset rather than closed, and a
/// reset costs the client the answer it was already sent. The bytes are read
/// away so the socket closes with nothing left in it; the ceiling is what
/// stops a client that keeps sending from being read forever.
const TRAILING_BYTES_CEILING: usize = 64 * 1024;

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
