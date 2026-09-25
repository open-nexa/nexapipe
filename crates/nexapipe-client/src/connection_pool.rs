use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

use crate::ClientError;
use crate::auth::TwoFactorAuth;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// Interval of the background watcher that removes closed/stale connections from the pool.
const CONNECTION_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
/// Per-pool timeout for preconnect / warm-up. Much shorter than CONNECTION_TIMEOUT
/// so that a single unreachable node does not hold up the entire preconnect phase.
///
/// Sized to fit a slow relay handshake plus [`AUTH_REQUIRED_GRACE`]: cutting the
/// observation short would turn a backend that demands 2FA into one that merely
/// looks unreachable, with the real reason lost.
pub(crate) const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(8);
/// Budget for the connect half of a preconnect.
///
/// Deliberately shorter than [`PRECONNECT_TIMEOUT`]: the caller cancels the whole
/// preconnect at its own deadline, and a cancelled connect reports nothing — so a
/// node that hangs stayed silent, which is exactly the case that needs explaining.
/// With a smaller budget here, the timeout (or iroh's error) surfaces in the log.
const PRECONNECT_CONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// How long a freshly established connection is watched for a 2FA refusal when
/// this client has no credentials.
///
/// Only such a client needs it: one with credentials fails the handshake itself
/// and knows at once. Without credentials the QUIC handshake succeeds and
/// nothing else happens, so the server is the only party that knows the
/// connection is unusable — it says so by closing once its own handshake
/// deadline (`AUTH_HANDSHAKE_TIMEOUT` in `crates/nexapipe/src/conn/mod.rs`)
/// passes. This wait covers that deadline plus a round trip, so it has to stay
/// above the server's constant — raising one without the other silently turns
/// "the server requires 2FA" back into "the backend looks unreachable".
const AUTH_REQUIRED_GRACE: tokio::time::Duration = tokio::time::Duration::from_secs(6);

/// The application error code the server closes a connection with when it
/// requires 2FA the client never performed. Must match `auth_close_code::REQUIRED`
/// in `crates/nexapipe/src/conn/mod.rs`.
const AUTH_REQUIRED_CLOSE_CODE: u32 = 2;

/// How traffic currently reaches a backend: direct, or through a relay.
///
/// iroh keeps several paths open per connection and marks exactly one of them *selected* — the
/// path application data actually takes. That, and not "a direct path exists", decides the
/// label: a connection that has opened a UDP path but still routes over the relay is a relay
/// connection until iroh promotes it.
///
/// This is the **runtime** answer on purpose. The relay URL in the configuration (or in an
/// invite) only names a relay that *may* be used; it says nothing about whether the hole punch
/// succeeded, so a UI must never infer the icon from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// The selected path is a direct UDP path to the backend.
    Direct,
    /// The selected path goes through a relay server.
    Relay,
    /// No path is known: nothing has connected yet, or the connection has no path.
    #[default]
    Unknown,
}

impl LinkKind {
    /// The stable name sent across the JNI and Tauri boundaries.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }

    /// Tolerant by design: this only ever feeds an icon, so an unfamiliar spelling means
    /// [`Self::Unknown`] rather than an error.
    pub fn parse(text: &str) -> Self {
        match text.trim() {
            "direct" => Self::Direct,
            "relay" => Self::Relay,
            _ => Self::Unknown,
        }
    }

    /// Reads the kind off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets [`Self::Unknown`]
    /// instead of a stale answer.
    pub fn of(conn: &Connection) -> Self {
        if conn.close_reason().is_some() {
            return Self::Unknown;
        }

        let paths = conn.paths();
        for path in paths.iter() {
            if path.is_selected() {
                return if path.is_ip() {
                    Self::Direct
                } else if path.is_relay() {
                    Self::Relay
                } else {
                    Self::Unknown
                };
            }
        }

        // Paths are open but none is selected (the handshake is still settling). A direct path,
        // once opened, is the one iroh will promote, so it outranks an also-open relay path.
        let mut has_relay = false;
        for path in paths.iter() {
            if path.is_ip() {
                return Self::Direct;
            }
            has_relay |= path.is_relay();
        }
        if has_relay {
            Self::Relay
        } else {
            Self::Unknown
        }
    }
}

struct PooledConnection {
    conn: Connection,
    created_at: std::time::Instant,
}

impl PooledConnection {
    /// True if the underlying iroh connection is still open (not closed by either side).
    fn is_live(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    inner: Arc<IrohConnectionPoolInner>,
}

struct IrohConnectionPoolInner {
    connections: Mutex<Vec<PooledConnection>>,
    ep: Arc<Mutex<Option<Endpoint>>>,
    endpoint_addr: EndpointAddr,
    /// Optional client 2FA credentials. When set, every freshly established
    /// connection is authenticated with the server before it is pooled/used.
    two_factor: Mutex<Option<TwoFactorAuth>>,
    /// Why the last preconnect failed with "2FA required", when the server said
    /// so: a client without credentials cannot fail the handshake on its own, so
    /// the refusal is only visible as a close, and this hands the reason to
    /// whoever reports the failure. Read (and cleared) by
    /// [`IrohConnectionPool::take_auth_required`].
    auth_required: Mutex<Option<String>>,
    /// Whether this pool created (and therefore owns) its iroh endpoint.
    ///
    /// `new()` binds a dedicated endpoint, so `close_all` must close it.
    /// `new_with_endpoint()` shares a caller-owned endpoint (e.g. the global
    /// ENDPOINT in the Android JNI layer); closing it here would break the
    /// next `nativeStartProxy`/`nativePreconnect` with "Endpoint is closed"
    /// and tear down a running tunnel on proxy restart / reconnect.
    owns_endpoint: bool,
    /// The last observed [`LinkKind`] for this backend.
    ///
    /// A pool hands its connections out to whoever is proxying traffic, so at any moment the
    /// pool itself may hold none — and a UI asking "direct or relay?" every few seconds must
    /// not be answered with "unknown" just because a request is in flight. The path watcher
    /// writes here; [`IrohConnectionPool::link_kind`] reads it whenever no pooled connection
    /// can be asked directly.
    link_kind: Mutex<LinkKind>,
}

impl IrohConnectionPool {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, crate::error::ClientError> {
        let (transport, tuning) = crate::transport::transport_config_with_tuning();
        #[cfg(feature = "tracing")]
        tracing::info!("QUIC transport tuning: {}", tuning.describe());
        // `tuning` is only read by the log line above; keep the binding "used"
        // when `tracing` is off so it is not reported as unused.
        #[cfg(not(feature = "tracing"))]
        let _ = &tuning;
        let ep = Endpoint::builder(presets::N0)
            .transport_config(transport)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: true,
            link_kind: Mutex::new(LinkKind::Unknown),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: false,
            link_kind: Mutex::new(LinkKind::Unknown),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Self { inner }
    }

    /// The **local** iroh endpoint's own ID — this client's identity on the
    /// network, not the ID of the backend this pool talks to.
    ///
    /// Careful: pools that share a caller-owned endpoint (`new_with_endpoint`)
    /// all report the *same* ID here, because they all use one local endpoint.
    /// Do not use this to tell backends apart; use [`Self::backend_id`].
    ///
    /// Returns the all-zero ID when the endpoint lock is momentarily held or the
    /// endpoint has already been closed.
    pub fn node_id(&self) -> EndpointId {
        match self.inner.ep.try_lock() {
            Ok(ep) => {
                if let Some(e) = ep.as_ref() {
                    e.id()
                } else {
                    EndpointId::from_bytes(&[0u8; 32])
                        .expect("Failed to create default endpoint id")
                }
            }
            Err(_) => {
                EndpointId::from_bytes(&[0u8; 32]).expect("Failed to create default endpoint id")
            }
        }
    }

    /// The **remote** node this pool dials: the configured `server_node_id`.
    ///
    /// Unlike [`Self::node_id`] this is a plain copy of the address the pool was
    /// built with, so it needs no lock, never returns a placeholder, and is
    /// stable across every pool in a group. Pool identity / deduplication must
    /// be based on this.
    pub fn backend_id(&self) -> EndpointId {
        self.inner.endpoint_addr.id
    }

    /// Configure client 2FA credentials. Connections established afterwards
    /// (including preconnect warm-ups) will run the 2FA handshake first.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        *self.inner.two_factor.lock().await = auth;
    }

    /// Test-only: whether this pool has credentials configured.
    #[cfg(test)]
    pub(crate) async fn has_two_factor(&self) -> bool {
        self.inner.two_factor.lock().await.is_some()
    }

    /// Takes the reason the backend last refused a connection for missing 2FA,
    /// and clears it.
    ///
    /// Only ever set after a preconnect that ended in [`AUTH_REQUIRED_CLOSE_CODE`],
    /// i.e. when the server wants credentials this client does not have.
    pub async fn take_auth_required(&self) -> Option<String> {
        self.inner.auth_required.lock().await.take()
    }

    /// Connect to the backend and run the 2FA handshake when configured.
    /// `timeout` is the budget for the QUIC handshake itself; see
    /// [`PRECONNECT_CONNECT_TIMEOUT`] for why a warm-up uses a tighter one than
    /// [`CONNECTION_TIMEOUT`].
    async fn connect_and_auth(
        &self,
        ep: &Endpoint,
        timeout: tokio::time::Duration,
    ) -> Result<Connection, ClientError> {
        let started = tokio::time::Instant::now();
        let conn = tokio::time::timeout(
            timeout,
            ep.connect(self.inner.endpoint_addr.clone(), ALPN_NEXAPIPE),
        )
        .await
        .map_err(|_| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} timed out after {}s (no QUIC handshake)",
                self.backend_id(),
                timeout.as_secs()
            );
            ClientError::TimeoutError
        })?
        .map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                "connect to {} failed after {:.1}s: {}",
                self.backend_id(),
                started.elapsed().as_secs_f32(),
                e
            );
            #[cfg(not(feature = "tracing"))]
            let _ = started;
            anyhow::anyhow!(e)
        })?;

        let two_factor = self.inner.two_factor.lock().await.clone();
        if let Some(auth) = two_factor {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Authenticating connection with 2FA as client '{}'",
                auth.client_id()
            );
            if let Err(e) = auth.authenticate(&conn).await {
                conn.close(0u32.into(), b"2FA authentication failed");
                #[cfg(feature = "tracing")]
                tracing::warn!("2FA authentication failed: {}", e);
                return Err(e);
            }
            #[cfg(feature = "tracing")]
            tracing::info!(
                "2FA authentication succeeded for client '{}'",
                auth.client_id()
            );
        }

        Ok(conn)
    }

    pub async fn get_connection(&self) -> Result<Connection, crate::error::ClientError> {
        let mut connections = self.inner.connections.lock().await;

        // Drop stale connections before handing one out: anything already closed
        // by the peer, or idle for longer than CONNECTION_IDLE_TIMEOUT.
        connections.retain(|pooled| {
            pooled.created_at.elapsed() < CONNECTION_IDLE_TIMEOUT && pooled.is_live()
        });

        if let Some(pooled) = connections.pop() {
            return Ok(pooled.conn);
        }

        drop(connections);

        let ep = self.inner.ep.lock().await;
        let ep = ep.as_ref().ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let conn = self.connect_and_auth(ep, CONNECTION_TIMEOUT).await?;
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());

        Ok(conn)
    }

    /// How traffic to this backend is currently routed.
    ///
    /// A pooled connection is asked directly when there is one, because its path list is the
    /// truth right now; otherwise the last value the path watcher recorded is used. Without
    /// that fallback a UI polling while requests are in flight — the pool empty, every
    /// connection out on loan — would read "unknown" and flap.
    pub async fn link_kind(&self) -> LinkKind {
        let connections = self.inner.connections.lock().await;
        for pooled in connections.iter().rev() {
            if pooled.is_live() {
                let kind = LinkKind::of(&pooled.conn);
                if kind != LinkKind::Unknown {
                    return kind;
                }
            }
        }
        drop(connections);

        *self.inner.link_kind.lock().await
    }

    /// Ensure at least one live connection to the backend is cached in the
    /// pool, establishing one if the pool is empty. Used for pre-connect /
    /// warm-up so the first real request does not pay the QUIC/relay handshake
    /// latency. Returns true if a connection is available in the pool
    /// afterwards.
    pub async fn preconnect(&self) -> bool {
        {
            let connections = self.inner.connections.lock().await;
            if let Some(pooled) = connections.last()
                && pooled.is_live()
            {
                return true;
            }
        }

        let conn = {
            let ep = self.inner.ep.lock().await;
            let Some(ep) = ep.as_ref() else {
                return false;
            };
            match tokio::time::timeout(
                PRECONNECT_TIMEOUT,
                self.connect_and_auth(ep, PRECONNECT_CONNECT_TIMEOUT),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect to {} failed: {}", self.backend_id(), e);
                    #[cfg(not(feature = "tracing"))]
                    let _ = &e;
                    return false;
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("preconnect timed out");
                    return false;
                }
            }
        };

        // A client without credentials never opens the auth stream, so a
        // completed QUIC handshake tells it nothing: whether the connection can
        // ever carry traffic is the server's call, and it answers by closing
        // once its handshake deadline passes. Watch for that instead of
        // reporting a connection the server already refused as a warm one.
        if self.inner.two_factor.lock().await.is_none()
            && let Some(reason) = wait_for_auth_required(&conn).await
        {
            #[cfg(feature = "tracing")]
            tracing::warn!("preconnect refused by the server: {}", reason);
            #[cfg(not(feature = "tracing"))]
            let _ = &reason;
            *self.inner.auth_required.lock().await = Some(reason);
            return false;
        }

        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());
        self.return_connection(conn).await;
        true
    }

    pub async fn return_connection(&self, conn: Connection) {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return;
        }

        let mut connections = self.inner.connections.lock().await;
        if connections.len() < MAX_CONNECTIONS {
            connections.push(PooledConnection {
                conn,
                created_at: std::time::Instant::now(),
            });
        }
    }

    pub async fn close_all(&self) {
        let mut connections = self.inner.connections.lock().await;
        connections.clear();
        // Every connection is gone, so the last observed kind describes nothing any more.
        // Leaving it would let the UI keep showing "direct" for a backend it cannot reach.
        *self.inner.link_kind.lock().await = LinkKind::Unknown;

        // Only close the endpoint if this pool owns it (created via `new()`).
        // Pools created via `new_with_endpoint()` share a caller-owned endpoint
        // (e.g. the global ENDPOINT in the Android JNI layer); closing it here
        // would break the next `nativeStartProxy`/`nativePreconnect` with
        // "Endpoint is closed" and tear down a running tunnel on reconnect.
        if !self.inner.owns_endpoint {
            return;
        }

        let mut ep = self.inner.ep.lock().await;
        if let Some(endpoint) = ep.take() {
            #[cfg(feature = "tracing")]
            tracing::info!("Closing iroh endpoint");
            endpoint.close().await;
        }
    }

    /// Closes and forgets every cached connection, leaving the endpoint alone.
    ///
    /// This is what a network switch needs. A connection opened on the previous network is
    /// *not* closed as far as QUIC is concerned — `close_reason()` stays `None` while its path
    /// is dead — so it would sit in the pool looking healthy and be handed to every request
    /// until QUIC gives up on it, which is long after the user has decided the backend is
    /// unreachable. Dropping them here makes the next request dial on the current network.
    ///
    /// Deliberately not [`Self::close_all`]: that also closes an endpoint the pool owns, and a
    /// pool that shares a caller-owned endpoint (the Android JNI shape) must keep it — closing
    /// it would tear down a running tunnel and break every later dial with "Endpoint is
    /// closed".
    pub async fn drop_connections(&self) {
        let mut connections = self.inner.connections.lock().await;
        // Close before clearing: `close()` only marks the connection, so doing it while the
        // pool still owns them is what stops a concurrent `get_connection` from handing one
        // out in between.
        for pooled in connections.iter() {
            pooled.conn.close(0u32.into(), b"network changed");
        }
        connections.clear();
        // Nothing is connected any more, so the last observed kind describes nothing.
        // Leaving it would let a UI keep showing "direct" for a backend it cannot reach.
        *self.inner.link_kind.lock().await = LinkKind::Unknown;
    }
}

/// Waits for a backend that demands 2FA to say so.
///
/// Returns the reason the server gave when it closes the connection with
/// [`AUTH_REQUIRED_CLOSE_CODE`], and `None` when the connection stays up — or
/// dies for any other reason, which is not what this is looking for.
async fn wait_for_auth_required(conn: &Connection) -> Option<String> {
    let closed = tokio::select! {
        _ = tokio::time::sleep(AUTH_REQUIRED_GRACE) => return None,
        error = conn.closed() => error,
    };

    match closed {
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == AUTH_REQUIRED_CLOSE_CODE as u64 =>
        {
            Some(String::from_utf8_lossy(&close.reason).into_owned())
        }
        _ => None,
    }
}

/// Watches one connection's paths and records which kind is carrying traffic.
///
/// The initial snapshot matters: right after the handshake iroh has already selected a path
/// (the relay one, usually) and only *later* promotes a direct one. Waiting for the first
/// event would leave the answer at [`LinkKind::Unknown`] for as long as the connection stays
/// on its first path — which, for a backend behind a symmetric NAT, is forever.
fn spawn_path_watcher(inner: Weak<IrohConnectionPoolInner>, conn: Connection) {
    let kind = LinkKind::of(&conn);
    // `try_lock`, not `lock`: this runs on the caller's task, and a lock held elsewhere must
    // not stall a connection being handed out. Losing the race only costs one stale reading.
    if let Some(inner) = inner.upgrade()
        && let Ok(mut slot) = inner.link_kind.try_lock()
    {
        *slot = kind;
    }

    tokio::spawn(async move {
        let mut path_events = conn.path_events();
        while let Some(event) = path_events.next().await {
            let iroh::endpoint::PathEvent::Selected { remote_addr, .. } = event else {
                continue;
            };

            let kind = if remote_addr.is_ip() {
                LinkKind::Direct
            } else if remote_addr.is_relay() {
                LinkKind::Relay
            } else {
                LinkKind::Unknown
            };

            let Some(inner) = inner.upgrade() else {
                // Pool dropped; nobody is left to tell.
                break;
            };
            *inner.link_kind.lock().await = kind;
        }
    });
}

/// Spawn a background task that periodically drops closed connections from the
/// pool. It holds only a [`Weak`] reference so it exits once the pool itself is
/// dropped (e.g. on shutdown), and never keeps the pool alive on its own.
fn spawn_cleanup_task(inner: Weak<IrohConnectionPoolInner>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_CLEANUP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(inner) = inner.upgrade() else {
                // Pool dropped; nothing left to clean.
                break;
            };
            let mut connections = inner.connections.lock().await;
            let before = connections.len();
            connections.retain(|pooled| pooled.is_live());
            let removed = before - connections.len();
            if removed > 0 {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    "Connection pool cleanup: removed {} closed connection(s)",
                    removed
                );
            }
        }
    });
}

pub fn parse_endpoint_addr(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<EndpointAddr, crate::error::ClientError> {
    if let Some(node_id_str) = server_node_id {
        let endpoint_id: EndpointId = node_id_str.parse().map_err(|e| {
            crate::error::ClientError::ParseError(format!("Failed to parse server_node_id: {}", e))
        })?;
        Ok(endpoint_id.into())
    } else if let Some(ticket_str) = server_ticket {
        if let Ok(ticket) = ticket_str.parse::<EndpointTicket>() {
            Ok(ticket.into())
        } else {
            let endpoint_id: EndpointId = ticket_str.parse().map_err(|e| {
                crate::error::ClientError::ParseError(format!(
                    "Failed to parse as ticket or node ID: {}",
                    e
                ))
            })?;
            Ok(endpoint_id.into())
        }
    } else {
        Err(crate::error::ClientError::InvalidConfig(
            "Either server_node_id or server_ticket must be provided".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::LinkKind;

    /// The name crosses the JNI and Tauri boundaries, so the two sides can only stay in sync
    /// if `as_str` and `parse` agree — and an unfamiliar spelling must degrade to `Unknown`
    /// rather than fail, because the value only ever feeds an icon.
    #[test]
    fn link_kind_name_round_trips() {
        for kind in [LinkKind::Direct, LinkKind::Relay, LinkKind::Unknown] {
            assert_eq!(LinkKind::parse(kind.as_str()), kind);
        }
        assert_eq!(LinkKind::parse(""), LinkKind::Unknown);
        assert_eq!(LinkKind::parse("hole-punched"), LinkKind::Unknown);
    }

    #[test]
    fn link_kind_serializes_in_snake_case() {
        assert_eq!(serde_json::to_string(&LinkKind::Direct).unwrap(), "\"direct\"");
        assert_eq!(serde_json::to_string(&LinkKind::Relay).unwrap(), "\"relay\"");
        assert_eq!(
            serde_json::to_string(&LinkKind::Unknown).unwrap(),
            "\"unknown\""
        );
    }
}
