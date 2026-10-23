//! The pool itself: what it holds, how it is written to, and what it does
//! when the credential or the network moves under it.

use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, watch};

#[cfg(feature = "tracing")]
use tracing;

use crate::auth::{Enrollment, IssuedCredential, TwoFactorAuth};
use nexapipe_proto::protocol::Protocol;
use nexapipe_proto::secret::SecretString;

use super::paths::PathHealth;
use super::{
    BorrowState, CONNECTION_CLEANUP_INTERVAL, CONNECTION_IDLE_TIMEOUT, DialOutcome, LinkKind,
    LinkStatus, alpns, identity_changed,
};

pub(super) struct PooledConnection {
    pub(super) conn: Connection,
    /// What this connection carries.
    ///
    /// The protocol is chosen at the handshake, so a connection speaks one
    /// thing: a connection that carries HTTP cannot carry an L4 tunnel, and
    /// the pool keeps them apart for the same reason it keeps a connection
    /// per protocol apart in the first place.
    pub(super) protocol: Protocol,
    /// What the pool and the flows on this connection share.
    ///
    /// The count is here because the pool owns the connection and the flows
    /// **borrow** it, so the pool cannot tell from the handle alone whether
    /// anyone is still on it — and it has to: a connection with a flow on it
    /// is not idle, and closing it would take that flow down with it.
    pub(super) state: Arc<BorrowState>,
    /// What the path watcher knows about this connection's paths.
    ///
    /// The watcher is the only thing that sees the path events, so this is
    /// where the answer to "can this connection still carry traffic?" is
    /// kept.
    pub(super) paths: Arc<PathHealth>,
}

impl PooledConnection {
    /// True if this connection can still carry traffic.
    ///
    /// **Not closed is not alive.** A QUIC connection whose path died — the
    /// network switched, the relay went away, the NAT mapping expired — is
    /// not closed by either side: QUIC keeps the connection open, waiting
    /// for a path to come back. So the question is not "was it closed" but
    /// "is there still a path to send on".
    ///
    /// The path watcher is what knows: a connection whose paths are all gone
    /// has nowhere left to send, and a connection that has never been seen
    /// to have a path is not a dead one — the watcher may not have looked
    /// at it yet, and a connection called dead before it has been looked at
    /// is a connection the pool throws away for nothing.
    pub(super) fn is_live(&self) -> bool {
        self.conn.close_reason().is_none() && !self.paths.all_gone()
    }

    /// True if this connection has been sitting in the pool unused for at least
    /// `timeout`.
    fn is_idle_for(&self, timeout: tokio::time::Duration) -> bool {
        self.state.is_idle_for(timeout)
    }
}

/// Drops the connections that are closed or idle, closing the idle ones.
///
/// A connection that is only dropped stays open as far as QUIC is concerned:
/// quinn closes a connection when its *last* handle goes away, and the path
/// watcher still holds one, so the socket and the NAT mapping on both sides
/// live on — and the watcher keeps reporting a route for a connection the pool
/// has abandoned.
///
/// The idle ones are closed with a reason, so the peer sees a connection that
/// went away on purpose rather than one that vanished.
pub(super) fn drop_stale_connections(connections: &mut Vec<PooledConnection>) {
    let mut idle = Vec::new();
    let mut pathless = Vec::new();
    connections.retain(|pooled| {
        if !pooled.is_live() {
            // A connection whose paths are gone is **not** closed yet — QUIC
            // is waiting for a path to come back — so it is closed here: a
            // connection with nowhere to send must not sit on the network
            // with the watcher's handle keeping it open, and the pool has
            // let go of it either way.
            if pooled.conn.close_reason().is_none() {
                pathless.push(pooled.conn.clone());
            }
            return false;
        }
        // **Idle means nobody is riding it.** The pool owns the connection
        // and the flows borrow it, so a connection that has not been handed
        // out for a minute may still be carrying a flow that opened ten
        // minutes ago and is still running. Closing that would take the flow
        // down with it, so a connection with a flow on it is never idle.
        if pooled.is_idle_for(CONNECTION_IDLE_TIMEOUT) && pooled.state.borrow_count() == 0 {
            idle.push(pooled.conn.clone());
            return false;
        }
        true
    });
    for conn in idle {
        conn.close(0u32.into(), b"idle");
    }
    for conn in pathless {
        conn.close(0u32.into(), b"no path");
    }
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    pub(super) inner: Arc<IrohConnectionPoolInner>,
}

/// Lock order, observed everywhere: `connections`, then `link_status`, then
/// `ep` — and never nested.
///
/// Nesting is what makes a pool that dials while another task shuts it down
/// deadlock-prone: `link_status` is also taken by the per-connection path
/// watcher, and `ep` by every dial, so holding one while waiting for another
/// turns a slow shutdown into a stall for every request.
pub(super) struct IrohConnectionPoolInner {
    pub(super) connections: Mutex<Vec<PooledConnection>>,
    /// The dial that is in progress, if one is.
    ///
    /// Everything that asks for a connection while a dial is running waits
    /// for **that** dial instead of starting one of its own. Without it, a
    /// hundred concurrent flows would each start a dial and a hundred
    /// connections would be made to carry a hundred flows — against a
    /// transport built to carry 1024 bi-streams on one connection.
    /// One slot per protocol, because a dial for one protocol is not a dial
    /// for another: a connection carries one thing, and waiting for an HTTP
    /// dial to hand over an L4 connection would be waiting for the wrong
    /// answer.
    pub(super) dialing: Mutex<HashMap<Protocol, watch::Receiver<Option<DialOutcome>>>>,
    pub(super) ep: Arc<Mutex<Option<Endpoint>>>,
    pub(super) endpoint_addr: EndpointAddr,
    /// Optional client 2FA credentials. When set, every freshly established
    /// connection is authenticated with the server before it is pooled/used.
    pub(super) two_factor: Mutex<Option<TwoFactorAuth>>,
    /// A one-time enrollment token to spend on the next connection instead of
    /// presenting credentials — what a `v=2` invite carries. Cleared once it
    /// has bought a secret, which lands in [`Self::two_factor`].
    pub(super) enrollment: Mutex<Option<Enrollment>>,
    /// The credential the server issued for that token.
    ///
    /// The process can use it for as long as it lives, but the token it came
    /// from is spent: an app that restarts without persisting this has nothing
    /// left to authenticate with. [`IrohConnectionPool::take_issued_credential`]
    /// hands it to whoever stores such things.
    pub(super) issued: Mutex<Option<TwoFactorAuth>>,
    /// Why the last preconnect failed with "2FA required", when the server said
    /// so: a client without credentials cannot fail the handshake on its own, so
    /// the refusal is only visible as a close, and this hands the reason to
    /// whoever reports the failure. Read (and cleared) by
    /// [`IrohConnectionPool::take_auth_required`].
    pub(super) auth_required: Mutex<Option<String>>,
    /// Whether this pool created (and therefore owns) its iroh endpoint.
    ///
    /// `new()` binds a dedicated endpoint, so `close_all` must close it.
    /// `new_with_endpoint()` shares a caller-owned endpoint (e.g. the global
    /// ENDPOINT in the Android JNI layer); closing it here would break the
    /// next `nativeStartProxy`/`nativePreconnect` with "Endpoint is closed"
    /// and tear down a running tunnel on proxy restart / reconnect.
    pub(super) owns_endpoint: bool,
    /// The last observed [`LinkStatus`] for this backend, and the connection it describes.
    ///
    /// A pool hands its connections out to whoever is proxying traffic, so at any moment the
    /// pool itself may hold none — and a UI asking "direct or relay, and how far?" every few
    /// seconds must not be answered with "unknown" just because a request is in flight. The path
    /// watcher writes here; [`IrohConnectionPool::link_status`] reads it whenever no pooled
    /// connection can be asked directly.
    ///
    /// The connection is part of the reading because the reading is about it: a status recorded
    /// for a connection that has since died describes no path at all, and a UI that keeps showing
    /// it shows a route to a backend it cannot reach.
    pub(super) link_status: Mutex<CachedLinkStatus>,
    /// Which network generation the pool is on.
    ///
    /// Moved by [`IrohConnectionPool::drop_connections`], which is what a
    /// network switch calls. The drop closes every connection the pool
    /// holds, and a flow that is still riding one of them keeps a borrow on
    /// a closed connection — its watcher keeps running, and the reading it
    /// would publish is the one of the network that is gone. A watcher that
    /// notices the generation moved stops publishing, and closes the
    /// connection on its way out.
    pub(super) epoch: AtomicU64,
    /// Which generation of the credential the pool is on.
    ///
    /// Moved by [`IrohConnectionPool::set_credential`], and only when the
    /// **identity** changed: a rotated secret is the same account, and the
    /// connections that stand for it still stand for it.
    ///
    /// It is the answer to "which identity is this pool on?", and a dial
    /// takes it with the credential it authenticates: a connection whose
    /// generation has moved on was authenticated as an identity that is
    /// gone, and it is closed rather than pooled.
    ///
    /// It is not the network generation above, and it is not the same
    /// thing: a network change closes the connections of a path that is
    /// gone, while this says whose name is on the connection.
    pub(super) credential_generation: AtomicU64,
}

/// A recorded [`LinkStatus`] and the connection it was recorded for.
#[derive(Default)]
pub(super) struct CachedLinkStatus {
    /// The connection the status describes, if there is one.
    pub(super) conn: Option<Connection>,
    /// The paths that connection has, if there is one.
    ///
    /// The reading is about the connection, and a connection whose path is
    /// gone describes no path at all — so the reading has to know about the
    /// paths as well, or it goes on describing a route that is not there.
    pub(super) paths: Option<Arc<PathHealth>>,
    /// What the path watcher saw on that connection.
    pub(super) status: LinkStatus,
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
            .alpns(alpns(Protocol::Legacy))
            .transport_config(transport)
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(HashMap::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: true,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
            credential_generation: AtomicU64::new(0),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            dialing: Mutex::new(HashMap::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: false,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
            credential_generation: AtomicU64::new(0),
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
    ///
    /// **A different identity drops the connections.** A connection is
    /// authenticated as whoever the handshake ran for, and the handshake runs
    /// once per connection — so a connection made under the old credential
    /// keeps serving traffic under the old identity after the credential has
    /// been replaced. The connections are closed when the identity changes.
    ///
    /// The same identity keeps them: a rotated secret is the same account
    /// with a different secret, and dropping the pool for that would close
    /// every connection in flight over a rotation that changes nothing about
    /// who they are.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        let _ = self.set_credential(auth).await;
    }

    /// Writes the pool's credential, and closes the connections of the
    /// identity that is gone.
    ///
    /// Every write of the credential goes through here. The enrollment
    /// writes a credential of its own — and it writes it **here**, so that
    /// the identity comparison, the move of the generation and the drop of
    /// the connections of the identity that is gone happen with it.
    ///
    /// **The generation comes back with the write.** The generation says
    /// which credential a connection was authenticated under, so a caller
    /// that has just written one has to carry the generation of *that*
    /// write: a generation read after the lock is released can be one that a
    /// later write has already moved, and a connection carrying that one is
    /// taken for the identity that replaced this one — the pool compares the
    /// two and finds them equal, and pools a connection that authenticated as
    /// an identity that is gone.
    pub(super) async fn set_credential(&self, auth: Option<TwoFactorAuth>) -> u64 {
        let mut slot = self.inner.two_factor.lock().await;
        let changed = identity_changed(slot.as_ref(), auth.as_ref());
        if changed {
            // **The identity moves with the credential.**
            //
            // A dial reads the generation when it takes the credential and
            // compares it before it pools the connection: a generation that
            // moved in between means the handshake ran for an identity that
            // is gone.
            //
            // The move happens here — under the lock the credential is
            // written under, and before the connections are dropped — so a
            // dial that reads the credential afterwards reads the new
            // generation with it, and a dial that read it before reads the
            // old one.
            self.inner
                .credential_generation
                .fetch_add(1, Ordering::AcqRel);
        }
        *slot = auth;
        // Read under the lock the credential is written under, so the two
        // cannot come from different moments.
        let generation = self.inner.credential_generation.load(Ordering::Acquire);
        // Released before the connections are touched: the lock order is
        // `connections` first, and nesting the two is what makes a pool that
        // dials while another task shuts it down deadlock-prone.
        drop(slot);

        if changed {
            // The connections were authenticated as the identity that is gone.
            self.drop_connections().await;
        }

        generation
    }

    /// Configure a one-time enrollment token instead of credentials: the next
    /// connection spends it and comes back with the real secret in
    /// `Self::two_factor`.
    ///
    /// What the server issues has to be persisted by the caller — see
    /// [`Self::take_issued_credential`] — because a token can only be spent
    /// once, so a process that forgets the secret cannot enroll again from the
    /// same invite.
    pub async fn set_enrollment(&self, enrollment: Option<Enrollment>) {
        *self.inner.enrollment.lock().await = enrollment;
    }

    /// Takes the credential the server issued when an enrollment token was
    /// spent, and clears it.
    ///
    /// `None` when nothing has been enrolled yet — or when it has already been
    /// taken, which is the normal case: this is read once, after the first
    /// successful connection, by whatever keeps the app's settings.
    pub async fn take_issued_credential(&self) -> Option<IssuedCredential> {
        self.inner
            .issued
            .lock()
            .await
            .take()
            .map(|auth| IssuedCredential {
                client_id: auth.client_id().to_string(),
                secret: SecretString::new(auth.secret_base32()),
                algorithm: auth.algorithm_name().to_string(),
                public_key: auth.public_key_hex(),
                device: auth.device_id().map(str::to_string),
            })
    }

    /// Test-only: whether this pool has credentials configured.
    #[cfg(test)]
    pub(crate) async fn has_two_factor(&self) -> bool {
        self.inner.two_factor.lock().await.is_some()
    }

    /// Test-only: how many flows are riding each pooled connection.
    #[cfg(test)]
    pub(crate) async fn borrow_counts(&self) -> Vec<usize> {
        let connections = self.inner.connections.lock().await;
        connections
            .iter()
            .map(|pooled| pooled.state.borrow_count())
            .collect()
    }

    /// Takes the reason the backend last refused a connection for missing 2FA,
    /// and clears it.
    ///
    /// Only ever set after a preconnect that ended in `AUTH_REQUIRED_CLOSE_CODE`,
    /// i.e. when the server wants credentials this client does not have.
    pub async fn take_auth_required(&self) -> Option<String> {
        self.inner.auth_required.lock().await.take()
    }

    /// How traffic to this backend is currently routed, and how far away it is.
    ///
    /// A pooled connection is asked directly when there is one, because its path list is the
    /// truth right now; otherwise the last value the path watcher recorded is used. Without
    /// that fallback a UI polling while the pool holds no connection at all would read
    /// "unknown" and flap.
    pub async fn link_status(&self) -> LinkStatus {
        let connections = self.inner.connections.lock().await;
        for pooled in connections.iter().rev() {
            if pooled.is_live() {
                let status = LinkStatus::of(&pooled.conn);
                if status.kind != LinkKind::Unknown {
                    return status;
                }
            }
        }
        drop(connections);

        // The cached reading describes the connection it was recorded for: one
        // that has since died describes no path at all, and the UI would keep
        // showing a route to a backend it cannot reach. A connection whose
        // path is gone has died in the same way a closed one has, so the
        // reading is worth nothing there either.
        let cached = self.inner.link_status.lock().await;
        match &cached.conn {
            Some(conn)
                if conn.close_reason().is_none()
                    && cached.paths.as_ref().is_none_or(|paths| !paths.all_gone()) =>
            {
                cached.status
            }
            _ => LinkStatus::default(),
        }
    }

    /// How traffic to this backend is currently routed, without the latency.
    ///
    /// The kind on its own, for the callers that only draw an icon.
    pub async fn link_kind(&self) -> LinkKind {
        self.link_status().await.kind
    }

    pub async fn close_all(&self) {
        // Scoped, not held: `endpoint.close()` below is awaited, and keeping
        // `connections` across it would make every request wait on the
        // endpoint's goodbye.
        {
            let mut connections = self.inner.connections.lock().await;
            // Close before clearing: a connection that is only dropped stays
            // open, and the path watcher that still holds it keeps writing the
            // status of a connection this call says is gone — which undoes
            // the reset below within a second.
            for pooled in connections.iter() {
                pooled.conn.close(0u32.into(), b"pool closed");
            }
            connections.clear();
        }
        // Every connection is gone, so the last observed kind describes nothing any more.
        // Leaving it would let the UI keep showing "direct" for a backend it cannot reach.
        //
        // The generation moves with it, under the same lock: a watcher that
        // is about to publish takes this lock too, so the two cannot
        // interleave — a reading of a connection this call says is gone cannot
        // land after the reading was cleared.
        {
            let mut cached = self.inner.link_status.lock().await;
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            *cached = CachedLinkStatus::default();
        }

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
        {
            let mut connections = self.inner.connections.lock().await;
            // Close before clearing: `close()` only marks the connection, so doing it while the
            // pool still owns them is what stops a concurrent `get_connection` from handing one
            // out in between.
            for pooled in connections.iter() {
                pooled.conn.close(0u32.into(), b"network changed");
            }
            connections.clear();
        }
        // Nothing is connected any more, so the last observed kind describes nothing.
        // Leaving it would let a UI keep showing "direct" for a backend it cannot reach.
        //
        // The generation moves with it, under the same lock: a watcher that is
        // about to publish takes this lock too, so the two cannot interleave —
        // a reading of the network that is gone cannot land after the reading
        // was cleared.
        {
            let mut cached = self.inner.link_status.lock().await;
            self.inner.epoch.fetch_add(1, Ordering::AcqRel);
            *cached = CachedLinkStatus::default();
        }
    }
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
            // Idle as well as closed: `get_connection` already dropped stale
            // entries before handing one out, but nothing else ever ran, so a
            // pool that stopped being used kept its connections — and the
            // sockets, and the NAT mappings on both sides — until then.
            drop_stale_connections(&mut connections);
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
