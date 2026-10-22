use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

#[cfg(feature = "tracing")]
use tracing;

use crate::ClientError;
use crate::auth::{CredentialIdentity, Enrollment, IssuedCredential, TwoFactorAuth};
use nexapipe_proto::secret::SecretString;

const ALPN_NEXAPIPE: &[u8] = b"\x05nexapipe";
const MAX_CONNECTIONS: usize = 10;
const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Idle connections older than this are evicted when a new connection is requested.
const CONNECTION_IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// Interval of the background watcher that removes closed/stale connections from the pool.
const CONNECTION_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
/// How often the round-trip time is re-read.
///
/// A second is quick enough for a figure that reads as "now" and slow enough
/// to be free: iroh keeps the estimate in memory and reading it is a lookup.
const RTT_POLL_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(1);
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

/// Budget for one preconnect / warm-up, covering both of its halves.
///
/// This is the whole of what [`IrohConnectionPool::preconnect`] may spend, not
/// only the connect: [`AUTH_REQUIRED_GRACE`] belongs *inside* the preconnect
/// rather than after it. It used to sit outside, with the connect alone
/// budgeted at 8s, so a backend that took more than two seconds to answer was
/// cancelled in the middle of being observed and reported unreachable for
/// being slow.
///
/// It has to hold both halves. Shortening the observation is its own failure —
/// a backend that demands 2FA starts to look like one that is merely
/// unreachable, with the reason lost — which is why this is the sum and not
/// something tighter.
pub(crate) const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(12);

/// Both halves have to fit, or the observation is what gets cut.
const _: () = assert!(
    PRECONNECT_TIMEOUT.as_secs()
        >= PRECONNECT_CONNECT_TIMEOUT.as_secs() + AUTH_REQUIRED_GRACE.as_secs()
);

/// The application error code the server closes a connection with when it
/// requires 2FA the client never performed. Must match `auth_close_code::REQUIRED`
/// in `crates/nexapipe/src/conn/mod.rs`.
const AUTH_REQUIRED_CLOSE_CODE: u32 = 2;

/// The application error code the server closes a connection with when a
/// `[peers]` allow-list refuses this Node ID. Must match
/// `PEER_NOT_ALLOWED_CLOSE_CODE` in `crates/nexapipe/src/conn/allow_list.rs`.
///
/// Reached from a different place than the 2FA codes: the server refuses inside
/// the QUIC handshake, so `connect` itself fails rather than a later stream. The
/// preconnect has to read the close reason from that failure to turn "connection
/// lost" into a cause the operator can act on.
const PEER_NOT_ALLOWED_CLOSE_CODE: u32 = 5;

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

/// How a backend is reached right now, and how long a round trip takes.
///
/// The two belong together: the round trip is only meaningful for the path
/// that is carrying the traffic, and the path can change under the reading —
/// a direct path that opens replaces a relay one, and with it the latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkStatus {
    /// Whether traffic goes straight to the peer or through a relay.
    pub kind: LinkKind,
    /// The round-trip time of the path carrying the traffic.
    ///
    /// `None` means "not measured": a connection that has just opened has no
    /// sample yet, a closed one has none either, and a path iroh cannot
    /// measure — a relay that does not report — has none at all. It is not a
    /// zero, and a UI must not draw it as one.
    ///
    /// The reading is also `None` while the path still carries quinn's initial
    /// guess rather than a measurement — see [`rtt_of`].
    pub rtt: Option<std::time::Duration>,
}

impl LinkStatus {
    /// Reads both halves off a live connection.
    ///
    /// A closed connection has no path left to report, so the caller gets
    /// [`LinkStatus::default`] rather than a stale answer.
    pub fn of(conn: &Connection) -> Self {
        let kind = LinkKind::of(conn);
        if kind == LinkKind::Unknown {
            return Self::default();
        }
        Self {
            kind,
            rtt: rtt_of(conn),
        }
    }
}

/// The wire form of one link reading: `<endpoint id>=<kind>/<rtt in ms>`.
///
/// The JNI boundary carries the readings in this form and the Kotlin side reads
/// them back: the id, the kind, and the round trip in whole milliseconds.
/// `-` stands for a reading with no sample, so that an unmeasured path is not
/// read as a round trip of zero milliseconds.
///
/// A function of its own so that the form is testable without an endpoint:
/// the Kotlin decoder has its own tests, and the two halves of a contract
/// that only one side tests can drift apart without anything failing.
pub fn encode_link_status(id: &EndpointId, status: &LinkStatus) -> String {
    let rtt = match status.rtt {
        Some(rtt) => rtt.as_millis().to_string(),
        None => "-".to_string(),
    };
    format!("{}={}/{}", id, status.kind.as_str(), rtt)
}

/// The round-trip time of the path carrying the traffic, if it can be read.
///
/// The selected path is the one the traffic takes, so that is the one whose
/// latency is worth showing.
///
/// Two readings are not measurements, and are reported as `None` rather than
/// as a number:
///
/// - **quinn's guess.** The RTT estimator of a path starts at the transport's
///   [`INITIAL_RTT`](crate::transport::INITIAL_RTT) and holds it until the
///   path has something to say. A path selected a moment ago — a direct path
///   that just won hole punching, a relay path that just became the selected
///   one — therefore reads as the guess, which is a number nobody measured.
/// - **anything below a millisecond.** The UI draws whole milliseconds, and a
///   reading that rounds to zero is drawn as a number nobody made.
///
/// The guess is recognised by its value, and quinn leaves it in more than one
/// way. A path validation measures the round trip of its challenge and puts
/// that in its place, which is a measurement of its own and is reported as
/// one; a path opened for the same peer address while another validated path
/// to that address exists starts from that path's conservative estimate rather
/// than from the initial RTT — quinn looks for a validated path on the same
/// network path, so a direct path and a relay path do not seed each other. A
/// round trip that happens to land exactly on the initial RTT is reported as
/// no measurement at all.
fn rtt_of(conn: &Connection) -> Option<std::time::Duration> {
    let paths = conn.paths();
    for path in paths.iter() {
        if path.is_selected() {
            let rtt = conn.rtt(path.id())?;
            return measured_rtt(rtt);
        }
    }
    None
}

/// The round trip of a path, when it is a measurement rather than a guess.
///
/// Split out of [`rtt_of`] so that a reading can be taken off a path the
/// caller names rather than off whichever one is selected now: the two halves
/// of a reading describe one path, and the selection can move under the
/// reading.
fn measured_rtt(rtt: std::time::Duration) -> Option<std::time::Duration> {
    is_measured_rtt(rtt).then_some(rtt)
}

/// Whether `rtt` is a measured round-trip time rather than a guess.
///
/// Split out from [`rtt_of`] so the rule can be tested without a live
/// connection: reading it off a connection needs an endpoint, and the rule is
/// the part that has to be right.
///
/// The rule is the value, so it is exact in one direction only: a round trip
/// that lands exactly on the initial RTT is reported as no measurement.
fn is_measured_rtt(rtt: std::time::Duration) -> bool {
    rtt != crate::transport::INITIAL_RTT && rtt >= std::time::Duration::from_millis(1)
}

struct PooledConnection {
    conn: Connection,
    /// The identity this connection was authenticated as.
    ///
    /// `None` when the connection was made without a credential: it carries no
    /// identity at all, which is what it is compared with.
    ///
    /// The handshake runs once per connection, so this is the only record of
    /// who the connection belongs to — and it is what a connection is checked
    /// against before it is handed out or put back.
    identity: Option<CredentialIdentity>,
    /// When the connection was last handed back to the pool.
    ///
    /// Not when it was dialled: a connection that is used continuously comes
    /// back every few seconds, and the idle timeout is about how long it has
    /// been sitting unused — not how old it is. A connection in constant use
    /// is not idle, and a ten-minute-old connection that was returned a
    /// second ago is not either.
    last_used: tokio::time::Instant,
}

impl PooledConnection {
    /// True if the underlying iroh connection is still open (not closed by either side).
    fn is_live(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// True if this connection has been sitting in the pool unused for at least
    /// `timeout`.
    fn is_idle_for(&self, timeout: tokio::time::Duration) -> bool {
        is_idle_since(self.last_used, timeout)
    }
}

/// A connection that is out of the pool, and the identity it was
/// authenticated as.
///
/// The identity travels with the connection because the pool cannot work it
/// out later: a connection that was out of the pool when the credential was
/// replaced comes back carrying the identity that is gone, and it must not go
/// back in.
struct LoanedConnection {
    conn: Connection,
    identity: Option<CredentialIdentity>,
}

/// Whether a connection that was last used at `last_used` has been sitting
/// unused for at least `timeout`.
///
/// Free rather than a method, so that the rule can be tested without a live
/// connection: reading it off one needs an endpoint, and the rule is the part
/// that has to be right.
fn is_idle_since(last_used: tokio::time::Instant, timeout: tokio::time::Duration) -> bool {
    last_used.elapsed() >= timeout
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
fn drop_stale_connections(connections: &mut Vec<PooledConnection>) {
    let mut idle = Vec::new();
    connections.retain(|pooled| {
        if !pooled.is_live() {
            return false;
        }
        if pooled.is_idle_for(CONNECTION_IDLE_TIMEOUT) {
            idle.push(pooled.conn.clone());
            return false;
        }
        true
    });
    for conn in idle {
        conn.close(0u32.into(), b"idle");
    }
}

#[derive(Clone)]
pub struct IrohConnectionPool {
    inner: Arc<IrohConnectionPoolInner>,
}

/// Lock order, observed everywhere: `connections`, then `link_status`, then
/// `ep` — and never nested.
///
/// Nesting is what makes a pool that dials while another task shuts it down
/// deadlock-prone: `link_status` is also taken by the per-connection path
/// watcher, and `ep` by every dial, so holding one while waiting for another
/// turns a slow shutdown into a stall for every request.
struct IrohConnectionPoolInner {
    connections: Mutex<Vec<PooledConnection>>,
    /// The connections that are out of the pool, with the identity each was
    /// authenticated as.
    ///
    /// A flow takes its connection out of the pool, so a credential that is
    /// replaced while a flow is running cannot close it: the drop only sees
    /// the connections that are in the pool. This is where the ones that are
    /// out are, so that the identity they carry can be checked when they come
    /// back — a connection of an identity that is gone does not go back in.
    loaned: Mutex<Vec<LoanedConnection>>,
    ep: Arc<Mutex<Option<Endpoint>>>,
    endpoint_addr: EndpointAddr,
    /// Optional client 2FA credentials. When set, every freshly established
    /// connection is authenticated with the server before it is pooled/used.
    two_factor: Mutex<Option<TwoFactorAuth>>,
    /// A one-time enrollment token to spend on the next connection instead of
    /// presenting credentials — what a `v=2` invite carries. Cleared once it
    /// has bought a secret, which lands in [`Self::two_factor`].
    enrollment: Mutex<Option<Enrollment>>,
    /// The credential the server issued for that token.
    ///
    /// The process can use it for as long as it lives, but the token it came
    /// from is spent: an app that restarts without persisting this has nothing
    /// left to authenticate with. [`IrohConnectionPool::take_issued_credential`]
    /// hands it to whoever stores such things.
    issued: Mutex<Option<TwoFactorAuth>>,
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
    link_status: Mutex<CachedLinkStatus>,
    /// Which network generation the pool is on.
    ///
    /// Moved by [`IrohConnectionPool::drop_connections`], which is what a
    /// network switch calls. A connection that was out on loan when the
    /// switch happened is neither in the pool nor closed by the drop, so its
    /// watcher keeps running — and the reading it would publish is the one
    /// of the network that is gone. A watcher that notices the generation
    /// moved stops publishing, and closes the connection on its way out.
    epoch: AtomicU64,
}

/// A recorded [`LinkStatus`] and the connection it was recorded for.
#[derive(Default)]
struct CachedLinkStatus {
    /// The connection the status describes, if there is one.
    conn: Option<Connection>,
    /// What the path watcher saw on that connection.
    status: LinkStatus,
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
            loaned: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: true,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
        });
        spawn_cleanup_task(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn new_with_endpoint(ep: Endpoint, endpoint_addr: EndpointAddr) -> Self {
        let inner = Arc::new(IrohConnectionPoolInner {
            connections: Mutex::new(Vec::new()),
            loaned: Mutex::new(Vec::new()),
            ep: Arc::new(Mutex::new(Some(ep))),
            endpoint_addr,
            two_factor: Mutex::new(None),
            enrollment: Mutex::new(None),
            issued: Mutex::new(None),
            auth_required: Mutex::new(None),
            owns_endpoint: false,
            link_status: Mutex::new(CachedLinkStatus::default()),
            epoch: AtomicU64::new(0),
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
    /// been replaced. The connections in the pool are closed when the identity
    /// changes, and a connection that was out of the pool when it changed is
    /// closed when it comes back rather than going back in.
    ///
    /// The same identity keeps them: a rotated secret is the same account
    /// with a different secret, and the connections still stand for that
    /// account. A rotation closes nothing — neither the connections in the
    /// pool nor the one a request is riding.
    pub async fn set_two_factor(&self, auth: Option<TwoFactorAuth>) {
        self.set_credential(auth).await;
    }

    /// Writes the pool's credential, and closes the connections of the
    /// identity that is gone.
    ///
    /// Every write of the credential goes through here. A path that wrote it
    /// directly — the enrollment writes one of its own — would change the
    /// identity without the comparison, and the connections of the old
    /// identity would stay in the pool.
    ///
    /// The connections in the pool are closed here; one that was out of the
    /// pool when the identity changed is closed when it comes back, and does
    /// not go back in — see [`Self::return_connection`].
    async fn set_credential(&self, auth: Option<TwoFactorAuth>) {
        let mut slot = self.inner.two_factor.lock().await;
        let changed = identity_changed(slot.as_ref(), auth.as_ref());
        *slot = auth;
        // Released before the connections are touched: the lock order is
        // `connections` first, and nesting the two is what makes a pool that
        // dials while another task shuts it down deadlock-prone.
        drop(slot);

        if changed {
            // The connections were authenticated as the identity that is gone.
            self.drop_connections().await;
        }
    }

    /// The identity the pool's credential stands for right now.
    ///
    /// `None` when the pool has no credential: a connection made without one
    /// carries no identity, which is what it is compared with.
    async fn current_identity(&self) -> Option<CredentialIdentity> {
        self.inner
            .two_factor
            .lock()
            .await
            .as_ref()
            .map(|auth| auth.identity())
    }

    /// Configure a one-time enrollment token instead of credentials: the next
    /// connection spends it and comes back with the real secret in
    /// [`Self::two_factor`].
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

    /// The endpoint to dial from, cloned out of the mutex.
    ///
    /// A copy, not a guard: the QUIC handshake — and the 2FA stream that
    /// follows it — runs for up to [`CONNECTION_TIMEOUT`], and `close_all`
    /// needs the very same lock to close the endpoint. Holding the guard
    /// across the handshake made shutdown lose that race, and the loser is not
    /// the one you want: the JNI layer gives `close_all` eight seconds
    /// (`CLOSE_ALL_TIMEOUT` in `jni.rs`) and then moves on, so the endpoint
    /// stayed open for the rest of the process. `Endpoint` is a handle over
    /// shared state, so cloning costs nothing and still dials from the
    /// endpoint this pool was built with.
    async fn endpoint(&self) -> Option<Endpoint> {
        self.inner.ep.lock().await.clone()
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
    ///
    /// The identity the connection was authenticated as comes back with it:
    /// the handshake runs once, so that is the only moment the connection's
    /// identity is known, and the pool has to keep it to tell this connection
    /// from one that belongs to another identity.
    async fn connect_and_auth(
        &self,
        ep: &Endpoint,
        timeout: tokio::time::Duration,
    ) -> Result<(Connection, Option<CredentialIdentity>), ClientError> {
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

            // A `[peers]` allow-list refuses inside the QUIC handshake, so the
            // only place its verdict shows up is the error from `connect`
            // itself — there is no connection left to ask. Turn it into the same
            // actionable sentence the 2FA refusals produce, instead of a bare
            // "connection lost".
            if let Some(reason) = peer_not_allowed_reason(&e) {
                return ClientError::AuthenticationFailed(reason);
            }
            ClientError::ConnectionFailed(e.to_string())
        })?;

        // Enrollment first: a token is spent once and buys the credentials the
        // block below then uses, so it only runs while there are none.
        let enrollment = self.inner.enrollment.lock().await.clone();
        if let Some(enrollment) = enrollment {
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Enrolling with a one-time token as client '{}'",
                enrollment.client_id()
            );
            match enrollment.exchange(&conn).await {
                Ok(issued) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        "Enrollment succeeded for client '{}'; the token is spent",
                        issued.client_id()
                    );
                    // The credential changes here, so it goes through the one
                    // place that writes it: the identity comparison and the
                    // drop of the connections of the identity that is gone
                    // have to happen with it.
                    self.set_credential(Some(issued.clone())).await;
                    *self.inner.enrollment.lock().await = None;
                    *self.inner.issued.lock().await = Some(issued);
                }
                Err(e) => {
                    conn.close(0u32.into(), b"2FA enrollment failed");
                    #[cfg(feature = "tracing")]
                    tracing::warn!("2FA enrollment failed: {}", e);
                    return Err(e);
                }
            }
        }

        let two_factor = self.inner.two_factor.lock().await.clone();
        let mut identity = None;
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
            // The connection is authenticated as this credential from here on:
            // this is the identity it carries for as long as it lives.
            identity = Some(auth.identity());
            #[cfg(feature = "tracing")]
            tracing::info!(
                "2FA authentication succeeded for client '{}'",
                auth.client_id()
            );
        }

        Ok((conn, identity))
    }

    pub async fn get_connection(&self) -> Result<Connection, crate::error::ClientError> {
        // The identity the pool's credential stands for right now. Read before
        // the connections are locked, and released again: the lock order is
        // `connections` first, and nesting the two is what makes a pool that
        // dials while another task shuts it down deadlock-prone.
        let current = self.current_identity().await;

        // A connection of an identity that is gone is closed rather than
        // handed out: it was authenticated as somebody else.
        let mut stale = Vec::new();
        let chosen = {
            let mut connections = self.inner.connections.lock().await;

            // Drop stale connections before handing one out: anything already closed
            // by the peer, or idle for longer than CONNECTION_IDLE_TIMEOUT.
            drop_stale_connections(&mut connections);

            let mut chosen = None;
            while let Some(pooled) = connections.pop() {
                if pooled.identity == current {
                    chosen = Some(pooled);
                    break;
                }
                stale.push(pooled.conn);
            }
            chosen
        };
        for conn in stale {
            #[cfg(feature = "tracing")]
            tracing::info!("Closing a pooled connection of an identity that is gone");
            conn.close(0u32.into(), b"credential changed");
        }

        if let Some(pooled) = chosen {
            self.loan(pooled.conn.clone(), pooled.identity).await;
            return Ok(pooled.conn);
        }

        let ep = self.endpoint().await.ok_or_else(|| {
            crate::error::ClientError::InvalidConfig("Endpoint has been closed".to_string())
        })?;

        let (conn, identity) = self.connect_and_auth(&ep, CONNECTION_TIMEOUT).await?;
        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());
        self.loan(conn.clone(), identity).await;

        Ok(conn)
    }

    /// Records that a connection is out of the pool, with the identity it was
    /// authenticated as.
    async fn loan(&self, conn: Connection, identity: Option<CredentialIdentity>) {
        self.inner
            .loaned
            .lock()
            .await
            .push(LoanedConnection { conn, identity });
    }

    /// Takes back the record of a connection that is out of the pool, and the
    /// identity it was authenticated as.
    ///
    /// `None` when the pool has no record of the connection — it was not the
    /// pool's, or it has already been taken back.
    ///
    /// The connection is found by iroh's stable id, which is fixed for the
    /// lifetime of the connection: the record that comes back is the one that
    /// belongs to this connection and not to another.
    async fn take_loan(&self, conn: &Connection) -> Option<Option<CredentialIdentity>> {
        let id = conn.stable_id();
        let mut loaned = self.inner.loaned.lock().await;
        let index = loaned.iter().position(|loan| loan.conn.stable_id() == id)?;
        Some(loaned.swap_remove(index).identity)
    }

    /// How traffic to this backend is currently routed, and how far away it is.
    ///
    /// A pooled connection is asked directly when there is one, because its path list is the
    /// truth right now; otherwise the last value the path watcher recorded is used. Without
    /// that fallback a UI polling while requests are in flight — the pool empty, every
    /// connection out on loan — would read "unknown" and flap.
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
        // showing a route to a backend it cannot reach.
        let cached = self.inner.link_status.lock().await;
        match &cached.conn {
            Some(conn) if conn.close_reason().is_none() => cached.status,
            _ => LinkStatus::default(),
        }
    }

    /// How traffic to this backend is currently routed, without the latency.
    ///
    /// The kind on its own, for the callers that only draw an icon.
    pub async fn link_kind(&self) -> LinkKind {
        self.link_status().await.kind
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

        // One deadline for the whole preconnect. The observation below is part
        // of it, not a wait that starts once the connect is over: a backend that
        // was merely slow used to be cancelled in the middle of that
        // observation and reported unreachable.
        let started = tokio::time::Instant::now();
        let deadline = started + PRECONNECT_TIMEOUT;

        let (conn, identity) = {
            let Some(ep) = self.endpoint().await else {
                return false;
            };
            match tokio::time::timeout_at(
                deadline,
                self.connect_and_auth(&ep, PRECONNECT_CONNECT_TIMEOUT),
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
        if self.inner.two_factor.lock().await.is_none() {
            // Only what is left of the budget, so the observation is never what
            // pushes the preconnect past it. It still gets the whole grace
            // whenever the connect kept to its own, which is the case that has
            // to work.
            let grace =
                AUTH_REQUIRED_GRACE.min(PRECONNECT_TIMEOUT.saturating_sub(started.elapsed()));
            if let Some(reason) = wait_for_auth_required(&conn, grace).await {
                #[cfg(feature = "tracing")]
                tracing::warn!("preconnect refused by the server: {}", reason);
                #[cfg(not(feature = "tracing"))]
                let _ = &reason;
                *self.inner.auth_required.lock().await = Some(reason);
                return false;
            }
        }

        spawn_path_watcher(Arc::downgrade(&self.inner), conn.clone());
        self.pool_connection(conn, identity).await;
        true
    }

    pub async fn return_connection(&self, conn: Connection) {
        // Never pool a connection that has already been closed: handing it out
        // again would just fail on the next request. The background watcher also
        // reaps such connections, but checking here avoids re-inserting them.
        if conn.close_reason().is_some() {
            return;
        }

        // The identity the connection was authenticated as, and the identity
        // the pool's credential stands for now. Neither lock is held while the
        // other is taken.
        let identity = self.take_loan(&conn).await;
        let current = self.current_identity().await;

        match identity {
            // The connection belongs to the identity that is current: it goes
            // back into the pool.
            Some(recorded) if recorded == current => {
                self.pool_connection(conn, recorded).await;
            }
            // It belongs to an identity that is gone. The credential was
            // replaced while this connection was out of the pool, so the drop
            // could not close it then; it is closed now, and it does not go
            // back in.
            Some(_) => {
                #[cfg(feature = "tracing")]
                tracing::info!("Closing a connection of an identity that is gone");
                conn.close(0u32.into(), b"credential changed");
            }
            // The pool has no record of this connection, so it cannot say which
            // identity it was authenticated as. It does not go back in either:
            // a connection nobody can vouch for is not one to hand out.
            None => {
                #[cfg(feature = "tracing")]
                tracing::warn!("Closing a connection the pool has no record of");
                conn.close(0u32.into(), b"unknown connection");
            }
        }
    }

    /// Puts a connection into the pool, with the identity it was
    /// authenticated as.
    async fn pool_connection(&self, conn: Connection, identity: Option<CredentialIdentity>) {
        let mut connections = self.inner.connections.lock().await;
        if connections.len() < MAX_CONNECTIONS {
            connections.push(PooledConnection {
                conn,
                identity,
                last_used: tokio::time::Instant::now(),
            });
            return;
        }

        // The pool is full, so this one is closed on the spot. Dropping the
        // handle would close it just as surely, but silently: the peer would
        // see a connection that vanished with no reason attached, which is
        // indistinguishable from a crash on this side.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "Connection pool is full ({}), closing the connection that came back",
            MAX_CONNECTIONS
        );
        conn.close(0u32.into(), b"connection pool full");
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

/// Whether a credential change is a change of identity.
///
/// A connection is authenticated as whoever the handshake ran for, and the
/// handshake runs once per connection — so a connection made under the old
/// credential keeps serving traffic under the old identity after the
/// credential has been replaced. The connections are closed when the identity
/// changes.
///
/// A rotated secret is the same account with a different secret, and the
/// connections still stand for that account: a rotation changes nothing about
/// who they are, so it closes nothing.
///
/// Split out of [`IrohConnectionPool::set_two_factor`] so the decision can be
/// tested without an endpoint: a connection needs one, a rule does not.
fn identity_changed(before: Option<&TwoFactorAuth>, after: Option<&TwoFactorAuth>) -> bool {
    before.map(|a| a.identity()) != after.map(|a| a.identity())
}

/// Waits for a backend that demands 2FA to say so.
///
/// Returns the reason the server gave when it closes the connection with
/// [`AUTH_REQUIRED_CLOSE_CODE`], and `None` when the connection stays up — or
/// dies for any other reason, which is not what this is looking for.
/// `grace` is however much of the preconnect budget is left rather than
/// [`AUTH_REQUIRED_GRACE`] itself: the caller owns the deadline, so it decides
/// how much of it this wait may spend. Passing the full constant is only right
/// when the connect has kept to its own budget.
async fn wait_for_auth_required(conn: &Connection, grace: tokio::time::Duration) -> Option<String> {
    let closed = tokio::select! {
        _ = tokio::time::sleep(grace) => return None,
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

/// The text to show when the server's `[peers]` allow-list refused this Node ID.
///
/// Read off the `connect` failure rather than a connection, because the refusal
/// happens inside the QUIC handshake: `after_handshake` closes with
/// [`PEER_NOT_ALLOWED_CLOSE_CODE`] and the connection is never handed to the
/// client at all. iroh surfaces that as an `ApplicationClosed` carrying the
/// code, so matching on it here is the only place the client can learn why.
fn peer_not_allowed_reason(error: &iroh::endpoint::ConnectError) -> Option<String> {
    let iroh::endpoint::ConnectError::Connection { source, meta: _ } = error else {
        return None;
    };
    let iroh::endpoint::ConnectionError::ApplicationClosed(close) = source else {
        return None;
    };
    if close.error_code.into_inner() != PEER_NOT_ALLOWED_CLOSE_CODE as u64 {
        return None;
    }
    Some(String::from_utf8_lossy(&close.reason).into_owned())
}
/// Whether a watcher that started in `generation` may still publish.
///
/// The pool's generation moves when the network changes, and a watcher whose
/// generation is behind describes a network that is gone: the round trip it
/// would publish is the one of a path that no longer carries anything.
fn may_publish(current: u64, generation: u64) -> bool {
    current == generation
}

/// Watches one connection's paths and records which kind is carrying traffic.
///
/// The initial snapshot matters: right after the handshake iroh has already selected a path
/// (the relay one, usually) and only *later* promotes a direct one. Waiting for the first
/// event would leave the answer at [`LinkKind::Unknown`] for as long as the connection stays
/// on its first path — which, for a backend behind a symmetric NAT, is forever.
fn spawn_path_watcher(inner: Weak<IrohConnectionPoolInner>, conn: Connection) {
    let status = LinkStatus::of(&conn);
    // The generation this connection belongs to. A watcher that outlives its
    // generation has a reading that describes a network that is gone, so it
    // stops publishing when the generation moves.
    let generation = inner
        .upgrade()
        .map(|inner| inner.epoch.load(Ordering::Acquire))
        .unwrap_or_default();
    // `try_lock`, not `lock`: this runs on the caller's task, and a lock held elsewhere must
    // not stall a connection being handed out. Losing the race only costs one stale reading.
    if let Some(inner) = inner.upgrade()
        && let Ok(mut slot) = inner.link_status.try_lock()
    {
        *slot = CachedLinkStatus {
            conn: Some(conn.clone()),
            status,
        };
    }

    tokio::spawn(async move {
        let mut path_events = conn.path_events();
        // The round-trip time moves on its own: iroh re-estimates it from every
        // acknowledgement, and says nothing when it does. A path event is rare —
        // the connection may sit on one path for hours — so the latency is
        // refreshed on a tick instead, or the reading a user sees would be the
        // one the connection happened to have when it opened.
        let mut ticker = tokio::time::interval(RTT_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                event = path_events.next() => {
                    let Some(event) = event else {
                        break;
                    };
                    let iroh::endpoint::PathEvent::Selected { id, remote_addr, .. } = event else {
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
                    // The pool moved to another network: this connection is
                    // from the one that is gone, and the reading it would
                    // publish is that network's — the round trip of a path
                    // that no longer carries anything. The connection is
                    // closed on the way out, because the drop could not close
                    // it — it was out on loan when the drop happened — and a
                    // closed connection is not pooled again.
                    //
                    // The check is under the lock the reading is written
                    // with, and the drop moves the generation under that
                    // same lock: so the two cannot interleave, and a reading
                    // of the network that is gone cannot land after the
                    // reading was cleared.
                    let mut cached = inner.link_status.lock().await;
                    if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                        conn.close(0u32.into(), b"network changed");
                        break;
                    }
                    *cached = CachedLinkStatus {
                        conn: Some(conn.clone()),
                        status: LinkStatus {
                            kind,
                            // The round trip is read off the path the event
                            // named, not off whichever path is selected at the
                            // moment of the read: the two halves of a reading
                            // describe one path, and the selection can move
                            // between the event and the read.
                            //
                            // An unknown kind has no path to measure, which
                            // is how [`LinkStatus::of`] reads it too.
                            rtt: if kind == LinkKind::Unknown {
                                None
                            } else {
                                conn.rtt(id).and_then(measured_rtt)
                            },
                        },
                    };
                }
                _ = ticker.tick() => {
                    let Some(inner) = inner.upgrade() else {
                        // Pool dropped; nobody is left to tell.
                        break;
                    };
                    let status = LinkStatus::of(&conn);
                    if status.kind == LinkKind::Unknown {
                        continue;
                    }
                    // The pool moved to another network: this connection is
                    // from the one that is gone, and the reading it would
                    // publish is that network's — the round trip of a path
                    // that no longer carries anything. The connection is
                    // closed on the way out, because the drop could not close
                    // it — it was out on loan when the drop happened — and a
                    // closed connection is not pooled again.
                    //
                    // The check is under the lock the reading is written
                    // with, and the drop moves the generation under that
                    // same lock: so the two cannot interleave, and a reading
                    // of the network that is gone cannot land after the
                    // reading was cleared.
                    let mut cached = inner.link_status.lock().await;
                    if !may_publish(inner.epoch.load(Ordering::Acquire), generation) {
                        conn.close(0u32.into(), b"network changed");
                        break;
                    }
                    *cached = CachedLinkStatus {
                        conn: Some(conn.clone()),
                        status,
                    };
                }
            }
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
            drop(connections);

            // The records of the connections that are out of the pool and are
            // closed: they will never come back, so the record of them is of
            // no use. A connection that is still open keeps its record — that
            // is what says which identity it was authenticated as.
            let mut loaned = inner.loaned.lock().await;
            loaned.retain(|loan| loan.conn.close_reason().is_none());
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
    use super::{
        CONNECTION_IDLE_TIMEOUT, IrohConnectionPool, LinkKind, LinkStatus, encode_link_status,
        identity_changed, is_idle_since, is_measured_rtt, may_publish,
    };
    use crate::auth::{Enrollment, TotpAlgorithm, TwoFactorAuth};
    use iroh::Endpoint;
    use iroh::endpoint::presets;
    use nexapipe_proto::auth::{Algorithm, AuthMessage};
    use nexapipe_proto::secret::SecretString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A credential for `client_id`, optionally naming a device.
    fn credential(client_id: &str, secret: &str, device: Option<&str>) -> TwoFactorAuth {
        let auth = TwoFactorAuth::new(client_id, secret, TotpAlgorithm::SHA1)
            .expect("a valid base32 secret");
        match device {
            Some(device) => auth.with_device(device),
            None => auth,
        }
    }

    /// A backend that completes the authentication handshake, and nothing else.
    ///
    /// A connection is authenticated when it is made, so a test that wants a
    /// connection of a given identity needs a server that answers the
    /// handshake. This one checks nothing: it issues a challenge and says the
    /// credential is good. The credential it enrolls is one of another client,
    /// so an enrollment changes the identity of the pool.
    async fn auth_backend() -> (Endpoint, Arc<AtomicUsize>) {
        let ep = Endpoint::builder(presets::N0)
            // Only the connections whose ALPN the endpoint knows are accepted.
            .alpns(vec![super::ALPN_NEXAPIPE.to_vec()])
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let server = ep.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let conn = incoming.await.expect("the QUIC handshake completes");
                    // More than one stream: an enrollment and the handshake
                    // that follows it share one stream, and the handshake
                    // that follows the enrollment opens another.
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        while let Some(message) = read_auth_message(&mut recv).await {
                            match message {
                                AuthMessage::EnrollStart { client_id, .. } => {
                                    let issue = AuthMessage::EnrollIssue {
                                        client_id,
                                        secret: SecretString::new(
                                            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
                                        ),
                                        algorithm: Algorithm::Sha1,
                                        digits: 6,
                                        period: 30,
                                        device_id: None,
                                    };
                                    write_auth_message(&mut send, &issue).await;
                                }
                                AuthMessage::Start { .. } => {
                                    let challenge = AuthMessage::Challenge {
                                        nonce: vec![1, 2, 3, 4],
                                    };
                                    write_auth_message(&mut send, &challenge).await;
                                }
                                AuthMessage::Response { .. } => {
                                    write_auth_message(&mut send, &AuthMessage::Ok).await;
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                });
            }
        });
        (ep, accepted)
    }

    /// Reads one length-prefixed authentication message.
    async fn read_auth_message(recv: &mut iroh::endpoint::RecvStream) -> Option<AuthMessage> {
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await.ok()?;
        let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
        recv.read_exact(&mut buf).await.ok()?;
        AuthMessage::from_bytes(&buf).ok()
    }

    /// Writes one length-prefixed authentication message.
    async fn write_auth_message(send: &mut iroh::endpoint::SendStream, message: &AuthMessage) {
        let bytes = message.to_bytes().expect("the message serializes");
        send.write_all(&(bytes.len() as u32).to_le_bytes())
            .await
            .expect("the message is written");
        send.write_all(&bytes)
            .await
            .expect("the message is written");
    }

    /// A pool pointed at a local backend that answers the handshake.
    async fn pool_harness() -> (IrohConnectionPool, Arc<AtomicUsize>) {
        let (backend, accepted) = auth_backend().await;
        let client = Endpoint::builder(presets::N0)
            .bind()
            .await
            .expect("binding a local endpoint needs no network");
        let pool = IrohConnectionPool::new_with_endpoint(client, backend.addr());
        (pool, accepted)
    }

    /// A connection that was out of the pool when the credential was replaced
    /// does not go back into it.
    ///
    /// The handshake runs once per connection, so the connection carries the
    /// identity it was authenticated as, whatever the pool's credential says
    /// afterwards. A credential of another identity means this connection
    /// belongs to somebody else now, and handing it out again would serve the
    /// old identity under the new credential.
    #[tokio::test]
    async fn a_connection_of_a_gone_identity_does_not_go_back_into_the_pool() {
        let (pool, _accepted) = pool_harness().await;
        pool.set_two_factor(Some(credential(
            "client-001",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            None,
        )))
        .await;

        let conn = pool.get_connection().await.expect("the connection is made");
        let old_id = conn.stable_id();

        // The credential is replaced while the connection is out of the pool.
        pool.set_two_factor(Some(credential(
            "client-002",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            None,
        )))
        .await;

        pool.return_connection(conn.clone()).await;

        assert!(
            conn.close_reason().is_some(),
            "the connection of the identity that is gone is closed instead of pooled"
        );

        // And it is not in the pool: the next request gets a connection of its own.
        let next = pool
            .get_connection()
            .await
            .expect("the next connection is made");
        assert_ne!(
            next.stable_id(),
            old_id,
            "the connection of the identity that is gone was handed out again"
        );
    }

    /// A connection of the identity that is current goes back into the pool.
    ///
    /// The other half of the rule above: a connection is only refused when
    /// its identity is gone, and the ordinary case — the same credential,
    /// the same connection — keeps working.
    #[tokio::test]
    async fn a_connection_of_the_current_identity_goes_back_into_the_pool() {
        let (pool, accepted) = pool_harness().await;
        pool.set_two_factor(Some(credential(
            "client-001",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            None,
        )))
        .await;

        let conn = pool.get_connection().await.expect("the connection is made");
        let id = conn.stable_id();
        pool.return_connection(conn).await;

        let next = pool
            .get_connection()
            .await
            .expect("the next connection is made");
        assert_eq!(
            next.stable_id(),
            id,
            "the connection went back into the pool"
        );
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "the second request rode the pooled connection instead of dialling again"
        );
    }

    /// The credential an enrollment buys goes through the same check.
    ///
    /// The enrollment writes the pool's credential itself, and a write that
    /// skipped the check would change the identity without the pool hearing
    /// about it: the connections of the old identity would carry on as if
    /// nothing had happened.
    #[tokio::test]
    async fn an_enrollment_of_another_identity_closes_the_old_connections() {
        let (pool, _accepted) = pool_harness().await;
        pool.set_two_factor(Some(credential(
            "client-001",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            None,
        )))
        .await;

        // A connection of client-001, out of the pool.
        let conn = pool.get_connection().await.expect("the connection is made");

        // The next dial spends the enrollment token, and the credential it
        // buys belongs to another client.
        pool.set_enrollment(Some(Enrollment::new("client-002", "enrollment-token")))
            .await;
        let next = pool
            .get_connection()
            .await
            .expect("the enrollment connection is made");

        assert_ne!(
            next.stable_id(),
            conn.stable_id(),
            "the enrollment opened a connection of its own"
        );
        assert!(
            wait_for_close(&conn).await,
            "the connection of the identity that is gone was not told the identity changed"
        );
    }

    /// Waits for a connection to be closed, and says whether it was.
    ///
    /// The pool tells the connections it made that the identity has changed
    /// by moving its generation, and the watcher of each connection notices
    /// that on its next tick — so this waits for the tick rather than for the
    /// instant.
    async fn wait_for_close(conn: &iroh::endpoint::Connection) -> bool {
        for _ in 0..50 {
            if conn.close_reason().is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// A different secret under the same name is the same account.
    ///
    /// A rotation changes the seed and nothing else, so the connections that
    /// were authenticated as that account still stand for it — and a rotation
    /// closes nothing, neither the connections in the pool nor the one a
    /// request is riding.
    #[test]
    fn a_rotated_secret_is_the_same_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let after = credential("client-001", "KRSXG5BAMFRGGZDFMZTWQ2LKNNWG23TP", None);

        assert!(!identity_changed(Some(&before), Some(&after)));
    }

    /// A different client is a different account, and the connections
    /// authenticated as the old one are not the new one's.
    #[test]
    fn a_different_client_is_a_different_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let after = credential("client-002", "JBSWY3DPEHPK3PXP", None);

        assert!(identity_changed(Some(&before), Some(&after)));
    }

    /// A different device of the same client is a different credential, and a
    /// connection authenticated as one device is not the other's.
    #[test]
    fn a_different_device_is_a_different_identity() {
        let before = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));
        let after = credential("client-001", "JBSWY3DPEHPK3PXP", Some("phone"));

        assert!(identity_changed(Some(&before), Some(&after)));
    }

    /// A named device and the client it belongs to are different identities:
    /// the named one answers with a secret of its own, the unnamed one with
    /// the client's.
    #[test]
    fn a_named_device_is_not_the_client_it_belongs_to() {
        let unnamed = credential("client-001", "JBSWY3DPEHPK3PXP", None);
        let named = credential("client-001", "JBSWY3DPEHPK3PXP", Some("laptop"));

        assert!(identity_changed(Some(&unnamed), Some(&named)));
    }

    /// Going from a credential to none, and from none to a credential, are
    /// both changes.
    #[test]
    fn dropping_or_adding_a_credential_is_a_change() {
        let auth = credential("client-001", "JBSWY3DPEHPK3PXP", None);

        assert!(identity_changed(Some(&auth), None));
        assert!(identity_changed(None, Some(&auth)));
        assert!(!identity_changed(None, None));
    }

    /// A connection is idle since it was last used, not since it was dialled.
    ///
    /// The clock is paused so that "a moment ago" and "61 seconds ago" are
    /// exact rather than approximate.
    #[tokio::test(start_paused = true)]
    async fn a_connection_is_idle_since_it_was_last_used() {
        let now = tokio::time::Instant::now();

        assert!(
            !is_idle_since(now, CONNECTION_IDLE_TIMEOUT),
            "a connection that was just handed back is not idle"
        );

        // Used for ten minutes, and handed back a second ago: the connection is
        // old, and it is not idle. The timeout measures how long the connection
        // has been sitting **unused**, not how old it is.
        let ten_minutes_of_use = tokio::time::Duration::from_secs(600);
        let handed_back_a_second_ago = now - tokio::time::Duration::from_secs(1);
        assert!(
            !is_idle_since(handed_back_a_second_ago, CONNECTION_IDLE_TIMEOUT),
            "a connection that was used for {ten_minutes_of_use:?} and handed back a second ago \
             is not idle"
        );

        assert!(
            is_idle_since(
                now - tokio::time::Duration::from_secs(61),
                CONNECTION_IDLE_TIMEOUT
            ),
            "a connection that has been sitting for longer than the timeout is idle"
        );
    }

    /// A watcher that started before the network changed must not publish: the
    /// reading it holds is the round trip of the network that is gone.
    #[test]
    fn a_watcher_from_an_older_generation_does_not_publish() {
        assert!(
            may_publish(3, 3),
            "the generation the watcher started in may publish"
        );
        assert!(
            !may_publish(4, 3),
            "a generation that moved on may not publish"
        );
    }

    /// quinn's estimator starts every path at the transport's initial RTT and
    /// replaces it once the path has something to say, so a path that was
    /// selected a moment ago reads as that guess. It is a number nobody
    /// measured, and the UI has to be able to say so.
    #[test]
    fn quinns_initial_guess_is_not_a_measurement() {
        // The guess itself is not a measurement.
        assert!(!is_measured_rtt(crate::transport::INITIAL_RTT));
        // A reading that differs from the guess is one.
        assert!(is_measured_rtt(Duration::from_millis(334)));
        assert!(is_measured_rtt(Duration::from_millis(20)));
    }

    /// The UI draws whole milliseconds: a reading that would be drawn as zero
    /// is not a number anybody made either.
    #[test]
    fn a_reading_below_a_millisecond_is_not_drawn_as_zero() {
        assert!(!is_measured_rtt(Duration::from_micros(0)));
        assert!(!is_measured_rtt(Duration::from_micros(999)));
        assert!(is_measured_rtt(Duration::from_millis(1)));
    }

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
        assert_eq!(
            serde_json::to_string(&LinkKind::Direct).unwrap(),
            "\"direct\""
        );
        assert_eq!(
            serde_json::to_string(&LinkKind::Relay).unwrap(),
            "\"relay\""
        );
        assert_eq!(
            serde_json::to_string(&LinkKind::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    /// A link with no path is nothing at all — not a direct link with no
    /// latency, which is what a caller would draw as "0 ms".
    #[test]
    fn a_link_with_no_path_has_neither_a_kind_nor_a_latency() {
        let status = LinkStatus::default();
        assert_eq!(status.kind, LinkKind::Unknown);
        assert_eq!(status.rtt, None);
    }

    /// The reading crosses the JNI boundary as `<id>=<kind>/<rtt>`, and the
    /// Kotlin side reads it back. The form is a contract between the two
    /// halves, so it is pinned here: the Kotlin decoder has its own tests,
    /// and a form only one side tests can drift apart without anything
    /// failing.
    #[test]
    fn a_link_reading_carries_the_kind_and_the_round_trip() {
        let id = iroh::SecretKey::generate().public();
        let status = LinkStatus {
            kind: LinkKind::Relay,
            rtt: Some(Duration::from_millis(15)),
        };

        assert_eq!(encode_link_status(&id, &status), format!("{}=relay/15", id));
    }

    /// A reading with no sample says so, rather than saying zero — a zero
    /// would be drawn as a round trip of no time at all.
    #[test]
    fn a_link_reading_without_a_sample_says_so() {
        let id = iroh::SecretKey::generate().public();
        let status = LinkStatus {
            kind: LinkKind::Direct,
            rtt: None,
        };

        assert_eq!(encode_link_status(&id, &status), format!("{}=direct/-", id));
    }
}
