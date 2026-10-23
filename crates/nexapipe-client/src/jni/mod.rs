//! The bridge to the Android app.
//!
//! The app talks to the proxy through JNI: every call is a `native` method
//! on the Kotlin side, and every one of them lands here. There are thirty-three
//! of them, and they are about six different things — so they are six
//! modules, and this one holds what they share.
//!
//! What they share is the state of this process: the runtime, the endpoint,
//! the proxy on top of it, the credentials the app has set, and the last
//! error the app has not read yet. It is here because it is the state of the
//! whole process rather than of one of them, and because a half-initialised
//! state is what a call into a module that is not there yet would look like.
//!
//! And they share one rule: every one of them catches a panic before it
//! leaves the frame. Unwinding out of an `extern "system"` frame is a native
//! crash on Android, not a Java exception, so a panic that reaches the
//! boundary takes the whole app down rather than the one call failing. Each
//! entry point therefore wraps its *whole* body in exactly one barrier:
//! `with_env_or` for the ones that need an `Env` first, `catching_panic`
//! for the ones that do not.

use crate::auth::{DeviceKey, Enrollment, TotpAlgorithm, TwoFactorAuth};
use crate::discovery::DiscoveryMode;
use crate::relay::RelayModeSpec;
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use crate::tun_proxy::TunProxy;
use crate::{DomainMapping, EndpointGroup, IrohConnectionPool, LoadBalancingStrategy, NodeConfig};
use iroh::Endpoint;
use iroh::dns::{DnsError, DnsResolver, NameserverConfig, Resolver, TxtRecordData};
use iroh::endpoint::presets;
use jni::objects::JString;
use jni::sys::jint;
use jni::{Env, EnvUnowned, Outcome};
use nexapipe_proto::secret::SecretString;
// Only `native_init` reads the Android context, and only on Android. Gated to
// match: an ungated import is an unused-import warning on every other `jni`
// build, which is what the release archives are.
#[cfg(target_os = "android")]
use ndk_context;
use once_cell::sync::{Lazy, OnceCell};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
// The TUN descriptor's ownership is taken in `start_tun_proxy`, which is the
// Android half of the tunnel. Gated to match that function: an ungated
// import is an unused-import warning on every other build, which is what the
// release archives are.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use std::os::fd::FromRawFd;
use std::panic;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

mod credentials;
mod network;
mod proxy;
mod routing;
mod status;
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
mod tun;

pub(crate) static RUNTIME: OnceCell<Runtime> = OnceCell::new();
pub(crate) static ENDPOINT: Mutex<Option<Endpoint>> = Mutex::new(None);
pub(crate) static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();
// 2FA config: Kotlin injects (client_id, secret, algorithm) via nativeSetTwoFactor before startup.
//
// The secret is a `SecretString`: this table lives for as long as the process
// does, and the seed in it is a working credential — it is wiped when the
// entry is replaced or cleared, rather than being left in the heap for the
// allocator to hand out again.
pub(crate) static TWO_FACTOR: Mutex<Option<(String, SecretString, String)>> = Mutex::new(None);

/// One endpoint's TOTP credentials, as Kotlin filed them: client id, secret,
/// algorithm, and the device the secret was issued to.
///
/// The last field is what decides whether a handshake claims a device name, so
/// it travels with the triple rather than being read from `DEVICE_ID` at apply
/// time: a pair issued to the client has to keep answering as the client.
///
/// The secret is a [`SecretString`], for the reason the table above gives.
type NodeCredential = (String, SecretString, String, Option<String>);

// 2FA credentials per backend, keyed by endpoint ID. Kotlin registers one entry
// per endpoint that carries 2FA (nativeSetTwoFactorForNode); a backend without
// an entry keeps none, so it never opens an auth stream. That is what lets one
// client talk to several servers with different secrets — the single global
// TWO_FACTOR above cannot express it.
pub(crate) static NODE_TWO_FACTOR: Lazy<Mutex<HashMap<String, NodeCredential>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// One-time enrollment tokens per backend, keyed by endpoint ID. An entry here means the
// endpoint has no credentials yet: the token is spent by the first connection, which comes
// back with the secret Kotlin then persists. Kept apart from NODE_TWO_FACTOR because a node
// holding a token must not present it as its TOTP secret.
//
// The token is a `SecretString`: an unspent invitation is a credential, and
// this table holds it for as long as the process lives.
pub(crate) static NODE_ENROLLMENT: Lazy<Mutex<HashMap<String, (String, SecretString)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// One device key per backend, keyed by endpoint ID.
//
// A key is the device's own credential rather than a copy of the server's: the
// private half never leaves the device and the server holds only the public
// one, so what Kotlin registers here is what an enrollment offers and what
// every later handshake signs with. Kept apart from `NODE_TWO_FACTOR` because
// the two travel together and mean different things — the credential record
// says *which* client and *which* device this is, the key says *how* it proves
// itself, and a node can have one without the other: a key with no device name
// yet is one that is about to enroll.
pub(crate) static NODE_DEVICE_KEYS: Lazy<Mutex<HashMap<String, iroh::SecretKey>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// The name this install answers as, injected once by Kotlin
/// (`nativeSetDeviceId`) rather than per credential.
///
/// One name for the whole install, because the device is the phone and not the
/// server. It names **enrollments only** — see `two_factor_auth` for why every
/// other credential answers unnamed — and it is set from its own entry point
/// rather than as one more argument on the calls that already exist, so a
/// Kotlin side that has never heard of devices keeps calling them as it does
/// and simply enrolls as the unnamed one.
pub(crate) static DEVICE_ID: Mutex<Option<String>> = Mutex::new(None);

// Generation counter: incremented each time nativeStopProxy releases the endpoint.
// nativeStartIroh compares this before/after bind(); if a stop happened in between, the late
// new endpoint is discarded to avoid a stray bind reviving an already-released tunnel.
pub(crate) static ENDPOINT_GEN: AtomicU64 = AtomicU64::new(0);

// System DNS servers passed down from Kotlin. iroh's internal JNI path for reading system DNS
// fails (Null pointer in call_method obj argument), and falling back to Google DNS is unstable
// domestically. Kotlin obtains these from ConnectivityManager.getLinkProperties().dnsServers
// and injects them; nativeStartIroh uses them to build the DnsResolver, bypassing iroh's
// broken JNI path.
pub(crate) static CUSTOM_DNS_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

// Pre-resolved IP overrides for iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link).
// The GFW drops UDP DNS responses for iroh.link domains, causing hickory resolution to time out.
// Kotlin pre-resolves these via the system DNS (which may use DoT/Private DNS to bypass the GFW)
// and passes them to Rust to store in this map. OverrideResolver returns the pre-resolved IPs for
// these domains directly; all other domains still go through hickory + the system DNS servers.
pub(crate) static DNS_OVERRIDES: Lazy<Mutex<HashMap<String, Vec<IpAddr>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Per-query timeout used when OverrideResolver delegates to DnsResolver.
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

// BoxFuture compatibility type, matching the return type of the iroh::dns::Resolver trait
// (n0_future::boxed::BoxFuture, i.e. futures_lite::future::Boxed =
// Pin<Box<dyn Future<Output = T> + Send + 'static>>).
// Must be 'static: the Future returned by Resolver methods cannot borrow self, so clone any
// needed data inside the method body.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type BoxIter<T> = Box<dyn Iterator<Item = T> + Send + 'static>;

// Per-stage timeouts. Discovery of STUN/relay/DNS can be slow on weak networks; these timeouts ensure we return failure instead of blocking forever when stuck.
const IROH_BIND_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
const START_PROXY_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);
const CLOSE_ALL_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(8);
/// Pre-connect / warm-up timeout for establishing iroh connections to all backends.
///
/// Derived from what the phase itself allows rather than written down: at a flat
/// 15s it left one second for a phase that may now spend fourteen, so a
/// start-up that legitimately used its budget was cancelled here instead of by
/// the pools that were still working. The slack covers setting the proxy up
/// around the probe.
const PRECONNECT_TIMEOUT: tokio::time::Duration =
    crate::endpoint_group::PRECONNECT_PHASE_CAP.saturating_add(tokio::time::Duration::from_secs(6));

// Why "pinned" exists at all, and why it is the default: iroh otherwise picks a home relay from
// the 4 N0 relays by latency, and here aps1-1 (Asia-Pacific) and euc1-1 (Europe) measure
// similarly, so iroh keeps flip-flopping between them. Each home-relay switch forces the
// connections routed through relay (WebSocket, etc.) to drop and reconnect. The URL itself is
// `crate::relay::PINNED_RELAY_URL`; DNS still pre-resolves aps1-1's IP on the Kotlin side via
// resolveIrohDnsOverrides and injects it into OverrideResolver.

// Relay configuration: mode and custom URL from Kotlin settings.
// "pinned" = aps1-1 (the default), "default" = iroh default (all N0 relays),
// "disabled" = no relay at all, "custom" = user-provided URL.
// An empty mode means nothing has been injected yet, which falls back to "pinned".
// A mode that is set but unusable is an error: see `crate::relay`.
pub(crate) static RELAY_MODE: Mutex<String> = Mutex::new(String::new());
pub(crate) static CUSTOM_RELAY_URL: Mutex<String> = Mutex::new(String::new());
// Bearer token for a `custom` relay that asks for one. Only ever read together with the two
// above; never logged.
//
// A `SecretString`, and a `Lazy` because a `Secret` cannot be built in a
// `static` initializer: the token is a credential, and it is wiped when the
// entry is replaced or the process ends.
pub(crate) static RELAY_AUTH_TOKEN: Lazy<Mutex<SecretString>> =
    Lazy::new(|| Mutex::new(SecretString::default()));

// Whether this endpoint may use n0's address lookup, from Kotlin settings.
// "n0" = the default (a Node ID is looked up through dns.iroh.link), "none" =
// no lookup at all, and a peer then has to bring an address of its own.
// An empty value means nothing has been injected yet, which falls back to "n0".
pub(crate) static DISCOVERY_MODE: Mutex<String> = Mutex::new(String::new());

// Reason behind the last failed native call, so Kotlin can read it back.
//
// The start entry points return a bare `jint` and therefore cannot carry a message. Without this
// the caller could not tell "the port is already in use" from "the configured node ID does not
// parse" and guessed the former for both: a malformed endpoint ID (e.g. 65 hex characters, an odd
// length) looked like a port conflict, burned 10 ports x 3 attempts, and finally reported
// "Failed to start proxy on ports 8080..8089" — a message that named neither the node nor the
// real cause.
pub(crate) static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Result code for a failure the caller must not retry: the configuration itself is wrong, so the
/// next port would fail identically, and [`LAST_ERROR`] holds a message meant for the user.
const RESULT_CONFIG_ERROR: jint = -2;

/// Reported when a backend accepted the connection and then refused it because
/// this client never performed the 2FA handshake. The credentials are missing
/// here, not on the server, so the message has to say where to add them.
const AUTH_REQUIRED_MESSAGE: &str =
    "the server requires 2FA, but this client has no 2FA credentials configured";

pub(crate) fn set_last_error(message: impl Into<String>) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = Some(message.into());
    }
}

pub(crate) fn clear_last_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

/// Runs `body` with a panic caught, turning one into `None`.
///
/// Unwinding out of an `extern "system"` frame is a native crash on Android,
/// not a Java exception, so every entry point that drives the runtime — and
/// that is most of them, since a start or a stop blocks on it — has to catch.
/// The entry points wrap their whole body in this and answer with whatever the
/// function returns on failure.
pub(crate) fn catching_panic<T, F>(what: &str, body: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    match panic::catch_unwind(panic::AssertUnwindSafe(body)) {
        Ok(value) => Some(value),
        Err(_) => {
            // `jni_log!` is a macro, so it is not in scope this early in the
            // file; this is the same call it would make.
            android_log(log::Level::Error, &format!("[WARN:jni] {what} panicked"));
            set_last_error(format!("{what} panicked"));
            None
        }
    }
}

pub(crate) fn take_last_error() -> Option<String> {
    match LAST_ERROR.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    }
}

/// Parse a node ID with the same parser the connection path uses.
///
/// Returns the parser's reason on failure. Checking up front means a bad ID is reported before any
/// port is bound, instead of surfacing as a bind failure from inside endpoint-group construction.
pub(crate) fn node_id_error(node_id: &str) -> Option<String> {
    node_id
        .parse::<iroh::EndpointId>()
        .err()
        .map(|e| e.to_string())
}

/// First configured endpoint that does not parse, as a message for the user.
///
/// Mirrors `parse_endpoint_addr` (which reads `server_node_id` first, then `server_ticket`), so a
/// problem is caught here — before any port is bound — instead of surfacing as a bind failure from
/// inside endpoint-group construction.
pub(crate) fn first_invalid_node_id(
    domain_mappings: &[DomainMapping],
    nodes: &[NodeConfig],
) -> Option<String> {
    for mapping in domain_mappings {
        if let Some(node_id) = mapping.server_node_id.as_deref()
            && let Some(reason) = node_id_error(node_id)
        {
            return Some(format!(
                "Invalid endpoint ID '{node_id}' for domain '{}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters.",
                mapping.domain
            ));
        }
    }
    for node in nodes {
        if let Some(node_id) = node.server_node_id.as_deref()
            && let Some(reason) = node_id_error(node_id)
        {
            return Some(format!(
                "Invalid endpoint ID '{node_id}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters."
            ));
        }
    }
    None
}

pub(crate) struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    nodes: Vec<NodeConfig>,
    domain_mappings: Vec<DomainMapping>,
    domains: Vec<String>,
    // TUN proxy (smoltcp user-space TCP/IP stack). Present only when the Android tun-proxy feature is enabled.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    tun_proxy: Option<TunProxy>,
}

pub(crate) fn get_runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_try_init(Runtime::new).ok()
}

pub(crate) fn get_endpoint() -> Option<Endpoint> {
    ENDPOINT.lock().ok()?.clone()
}

pub(crate) fn get_state() -> Option<&'static Arc<Mutex<ProxyState>>> {
    STATE.get()
}

pub(crate) fn init_state() -> &'static Arc<Mutex<ProxyState>> {
    STATE.get_or_init(|| {
        Arc::new(Mutex::new(ProxyState {
            conn_pool: None,
            endpoint_group: None,
            nodes: Vec::new(),
            domain_mappings: Vec::new(),
            domains: Vec::new(),
            #[cfg(all(feature = "tun-proxy", target_os = "android"))]
            tun_proxy: None,
        }))
    })
}

#[cfg(feature = "jni")]
#[cfg(target_os = "android")]
pub(crate) fn android_log(level: log::Level, msg: &str) {
    log::log!(level, "{}", msg);
}

#[cfg(feature = "jni")]
#[cfg(not(target_os = "android"))]
pub(crate) fn android_log(_level: log::Level, msg: &str) {
    eprintln!("{}", msg);
}

#[cfg(feature = "jni")]
#[inline]
pub fn debug_log_enabled() -> bool {
    log::log_enabled!(log::Level::Debug)
}

#[cfg(feature = "jni")]
#[inline]
pub fn debug_log(msg: &str) {
    android_log(log::Level::Debug, msg);
}

/// A warning the Android build can show.
///
/// The Android logger is installed at `Info`, so a `Debug` line is dropped
/// before it is ever formatted — and the Android build has no tracing
/// subscriber to fall back on. A warning nobody can read is not a warning,
/// so this one goes through the `log` crate at `Warn`.
#[cfg(feature = "jni")]
pub(crate) fn warn_log(msg: &str) {
    android_log(log::Level::Warn, msg);
}

/// A line of information the Android build can show, on the same terms as
/// [`warn_log`].
#[cfg(feature = "jni")]
pub(crate) fn info_log(msg: &str) {
    android_log(log::Level::Info, msg);
}

/// Debug log that is a no-op when the `log` level filter is below `Debug`.
///
/// The guard matters: without it every call site formatted its arguments into a `String`
/// before the level was ever consulted, so the proxy paid a heap allocation per packet even
/// with logging disabled.
#[cfg(feature = "jni")]
#[macro_export]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if $crate::jni::debug_log_enabled() {
            $crate::jni::debug_log(&format!($($arg)*))
        }
    };
}

/// Runs `body` with a temporary `Env`, answering `failure` when it failed or
/// panicked.
///
/// jni 0.22 hands the environment to a closure rather than handing it over, and
/// the `ErrorPolicy`s it ships with answer `Default` when that closure fails.
/// For a `jint` that is `0` — the value every entry point here returns for
/// success — so a panic would reach Kotlin as "started fine", which is worse
/// than the native crash it replaces. Failure is worth saying out loud, so the
/// value to answer with is passed in: -1, or a null string.
pub(crate) fn with_env_or<T, F>(unowned_env: &mut EnvUnowned<'_>, failure: T, body: F) -> T
where
    F: FnOnce(&mut Env<'_>) -> T,
{
    let outcome = unowned_env.with_env(|env| -> jni::errors::Result<T> { Ok(body(env)) });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(e) => {
            jni_log!("[WARN:jni] a JNI call failed: {e}");
            failure
        }
        Outcome::Panic(_) => {
            // The hook `nativeInit` installs has already logged the message and
            // the location. All this has to do is stop the unwind from leaving
            // the frame, which on Android is a native crash rather than
            // something the JVM can report.
            jni_log!("[WARN:jni] a native method panicked");
            // The reason is left behind as well: the entry points that answer
            // with a bare `jint` have nowhere else to put it, and the app
            // reads it back through `nativeTakeLastError`.
            set_last_error("a native method panicked");
            failure
        }
    }
}

/// Reads a Java string argument; None when it is null or not valid UTF-8.
pub(crate) fn read_jstring(env: &Env<'_>, s: &JString<'_>) -> Option<String> {
    s.try_to_string(env).ok()
}

/// The name this install answers as, if Kotlin gave it one.
///
/// An empty name is not a name: it is a field left blank, and sending it would
/// have the server refuse the handshake for a reason about printable ASCII
/// rather than about this side.
pub(crate) fn device_id() -> Option<String> {
    DEVICE_ID
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

// ============================================================
// The virtual block — the addresses the tunnel claims
// ============================================================

// ============================================================
// TUN proxy (smoltcp user-space TCP/IP stack) — Android tun-proxy feature only
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The two tests below share one global — the last error — so they take a
    /// turn rather than race over it.
    static LAST_ERROR_LOCK: Mutex<()> = Mutex::new(());

    /// An entry point whose body panics answers with the failure value
    /// instead of unwinding.
    ///
    /// Unwinding out of an `extern "system"` frame is a native crash on
    /// Android: the app goes down, not the one call. So the barrier an entry
    /// point puts around its body has to turn a panic into the value that
    /// entry point answers with — and this is that shape, with the body
    /// panicking on purpose.
    #[test]
    fn an_entry_point_whose_body_panics_answers_the_failure_value() {
        let _turn = LAST_ERROR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let code: jint = catching_panic("nativeStartProxy", || -> jint {
            panic!("the body panicked on purpose");
        })
        .unwrap_or(-1);

        assert_eq!(code, -1, "the failure value answers the panic");
    }

    /// A panic is not a value: `catching_panic` turns one into `None` and
    /// leaves the reason behind. The entry points that answer with a bare
    /// `jint` have nowhere else to put it, and the app reads it back through
    /// `nativeTakeLastError`.
    #[test]
    fn catching_panic_turns_a_panic_into_none_and_records_the_reason() {
        let _turn = LAST_ERROR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_last_error();

        let value = catching_panic("nativeStartProxy", || -> jint {
            panic!("the body panicked on purpose");
        });

        assert!(value.is_none(), "a panic is not a value");
        assert_eq!(
            take_last_error().as_deref(),
            Some("nativeStartProxy panicked"),
            "the reason is left behind for the app to read"
        );
    }
}
