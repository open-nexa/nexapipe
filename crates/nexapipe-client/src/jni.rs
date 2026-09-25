#[cfg(all(feature = "tun-proxy", target_os = "android"))]
use crate::tun_proxy::TunProxy;
use crate::auth::{Enrollment, TotpAlgorithm, TwoFactorAuth};
use crate::{
    DomainMapping, EndpointGroup, IrohConnectionPool, LoadBalancingStrategy, LocalProxy, NodeConfig,
};
use crate::relay::RelayModeSpec;
use iroh::dns::{DnsError, DnsProtocol, DnsResolver, Resolver, TxtRecordData};
use iroh::endpoint::presets;
use iroh::Endpoint;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use ndk_context;
use once_cell::sync::{Lazy, OnceCell};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static ENDPOINT: Mutex<Option<Endpoint>> = Mutex::new(None);
static STATE: OnceCell<Arc<Mutex<ProxyState>>> = OnceCell::new();
// 2FA config: Kotlin injects (client_id, secret, algorithm) via nativeSetTwoFactor before startup.
static TWO_FACTOR: Mutex<Option<(String, String, String)>> = Mutex::new(None);
// 2FA credentials per backend, keyed by endpoint ID. Kotlin registers one entry
// per endpoint that carries 2FA (nativeSetTwoFactorForNode); a backend without
// an entry keeps none, so it never opens an auth stream. That is what lets one
// client talk to several servers with different secrets — the single global
// TWO_FACTOR above cannot express it.
static NODE_TWO_FACTOR: Lazy<Mutex<HashMap<String, (String, String, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
// One-time enrollment tokens per backend, keyed by endpoint ID. An entry here means the
// endpoint has no credentials yet: the token is spent by the first connection, which comes
// back with the secret Kotlin then persists. Kept apart from NODE_TWO_FACTOR because a node
// holding a token must not present it as its TOTP secret.
static NODE_ENROLLMENT: Lazy<Mutex<HashMap<String, (String, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Generation counter: incremented each time nativeStopProxy releases the endpoint.
// nativeStartIroh compares this before/after bind(); if a stop happened in between, the late
// new endpoint is discarded to avoid a stray bind reviving an already-released tunnel.
static ENDPOINT_GEN: AtomicU64 = AtomicU64::new(0);

// System DNS servers passed down from Kotlin. iroh's internal JNI path for reading system DNS
// fails (Null pointer in call_method obj argument), and falling back to Google DNS is unstable
// domestically. Kotlin obtains these from ConnectivityManager.getLinkProperties().dnsServers
// and injects them; nativeStartIroh uses them to build the DnsResolver, bypassing iroh's
// broken JNI path.
static CUSTOM_DNS_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

// Pre-resolved IP overrides for iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link).
// The GFW drops UDP DNS responses for iroh.link domains, causing hickory resolution to time out.
// Kotlin pre-resolves these via the system DNS (which may use DoT/Private DNS to bypass the GFW)
// and passes them to Rust to store in this map. OverrideResolver returns the pre-resolved IPs for
// these domains directly; all other domains still go through hickory + the system DNS servers.
static DNS_OVERRIDES: Lazy<Mutex<HashMap<String, Vec<IpAddr>>>> =
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
const PROXY_RUN_JOIN_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_millis(500);
/// Pre-connect / warm-up timeout for establishing iroh connections to all backends.
const PRECONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(15);

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
static RELAY_MODE: Mutex<String> = Mutex::new(String::new());
static CUSTOM_RELAY_URL: Mutex<String> = Mutex::new(String::new());
// Bearer token for a `custom` relay that asks for one. Only ever read together with the two
// above; never logged.
static RELAY_AUTH_TOKEN: Mutex<String> = Mutex::new(String::new());

// Reason behind the last failed native call, so Kotlin can read it back.
//
// The start entry points return a bare `jint` and therefore cannot carry a message. Without this
// the caller could not tell "the port is already in use" from "the configured node ID does not
// parse" and guessed the former for both: a malformed endpoint ID (e.g. 65 hex characters, an odd
// length) looked like a port conflict, burned 10 ports x 3 attempts, and finally reported
// "Failed to start proxy on ports 8080..8089" — a message that named neither the node nor the
// real cause.
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Result code for a failure the caller must not retry: the configuration itself is wrong, so the
/// next port would fail identically, and [`LAST_ERROR`] holds a message meant for the user.
const RESULT_CONFIG_ERROR: jint = -2;

/// Reported when a backend accepted the connection and then refused it because
/// this client never performed the 2FA handshake. The credentials are missing
/// here, not on the server, so the message has to say where to add them.
const AUTH_REQUIRED_MESSAGE: &str =
    "the server requires 2FA, but this client has no 2FA credentials configured";

fn set_last_error(message: impl Into<String>) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

fn take_last_error() -> Option<String> {
    match LAST_ERROR.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    }
}

/// Parse a node ID with the same parser the connection path uses.
///
/// Returns the parser's reason on failure. Checking up front means a bad ID is reported before any
/// port is bound, instead of surfacing as a bind failure from inside endpoint-group construction.
fn node_id_error(node_id: &str) -> Option<String> {
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
fn first_invalid_node_id(domain_mappings: &[DomainMapping], nodes: &[NodeConfig]) -> Option<String> {
    for mapping in domain_mappings {
        if let Some(node_id) = mapping.server_node_id.as_deref() {
            if let Some(reason) = node_id_error(node_id) {
                return Some(format!(
                    "Invalid endpoint ID '{node_id}' for domain '{}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters.",
                    mapping.domain
                ));
            }
        }
    }
    for node in nodes {
        if let Some(node_id) = node.server_node_id.as_deref() {
            if let Some(reason) = node_id_error(node_id) {
                return Some(format!(
                    "Invalid endpoint ID '{node_id}': {reason}. \
                     Endpoint IDs are 64 hexadecimal characters."
                ));
            }
        }
    }
    None
}

struct ProxyState {
    conn_pool: Option<IrohConnectionPool>,
    endpoint_group: Option<Arc<EndpointGroup>>,
    local_proxy: Option<LocalProxy>,
    // Background proxy.run() task handle; aborted + awaited on stop for a deterministic port release.
    proxy_task: Option<JoinHandle<()>>,
    nodes: Vec<NodeConfig>,
    domain_mappings: Vec<DomainMapping>,
    domains: Vec<String>,
    // TUN proxy (smoltcp user-space TCP/IP stack). Present only when the Android tun-proxy feature is enabled.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    tun_proxy: Option<TunProxy>,
}

fn get_runtime() -> Option<&'static Runtime> {
    RUNTIME.get_or_try_init(|| Runtime::new()).ok()
}

fn get_endpoint() -> Option<Endpoint> {
    ENDPOINT.lock().ok()?.clone()
}

fn get_state() -> Option<&'static Arc<Mutex<ProxyState>>> {
    STATE.get()
}

fn init_state() -> &'static Arc<Mutex<ProxyState>> {
    STATE.get_or_init(|| {
        Arc::new(Mutex::new(ProxyState {
            conn_pool: None,
            endpoint_group: None,
            local_proxy: None,
            proxy_task: None,
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

/// Custom DNS Resolver that wraps the hickory resolver and returns pre-resolved IPs for specific domains.
///
/// The GFW drops UDP DNS responses for `iroh.link` domains, causing hickory resolution to time out.
/// This resolver returns Kotlin's pre-resolved IPs directly for domains in `DNS_OVERRIDES`
/// (Kotlin uses the system DNS, which may go through DoT/Private DNS to bypass the GFW); all other
/// domains still go through hickory.
struct OverrideResolver {
    inner: DnsResolver,
    overrides: HashMap<String, Vec<IpAddr>>,
    nameservers: Vec<SocketAddr>,
}

impl OverrideResolver {
    fn new(nameservers: Vec<SocketAddr>, overrides: HashMap<String, Vec<IpAddr>>) -> Self {
        let inner = if nameservers.is_empty() {
            DnsResolver::new()
        } else {
            DnsResolver::builder()
                .with_nameservers(nameservers.iter().map(|a| (*a, DnsProtocol::Udp)))
                .build()
        };
        Self {
            inner,
            overrides,
            nameservers,
        }
    }
}

impl fmt::Debug for OverrideResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverrideResolver")
            .field(
                "override_domains",
                &self.overrides.keys().collect::<Vec<_>>(),
            )
            .field("nameservers", &self.nameservers)
            .finish()
    }
}

impl Resolver for OverrideResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        if let Some(ips) = self.overrides.get(&host) {
            let ipv4s: Vec<Ipv4Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                })
                .collect();
            if !ipv4s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv4 addrs",
                    host,
                    ipv4s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv4(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv4s: Vec<Ipv4Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        if let Some(ips) = self.overrides.get(&host) {
            let ipv6s: Vec<Ipv6Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(*v6),
                    _ => None,
                })
                .collect();
            if !ipv6s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv6 addrs",
                    host,
                    ipv6s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv6(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv6s: Vec<Ipv6Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_txt(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let v: Vec<TxtRecordData> = result.collect();
            Ok(Box::new(v.into_iter()) as BoxIter<TxtRecordData>)
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(OverrideResolver::new(
            self.nameservers.clone(),
            self.overrides.clone(),
        ))
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(
    env: JNIEnv,
    _class: JClass,
) -> jint {
    #[cfg(target_os = "android")]
    {
        unsafe {
            let raw_env = env.get_raw();
            let mut raw_vm = std::ptr::null_mut();
            (**raw_env).GetJavaVM.unwrap()(raw_env, &mut raw_vm);
            ndk_context::initialize_android_context(raw_vm as *mut _, std::ptr::null_mut());
        }
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("NexaVpnService"),
        );
    }

    std::panic::set_hook(Box::new(|panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        let location = panic_info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        jni_log!("RUST PANIC: {}{}", msg, location);
    }));

    // Four workers left two cores idle on every modern phone and made the TUN pump,
    // the QUIC driver and the smoltcp runner compete for the same threads. Scale with the
    // device instead, but keep a floor (4) and a ceiling (8) so a 16-core phone does not
    // spread the data path across enough threads to hurt cache locality.
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 8);
    let rt = Builder::new_multi_thread()
        .thread_name("nexapipe-worker")
        .worker_threads(worker_threads)
        .enable_all()
        .build();
    jni_log!(
        "[DEBUG:jni] tokio runtime worker_threads={}",
        worker_threads
    );

    match rt {
        Ok(rt) => {
            let _ = RUNTIME.set(rt);
        }
        Err(e) => {
            jni_log!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    }
    let _ = init_state();
    0
}

/// Kotlin obtains the system DNS from ConnectivityManager.getLinkProperties().dnsServers and
/// passes it as a comma-separated IP string (e.g. "192.168.1.1,8.8.8.8"). This function parses it
/// into SocketAddr (port fixed to 53, UDP) and stores it in CUSTOM_DNS_SERVERS. nativeStartIroh
/// reads it before bind. Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsServers(
    mut env: JNIEnv,
    _class: JClass,
    dns_servers: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetDnsServers");
        env.exception_clear().unwrap();
        return -1;
    }

    let dns_str = match env.get_string(&dns_servers) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert DNS servers string to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get DNS servers string from JNI");
            return -1;
        }
    };

    // Parse the comma-separated IP list. Kotlin passes bare IPs (no port), so we always append port 53.
    let servers: Vec<SocketAddr> = dns_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeSetDnsServers: parsed {} servers from '{}'",
        servers.len(),
        dns_str
    );

    match CUSTOM_DNS_SERVERS.lock() {
        Ok(mut guard) => {
            *guard = servers;
        }
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS mutex");
            return -1;
        }
    }
    0
}

/// Kotlin pre-resolves iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link) via the
/// system DNS (which may use DoT/Private DNS to bypass the GFW) and passes them in the format
/// "domain=ip1,ip2;domain2=ip3,ip4". This function parses and stores them in DNS_OVERRIDES.
/// OverrideResolver returns the pre-resolved IPs directly for these domains, bypassing hickory's
/// UDP DNS queries (the GFW drops UDP DNS responses for iroh.link domains).
/// This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/<z32>) reach iroh's pkarr server and fetch
/// the target node's EndpointInfo (relay URL + direct addr), even if DNS TXT is blocked by the GFW.
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsOverride(
    mut env: JNIEnv,
    _class: JClass,
    overrides: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetDnsOverride");
        env.exception_clear().unwrap();
        return -1;
    }

    let overrides_str = match env.get_string(&overrides) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert DNS overrides string to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get DNS overrides string from JNI");
            return -1;
        }
    };

    // Parse the "domain=ip1,ip2;domain2=ip3,ip4" format.
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in overrides_str.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '=');
        let domain = match parts.next() {
            Some(d) => d.trim().to_lowercase(),
            None => continue,
        };
        if domain.is_empty() {
            continue;
        }
        let ips_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let ips: Vec<IpAddr> = ips_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        if ips.is_empty() {
            jni_log!(
                "[DEBUG:jni] nativeSetDnsOverride: no valid IPs for domain '{}'",
                domain
            );
            continue;
        }
        jni_log!(
            "[DEBUG:jni] nativeSetDnsOverride: {} -> {} IPs {:?}",
            domain,
            ips.len(),
            ips
        );
        map.insert(domain, ips);
    }

    jni_log!(
        "[DEBUG:jni] nativeSetDnsOverride: parsed {} override entries from '{}'",
        map.len(),
        overrides_str
    );

    match DNS_OVERRIDES.lock() {
        Ok(mut guard) => {
            *guard = map;
        }
        Err(_) => {
            jni_log!("Failed to lock DNS_OVERRIDES mutex");
            return -1;
        }
    }
    0
}

/// Configure the relay mode, custom URL and, for a relay that asks for one, the bearer token.
/// relay_mode: "pinned"/"default"/"disabled"/"custom". relay_url and relay_auth_token are only
/// used when relay_mode="custom".
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetRelayConfig(
    mut env: JNIEnv,
    _class: JClass,
    relay_mode: JString,
    relay_url: JString,
    relay_auth_token: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetRelayConfig");
        env.exception_clear().unwrap();
        return -1;
    }

    let mode_str = match env.get_string(&relay_mode) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert relay_mode string to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get relay_mode string from JNI");
            return -1;
        }
    };

    let url_str = match env.get_string(&relay_url) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    };

    let token_str = match env.get_string(&relay_auth_token) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    };

    jni_log!(
        "[DEBUG:jni] nativeSetRelayConfig: mode='{}', url='{}', auth_token={}",
        mode_str,
        url_str,
        if token_str.is_empty() { "none" } else { "set" }
    );

    if let Ok(mut mode) = RELAY_MODE.lock() {
        *mode = mode_str;
    }
    if let Ok(mut url) = CUSTOM_RELAY_URL.lock() {
        *url = url_str;
    }
    if let Ok(mut token) = RELAY_AUTH_TOKEN.lock() {
        *token = token_str;
    }
    0
}

/// Reads a Java string argument; None when it is null or not valid UTF-8.
fn read_jstring(env: &mut JNIEnv, s: &JString) -> Option<String> {
    env.get_string(s).ok().and_then(|j| match j.to_str() {
        Ok(s) => Some(s.to_string()),
        Err(_) => None,
    })
}

/// Builds a [`TwoFactorAuth`] from a stored (client id, secret, algorithm) triple.
///
/// An empty secret means "no 2FA", which is how an endpoint that was never
/// given credentials — or whose credentials were cleared — is represented.
fn two_factor_auth(cfg: &(String, String, String)) -> Option<TwoFactorAuth> {
    let (client_id, secret, algorithm) = cfg;
    if secret.trim().is_empty() {
        return None;
    }
    match TwoFactorAuth::new(client_id, secret, TotpAlgorithm::from_name(algorithm)) {
        Ok(auth) => Some(auth),
        Err(e) => {
            jni_log!("2FA auth config invalid: {}", e);
            None
        }
    }
}

/// Read the 2FA credentials injected by Kotlin and build a TwoFactorAuth; returns None when unset or secret is empty.
fn current_two_factor_auth() -> Option<TwoFactorAuth> {
    let cfg = TWO_FACTOR.lock().map(|g| g.clone()).unwrap_or_default()?;
    two_factor_auth(&cfg)
}

/// A snapshot of the per-endpoint credentials, so the mutex is not held across
/// the async calls that apply them.
fn node_two_factor_snapshot() -> Vec<(String, (String, String, String))> {
    match NODE_TWO_FACTOR.lock() {
        Ok(map) => map
            .iter()
            .map(|(id, cfg)| (id.clone(), cfg.clone()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The credentials registered for one endpoint, if any.
fn node_two_factor_for(node_id: &str) -> Option<(String, String, String)> {
    NODE_TWO_FACTOR
        .lock()
        .ok()
        .and_then(|map| map.get(node_id).cloned())
}

/// A snapshot of the per-endpoint enrollment tokens, so the mutex is not held across the
/// async calls that apply them.
fn node_enrollment_snapshot() -> Vec<(String, (String, String))> {
    match NODE_ENROLLMENT.lock() {
        Ok(map) => map
            .iter()
            .map(|(id, cfg)| (id.clone(), cfg.clone()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The enrollment token registered for one endpoint, if any.
fn node_enrollment_for(node_id: &str) -> Option<(String, String)> {
    NODE_ENROLLMENT
        .lock()
        .ok()
        .and_then(|map| map.get(node_id).cloned())
}

/// Configure the client's 2FA credentials. Must be called before nativeStartProxy /
/// nativeStartProxyLegacy. algorithm: "sha1" / "sha256" / "sha512".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetTwoFactor(
    mut env: JNIEnv,
    _class: JClass,
    client_id: JString,
    secret: JString,
    algorithm: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetTwoFactor");
        env.exception_clear().unwrap();
        return -1;
    }

    let client_id = match read_jstring(&mut env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetTwoFactor");
            return -1;
        }
    };
    let secret = read_jstring(&mut env, &secret).unwrap_or_default();
    let algorithm = read_jstring(&mut env, &algorithm).unwrap_or_else(|| "sha1".to_string());

    jni_log!(
        "[DEBUG:jni] nativeSetTwoFactor: client_id='{}', algorithm='{}', secret={} chars",
        client_id,
        algorithm,
        secret.len()
    );

    if let Ok(mut tf) = TWO_FACTOR.lock() {
        *tf = Some((client_id, secret, algorithm));
    }
    0
}

/// Configure the 2FA credentials of a single endpoint.
///
/// node_id:   endpoint ID these credentials belong to.
/// client_id: must match the ID configured in that server's [auth.clients].
/// secret:    Base32-encoded TOTP key (generated by `nexapipe --generate-2fa`).
/// algorithm: "sha1" / "sha256" / "sha512".
///
/// Only the pools of that backend get the credentials; every other endpoint is
/// left alone, so servers that do not share a secret — or that have 2FA turned
/// off altogether — stay reachable. Call `nativeClearNodeTwoFactor` first when
/// re-reading the configuration, otherwise credentials of an endpoint that no
/// longer has any are still applied.
///
/// Must be called before nativeStartProxy / nativeStartProxyLegacy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetTwoFactorForNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    client_id: JString,
    secret: JString,
    algorithm: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetTwoFactorForNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id = match read_jstring(&mut env, &node_id) {
        Some(v) => v.trim().to_string(),
        None => {
            jni_log!("Failed to read node_id in nativeSetTwoFactorForNode");
            return -1;
        }
    };
    let client_id = match read_jstring(&mut env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetTwoFactorForNode");
            return -1;
        }
    };
    let secret = read_jstring(&mut env, &secret).unwrap_or_default();
    let algorithm = read_jstring(&mut env, &algorithm).unwrap_or_else(|| "sha1".to_string());

    if node_id.is_empty() {
        jni_log!("nativeSetTwoFactorForNode: empty node_id");
        return -1;
    }

    jni_log!(
        "[DEBUG:jni] nativeSetTwoFactorForNode: node='{}', client_id='{}', algorithm='{}', secret={} chars",
        node_id,
        client_id,
        algorithm,
        secret.len()
    );

    if let Ok(mut map) = NODE_TWO_FACTOR.lock() {
        map.insert(node_id, (client_id, secret, algorithm));
    }
    0
}

/// Drops every credential registered with `nativeSetTwoFactorForNode`.
///
/// Read the configuration back through this pair on every connect: without the
/// clear, an endpoint whose 2FA the user just turned off would keep the old
/// credentials for the lifetime of the process and keep opening auth streams
/// the server no longer expects.
/// Registers a one-time enrollment token for a single endpoint.
///
/// node_id:   endpoint ID the token belongs to.
/// client_id: which `[auth.clients]` entry the token is pending for.
/// token:     the token itself, as carried by a `v=2` invite.
///
/// The first connection to that endpoint spends it and answers with the real secret; see
/// `nativeTakeIssuedCredential` for what Kotlin has to do with the answer. A node that
/// already has credentials keeps them and never enrolls, so a token is only ever set for
/// an endpoint that has none.
///
/// Must be called before nativeStartProxy / nativeStartProxyLegacy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetEnrollmentForNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    client_id: JString,
    token: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeSetEnrollmentForNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id = match read_jstring(&mut env, &node_id) {
        Some(v) => v.trim().to_string(),
        None => {
            jni_log!("Failed to read node_id in nativeSetEnrollmentForNode");
            return -1;
        }
    };
    let client_id = match read_jstring(&mut env, &client_id) {
        Some(v) => v,
        None => {
            jni_log!("Failed to read client_id in nativeSetEnrollmentForNode");
            return -1;
        }
    };
    let token = read_jstring(&mut env, &token).unwrap_or_default();

    if node_id.is_empty() {
        jni_log!("nativeSetEnrollmentForNode: empty node_id");
        return -1;
    }

    jni_log!(
        "[DEBUG:jni] nativeSetEnrollmentForNode: node='{}', client_id='{}', token={} chars",
        node_id,
        client_id,
        token.len()
    );

    if let Ok(mut map) = NODE_ENROLLMENT.lock() {
        map.insert(node_id, (client_id, token));
    }
    0
}

/// Drops every credential — and every enrollment token — registered per endpoint.
///
/// The token table rides along on purpose: the two are the same question ("how does this
/// endpoint authenticate?"), and reading the configuration back through one call is what
/// keeps a stale entry from applying to a node that no longer has one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodeTwoFactor(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    if let Ok(mut map) = NODE_TWO_FACTOR.lock() {
        map.clear();
    }
    if let Ok(mut map) = NODE_ENROLLMENT.lock() {
        map.clear();
    }
    0
}

/// The credential the server issued for an enrollment token, cleared on read.
///
/// `client_id`, `secret` and `algorithm`, newline separated, or null when this run enrolled
/// nothing. Spending a token rotates that client's secret server-side, so this is the only
/// chance to read what it bought: without it the device holds an invite the server has
/// already forgotten and cannot enroll again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTakeIssuedCredential(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let issued = runtime.block_on(async {
        // The endpoint group is where a start with several nodes keeps its pools; the
        // single-pool legacy path keeps the same answer one level down.
        if let Some(state) = get_state() {
            let group = {
                let guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => return None,
                };
                guard.endpoint_group.clone()
            };
            if let Some(group) = group {
                if let Some(issued) = group.take_issued_credential().await {
                    return Some(issued);
                }
            }
            let pool = {
                let guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => return None,
                };
                guard.conn_pool.clone()
            };
            if let Some(pool) = pool {
                return pool.take_issued_credential().await;
            }
        }
        None
    });

    let Some(issued) = issued else {
        return std::ptr::null_mut();
    };
    let encoded = format!(
        "{}\n{}\n{}",
        issued.client_id, issued.secret, issued.algorithm
    );
    match env.new_string(encoded) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartIroh");
        env.exception_clear().unwrap();
        return std::ptr::null_mut();
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    // Fast path: if an endpoint already exists, return immediately. Holds the lock briefly without crossing any await.
    {
        if let Ok(guard) = ENDPOINT.lock() {
            if let Some(ep) = guard.as_ref() {
                let id = ep.id().to_string();
                return match env.new_string(id) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        }
    }

    // Don't hold the ENDPOINT lock during bind() to avoid deadlocking with nativeStopProxy.
    let gen_before = ENDPOINT_GEN.load(Ordering::Acquire);

    // Read the system DNS servers injected by Kotlin plus the pre-resolved iroh infrastructure IPs.
    // Hold the lock briefly to clone, then release immediately, without crossing await.
    let custom_dns: Vec<SocketAddr> = CUSTOM_DNS_SERVERS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let dns_overrides: HashMap<String, Vec<IpAddr>> =
        DNS_OVERRIDES.lock().map(|g| g.clone()).unwrap_or_default();

    let bind_result: Result<Endpoint, ()> = runtime.block_on(async move {
        // Read the relay config injected by Kotlin (set by nativeSetRelayConfig).
        // An empty mode means Kotlin has not injected one yet -> "pinned", which is what the
        // UI defaults to. Anything else either resolves or is a hard error; no mode is ever
        // silently substituted for the one that was asked for.
        let cfg_mode = RELAY_MODE.lock().map(|g| g.clone()).unwrap_or_default();
        let cfg_url = CUSTOM_RELAY_URL
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let cfg_token = RELAY_AUTH_TOKEN
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let relay = match RelayModeSpec::parse(Some(&cfg_mode), Some(&cfg_url), Some(&cfg_token)) {
            Ok(spec) => spec.unwrap_or(RelayModeSpec::Pinned),
            Err(e) => {
                jni_log!("[iroh] invalid relay configuration: {e}");
                return Err(());
            }
        };
        if !relay.uses_url() && !cfg_url.is_empty() {
            jni_log!(
                "[iroh] ignoring relay_url {:?}: mode {} does not use one",
                cfg_url,
                cfg_mode
            );
        }
        jni_log!("[iroh] relay: {}", relay.describe());
        let builder = Endpoint::builder(presets::N0).relay_mode(relay.relay_mode());
        // Always wrap hickory with OverrideResolver:
        // - For iroh infrastructure domains in DNS_OVERRIDES (dns.iroh.link, *.relay.n0.iroh.link),
        //   return Kotlin's pre-resolved IPs directly, bypassing the GFW's blocking of iroh.link
        //   UDP DNS responses. This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/<z32>) reach the
        //   pkarr server and fetch the target node's EndpointInfo; relay domains can also reach the
        //   relay server.
        // - All other domains go through hickory + the system DNS servers (custom_dns).
        //   Even if custom_dns is empty, OverrideResolver internally falls back to DnsResolver::new().
        jni_log!(
            "[DEBUG:jni] Building OverrideResolver: {} DNS servers, {} override domains {:?}",
            custom_dns.len(),
            dns_overrides.len(),
            dns_overrides.keys().collect::<Vec<_>>()
        );
        let override_resolver = OverrideResolver::new(custom_dns.clone(), dns_overrides);
        let dns_resolver = DnsResolver::custom(override_resolver);
        // One inner TCP connection == one QUIC bi-stream, so the per-stream receive window is
        // the throughput ceiling of every proxied connection. iroh's 1.25 MB default caps a
        // 200 ms path at roughly 50 Mbps; see crate::transport for the full rationale.
        let (transport, tuning) = crate::transport::transport_config_with_tuning();
        jni_log!("[DEBUG:jni] QUIC transport tuning: {}", tuning.describe());
        let builder = builder
            .dns_resolver(dns_resolver)
            .transport_config(transport);

        match tokio::time::timeout(IROH_BIND_TIMEOUT, builder.bind()).await {
            Ok(Ok(ep)) => Ok(ep),
            Ok(Err(e)) => {
                jni_log!("Failed to start iroh endpoint: {}", e);
                Err(())
            }
            Err(_) => {
                jni_log!(
                    "iroh endpoint bind timed out after {}s",
                    IROH_BIND_TIMEOUT.as_secs()
                );
                Err(())
            }
        }
    });
    let ep = match bind_result {
        Ok(ep) => ep,
        Err(()) => return std::ptr::null_mut(),
    };

    // Re-lock to commit: if a stop happened in between (generation changed), discard the late endpoint;
    // if a concurrent startIroh already wrote one, return its id; otherwise write our own.
    let node_id = match ENDPOINT.lock() {
        Ok(mut guard) => {
            let gen_now = ENDPOINT_GEN.load(Ordering::Acquire);
            if gen_now != gen_before {
                jni_log!("endpoint generation changed during bind, discarding late endpoint");
                drop(ep); // Stray late result of an isolated bind: discard it; don't revive a released tunnel.
                return std::ptr::null_mut();
            }
            if let Some(existing) = guard.as_ref() {
                existing.id().to_string()
            } else {
                let id = ep.id().to_string();
                *guard = Some(ep);
                id
            }
        }
        Err(_) => {
            jni_log!("Failed to lock endpoint mutex on commit");
            return std::ptr::null_mut();
        }
    };

    match env.new_string(node_id) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxy(
    env: JNIEnv,
    _class: JClass,
    listen_port: jint,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxy");
        env.exception_clear().unwrap();
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            set_last_error("Native runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            set_last_error("Native state not initialized");
            return -1;
        }
    };

    let nodes: Vec<NodeConfig>;
    let domain_mappings: Vec<DomainMapping>;

    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        nodes = guard.nodes.clone();
        domain_mappings = guard.domain_mappings.clone();
    }

    // Pre-flight: every configured endpoint ID must parse. Checked before anything is bound, so a
    // malformed ID is reported as a malformed ID (and not retried as if the port were taken).
    if let Some(message) = first_invalid_node_id(&domain_mappings, &nodes) {
        jni_log!("[DEBUG:jni] nativeStartProxy rejected: {}", message);
        set_last_error(message);
        return RESULT_CONFIG_ERROR;
    }
    clear_last_error();

    let listen_addr = format!("127.0.0.1:{}", listen_port);
    jni_log!(
        "[DEBUG:jni] nativeStartProxy called for port {}",
        listen_port
    );

    // Fail fast: refuse to continue when there is no endpoint. Otherwise we'd fall into the
    // "one bind() per node" branch (connection_pool.rs, no timeout, scales with backend count) and
    // reintroduce the hang.
    let ep = match get_endpoint() {
        Some(ep) => ep,
        None => {
            jni_log!("[DEBUG:jni] No iroh endpoint available; call nativeStartIroh first");
            set_last_error("No iroh endpoint available; call nativeStartIroh first");
            return -1;
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let endpoint_group: EndpointGroup;
            let proxy_domains: Vec<String>;

            if !domain_mappings.is_empty() {
                jni_log!(
                    "[DEBUG:jni] Using domain_mappings ({} entries)",
                    domain_mappings.len()
                );
                proxy_domains = domain_mappings.iter().map(|m| m.domain.clone()).collect();

                endpoint_group = match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_domain_mappings_and_endpoint(
                        domain_mappings,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                };
            } else if !nodes.is_empty() {
                jni_log!("[DEBUG:jni] Using nodes ({} entries)", nodes.len());
                proxy_domains = nodes
                    .iter()
                    .flat_map(|node| node.domains.iter().cloned())
                    .collect();

                if proxy_domains.is_empty() {
                    jni_log!("No domains configured for nodes");
                    return Err("No domains configured for nodes".to_string());
                }

                endpoint_group = match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_nodes_and_endpoint(
                        nodes,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                };
            } else {
                jni_log!("No nodes or domain mappings configured");
                return Err("No nodes or domain mappings configured".to_string());
            }

            // 2FA: push the Kotlin-injected credentials to the connection group; new connections run the auth handshake first.
            // The global pair goes to every pool first, then each endpoint's own
            // credentials override it. An endpoint with no entry of its own —
            // and an empty secret counts as an explicit "none" — ends up with
            // no credentials, so it never opens an auth stream against a server
            // that does not expect one.
            if let Some(auth) = current_two_factor_auth() {
                endpoint_group.set_two_factor(Some(auth)).await;
            }
            for (node_id, cfg) in node_two_factor_snapshot() {
                endpoint_group
                    .set_two_factor_for(&node_id, two_factor_auth(&cfg))
                    .await;
            }
            // Enrollment last, and only where no credentials were registered: enrolling
            // rotates that client's secret, so a node that already has one must not spend a
            // token again — every other device enrolled from the same code would be locked
            // out by it.
            for (node_id, (client_id, token)) in node_enrollment_snapshot() {
                if node_two_factor_for(&node_id).is_some() {
                    continue;
                }
                endpoint_group
                    .set_enrollment_for(&node_id, Some(Enrollment::new(&client_id, &token)))
                    .await;
                jni_log!("[DEBUG:jni] enrollment armed for node '{}'", node_id);
            }

            jni_log!("[DEBUG:jni] Creating LocalProxy on {}", listen_addr);
            let endpoint_group_arc = Arc::new(endpoint_group);
            let proxy = match tokio::time::timeout(
                START_PROXY_TIMEOUT,
                LocalProxy::new(&listen_addr, proxy_domains, endpoint_group_arc.clone()),
            )
            .await
            {
                Ok(Ok(p)) => {
                    jni_log!("[DEBUG:jni] LocalProxy created successfully");
                    p
                }
                Ok(Err(e)) => {
                    jni_log!("[DEBUG:jni] Failed to create local proxy: {}", e);
                    return Err(format!("Failed to create local proxy: {}", e));
                }
                Err(_) => {
                    jni_log!(
                        "[DEBUG:jni] LocalProxy creation timed out after {}s",
                        START_PROXY_TIMEOUT.as_secs()
                    );
                    return Err("LocalProxy creation timed out".to_string());
                }
            };

            // Clone one copy for the background task; keep the original proxy in state.
            let proxy_for_run = proxy.clone();
            let join_handle = runtime.spawn(async move {
                let proxy_run = match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                    proxy_for_run.run().await
                })) {
                    Ok(future) => future,
                    Err(_) => {
                        jni_log!("Proxy run panicked during setup");
                        return;
                    }
                };
                match proxy_run.await {
                    Err(e) => jni_log!("Proxy run failed: {}", e),
                    Ok(_) => jni_log!("Proxy run completed"),
                }
            });

            // Write back to state: re-lock and verify it wasn't cleared by a concurrent stop, then store the JoinHandle for deterministic cleanup.
            {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        jni_log!("Failed to lock state mutex (poisoned)");
                        return Err("Failed to update state".to_string());
                    }
                };
                if guard.local_proxy.is_some() || guard.proxy_task.is_some() {
                    jni_log!(
                        "[DEBUG:jni] State already has a proxy (concurrent start/stop), aborting"
                    );
                    // Abort the just-started task to avoid leaking it.
                    join_handle.abort();
                    return Err("Proxy already running".to_string());
                }
                guard.local_proxy = Some(proxy);
                guard.endpoint_group = Some(endpoint_group_arc);
                guard.proxy_task = Some(join_handle);
            }

            Ok(())
        })
    }));

    match result {
        Ok(Ok(_)) => {
            jni_log!("[DEBUG:jni] nativeStartProxy returning success");
            0
        }
        Ok(Err(e)) => {
            jni_log!("[DEBUG:jni] Proxy start error: {}", e);
            let code = if e.contains("Parse error") || e.contains("No nodes or domain mappings") {
                RESULT_CONFIG_ERROR
            } else {
                -1
            };
            set_last_error(e);
            code
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during proxy start");
            set_last_error("Native proxy start panicked");
            -1
        }
    }
}

/// Returns the reason behind the last failed native call, and clears it.
///
/// The start entry points return only an int, so this is how Kotlin learns what actually went
/// wrong (a malformed node ID, an occupied port, ...). Returns null when there is nothing to
/// report.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTakeLastError(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let message = match take_last_error() {
        Some(message) => message,
        None => return std::ptr::null_mut(),
    };
    match env.new_string(message) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Validates a node ID with the exact parser the connection path uses.
///
/// Returns null when it parses, otherwise the parser's reason. Callers use this for pre-flight
/// checks and to give immediate feedback while the user edits a node.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeValidateNodeId(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
) -> jstring {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeValidateNodeId");
        env.exception_clear().ok();
        return std::ptr::null_mut();
    }

    let node_id = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        },
        Err(_) => return std::ptr::null_mut(),
    };

    let reason = match node_id_error(node_id.trim()) {
        Some(reason) => reason,
        None => return std::ptr::null_mut(),
    };

    match env.new_string(reason) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Pre-connect / warm-up: establish one iroh connection per configured backend
/// and cache it in the connection pool, so the first real request does not pay
/// the QUIC/relay handshake latency. Must be called after `nativeStartProxy`
/// (which creates the `EndpointGroup`). Returns the number of backends warmed,
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativePreconnect(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativePreconnect called");

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: state not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativePreconnect: failed to lock state (poisoned)");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!(
                    "[DEBUG:jni] nativePreconnect: endpoint_group is None - call nativeStartProxy first"
                );
                return -1;
            }
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move {
            match tokio::time::timeout(PRECONNECT_TIMEOUT, endpoint_group.preconnect_report()).await
            {
                Ok(report) => {
                    // A backend that answered and then refused the connection
                    // for missing 2FA is counted as unreachable, which on its
                    // own reads like "server down". Say what actually happened:
                    // the credentials are missing on this side.
                    if report.any_auth_required() && !report.any_reachable() {
                        jni_log!("[DEBUG:jni] nativePreconnect: backend requires 2FA");
                        set_last_error(AUTH_REQUIRED_MESSAGE);
                    }
                    report.reachable.len() as jint
                }
                Err(_) => {
                    jni_log!("[DEBUG:jni] nativePreconnect timed out");
                    -1
                }
            }
        })
    }));

    match result {
        Ok(count) => {
            jni_log!(
                "[DEBUG:jni] nativePreconnect finished: {} backend(s) warmed",
                count
            );
            count
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativePreconnect");
            -1
        }
    }
}

/// How each configured backend is currently reached: one `<endpointId>=<kind>` pair per
/// backend, joined with `;`, where `kind` is `direct`, `relay` or `unknown`.
///
/// This is the *runtime* answer, read off the paths iroh actually selected — not the relay URL
/// from the configuration, which only names a relay that may be used. A backend that has never
/// connected reports `unknown`.
///
/// Returns null when there is no endpoint group yet (nothing was started), so Kotlin can tell
/// "nothing to report" from "asked and answered".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeLinkKinds(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => return std::ptr::null_mut(),
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.link_kinds().await })
    }));

    let kinds = match result {
        Ok(kinds) => kinds,
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeLinkKinds");
            return std::ptr::null_mut();
        }
    };

    let encoded = kinds
        .iter()
        .map(|(id, kind)| format!("{}={}", id, kind.as_str()))
        .collect::<Vec<_>>()
        .join(";");

    jni_log!("[DEBUG:jni] nativeLinkKinds: {}", encoded);

    match env.new_string(encoded) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Closes and forgets every cached backend connection, keeping the iroh endpoint.
///
/// This is the Android network-switch recovery step. A connection opened on the previous
/// network is not closed as far as QUIC is concerned — its `close_reason()` is still `None`
/// while its path is dead — so the pool keeps handing it out and every proxied request fails
/// or hangs, even though the tunnel itself was rebuilt correctly. Dropping them makes the next
/// request dial on the current network; `nativePreconnect` then fills the pool again.
///
/// The endpoint is deliberately left alone: it is shared with the running TUN proxy, and
/// rebinding it would pull a working tunnel apart.
///
/// Returns 0 when the connections were dropped, -1 when nothing has been started yet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDropConnections(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativeDropConnections: runtime not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: state not initialized");
                return -1;
            }
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativeDropConnections: failed to lock state");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: no endpoint group yet");
                return -1;
            }
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.drop_connections().await })
    }));

    match result {
        Ok(()) => {
            jni_log!("[DEBUG:jni] nativeDropConnections: dropped every cached connection");
            0
        }
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeDropConnections");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxyLegacy(
    mut env: JNIEnv,
    _class: JClass,
    listen_port: jint,
    target_endpoint_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartProxyLegacy");
        env.exception_clear().unwrap();
        return -1;
    }

    let target_id = match env.get_string(&target_endpoint_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert target endpoint ID to string");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get target endpoint ID from JNI");
            return -1;
        }
    };

    if target_id.is_empty() {
        jni_log!("Target endpoint ID is empty");
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    let domains: Vec<String> = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        guard.domains.clone()
    };

    let listen_addr = format!("127.0.0.1:{}", listen_port);

    let result = runtime.block_on(async move {
        match crate::connection_pool::parse_endpoint_addr(Some(&target_id), None) {
            Ok(addr) => {
                let pool: IrohConnectionPool;
                if let Some(ep) = get_endpoint() {
                    pool = IrohConnectionPool::new_with_endpoint(ep.clone(), addr);
                } else {
                    match IrohConnectionPool::new(addr).await {
                        Ok(p) => pool = p,
                        Err(e) => {
                            jni_log!("Failed to create connection pool: {}", e);
                            return Err(format!("Failed to create connection pool: {}", e));
                        }
                    }
                }

                // 2FA: push the Kotlin-injected credentials to the connection pool; new connections run the auth handshake first.
                if let Some(auth) = current_two_factor_auth() {
                    pool.set_two_factor(Some(auth)).await;
                }
                // Per-endpoint credentials win over the global pair, and a node that has
                // them never enrolls: enrolling rotates the secret out from under every
                // other device that scanned the same code.
                let credentials = node_two_factor_for(&target_id);
                if let Some(cfg) = &credentials {
                    pool.set_two_factor(two_factor_auth(cfg)).await;
                }
                if credentials.is_none() {
                    if let Some((client_id, token)) = node_enrollment_for(&target_id) {
                        pool.set_enrollment(Some(Enrollment::new(&client_id, &token)))
                            .await;
                        jni_log!("[DEBUG:jni] enrollment armed for node '{}'", target_id);
                    }
                }

                match LocalProxy::new_with_single_pool(&listen_addr, domains, pool.clone()).await {
                    Ok(proxy) => {
                        {
                            let mut guard = match state.lock() {
                                Ok(g) => g,
                                Err(_) => {
                                    jni_log!("Failed to lock state mutex (poisoned)");
                                    return Err("Failed to update state".to_string());
                                }
                            };
                            guard.conn_pool = Some(pool);
                        }

                        tokio::spawn(async move {
                            let proxy_run =
                                match panic::catch_unwind(panic::AssertUnwindSafe(|| async move {
                                    proxy.run().await
                                })) {
                                    Ok(future) => future,
                                    Err(_) => {
                                        jni_log!("Proxy run panicked during setup");
                                        return;
                                    }
                                };
                            match proxy_run.await {
                                Err(e) => jni_log!("Proxy run failed: {}", e),
                                Ok(_) => jni_log!("Proxy run completed"),
                            }
                        });

                        Ok(())
                    }
                    Err(e) => {
                        jni_log!("Failed to create local proxy: {}", e);
                        Err(format!("Failed to create local proxy: {}", e))
                    }
                }
            }
            Err(e) => {
                jni_log!("Failed to parse endpoint address: {}", e);
                Err(format!("Failed to parse endpoint address: {}", e))
            }
        }
    });

    match result {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeStopProxy called (proxy-only, keeping iroh endpoint)");

    // Note: this function only stops local_proxy / endpoint_group / conn_pool / proxy_task,
    // and does not touch the global ENDPOINT. This way startProxyWithRetries can call it before
    // rebinding the port without tearing down the endpoint that ensureIrohStarted already built.
    // For a full teardown (including the endpoint), use nativeDestroy.
    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    // Phase 1.5: stop the TUN proxy first (must happen before endpoint_group.close_all()).
    // The TUN proxy's TCP connection tasks hold an Arc<EndpointGroup> clone; closing first would
    // make them access an already-closed connection pool. shutdown() aborts and waits for the
    // tasks to finish, ensuring the fd is closed.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    {
        let tun_proxy = {
            let mut guard = match state.lock() {
                Ok(g) => g,
                Err(_) => {
                    jni_log!("[DEBUG:jni] Failed to lock state for tun_proxy cleanup");
                    return 0;
                }
            };
            guard.tun_proxy.take()
        }; // guard dropped
        if let Some(tp) = tun_proxy {
            if let Some(r) = get_runtime() {
                tp.shutdown(r);
                jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
            } else {
            // No runtime — just abort; Drop will call stop().
            jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            }
            // tp dropped here (if not consumed by shutdown)
        }
    }

    // Phase 2: lock state, take the resources out (fields set to None), drop the guard immediately, then enter any block_on.
    let (local_proxy, endpoint_group, conn_pool, proxy_task) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] Failed to lock state, aborting stop");
                return 0;
            }
        };
        jni_log!(
            "[DEBUG:jni] Stop: endpoint_group exists = {}, conn_pool exists = {}, local_proxy exists = {}, proxy_task exists = {}",
            guard.endpoint_group.is_some(),
            guard.conn_pool.is_some(),
            guard.local_proxy.is_some(),
            guard.proxy_task.is_some()
        );
        (
            guard.local_proxy.take(),
            guard.endpoint_group.take(),
            guard.conn_pool.take(),
            guard.proxy_task.take(),
        )
    }; // guard dropped here -- no longer holding the state lock.

    let runtime = get_runtime();

    // Phase 3a: signal proxy.run() to exit (AtomicBool).
    if let Some(proxy) = local_proxy.as_ref() {
        proxy.stop();
        jni_log!("[DEBUG:jni] LocalProxy stopped");
    }

    // Phase 3b: abort + await the background task for a deterministic port release (no longer relying on 100ms polling).
    if let Some(handle) = proxy_task {
        handle.abort();
        if let Some(r) = runtime {
            let _ = r.block_on(async {
                let _ = tokio::time::timeout(PROXY_RUN_JOIN_TIMEOUT, handle).await;
            });
        }
        jni_log!("[DEBUG:jni] Proxy task joined/aborted");
    }

    // Phase 3c: close the endpoint group / pool, each with its own timeout, without holding the state lock.
    if let Some(r) = runtime {
        if let Some(group) = endpoint_group.as_ref() {
            let _ = r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, group.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] endpoint_group close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] endpoint_group close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
        if let Some(pool) = conn_pool.as_ref() {
            let _ = r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, pool.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] conn_pool close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] conn_pool close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
    }

    jni_log!("[DEBUG:jni] nativeStopProxy returning after cleanup");
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    domains: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let domains_str = match env.get_string(&domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let domains_list: Vec<String> = domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if domains_list.is_empty() {
        jni_log!("Warning: Domains list is empty for node: {}", node_id_str);
    }

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let node_config = NodeConfig {
        server_node_id: Some(node_id_str),
        server_ticket: None,
        domains: domains_list,
    };

    guard.nodes.push(node_config);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomainMapping(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomainMapping");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let domain_mapping = DomainMapping {
        domain: domain_str,
        server_node_id: Some(node_id_str),
        server_ticket: None,
    };

    guard.domain_mappings.push(domain_mapping);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveNode(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveNode");
        env.exception_clear().unwrap();
        return -1;
    }

    let node_id_str = match env.get_string(&node_id) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard
        .nodes
        .retain(|n| n.server_node_id.as_deref() != Some(&node_id_str));
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodes(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let state = match get_state() {
        Some(s) => s,
        None => return 0,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    guard.nodes.clear();
    guard.domain_mappings.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeAddDomain");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.domains.contains(&domain_str) {
        guard.domains.push(domain_str);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeRemoveDomain");
        env.exception_clear().unwrap();
        return -1;
    }

    let domain_str = match env.get_string(&domain) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        },
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.domains.retain(|d| d != &domain_str);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeDestroy called (full teardown: endpoint + proxy)");
    // Phase 1: briefly lock ENDPOINT, bump the generation and take the endpoint out so the next
    // nativeStartIroh rebuilds it. nativeStartIroh's bind() doesn't hold the ENDPOINT lock, so this
    // won't deadlock against startIroh.
    let endpoint = {
        if let Ok(mut guard) = ENDPOINT.lock() {
            ENDPOINT_GEN.fetch_add(1, Ordering::AcqRel);
            let ep = guard.take();
            jni_log!(
                "[DEBUG:jni] Endpoint released (generation bumped), present={}",
                ep.is_some()
            );
            ep
        } else {
            jni_log!("[DEBUG:jni] Failed to lock ENDPOINT, continuing with proxy cleanup");
            None
        }
    };
    // Phase 2+3: stop the local proxy / endpoint_group / conn_pool / proxy_task (without touching ENDPOINT).
    let result = Java_com_nexa_pipe_IrohProxy_nativeStopProxy(_env, _class);

    // Phase 4: explicitly close the endpoint. conn_pool.close_all() now only closes the pool's own
    // endpoint (new()); the shared global endpoint is closed here.
    if let Some(ep) = endpoint {
        if let Some(r) = get_runtime() {
            let _ = r.block_on(async {
                let _ = tokio::time::timeout(CLOSE_ALL_TIMEOUT, ep.close()).await;
            });
            jni_log!("[DEBUG:jni] Endpoint closed");
        }
    }
    result
}

// ============================================================
// TUN proxy (smoltcp user-space TCP/IP stack) — Android tun-proxy feature only
// ============================================================

/// Start the TUN proxy: process the TUN fd's TCP/UDP traffic on the Rust side with smoltcp.
///
/// Must be called after `nativeStartProxy` (endpoint_group already created) and after the VPN is
/// established. Kotlin transfers fd ownership to Rust via `ParcelFileDescriptor.detachFd()`.
///
/// Arguments:
/// - `tun_fd`: the TUN file descriptor (return value of detachFd)
/// - `proxy_domains`: comma-separated list of proxied domains
///
/// Returns 0 on success, -1 on failure.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
) -> jint {
    if env.exception_check().unwrap_or(false) {
        jni_log!("JNI exception pending before nativeStartTunProxy");
        env.exception_clear().unwrap();
        return -1;
    }

    // Parse the proxied domains (comma-separated).
    let proxy_domains_str = match env.get_string(&proxy_domains) {
        Ok(s) => match s.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                jni_log!("Failed to convert proxy_domains to UTF-8");
                return -1;
            }
        },
        Err(_) => {
            jni_log!("Failed to get proxy_domains string from JNI");
            return -1;
        }
    };
    let proxy_domains_list: Vec<String> = proxy_domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeStartTunProxy: fd={}, proxy_domains={} items",
        tun_fd,
        proxy_domains_list.len()
    );

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    // Clone the endpoint_group from ProxyState (created by nativeStartProxy).
    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for endpoint_group");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] endpoint_group is None — nativeStartProxy not called yet?");
                return -1;
            }
        }
    };

    // Read the system DNS server list (set by nativeSetDnsServers).
    let custom_dns_servers = match CUSTOM_DNS_SERVERS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS");
            return -1;
        }
    };

    // Check whether a tun_proxy is already running.
    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy check");
                return -1;
            }
        };
        if guard.tun_proxy.is_some() {
            jni_log!("[DEBUG:jni] TUN proxy already running, stopping old one first");
            drop(guard);
            let _ = Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(env, _class);
        }
    }

    // Enter the runtime context (TunProxy::new spawns tasks via tokio::spawn internally).
    let _enter_guard = runtime.enter();

    let tun_proxy = match TunProxy::new(
        tun_fd as std::os::fd::RawFd,
        endpoint_group,
        proxy_domains_list,
        custom_dns_servers,
    ) {
        Ok(tp) => tp,
        Err(e) => {
            jni_log!("[DEBUG:jni] Failed to create TUN proxy: {}", e);
            return -1;
        }
    };

    // Store it in ProxyState.
    {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy storage");
                // tun_proxy dropped → stop() called → tasks aborted + fd closed
                return -1;
            }
        };
        guard.tun_proxy = Some(tun_proxy);
    }

    jni_log!("[DEBUG:jni] nativeStartTunProxy returning success");
    0
}

/// Stop the TUN proxy: abort all background tasks and close the dup'd fd.
///
/// Called by `NexaVpnService.stopVPN()` before closing the TUN fd.
/// `nativeDestroy` also reaches it indirectly via `nativeStopProxy` (Phase 1.5).
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    jni_log!("[DEBUG:jni] nativeStopTunProxy called");

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    let tun_proxy = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] Failed to lock state for tun_proxy stop");
                return 0;
            }
        };
        guard.tun_proxy.take()
    }; // guard dropped

    if let Some(tp) = tun_proxy {
        if let Some(r) = get_runtime() {
            tp.shutdown(r);
            jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
        } else {
            jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            // tp dropped here → stop() called via Drop
        }
    } else {
        jni_log!("[DEBUG:jni] No TUN proxy to stop");
    }

    0
}
