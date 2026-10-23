use crate::auth::ClientAcl;
use crate::config::{BackendProtocol, CircuitBreaker, Retry, RouteMode, Timeouts};
use crate::lb::{BackendLease, BackendPool, LoadBalancingStrategy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// The one host-matching rule, and the one place it lives.
//
// It is in `nexapipe-proto` rather than here because the client library links
// the same crate and has to answer the same question: the client decides
// which names it proxies, the server decides which names a route serves, and
// a name the two spell differently is a name the client tunnels and the
// server has no route for. The rule and the drift it replaced are written up
// in `nexapipe_proto::host`.
pub(crate) use nexapipe_proto::{host_matches, normalize_host, normalize_pattern, pattern_error};

/// The host a `Host` header names, with the port taken off.
///
/// `split(':')` is wrong for IPv6 twice over: `[::1]:8080` yields `[`, and a
/// bare `::1` yields the empty string. Either way the host matches no route
/// and every request to it 404s. A bracketed literal keeps its brackets here;
/// [`normalize_host`] drops them.
pub(crate) fn host_without_port(host: &str) -> &str {
    host_and_port(host).0
}

/// The host a `Host` header names, and the port it names if it names one.
///
/// The port is `None` when the header names none: the request did not say
/// which port it wanted, and the proxy routes by host alone, so there is no
/// port to hold against the client that asked.
///
/// Split off the same way [`host_without_port`] takes the port off, so the two
/// cannot disagree about where the host ends.
pub(crate) fn host_and_port(host: &str) -> (&str, Option<u16>) {
    // The rule lives in `nexapipe-proto`, which the client links too: the
    // server routes by what this says and the client decides whether to
    // tunnel by what this says, and the two cannot disagree about where the
    // host ends.
    nexapipe_proto::host_and_port(host)
}

/// The most a path is allowed to add to [`Route::priority`], so that length
/// breaks ties between two routes instead of deciding the winner outright.
const PATH_LENGTH_TIE_BREAK: u32 = 99;

/// The extra knobs only `tcp` / `udp` routes have.
///
/// Kept out of [`Route::new`] so that the many HTTP and passthrough call sites — and
/// their tests — do not have to name two fields they will never use.
#[derive(Debug, Clone, Default)]
pub struct L4Options {
    /// Client ports this route accepts. `None` accepts every port. Only a selector:
    /// it never changes the address that is dialled.
    pub client_ports: Option<Vec<u16>>,
    /// Silence after which a UDP flow is closed. `None` means the server default.
    pub idle_timeout: Option<Duration>,
    /// How long one flow may run before it is closed. `None` means the server
    /// default.
    ///
    /// Separate from `idle_timeout` because the two bound different things: the
    /// idle one is the *gap* between packets and re-arms on each one, which is
    /// what a UDP flow needs, while this one is the whole flow. A peer that
    /// sends one packet just before each idle expiry keeps a flow alive with the
    /// idle bound alone, so the flow is also bounded as a whole.
    ///
    /// Raise it for a long-lived session over the tunnel — an interactive SSH
    /// connection or a database session is meant to outlive any default here.
    pub flow_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct Route {
    host_pattern: String,
    path_pattern: String,
    path_is_prefix: bool,
    /// Every mode this route serves, in declaration order.
    ///
    /// More than one is the ordinary case for a host that has to answer both a
    /// request and a tunnel: the same `backends` serve whichever of these the
    /// connection turned out to be. Which one a *connection* gets is still
    /// decided before matching, by its first byte.
    modes: Vec<RouteMode>,
    backend_pool: Arc<BackendPool>,
    /// The wire protocol the backends of this route are spoken to.
    ///
    /// Part of the route rather than of the pool, because it is a property of
    /// the hop to the backend and every backend of a route is reached the same
    /// way. See [`crate::config::BackendProtocol`].
    backend_protocol: BackendProtocol,
    path_rewrite: Option<String>,
    l4: L4Options,
}

impl Route {
    // A plain constructor mirroring the `[proxy.routes]` schema in config.toml.
    // Bundling the fields into a params struct would just move the argument list
    // somewhere else, so the lint is silenced here instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_pattern: &str,
        path_pattern: &str,
        path_is_prefix: bool,
        backends: Vec<String>,
        strategy: LoadBalancingStrategy,
        mode: RouteMode,
        path_rewrite: Option<String>,
    ) -> Self {
        Route {
            // The pattern is folded as a pattern, not as a host: a spelling
            // that would fold into the catch-all keeps its own shape, so a
            // route can never end up serving every host.
            host_pattern: normalize_pattern(host_pattern).into_owned(),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            modes: vec![mode],
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            backend_protocol: BackendProtocol::default(),
            path_rewrite,
            l4: L4Options::default(),
        }
    }

    /// Speak to this route's backends with this protocol.
    ///
    /// A builder rather than another constructor argument: the protocol is
    /// about the hop to the backend, and a route that does not name one speaks
    /// HTTP/1.1 — which is what the default says.
    pub fn with_backend_protocol(mut self, protocol: BackendProtocol) -> Self {
        self.backend_protocol = protocol;
        self
    }

    /// Serve several modes from one route instead of one.
    ///
    /// Replaces rather than extends, because the caller (the config parser) has
    /// already merged what the file said; duplicates collapse, so `mode = "http"`
    /// together with `modes = ["http", "tcp"]` is not two entries. An empty list
    /// is ignored: a route serving nothing would be a silent hole in the table,
    /// and the constructor has already given it exactly one mode.
    pub fn with_modes(mut self, modes: Vec<RouteMode>) -> Self {
        let mut merged: Vec<RouteMode> = Vec::with_capacity(modes.len());
        for mode in modes {
            if !merged.contains(&mode) {
                merged.push(mode);
            }
        }
        if !merged.is_empty() {
            self.modes = merged;
        }
        self
    }

    /// Attach the `tcp` / `udp` knobs. A no-op for the other modes, which have no
    /// use for them.
    pub fn with_l4_options(mut self, options: L4Options) -> Self {
        self.l4 = options;
        self
    }

    /// Host-only match, after [`normalize_host`] has folded both sides.
    ///
    /// The TLS passthrough path selects on SNI, i.e. before a request line
    /// exists, so there is no path to match against.
    pub fn matches_host(&self, host: &str) -> bool {
        self.serves_host(&normalize_host(host))
    }

    /// Host-only match against a host the caller has **already folded**.
    ///
    /// The routes are walked one after another, and every one of them was
    /// folding the same name again — once per route, for every request. The
    /// fold is the caller's, done once for the whole walk.
    pub fn serves_host(&self, host: &str) -> bool {
        host_matches(&self.host_pattern, host)
    }

    /// Match for an L4 flow: the host, plus the optional client-port allow list.
    ///
    /// `client_ports` only decides whether *this* route answers. Where the connection
    /// is then dialled is entirely the route's `backends`, so a client cannot use the
    /// list to steer the tunnel somewhere else.
    pub fn matches_l4(&self, host: &str, port: u16) -> bool {
        self.serves_l4(&normalize_host(host), port)
    }

    /// Match for an L4 flow, against a host the caller has **already folded**.
    ///
    /// The fold is the caller's, done once for the whole walk — see
    /// [`Self::serves_host`]. The port rule lives here, once: the walk calls
    /// this, and [`Self::matches_l4`] is this with the fold put back in, so a
    /// change to the rule cannot leave one of the two behind.
    pub fn serves_l4(&self, host: &str, port: u16) -> bool {
        if !self.serves_host(host) {
            return false;
        }
        match &self.l4.client_ports {
            Some(allowed) => allowed.contains(&port),
            None => true,
        }
    }

    /// `udp` routes only: how long a flow may sit idle.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.l4.idle_timeout
    }

    /// How long one flow on this route may run, if the route says.
    pub fn flow_timeout(&self) -> Option<Duration> {
        self.l4.flow_timeout
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.serves_request(&normalize_host(host), path)
    }

    /// The match, against a host the caller has **already folded**.
    ///
    /// The fold is the caller's, done once for the whole walk — see
    /// [`Self::serves_host`].
    pub fn serves_request(&self, host: &str, path: &str) -> bool {
        // The host first, and the path only if the host matched: the path is
        // the more expensive half, and a route whose host does not match must
        // not pay for it. Before the fold moved out here the path was
        // compared eagerly for every route, so this order is a change and not
        // the preservation of one.
        if !self.serves_host(host) {
            return false;
        }

        if self.path_is_prefix {
            path_suffix(&self.path_pattern, path).is_some()
        } else {
            path == self.path_pattern
        }
    }

    /// How specific this route is; `best_match` keeps the highest.
    ///
    /// Tiers, not a sum: each one is worth strictly more than everything below
    /// it can add up to. They used to be one number, so a `path_pattern` longer
    /// than 101 characters outweighed an exact host — a route written for `*`
    /// with a long path outranked the route written for the host itself, and
    /// nothing in the logs said so.
    pub fn priority(&self) -> u32 {
        // Three tiers, not two: the bare `*` matches everything, so it has to
        // lose to a `*.suffix` wildcard, which loses to an exact name. Two
        // tiers put the catch-all and a wildcard in the same one, and a tie
        // goes to whichever was declared first — the declaration-order outcome
        // this function exists to rule out.
        let host = if self.host_pattern == "*" {
            0
        } else if self.host_pattern.starts_with('*') {
            1
        } else {
            2
        };
        // Naming the ports it serves makes an L4 route more specific than one
        // that takes every port for the same host. Without this tier,
        // "port 443" and "any port" scored the same and the first one declared
        // won for good, leaving the other route unreachable.
        let ports = u32::from(self.l4.client_ports.is_some());
        let path = u32::from(!self.path_is_prefix);
        // Longest path wins between two otherwise equal routes, which is the
        // point of a prefix match — but only as a tie-break, so it is capped.
        let length = (self.path_pattern.len() as u32).min(PATH_LENGTH_TIE_BREAK);

        host * 10_000 + ports * 1_000 + path * 100 + length
    }

    pub fn host_pattern(&self) -> &str {
        &self.host_pattern
    }

    pub fn path_pattern(&self) -> &str {
        &self.path_pattern
    }

    pub fn path_is_prefix(&self) -> bool {
        self.path_is_prefix
    }

    /// Every mode this route serves, in declaration order.
    pub fn modes(&self) -> &[RouteMode] {
        &self.modes
    }

    /// Whether this route takes part in `mode`'s lookup.
    ///
    /// A route may serve several modes, and which one a connection gets is
    /// decided earlier — by its first byte — so this is a membership test, not a
    /// choice between alternatives.
    pub fn serves(&self, mode: RouteMode) -> bool {
        self.modes.contains(&mode)
    }

    pub fn backend_pool(&self) -> &Arc<BackendPool> {
        &self.backend_pool
    }

    /// The wire protocol this route's backends are spoken to.
    pub fn backend_protocol(&self) -> BackendProtocol {
        self.backend_protocol
    }

    /// Run the circuit on this route's backends with these settings.
    ///
    /// A builder rather than a constructor argument: a pool built in code —
    /// in a test, or by the local proxy — has no circuit, and one built from a
    /// config has the settings the config resolved to.
    pub fn with_circuit_breaker(self, breaker: CircuitBreaker) -> Self {
        self.backend_pool.set_circuit_breaker(breaker);
        self
    }

    /// What makes this the same route across a reload, for the two things that
    /// hang off it: its backend pool and the health probe watching that pool.
    ///
    /// A host alone does not identify a route — two may share one and differ in
    /// path or in the modes they serve, and each carries its own pool. The
    /// backends are part of the key because a pool *is* its backends: change
    /// them and the old pool is no longer the one traffic goes through, even
    /// though the route looks the same.
    pub async fn pool_key(&self) -> String {
        // The strategy is part of what a pool *is*: a pool that hands requests
        // out round-robin and one that picks at random are not the same object,
        // and reusing the first for a route that now asks for the second makes
        // an edit to the config do nothing — silently, and with nothing in the
        // logs to suggest why.
        format!(
            "{}|{}|{:?}|{:?}|{:?}",
            self.host_pattern,
            self.path_pattern,
            self.modes,
            self.backend_pool.strategy(),
            self.backend_pool.backends().await
        )
    }

    pub fn path_rewrite(&self) -> &Option<String> {
        &self.path_rewrite
    }
}

#[derive(Debug, Clone)]
/// What looking up a backend can come back with.
///
/// Two of the three carry nothing, and they are not the same nothing:
///
/// - [`Self::NoRoute`] — this proxy does not serve that name. A **routing**
///   answer: "forward this host" was never configured, so the fix is in
///   `[[routes]]`.
/// - [`Self::Unavailable`] — the name is served, and every backend behind it is
///   currently unhealthy. An **operations** answer: routing is correct and
///   something downstream is down.
///
/// Collapsing the second into the first would be the expensive mistake: the
/// proxy would answer `404` for a healthy route whose backends died, and whoever
/// is reading those codes goes looking in the one file that is already right.
/// That is why this exists rather than `Option`.
pub enum BackendLookup<T> {
    NoRoute,
    Unavailable,
    Found(T),
}

impl<T> BackendLookup<T> {
    /// The backend, and only when there is one to forward to.
    ///
    /// Both refusals map to `None`, so this is the first choice for anything
    /// about the request. A caller that needs to answer them differently asks
    /// [`Self::reason`].
    pub fn backend(self) -> Option<T> {
        match self {
            BackendLookup::Found(value) => Some(value),
            BackendLookup::NoRoute | BackendLookup::Unavailable => None,
        }
    }

    /// Borrowed version of [`Self::backend`].
    pub fn found(&self) -> Option<&T> {
        match self {
            BackendLookup::Found(value) => Some(value),
            BackendLookup::NoRoute | BackendLookup::Unavailable => None,
        }
    }

    pub fn is_found(&self) -> bool {
        self.found().is_some()
    }

    /// `true` when this is a routing question rather than an outage — nothing
    /// here serves that name.
    ///
    /// Ask for this one in a test rather than [`Self::is_not_found`] whenever
    /// what is being pinned is "no route": the two refusals both mean "no
    /// backend", and leaving them collapsed is how a test that used to say "no
    /// route matches" quietly starts passing because the pool was marked down.
    pub fn is_no_route(&self) -> bool {
        matches!(self, BackendLookup::NoRoute)
    }

    /// `true` when there is nothing to forward to, for either reason.
    pub fn is_not_found(&self) -> bool {
        !self.is_found()
    }

    /// Which refusal this is, for a caller that answers them differently.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            BackendLookup::Found(_) => None,
            BackendLookup::NoRoute => Some("no route matches"),
            BackendLookup::Unavailable => Some("no healthy backend behind the route"),
        }
    }
}

pub struct BackendInfo {
    /// The backend's address.
    ///
    /// Shared, so that a request does not copy it: the address belongs to the
    /// pool and does not change.
    pub url: Arc<str>,
    /// The scheme, the host and the port of the address, ready to be joined
    /// to a path.
    ///
    /// Parsed **once**, when the pool was built — a backend does not move,
    /// and parsing it per request is a measurable share of what a request
    /// costs. The error is kept rather than thrown, so that the request path
    /// is where it is reported.
    pub origin: Result<Arc<str>, String>,
    /// The wire protocol this backend is to be spoken to.
    ///
    /// Carried with the address because it is the other half of "where this
    /// request goes": the same address is reached differently depending on
    /// what the route says, and a caller that picked the backend has to pick
    /// the client with it.
    pub protocol: BackendProtocol,
    pub path_rewrite: Option<String>,
    pub path_pattern: String,
    pub path_is_prefix: bool,
    /// Alive for exactly as long as this request is outstanding against that
    /// backend: dropping it is what releases the backend's slot in the balancer,
    /// so nothing reads this field — moving it along with the requests is the
    /// whole point. See [`crate::lb::BackendLease`].
    ///
    /// Taken rather than borrowed, because the work against a backend is not
    /// over when the response head arrives: a body that is still streaming is
    /// a backend that is still busy, and the caller that owns the body is the
    /// one that has to keep the lease until it is dropped.
    _lease: Option<BackendLease>,
}

impl BackendInfo {
    /// Takes the lease out, so the caller can hold it for as long as the work
    /// lasts.
    ///
    /// The lease counts the backend as busy until it is dropped, and the work
    /// is not over when the response head is in: the body may still be
    /// streaming. A caller that keeps the lease with the body is what makes
    /// `least_conn` count what is really in flight.
    pub fn take_lease(&mut self) -> Option<BackendLease> {
        self._lease.take()
    }

    /// The backend answered.
    ///
    /// What the circuit counts. A backend that answers is a backend that is
    /// up, however long it took.
    pub fn report_success(&self) {
        if let Some(lease) = &self._lease {
            lease.record_success();
        }
    }

    /// The backend did not answer.
    ///
    /// What the circuit counts. Only the failures that say the backend is
    /// unreachable are counted — a response that broke halfway says something
    /// else, and the backend did answer.
    pub fn report_failure(&self) {
        if let Some(lease) = &self._lease {
            lease.record_failure();
        }
    }

    /// The path this request is forwarded with, after the route's rewrite.
    ///
    /// A route may say "the paths under `/api` are served as `/v2`", by
    /// pairing a `path_pattern` with a `path_rewrite` that holds a `{}` where
    /// the matched part goes. A request whose path does not match the pattern
    /// is forwarded unchanged.
    ///
    /// The rule lives here, on the one type that carries the three things it
    /// needs, because it used to live in two places and be applied in one of
    /// them. The plaintext listener rewrote the path; the tunnel path did not,
    /// and a route that named a rewrite looked configured and worked against
    /// `curl` and did nothing for every real client.
    pub fn rewritten_path(&self, original_path: &str) -> String {
        let Some(rewrite_pattern) = &self.path_rewrite else {
            return original_path.to_string();
        };
        if self.path_is_prefix {
            // The same predicate the match uses, so the suffix that comes off
            // the front is the one that matched.
            if let Some(suffix) = path_suffix(&self.path_pattern, original_path) {
                return rewrite_pattern.replace("{}", suffix);
            }
        } else if original_path == self.path_pattern {
            return rewrite_pattern.replace("{}", "");
        }
        original_path.to_string()
    }
}

/// The part of `path` that `pattern` does not cover, if it covers any of it.
///
/// A path prefix in the **path** sense: the pattern covers the path when the
/// path is the pattern, or when it continues with a `/`. So `/api` covers
/// `/api` and `/api/x`, and not `/apifoo` — which is what `starts_with` alone
/// would say, and what a path prefix is not.
///
/// The pattern's own trailing slash is normalised away, so `/api/` covers the
/// same paths as `/api` and the path does not need a second slash to match.
///
/// The suffix is what the pattern did not cover, so it is the same string
/// whether the path matched exactly or continued past the pattern — which is
/// what makes the rewrite and the match agree.
///
/// One function, because the match and the rewrite have to agree: a prefix
/// that is not a prefix is a routing surprise either way.
pub(crate) fn path_suffix<'a>(pattern: &str, path: &'a str) -> Option<&'a str> {
    let pattern = pattern.trim_end_matches('/');
    if path == pattern {
        return Some("");
    }
    let rest = path.strip_prefix(pattern)?;
    // Only a segment boundary counts: `/apifoo` is not under `/api`. The
    // separator stays in the suffix: it is part of what the pattern did not
    // cover, and a rewrite of `/v2{}` wants `/v2/users`, not `/v2users`.
    rest.strip_prefix('/')?;
    Some(rest)
}

/// What the L4 tunnel needs in order to serve one flow.
pub struct L4RouteInfo {
    /// The address to dial, and the only address involved: the route decides
    /// it, the client cannot. See [`RoutingTable::get_l4_backend`].
    pub backend: String,
    /// `udp` routes only; `None` means the caller's own default.
    pub idle_timeout: Option<Duration>,
    /// `tcp` and `udp` routes; `None` means the caller's own default.
    ///
    /// How long the whole flow may run, as against the gap between packets that
    /// `idle_timeout` bounds. Separate because a peer can keep a flow alive
    /// forever by sending one packet before each idle expiry.
    pub flow_timeout: Option<Duration>,
    /// Held until this flow finishes, so the balancer knows the slot is still
    /// taken. Nothing reads it; see [`BackendInfo::_lease`].
    _lease: BackendLease,
}

// Hand-written rather than derived, because the lease it carries cannot be
// cloned — it is a count of one — and a `Debug` that printed it would print a
// different number every time someone looked.
impl std::fmt::Debug for L4RouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4RouteInfo")
            .field("backend", &self.backend)
            .field("idle_timeout", &self.idle_timeout)
            .field("flow_timeout", &self.flow_timeout)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// The routing table.
    ///
    /// **The routes are shared.** A lookup that found a route used to copy it
    /// out of the table — three strings and a vector, so four or five heap
    /// allocations for every request that matched — and the copy was thrown
    /// away as soon as the backend was picked. A reference count is the whole
    /// of what a table entry needs to be passed around.
    routes: Arc<RwLock<Vec<Arc<Route>>>>,
    /// How long to wait on a backend, resolved once at startup.
    ///
    /// Held here rather than threaded down to each stream handler because this
    /// object is what every one of them already receives — routing and the
    /// deadlines its choices are carried out under arrive together, so there is
    /// no third thing for every call site in `conn` to remember to pass. It is
    /// not part of the routing table and a reload leaves it alone: changing a
    /// timeout takes a restart, like every key outside `[[routes]]`.
    timeouts: Timeouts,
    /// How often a failed request is tried again, and on which backend.
    ///
    /// Held here rather than threaded down to each handler because this object
    /// is what every one of them already receives, for the same reason the
    /// deadlines are: routing and the rules its choices are carried out under
    /// arrive together. A reload leaves it alone, like every key outside
    /// `[[routes]]`.
    retry: Retry,
}

impl RoutingTable {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts: Timeouts::default(),
            retry: Retry::default(),
        }
    }

    /// A table whose flows wait on these deadlines rather than the defaults.
    ///
    /// The only construction that matters outside a test: defaults exist so a
    /// table built anywhere else — the local proxy, the tests — behaves exactly
    /// as it did before this field existed.
    pub fn with_timeouts(routes: Vec<Route>, timeouts: Timeouts) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts,
            retry: Retry::default(),
        }
    }

    /// A table whose flows wait on these deadlines and retry like this.
    ///
    /// The only construction that matters outside a test: defaults exist so a
    /// table built anywhere else — the local proxy, the tests — behaves exactly
    /// as it did before this field existed.
    pub fn with_settings(routes: Vec<Route>, timeouts: Timeouts, retry: Retry) -> Self {
        Self {
            routes: Arc::new(RwLock::new(shared(routes))),
            timeouts,
            retry,
        }
    }

    /// The deadlines a flow reaching through this table waits on.
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// How often a request that failed is tried again.
    pub fn retry(&self) -> Retry {
        self.retry
    }

    /// Backend for an HTTP request. Callers answer
    /// [`BackendLookup::NoRoute`] with `404` and [`BackendLookup::Unavailable`]
    /// with `503` — see the enum for why the two are not one answer.
    pub async fn get_backend(&self, host: &str, path: &str) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl(host, path, None, None).await
    }

    /// [`Self::get_backend`], preferring a backend that is not on the list.
    ///
    /// The list is the backends an earlier attempt already failed against, and
    /// it is what a retry is built on: the backend that just failed is the one
    /// most likely to fail again.
    pub async fn get_backend_excluding(
        &self,
        host: &str,
        path: &str,
        exclude: &[String],
    ) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl_excluding(host, path, None, None, exclude)
            .await
    }

    /// [`Self::get_backend`] under a client's authorization.
    ///
    /// One rule beyond the plain lookup: a host the ACL does not list is
    /// refused before any route is consulted, and so is a port the ACL does
    /// list — the refusal is indistinguishable from "no route" — a 404, not a
    /// 403, so a client cannot use the difference to probe which hosts exist
    /// behind the proxy.
    ///
    /// `port` is the port the client named, if it named one. `None` means it
    /// named none, and there is then no port to hold against it.
    pub async fn get_backend_with_acl(
        &self,
        host: &str,
        path: &str,
        port: Option<u16>,
        acl: Option<&ClientAcl>,
    ) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl_excluding(host, path, port, acl, &[])
            .await
    }

    /// [`Self::get_backend_with_acl`], preferring a backend that is not on the
    /// list.
    pub async fn get_backend_with_acl_excluding(
        &self,
        host: &str,
        path: &str,
        port: Option<u16>,
        acl: Option<&ClientAcl>,
        exclude: &[String],
    ) -> BackendLookup<BackendInfo> {
        if acl.is_some_and(|acl| !acl.allows(host)) {
            tracing::debug!("Host {host} is not allowed for this client, answering 404");
            return BackendLookup::NoRoute;
        }

        // The port half of the same question. Only asked when the client named
        // one: a request that names no port has no port to hold against it.
        if let (Some(acl), Some(port)) = (acl, port)
            && !acl.allows_port(port)
        {
            tracing::debug!("Port {port} is not allowed for this client, answering 404");
            return BackendLookup::NoRoute;
        }

        tracing::debug!("Looking up backend for host={}, path={}", host, path);

        // Only `http` routes take requests. A passthrough route exists so its
        // bytes can be copied to a TLS backend, and that listener is not an
        // HTTP server: letting one match here would send a plain request to a
        // TLS port.
        let matched_route = {
            let routes = self.routes.read().await;
            // The host is folded once for the whole walk, rather than once
            // for every route in it.
            let folded = normalize_host(host);
            best_match(&routes, RouteMode::Http, |route| {
                route.serves_request(&folded, path)
            })
        };

        let Some(route) = matched_route else {
            tracing::debug!("No http route matched: host={host}, path={path} -> 404");
            return BackendLookup::NoRoute;
        };

        // A route matched, so this stopped being a routing question: every
        // backend behind it is down, and dialling one anyway spends a whole
        // connect timeout delivering the refusal the caller can write now.
        let Some(lease) = route.backend_pool().select_backend_excluding(exclude).await else {
            tracing::warn!(
                "Route {}:{} matched host={host} path={path} but no backend is healthy -> 503",
                route.host_pattern(),
                route.path_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        // The port the request is actually **served from** — the backend's,
        // not the one the client named in its `Host` header. A client asking
        // for `https://api.example.com` is served from
        // `http://127.0.0.1:18080`; the port the client named is a virtual
        // one, and the request never reaches it.
        //
        // Only asked when the ACL is strict. Without that, the port list is
        // checked where the client names a port, and this has nothing to add.
        if let Some(acl) = acl
            && let Some(port) = backend_port(lease.url())
            && !acl.allows_backend_port(port)
        {
            tracing::debug!(
                "Port {port} (the backend for {host}) is not allowed for this client, answering 404"
            );
            return BackendLookup::NoRoute;
        }

        tracing::debug!(
            "Selected backend: {} for host={}, path={}",
            lease.url(),
            host,
            path,
        );
        BackendLookup::Found(BackendInfo {
            url: lease.shared_url().clone(),
            origin: lease.origin().clone(),
            protocol: route.backend_protocol(),
            path_rewrite: route.path_rewrite().clone(),
            path_pattern: route.path_pattern().to_string(),
            path_is_prefix: route.path_is_prefix(),
            _lease: Some(lease),
        })
    }

    /// Backend for a raw TLS passthrough connection, selected by SNI.
    ///
    /// Only `mode = "passthrough"` routes take part, so [`BackendLookup::NoRoute`]
    /// means nothing serves this name and the caller hangs up rather than
    /// guessing at a backend. [`BackendLookup::Unavailable`] is reachable too: a
    /// route may serve both `http` and `passthrough`, and then health probes run
    /// against the pool both modes dial into.
    ///
    /// The lease comes back with it rather than only its address, because a TLS
    /// session is exactly the load `least_conn` is counting: copying bytes to a
    /// backend for as long as the client keeps the session open. Handing back a
    /// bare `String` would release it on return and leave every passthrough
    /// session invisible to the balancer.
    pub async fn get_passthrough_backend(&self, sni: &str) -> BackendLookup<BackendLease> {
        let matched_route = {
            let routes = self.routes.read().await;
            // The name is folded once for the whole walk.
            let folded = normalize_host(sni);
            best_match(&routes, RouteMode::Passthrough, |route| {
                route.serves_host(&folded)
            })
        };

        let Some(route) = matched_route else {
            tracing::debug!("No passthrough route matched: sni={sni}, hanging up");
            return BackendLookup::NoRoute;
        };

        // Nothing to copy toward, then: say so where the operator can read it,
        // rather than letting it look like a name nothing serves.
        let Some(lease) = route.backend_pool().select_backend().await else {
            tracing::warn!(
                "Passthrough route {} matched sni={sni} but no backend is healthy; refusing \
                 rather than copying into a connection nobody answers",
                route.host_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        tracing::debug!(
            "Passthrough route matched: sni={}, host={}, backend={}",
            sni,
            route.host_pattern(),
            lease.url()
        );
        BackendLookup::Found(lease)
    }

    /// Backend for one L4 flow, selected by host and port.
    ///
    /// Only `mode`'s own routes take part — a `tcp` lookup never sees a `udp` route and
    /// vice versa — and [`BackendLookup::NoRoute`] means nothing serves this host.
    ///
    /// **There is no fallback.** A `tcp` or `udp` lookup sees only the routes of
    /// its own mode, so a host with none of them is refused: forwarding a
    /// mistyped or unconfigured domain to some other service is exactly the
    /// failure this lookup exists to prevent.
    ///
    /// The two refusals do **not** reach the client as the same status — see
    /// [`BackendLookup`]. A route serving `http` alongside `tcp` is probed on the
    /// pool both modes share, so an L4 flow can find a healthy route whose every
    /// backend is down, and answering `NoRoute` for that would tell the client its
    /// request was misconfigured when what actually happened is that there is
    /// nothing to dial.
    pub async fn get_l4_backend(
        &self,
        host: &str,
        port: u16,
        mode: RouteMode,
    ) -> BackendLookup<L4RouteInfo> {
        debug_assert!(mode.is_l4(), "get_l4_backend called with {mode:?}");

        let matched_route = {
            let routes = self.routes.read().await;
            // The host is folded once for the whole walk.
            let folded = normalize_host(host);
            best_match(&routes, mode, |route| route.serves_l4(&folded, port))
        };

        let Some(route) = matched_route else {
            tracing::debug!("No l4 route matched: host={host}, port={port}, mode={mode:?}");
            return BackendLookup::NoRoute;
        };

        let Some(lease) = route.backend_pool().select_backend().await else {
            tracing::warn!(
                "L4 route {} matched host={host} port={port} ({mode:?}) but no backend is healthy",
                route.host_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        tracing::debug!(
            "L4 route matched: host={}, port={}, mode={:?}, route={}, backend={}",
            host,
            port,
            mode,
            route.host_pattern(),
            lease.url()
        );
        BackendLookup::Found(L4RouteInfo {
            backend: lease.url().to_string(),
            idle_timeout: route.idle_timeout(),
            flow_timeout: route.flow_timeout(),
            _lease: lease,
        })
    }

    /// The whole table, copied out.
    ///
    /// For the admin API and the startup log, not for the request path: a copy
    /// of a route is four or five allocations, and a listing wants the routes
    /// themselves rather than the table's references to them.
    pub async fn routes(&self) -> Vec<Route> {
        self.routes
            .read()
            .await
            .iter()
            .map(|route| (**route).clone())
            .collect()
    }

    /// Swaps the routing table, keeping the pool of every route that is still
    /// the route it was.
    ///
    /// A reload builds brand-new `Route`s from the file, and a brand-new
    /// `BackendPool` with each. Everything that was handed a pool earlier —
    /// above all the health probe, which holds its `Arc` and runs until the
    /// process ends — would then be left holding a pool the routing table no
    /// longer hands out: the probe would keep marking backends up and down
    /// where no traffic can see it, and the live pool would go unprobed, so a
    /// backend that died would stay in rotation until the next restart.
    ///
    /// Carrying the old pool over also keeps its health state. An edit to an
    /// unrelated route is not a reason to decide that every backend is healthy
    /// again.
    ///
    /// `timeouts` is not touched: it was read once at startup, into the HTTP
    /// client and into this table, and a reload is a routing change rather than a
    /// restatement of how long a dial may take.
    pub async fn update_routes(&self, new_routes: Vec<Route>) {
        // **The keys are computed before the lock is taken.** Computing one is
        // an await, and holding the routing table's write lock across an await
        // stops every request in the process: the table is read on the way to
        // every backend, and a read lock waits for a write lock. So a reload
        // that took a moment to work out its keys held the whole server still
        // while it did.
        let mut previous: HashMap<String, Arc<BackendPool>> = HashMap::new();
        {
            let routes = self.routes.read().await;
            for route in routes.iter() {
                previous.insert(route.pool_key().await, route.backend_pool().clone());
            }
        }

        let mut updated = Vec::with_capacity(new_routes.len());
        for mut route in new_routes {
            let key = route.pool_key().await;
            // `remove`, not `get`: two routes can share a key, and each keeps
            // its own pool rather than ending up sharing one.
            if let Some(pool) = previous.remove(&key) {
                route.backend_pool = pool;
            }
            updated.push(Arc::new(route));
        }

        // The write lock is held for the swap and nothing else.
        let mut routes = self.routes.write().await;
        *routes = updated;
        tracing::info!("Routes updated successfully");
    }
}

/// The routes of a table, shared.
///
/// A table hands out references to its routes rather than copies of them, so
/// this is where a list of routes becomes a list of references.
fn shared(routes: Vec<Route>) -> Vec<Arc<Route>> {
    routes.into_iter().map(Arc::new).collect()
}

/// The port a backend is reached on.
///
/// `None` when the backend does not say, and when it does not say, the port is
/// the scheme's default — which is what the URL itself would use.
///
/// **Both spellings are read.** A backend is written as a URL
/// (`http://10.0.0.5:18080`) for an HTTP route, and as a bare `host:port`
/// (`127.0.0.1:443`) for a TLS passthrough — and a bare `host:port` is not a
/// URL at all: `Url::parse` reads `host.docker.internal:8443` as a scheme
/// with no port, and refuses `127.0.0.1:443` outright. So the passthrough's own
/// parser is the one that answers, and it knows both.
pub(crate) fn backend_port(url: &str) -> Option<u16> {
    crate::passthrough::parse_backend_addr(url).map(|(_host, port)| port)
}

/// Highest-priority route of `mode` that `matches` accepts.
///
/// Ties keep the first declaration. A route serves only the modes it declares,
/// and which of them a connection uses is decided before matching, by the first
/// byte of the connection — a TLS handshake goes to `Passthrough`, an L4 preface
/// to `Tcp` or `Udp`, anything else to `Http`. One route may declare several
/// modes; a connection still takes exactly one path.
fn best_match(
    routes: &[Arc<Route>],
    mode: RouteMode,
    matches: impl Fn(&Route) -> bool,
) -> Option<Arc<Route>> {
    let mut best: Option<(Arc<Route>, u32)> = None;

    for route in routes.iter() {
        if !route.serves(mode) || !matches(route) {
            continue;
        }

        let priority = route.priority();
        tracing::debug!(
            "Route matched: host={}, path={}, mode={:?}, priority={}",
            route.host_pattern(),
            route.path_pattern(),
            mode,
            priority
        );

        if best
            .as_ref()
            .is_none_or(|(_, best_priority)| priority > *best_priority)
        {
            best = Some((route.clone(), priority));
        }
    }

    best.map(|(route, _)| route)
}

#[cfg(test)]
mod tests;
