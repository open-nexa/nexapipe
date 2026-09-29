use crate::auth::ClientAcl;
use crate::config::RouteMode;
use crate::lb::{BackendLease, BackendPool, LoadBalancingStrategy};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Compares host names the way DNS does: case-insensitively, without a
/// trailing dot.
///
/// A `Host` header may arrive in any case (`API.example.com`) and may carry a
/// fully-qualified trailing dot (`api.example.com.`) — both name the same host
/// the route was written for. Matching them raw would let such a request slip
/// past its route and reach a different service entirely. Both the pattern and
/// every input go through here, so a config written with uppercase letters
/// keeps working too.
pub(crate) fn normalize_host(host: &str) -> String {
    // Every trailing dot, not just one: a name may arrive carrying more than
    // the single dot of a fully-qualified spelling, and leaving one behind
    // makes it a different string than the route it names.
    let host = host.trim_end_matches('.');
    // An IPv6 literal is bracketed in a `Host` header — that is how its port is
    // told apart from the address — and may be written the same way in a
    // config. The brackets are not part of the name, so both sides lose them
    // here and a pattern spelled `[::1]` matches a request for `[::1]:8080`.
    let host = host.trim_matches(|c| c == '[' || c == ']');
    host.to_ascii_lowercase()
}

/// The host a `Host` header names, with the port taken off.
///
/// `split(':')` is wrong for IPv6 twice over: `[::1]:8080` yields `[`, and a
/// bare `::1` yields the empty string. Either way the host matches no route
/// and every request to it 404s. A bracketed literal keeps its brackets here;
/// [`normalize_host`] drops them.
pub(crate) fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            // Up to and including the closing bracket: a port can only follow
            // it, and the colons inside belong to the address.
            Some(end) => &host[..=end],
            // A bracket that is never closed is not a port separator, so
            // nothing is taken off.
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// Whether a (already folded) host matches a (already folded) pattern.
///
/// The one host-matching rule, shared by route patterns and
/// [`ClientAcl`] allowlists so the two can never drift apart: an exact
/// name, a `*.suffix` wildcard, or the bare `*` catch-all.
///
/// The dot is load-bearing. Without it a wildcard is a bare `ends_with`, so
/// `*.example.com` would also match `notexample.com` — a host that merely
/// ends in the same letters, belonging to somebody else entirely.
pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix('*') {
        None => pattern == host,
        // `*` on its own is the catch-all: how "send everything here" is
        // spelled now that there is no default backend.
        Some("") => true,
        // A `*` followed by anything but a dot matches nothing. Those are
        // refused when the config is loaded, so reaching here means the
        // pattern came from somewhere that skipped the check — and the one
        // thing it must not do is quietly match more than it says.
        Some(rest) => rest
            .strip_prefix('.')
            .and_then(|suffix| host.strip_suffix(suffix))
            // The label boundary: the apex itself is not under the wildcard,
            // which is what DNS means by `*.example.com`.
            .is_some_and(|prefix| prefix.ends_with('.')),
    }
}

/// Why `pattern` cannot be matched with, or `None` when it can.
///
/// Checked when a config is loaded rather than left to the matcher, because the
/// failure mode of a loose wildcard is silent: `allow_hosts = ["*iakl.top"]`
/// looks like it names one domain and in fact authorizes every host ending in
/// those letters, `eviliakl.top` included. Refusing to start is the only
/// answer an operator can see.
pub(crate) fn host_pattern_error(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return Some("is empty; name the host, or use \"*\" for every host".to_string());
    }

    // Not a wildcard at all, so there is nothing a `*` could get wrong.
    let rest = pattern.strip_prefix('*')?;
    match rest.strip_prefix('.') {
        None if rest.is_empty() => None,
        Some(suffix) if !suffix.is_empty() => None,
        _ => Some(format!(
            "\"{pattern}\" has to be \"*\" or start with \"*.\": the dot is what marks the \
             label boundary, and without it the pattern also matches any host that merely \
             ends in the same letters"
        )),
    }
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
            host_pattern: normalize_host(host_pattern),
            path_pattern: path_pattern.to_string(),
            path_is_prefix,
            modes: vec![mode],
            backend_pool: Arc::new(BackendPool::new(backends, strategy)),
            path_rewrite,
            l4: L4Options::default(),
        }
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
        host_matches(&self.host_pattern, &normalize_host(host))
    }

    /// Match for an L4 flow: the host, plus the optional client-port allow list.
    ///
    /// `client_ports` only decides whether *this* route answers. Where the connection
    /// is then dialled is entirely the route's `backends`, so a client cannot use the
    /// list to steer the tunnel somewhere else.
    pub fn matches_l4(&self, host: &str, port: u16) -> bool {
        if !self.matches_host(host) {
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

    pub fn matches(&self, host: &str, path: &str) -> bool {
        let path_matches = if self.path_is_prefix {
            path.starts_with(&self.path_pattern)
        } else {
            path == self.path_pattern
        };

        self.matches_host(host) && path_matches
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

    pub fn rewrite_path(&self, original_path: &str) -> String {
        if let Some(rewrite_pattern) = &self.path_rewrite {
            if self.path_is_prefix && original_path.starts_with(&self.path_pattern) {
                let suffix = &original_path[self.path_pattern.len()..];
                rewrite_pattern.replace("{}", suffix)
            } else if !self.path_is_prefix && original_path == self.path_pattern {
                rewrite_pattern.replace("{}", "")
            } else {
                original_path.to_string()
            }
        } else {
            original_path.to_string()
        }
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
    /// [`Self::kind`].
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
    pub url: String,
    pub path_rewrite: Option<String>,
    pub path_pattern: String,
    pub path_is_prefix: bool,
    /// Alive for exactly as long as this request is outstanding against that
    /// backend: dropping it is what releases the backend's slot in the balancer,
    /// so nothing reads this field — moving it along with the requests is the
    /// whole point. See [`crate::lb::BackendLease`].
    _lease: BackendLease,
}

/// What the L4 tunnel needs in order to serve one flow.
pub struct L4RouteInfo {
    /// The address to dial, and the only address involved: the route decides
    /// it, the client cannot. See [`RouteConfig::get_l4_backend`].
    pub backend: String,
    /// `udp` routes only; `None` means the caller's own default.
    pub idle_timeout: Option<Duration>,
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
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    routes: Arc<RwLock<Vec<Route>>>,
}

impl RouteConfig {
    pub fn new(routes: Vec<Route>) -> Self {
        Self {
            routes: Arc::new(RwLock::new(routes)),
        }
    }

    /// Backend for an HTTP request. Callers answer
    /// [`BackendLookup::NoRoute`] with `404` and [`BackendLookup::Unavailable`]
    /// with `503` — see the enum for why the two are not one answer.
    pub async fn get_backend(&self, host: &str, path: &str) -> BackendLookup<BackendInfo> {
        self.get_backend_with_acl(host, path, None).await
    }

    /// [`Self::get_backend`] under a client's host authorization.
    ///
    /// One rule beyond the plain lookup: a host the ACL does not list is
    /// refused before any route is consulted, and the refusal is
    /// indistinguishable from "no route" — a 404, not a 403, so a client cannot
    /// use the difference to probe which hosts exist behind the proxy.
    pub async fn get_backend_with_acl(
        &self,
        host: &str,
        path: &str,
        acl: Option<&ClientAcl>,
    ) -> BackendLookup<BackendInfo> {
        if acl.is_some_and(|acl| !acl.allows(host)) {
            tracing::debug!("Host {host} is not allowed for this client, answering 404");
            return BackendLookup::NoRoute;
        }

        tracing::debug!("Looking up backend for host={}, path={}", host, path);

        // Only `http` routes take requests. A passthrough route exists so its
        // bytes can be copied to a TLS backend, and that listener is not an
        // HTTP server: letting one match here would send a plain request to a
        // TLS port.
        let matched_route = {
            let routes = self.routes.read().await;
            best_match(&routes, RouteMode::Http, |route| route.matches(host, path))
        };

        let Some(route) = matched_route else {
            tracing::debug!("No http route matched: host={host}, path={path} -> 404");
            return BackendLookup::NoRoute;
        };

        // A route matched, so this stopped being a routing question: every
        // backend behind it is down, and dialling one anyway spends a whole
        // connect timeout delivering the refusal the caller can write now.
        let Some(lease) = route.backend_pool().select_backend().await else {
            tracing::warn!(
                "Route {}:{} matched host={host} path={path} but no backend is healthy -> 503",
                route.host_pattern(),
                route.path_pattern(),
            );
            return BackendLookup::Unavailable;
        };

        tracing::debug!(
            "Selected backend: {} for host={}, path={}",
            lease.url(),
            host,
            path,
        );
        BackendLookup::Found(BackendInfo {
            url: lease.url().to_string(),
            path_rewrite: route.path_rewrite().clone(),
            path_pattern: route.path_pattern().to_string(),
            path_is_prefix: route.path_is_prefix(),
            _lease: lease,
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
            best_match(&routes, RouteMode::Passthrough, |route| {
                route.matches_host(sni)
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
            best_match(&routes, mode, |route| route.matches_l4(host, port))
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
            _lease: lease,
        })
    }

    pub async fn routes(&self) -> Vec<Route> {
        self.routes.read().await.clone()
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
    pub async fn update_routes(&self, new_routes: Vec<Route>) {
        let mut routes = self.routes.write().await;

        let mut previous: HashMap<String, Arc<BackendPool>> = HashMap::new();
        for route in routes.iter() {
            previous.insert(route.pool_key().await, route.backend_pool().clone());
        }

        let mut updated = Vec::with_capacity(new_routes.len());
        for mut route in new_routes {
            let key = route.pool_key().await;
            // `remove`, not `get`: two routes can share a key, and each keeps
            // its own pool rather than ending up sharing one.
            if let Some(pool) = previous.remove(&key) {
                route.backend_pool = pool;
            }
            updated.push(route);
        }

        *routes = updated;
        tracing::info!("Routes updated successfully");
    }
}

/// Highest-priority route of `mode` that `matches` accepts.
///
/// Ties keep the first declaration. A route serves only the modes it declares,
/// and which of them a connection uses is decided before matching, by the first
/// byte of the connection — a TLS handshake goes to `Passthrough`, an L4 preface
/// to `Tcp` or `Udp`, anything else to `Http`. One route may declare several
/// modes; a connection still takes exactly one path.
fn best_match(
    routes: &[Route],
    mode: RouteMode,
    matches: impl Fn(&Route) -> bool,
) -> Option<Route> {
    let mut best: Option<(Route, u32)> = None;

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
mod tests {
    use super::*;

    /// Health says which of several backends to send to, so a pool that has only
    /// one has nothing to decide — and refusing is not "safer" there, it is answering
    /// for every request to a route in order to report that nothing is up. See
    /// [`crate::lb::BackendPool::select_backend`].
    #[tokio::test]
    async fn one_unhealthy_backend_is_still_the_answer() {
        let route = http_route("api.iakl.top", &["http://10.0.0.5:8080"]);
        route
            .backend_pool()
            .set_backend_health("http://10.0.0.5:8080", false)
            .await;
        let config = RouteConfig::new(vec![route]);

        assert!(
            config.get_backend("api.iakl.top", "/").await.is_found(),
            "the one backend behind this route is the only path it has"
        );
    }

    /// The same pool state, one more backend: now the health information means
    /// something, and the lookup has to say "unavailable" rather than hand out a
    /// backend it knows is down. 503 and 404 differ in which file the operator
    /// opens.
    #[tokio::test]
    async fn unhealthy_backends_are_not_confused_with_a_missing_route() {
        let route = http_route(
            "api.iakl.top",
            &["http://10.0.0.5:8080", "http://10.0.0.6:8080"],
        );
        let pool = route.backend_pool().clone();
        pool.set_backend_health("http://10.0.0.5:8080", false).await;
        pool.set_backend_health("http://10.0.0.6:8080", false).await;
        let config = RouteConfig::new(vec![route]);

        assert!(
            matches!(
                config.get_backend("api.iakl.top", "/").await,
                BackendLookup::Unavailable
            ),
            "every backend is down, and the route that matched still exists"
        );
        assert!(
            matches!(
                config.get_backend("nope.iakl.top", "/").await,
                BackendLookup::NoRoute
            ),
            "no route serves this host at all, which is a different answer"
        );
    }

    /// A pool shared by `http` and another mode carries one health state, so the
    /// tunnel and the TLS passthrough see the same refusal as a request does —
    /// which is why all three lookups speak in [`BackendLookup`] rather than
    /// `Option`.
    #[tokio::test]
    async fn the_same_refusal_reaches_the_tunnel_and_the_passthrough() {
        // One route, three modes, one pool — exactly the shape a health probe
        // marks through `http` and the other two dial into.
        let route = http_route("fn.iroh.iakl.top", &["caddy:443", "caddy2:443"]).with_modes(vec![
            RouteMode::Http,
            RouteMode::Passthrough,
            RouteMode::Tcp,
        ]);
        let pool = route.backend_pool().clone();
        let config = RouteConfig::new(vec![route]);
        pool.set_backend_health("caddy:443", false).await;
        pool.set_backend_health("caddy2:443", false).await;

        assert!(matches!(
            config.get_passthrough_backend("fn.iroh.iakl.top").await,
            BackendLookup::Unavailable
        ));
        assert!(matches!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
                .await,
            BackendLookup::Unavailable
        ));
    }

    fn http_route(host: &str, backends: &[&str]) -> Route {
        Route::new(
            host,
            "/",
            true,
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        )
    }

    fn passthrough_route(host: &str, backends: &[&str]) -> Route {
        Route::new(
            host,
            "/",
            true,
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Passthrough,
            None,
        )
    }

    /// The two modes are separate tables: a TLS session is served by the
    /// passthrough route and a plain request by the http one, even when they
    /// share a host name.
    #[tokio::test]
    async fn each_mode_only_sees_its_own_routes() {
        let config = RouteConfig::new(vec![
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("mt.iroh.iakl.top", &["http://10.0.0.6:9000"]),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("fn.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
        // A host that is only served over plain HTTP has no TLS backend, and
        // the default backend is not a passthrough fallback.
        assert_eq!(
            config
                .get_passthrough_backend("mt.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            None
        );
        assert!(
            config
                .get_passthrough_backend("unknown.test")
                .await
                .is_no_route()
        );
    }

    /// `modes = ["http", "tcp"]` in the form of a lookup: one route, two tables,
    /// one shared pool.
    ///
    /// This is the configuration a TUN client needs — every one of its flows
    /// arrives as an L4 preface, even on port 80 — and it used to take two
    /// entries, where forgetting the second one cost a runtime `NoRoute`.
    #[tokio::test]
    async fn one_route_may_serve_both_a_request_and_a_tunnel() {
        let config = RouteConfig::new(vec![
            http_route("fn.iroh.iakl.top", &["http://host.docker.internal:15666"])
                .with_modes(vec![RouteMode::Http, RouteMode::Tcp]),
        ]);

        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the route serves this host as a request")
                .url,
            "http://host.docker.internal:15666"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
                .backend()
                .expect("the same route serves this host as a tunnel")
                .backend,
            "http://host.docker.internal:15666"
        );
        // Declaring two modes did not turn the route into a catch-all: udp was
        // never one of them, and there is no default backend to fall back on.
        assert!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 80, RouteMode::Udp)
                .await
                .is_no_route()
        );
    }

    /// One server, four kinds of traffic — the question "can http, https, tcp and udp
    /// run at the same time" in the form of a test.
    ///
    /// They can, because a route belongs to exactly one mode and each lookup only ever
    /// searches its own mode: the same host name may appear four times without the
    /// entries shadowing each other. What decides which one a *connection* gets is the
    /// first byte it arrives with, so a single connection still only ever takes one path
    /// — a TLS `ClientHello` cannot reach the `tcp` route, and an L4 preface cannot reach
    /// `passthrough`, even though both point at the same backend here.
    #[tokio::test]
    async fn one_config_serves_http_https_tcp_and_udp_at_once() {
        let config = RouteConfig::new(vec![
            // https:// reaching the server as raw TLS, routed by SNI.
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            // http:// reaching it as a request, routed by Host.
            http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]),
            // The same https:// service seen through a TUN or a CONNECT tunnel,
            // where the client announces host and port instead of sending TLS.
            l4_route("fn.iroh.iakl.top", RouteMode::Tcp, "caddy:443", None),
            // A UDP service on the same name.
            l4_route("fn.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None),
        ]);

        // Plain HTTP request.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
        // TLS session, routed by SNI.
        assert_eq!(
            config
                .get_passthrough_backend("fn.iroh.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        // TCP tunnel, and UDP tunnel.
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "caddy:443"
        );
        assert_eq!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Udp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.60:3478"
        );

        // The two directions of the same claim: the tunnels refuse what they do not
        // serve, while HTTP still has somewhere to go.
        assert!(
            config
                .get_l4_backend("fn.iroh.iakl.top", 3478, RouteMode::Tcp)
                .await
                .is_found(),
            "a tcp route with no client_ports serves every port"
        );
        assert!(
            config
                .get_l4_backend("nothing.iroh.iakl.top", 443, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        // The one thing HTTP does not share with the tunnels: it is the only
        // lookup with no route for this host either, so it says 404.
        assert!(
            config
                .get_backend("nothing.iroh.iakl.top", "/")
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn passthrough_catch_all_and_exact_host_priority() {
        let config = RouteConfig::new(vec![
            passthrough_route("*", &["caddy:443"]),
            passthrough_route("other.iakl.top", &["caddy-alt:443"]),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("anything.test")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        // An exact host outranks the wildcard regardless of declaration order.
        assert_eq!(
            config
                .get_passthrough_backend("other.iakl.top")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy-alt:443".to_string())
        );
    }

    fn l4_route(host: &str, mode: RouteMode, backend: &str, ports: Option<&[u16]>) -> Route {
        Route::new(
            host,
            "/",
            true,
            vec![backend.to_string()],
            LoadBalancingStrategy::RoundRobin,
            mode,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: ports.map(|p| p.to_vec()),
            idle_timeout: None,
        })
    }

    #[tokio::test]
    async fn l4_lookups_only_see_their_own_mode() {
        let config = RouteConfig::new(vec![
            l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
            http_route("web.iroh.iakl.top", &["http://10.0.0.5:8080"]),
        ]);

        let tcp = config
            .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
            .await
            .backend()
            .expect("the tcp route should answer");
        assert_eq!(tcp.backend, "10.0.0.50:5432");

        // The tcp route is not reachable as UDP...
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_no_route()
        );
        // ...and an HTTP route is not an L4 target in either mode, while the HTTP path
        // still serves it.
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("web.iroh.iakl.top", 80, RouteMode::Udp)
                .await
                .is_no_route()
        );
        assert_eq!(
            config
                .get_backend("web.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
    }

    #[tokio::test]
    async fn an_unrouted_host_is_refused() {
        // The other route's backend is a real, working address here. If the
        // lookup served a host it has no route for, a mistyped domain would
        // quietly reach it instead of being refused.
        let config = RouteConfig::new(vec![l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            None,
        )]);

        assert!(
            config
                .get_l4_backend("typo.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Udp)
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn client_ports_pick_a_route_without_changing_its_target() {
        let config = RouteConfig::new(vec![
            l4_route(
                "db.iroh.iakl.top",
                RouteMode::Tcp,
                "10.0.0.50:5432",
                Some(&[5432]),
            ),
            l4_route(
                "db.iroh.iakl.top",
                RouteMode::Tcp,
                "10.0.0.51:6432",
                Some(&[6432]),
            ),
        ]);

        // Each port selects its own route, and each route dials its own backend: the
        // client's port is a selector, never the address that is dialled.
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 5432, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.50:5432"
        );
        assert_eq!(
            config
                .get_l4_backend("db.iroh.iakl.top", 6432, RouteMode::Tcp)
                .await
                .backend()
                .unwrap()
                .backend,
            "10.0.0.51:6432"
        );
        // A port no route lists is refused rather than served by the nearest match.
        assert!(
            config
                .get_l4_backend("db.iroh.iakl.top", 9999, RouteMode::Tcp)
                .await
                .is_no_route()
        );
    }

    #[tokio::test]
    async fn without_client_ports_every_port_matches() {
        let config = RouteConfig::new(vec![l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            None,
        )]);

        for port in [1u16, 443, 5432, 65535] {
            assert_eq!(
                config
                    .get_l4_backend("db.iroh.iakl.top", port, RouteMode::Tcp)
                    .await
                    .backend()
                    .map(|r| r.backend),
                Some("10.0.0.50:5432".to_string()),
                "port {port}"
            );
        }
    }

    #[test]
    fn l4_matching_is_host_then_ports() {
        let exact = l4_route(
            "db.iroh.iakl.top",
            RouteMode::Tcp,
            "10.0.0.50:5432",
            Some(&[5432]),
        );
        assert!(exact.matches_l4("db.iroh.iakl.top", 5432));
        assert!(!exact.matches_l4("db.iroh.iakl.top", 5433));
        assert!(!exact.matches_l4("other.iakl.top", 5432));

        let wildcard = l4_route("*.iroh.iakl.top", RouteMode::Udp, "10.0.0.60:3478", None);
        assert!(wildcard.matches_l4("turn.iroh.iakl.top", 1));
        assert!(!wildcard.matches_l4("iroh.iakl.top.bad.test", 1));
    }

    #[test]
    fn idle_timeouts_travel_with_the_route() {
        let route = Route::new(
            "turn.iroh.iakl.top",
            "/",
            true,
            vec!["10.0.0.60:3478".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Udp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: None,
            idle_timeout: Some(std::time::Duration::from_secs(120)),
        });
        assert_eq!(
            route.idle_timeout(),
            Some(std::time::Duration::from_secs(120))
        );

        // An HTTP route has no L4 knobs, and asking for them must not invent one.
        assert_eq!(http_route("a.test", &["http://b:80"]).idle_timeout(), None);
    }

    /// An unrouted host has nowhere to go, and says so.
    ///
    /// There is no fallback a config can name any more: a route is the only way
    /// to serve a host, so a mistyped or unknown `Host` is a 404 instead of
    /// quietly reaching whatever service happened to be listed.
    #[tokio::test]
    async fn an_unrouted_host_is_answered_404() {
        let config = RouteConfig::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);

        assert!(
            config
                .get_backend("typo.iroh.iakl.top", "/")
                .await
                .is_no_route()
        );
        // The routed host is unaffected.
        assert_eq!(
            config
                .get_backend("fn.iroh.iakl.top", "/")
                .await
                .backend()
                .expect("the http route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
    }

    /// `host_pattern = "*"` is how "send everything here" is spelled now.
    ///
    /// It is an ordinary `http` route — same pool, same priority rules, same
    /// lookup — so an exact host still outranks it, and it is not a fallback for
    /// anything else: an SNI or L4 lookup cannot reach it.
    #[tokio::test]
    async fn a_catch_all_route_serves_every_unrouted_host() {
        let config = RouteConfig::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("*", &["http://10.0.0.9:9000"]),
        ]);

        assert_eq!(
            config
                .get_backend("anything.test", "/")
                .await
                .backend()
                .expect("the catch-all serves what no other route names")
                .url,
            "http://10.0.0.9:9000"
        );
        // An exact host still outranks the catch-all.
        assert_eq!(
            config
                .get_backend("api.iakl.top", "/")
                .await
                .backend()
                .expect("the exact route serves this host")
                .url,
            "http://10.0.0.5:8080"
        );
        // It is an `http` route, not a fallback for the other modes.
        assert!(
            config
                .get_passthrough_backend("anything.test")
                .await
                .is_no_route()
        );
        assert!(
            config
                .get_l4_backend("anything.test", 443, RouteMode::Tcp)
                .await
                .is_no_route()
        );
    }

    /// A restricted client reaches the hosts its allowlist names, and nothing
    /// else — the refusal for a host not on the list is the same 404 an
    /// unrouted host gets, so the difference cannot be used as a probe.
    #[tokio::test]
    async fn a_restricted_client_reaches_only_its_allowed_hosts() {
        use crate::auth::ClientAcl;

        let config = RouteConfig::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("admin.iakl.top", &["http://10.0.0.9:9090"]),
        ]);
        let acl = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));

        // The allowed host reaches its own route.
        assert_eq!(
            config
                .get_backend_with_acl("api.iakl.top", "/", Some(&acl))
                .await
                .backend()
                .expect("an allowed host reaches its route")
                .url,
            "http://10.0.0.5:8080"
        );
        // A routed host the allowlist never named is refused, not served.
        assert!(
            config
                .get_backend_with_acl("admin.iakl.top", "/", Some(&acl))
                .await
                .is_no_route()
        );
        // So is an unrouted one: being on the allowlist does not conjure a
        // route for a host the server does not serve.
        assert!(
            config
                .get_backend_with_acl("typo.iakl.top", "/", Some(&acl))
                .await
                .is_no_route()
        );
    }

    /// A restricted client is served by routes, not by anything unnamed: a host
    /// on the allowlist with no route of its own is a 404, the same one an
    /// unrouted host gets, so the difference cannot be used as a probe.
    #[tokio::test]
    async fn a_restricted_client_needs_a_route_and_not_just_a_host() {
        use crate::auth::ClientAcl;

        let config = RouteConfig::new(vec![
            http_route("api.iakl.top", &["http://10.0.0.5:8080"]),
            http_route("*", &["http://10.0.0.9:9000"]),
        ]);

        // `other.iakl.top` is on the allowlist and has no route of its own; the
        // catch-all matches it, and that is a route like any other, so the
        // allowlist is what decides.
        let acl = ClientAcl::from_hosts(Some(&[
            "api.iakl.top".to_string(),
            "other.iakl.top".to_string(),
        ]));
        assert_eq!(
            config
                .get_backend_with_acl("other.iakl.top", "/", Some(&acl))
                .await
                .backend()
                .expect("the allowlist names this host")
                .url,
            "http://10.0.0.9:9000"
        );

        // A host the allowlist never named is refused even though the catch-all
        // would serve it for anyone else.
        let narrow = ClientAcl::from_hosts(Some(&["api.iakl.top".to_string()]));
        assert!(
            config
                .get_backend_with_acl("other.iakl.top", "/", Some(&narrow))
                .await
                .is_no_route()
        );
        assert!(config.get_backend("other.iakl.top", "/").await.is_found());
    }

    #[test]
    fn host_matching_handles_wildcards() {
        let route = passthrough_route("*.iroh.iakl.top", &["caddy:443"]);
        assert!(route.matches_host("fn.iroh.iakl.top"));
        assert!(route.matches_host(".iroh.iakl.top"));
        assert!(!route.matches_host("iroh.iakl.top.bad.test"));

        let exact = passthrough_route("fn.iroh.iakl.top", &["caddy:443"]);
        assert!(exact.matches_host("fn.iroh.iakl.top"));
        assert!(!exact.matches_host("comfyui.iroh.iakl.top"));
    }

    /// A `Host` header is case-insensitive and may carry a fully-qualified
    /// trailing dot. Both spellings name the host the route was written for, so
    /// neither may slip past it and reach a different service entirely.
    #[tokio::test]
    async fn a_differently_spelled_host_still_reaches_its_route() {
        let config = RouteConfig::new(vec![http_route("api.iakl.top", &["http://10.0.0.5:8080"])]);

        for host in ["API.IAKL.TOP", "Api.Iakl.Top", "api.iakl.top."] {
            assert_eq!(
                config
                    .get_backend(host, "/")
                    .await
                    .backend()
                    .unwrap_or_else(|| panic!("host {host} must reach its route"))
                    .url,
                "http://10.0.0.5:8080",
                "host {host} fell through to the default backend"
            );
        }

        // The pattern side is folded the same way, so a config written with
        // uppercase letters answers the lowercase request.
        let uppercase =
            RouteConfig::new(vec![http_route("API.Iakl.Top", &["http://10.0.0.7:8080"])]);
        assert_eq!(
            uppercase
                .get_backend("api.iakl.top", "/")
                .await
                .backend()
                .expect("the folded pattern matches the lowercase host")
                .url,
            "http://10.0.0.7:8080"
        );
    }

    /// The lookup-level view of the same rule for SNI and L4 hosts: both feed
    /// `matches_host`, so both are folded.
    #[tokio::test]
    async fn sni_and_l4_hosts_are_folded_the_same_way() {
        let config = RouteConfig::new(vec![
            passthrough_route("fn.iroh.iakl.top", &["caddy:443"]),
            l4_route("db.iroh.iakl.top", RouteMode::Tcp, "10.0.0.50:5432", None),
        ]);

        assert_eq!(
            config
                .get_passthrough_backend("FN.IROH.IAKL.TOP.")
                .await
                .found()
                .map(|lease| lease.url().to_string()),
            Some("caddy:443".to_string())
        );
        assert_eq!(
            config
                .get_l4_backend("DB.Iroh.Iakl.Top.", 5432, RouteMode::Tcp)
                .await
                .backend()
                .expect("the folded host reaches the L4 route")
                .backend,
            "10.0.0.50:5432"
        );
    }

    /// A reload keeps the pool of a route that did not change, which is what
    /// lets the health probe already running keep watching the pool traffic
    /// actually goes through.
    #[tokio::test]
    async fn a_reload_keeps_the_pool_of_a_route_that_did_not_change() {
        let config = RouteConfig::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);
        let before = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        // A reload of the very same table, which is what an edit to a second
        // route — or to any other section — looks like from here.
        config
            .update_routes(vec![http_route(
                "fn.iroh.iakl.top",
                &["http://10.0.0.5:8080"],
            )])
            .await;

        let after = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        assert!(
            Arc::ptr_eq(&before, &after),
            "an unchanged route must keep the pool it had, so its health probe stays attached"
        );
    }

    /// The counterpart: a route that now points elsewhere is a different pool,
    /// because a pool *is* the backends it dials.
    #[tokio::test]
    async fn a_route_that_changed_backends_gets_a_new_pool() {
        let config = RouteConfig::new(vec![http_route(
            "fn.iroh.iakl.top",
            &["http://10.0.0.5:8080"],
        )]);
        let before = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        config
            .update_routes(vec![http_route(
                "fn.iroh.iakl.top",
                &["http://10.0.0.9:8080"],
            )])
            .await;

        let after = config
            .routes()
            .await
            .first()
            .expect("one route")
            .backend_pool()
            .clone();

        assert!(
            !Arc::ptr_eq(&before, &after),
            "new backends mean a new pool, and the old probe has to be stopped"
        );
    }

    /// Two routes on one host, differing only in path, are not the same route
    /// and must not be treated as one — sharing a key would leave one of them
    /// without a health probe.
    #[tokio::test]
    async fn routes_sharing_a_host_are_still_different_routes() {
        let mut route = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
        let same_host_other_path = {
            let mut other = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
            other.path_pattern = "/api".to_string();
            other
        };

        assert_ne!(
            route.pool_key().await,
            same_host_other_path.pool_key().await
        );

        route.path_pattern = "/api".to_string();
        assert_eq!(
            route.pool_key().await,
            same_host_other_path.pool_key().await
        );
    }

    /// A pool is its backends *and* the way it picks between them, so a reload
    /// that changes only the strategy has to be a new pool. Keyed without it,
    /// the old pool was reused and the edit did nothing, with no log line to
    /// say why the traffic still went out the same way.
    #[tokio::test]
    async fn changing_only_the_strategy_is_a_different_pool() {
        let round_robin = http_route("fn.iroh.iakl.top", &["http://10.0.0.5:8080"]);
        let random = Route::new(
            "fn.iroh.iakl.top",
            "/",
            true,
            vec!["http://10.0.0.5:8080".to_string()],
            LoadBalancingStrategy::Random,
            RouteMode::Http,
            None,
        );

        assert_ne!(round_robin.pool_key().await, random.pool_key().await);
    }

    /// The dot is what makes a wildcard a wildcard over *labels*. Without it
    /// the match is a bare `ends_with`, and a host that merely ends in the same
    /// letters — belonging to somebody else — is in.
    #[test]
    fn a_wildcard_stops_at_the_label_boundary() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));

        assert!(
            !host_matches("*.example.com", "notexample.com"),
            "a host that merely ends in the same letters is not under the wildcard"
        );
        assert!(
            !host_matches("*.example.com", "example.com"),
            "the apex is not under its own wildcard, the way DNS reads it"
        );
        assert!(host_matches("*", "anything.at.all"), "`*` is the catch-all");
    }

    /// A `*` with anything but a dot after it matches nothing: it is refused
    /// when the config loads, and whatever slipped past the check must not
    /// quietly match more than it says.
    #[test]
    fn a_wildcard_without_its_dot_matches_nothing() {
        assert!(!host_matches("*iakl.top", "eviliakl.top"));
        assert!(!host_matches("*iakl.top", "iakl.top"));
    }

    #[test]
    fn a_loose_wildcard_is_refused_when_the_config_loads() {
        assert!(host_pattern_error("*").is_none());
        assert!(host_pattern_error("*.example.com").is_none());
        assert!(host_pattern_error("example.com").is_none());

        let why = host_pattern_error("*iakl.top").expect("*iakl.top must be refused");
        assert!(why.contains("label boundary"), "{why}");
        assert!(
            host_pattern_error("").is_some(),
            "an empty pattern names nothing"
        );
    }

    /// An IPv6 literal carries colons of its own, so splitting on the first one
    /// does not leave a host behind — it leaves `[`, and every request to that
    /// host 404s.
    #[test]
    fn a_host_header_keeps_an_ipv6_literal_whole() {
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(host_without_port("api.example.com:8080"), "api.example.com");
        assert_eq!(host_without_port("api.example.com"), "api.example.com");

        // What the routing table is asked about, brackets dropped.
        assert_eq!(normalize_host(host_without_port("[::1]:8080")), "::1");
        assert_eq!(normalize_host("[::1]"), "::1");
    }

    /// A name may carry more than one trailing dot. Stripping a single one left
    /// `a.example.com..` as `a.example.com.`, which is a different string than
    /// the route it names.
    #[test]
    fn every_trailing_dot_is_dropped() {
        assert_eq!(normalize_host("a.example.com"), "a.example.com");
        assert_eq!(normalize_host("a.example.com."), "a.example.com");
        assert_eq!(normalize_host("a.example.com.."), "a.example.com");
        assert_eq!(normalize_host("A.Example.COM.."), "a.example.com");
    }

    /// The tiers: an exact host outranks a wildcard no matter how long the
    /// wildcard's path is. They used to be one sum, so a path of 102 characters
    /// outweighed the host.
    #[test]
    fn an_exact_host_beats_any_path_length() {
        let long_path = "/".to_string() + &"x".repeat(200);
        let exact = Route::new(
            "api.example.com",
            "/",
            true,
            vec!["a".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );
        let wildcard_with_a_long_path = Route::new(
            "*.example.com",
            &long_path,
            true,
            vec!["b".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Http,
            None,
        );

        assert!(exact.priority() > wildcard_with_a_long_path.priority());
    }

    /// Two tcp routes for one host: the one that names its ports wins for those
    /// ports, and the other one stays reachable for everything else. With no
    /// tie-break the first declared won for good and the second never matched.
    #[tokio::test]
    async fn a_route_that_names_its_ports_wins_over_one_that_takes_them_all() {
        let every_port = Route::new(
            "ssh.example.com",
            "/",
            true,
            vec!["fallback:22".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Tcp,
            None,
        );
        // Declared second on purpose: declaration order must not decide it.
        let only_443 = Route::new(
            "ssh.example.com",
            "/",
            true,
            vec!["tls-backend:443".to_string()],
            LoadBalancingStrategy::RoundRobin,
            RouteMode::Tcp,
            None,
        )
        .with_l4_options(L4Options {
            client_ports: Some(vec![443]),
            idle_timeout: None,
        });

        let config = RouteConfig::new(vec![every_port, only_443]);

        assert_eq!(
            config
                .get_l4_backend("ssh.example.com", 443, RouteMode::Tcp)
                .await
                .backend()
                .expect("port 443 has a route")
                .backend,
            "tls-backend:443"
        );
        // The catch-all is not shadowed: a port it was the only answer for
        // still reaches it.
        assert_eq!(
            config
                .get_l4_backend("ssh.example.com", 22, RouteMode::Tcp)
                .await
                .backend()
                .expect("port 22 falls to the catch-all")
                .backend,
            "fallback:22"
        );
    }

    /// A `*.suffix` wildcard is more specific than the bare `*`, so it wins in
    /// either declaration order. Two tiers put them level and the winner was
    /// whichever came first in the file — the thing tiers are for.
    #[tokio::test]
    async fn a_wildcard_host_beats_the_catch_all_in_either_order() {
        let catch_all = http_route("*", &["http://10.0.0.1:8080"]);
        let wildcard = http_route("*.example.com", &["http://10.0.0.2:8080"]);

        let catch_all_first = RouteConfig::new(vec![catch_all.clone(), wildcard.clone()]);
        assert_eq!(
            catch_all_first
                .get_backend("api.example.com", "/")
                .await
                .backend()
                .expect("the wildcard has a route")
                .url,
            "http://10.0.0.2:8080"
        );

        let wildcard_first = RouteConfig::new(vec![wildcard, catch_all]);
        assert_eq!(
            wildcard_first
                .get_backend("api.example.com", "/")
                .await
                .backend()
                .expect("the wildcard has a route")
                .url,
            "http://10.0.0.2:8080"
        );

        // The catch-all is not shadowed: it still answers everything else.
        assert_eq!(
            wildcard_first
                .get_backend("elsewhere.test", "/")
                .await
                .backend()
                .expect("the catch-all has a route")
                .url,
            "http://10.0.0.1:8080"
        );
    }

    /// The end-to-end shape of the same thing: a request for an IPv6 literal
    /// reaches the route written for that address.
    #[tokio::test]
    async fn a_request_for_an_ipv6_literal_reaches_its_route() {
        let config = RouteConfig::new(vec![http_route("::1", &["http://10.0.0.5:8080"])]);

        assert_eq!(
            config
                .get_backend(host_without_port("[::1]:8080"), "/")
                .await
                .backend()
                .expect("the literal host reaches the route")
                .url,
            "http://10.0.0.5:8080"
        );
    }
}
