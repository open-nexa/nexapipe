//! The rules a configuration has to satisfy.
//!
//! A value that is present but wrong is **refused**, not guessed: a deployment
//! that runs differently from the one in the file is one nobody was told about.

use super::*;

/// Reads the `strategy` key.
///
/// **Refused rather than guessed.** A strategy the operator did not ask for is
/// a deployment that runs differently from the one in the file, and nothing
/// says so: the traffic still flows, just not the way the config claims, and a
/// mistyped strategy is otherwise invisible.
///
/// The spellings that have always worked are still accepted.
pub fn get_strategy(strategy: &Option<String>) -> anyhow::Result<crate::lb::LoadBalancingStrategy> {
    match strategy.as_deref() {
        Some("random") | Some("Random") => Ok(crate::lb::LoadBalancingStrategy::Random),
        Some("round_robin") | Some("RoundRobin") | Some("roundrobin") => {
            Ok(crate::lb::LoadBalancingStrategy::RoundRobin)
        }
        Some("least_conn") | Some("LeastConn") | Some("leastconn") => {
            Ok(crate::lb::LoadBalancingStrategy::LeastConn)
        }
        None => Ok(crate::lb::LoadBalancingStrategy::RoundRobin),
        Some(other) => anyhow::bail!(
            "strategy {other:?} is not a load balancing strategy; expected \"round_robin\" \
             (the default), \"random\" or \"least_conn\""
        ),
    }
}

/// Reads the `mode` key.
///
/// Refused rather than guessed, for the reason [`get_strategy`] gives: a route
/// that serves something other than what the file says is a routing surprise
/// nobody is told about.
pub fn get_route_mode(mode: &Option<String>) -> anyhow::Result<RouteMode> {
    match mode.as_deref() {
        None => Ok(RouteMode::Http),
        Some(name) => parse_route_mode(name),
    }
}

/// One mode name, as written in `mode` or in one entry of `modes`.
///
/// Refused rather than guessed, for the reason [`get_strategy`] gives. The
/// spellings that have always worked are still accepted.
pub fn parse_route_mode(mode: &str) -> anyhow::Result<RouteMode> {
    match mode {
        "http" | "Http" | "HTTP" => Ok(RouteMode::Http),
        "passthrough" | "Passthrough" => Ok(RouteMode::Passthrough),
        "tcp" | "Tcp" | "TCP" => Ok(RouteMode::Tcp),
        "udp" | "Udp" | "UDP" => Ok(RouteMode::Udp),
        other => anyhow::bail!(
            "mode {other:?} is not a route mode; expected \"http\" (the default), \
             \"passthrough\", \"tcp\" or \"udp\""
        ),
    }
}

/// Every mode a route serves: the union of `mode` and `modes`, deduplicated.
///
/// Two keys exist so that the common case stays one line — `modes = ["http", "tcp"]`
/// — while `mode = "tcp"` keeps working. An empty `modes` list is not "serve
/// nothing": it leaves `mode` (or the `http` default) in place, because a route
/// that serves no mode is a silent hole in the table rather than a meaningful
/// configuration.
pub fn get_route_modes(
    mode: &Option<String>,
    modes: &Option<Vec<String>>,
) -> anyhow::Result<Vec<RouteMode>> {
    let mut resolved: Vec<RouteMode> = Vec::new();

    if let Some(single) = mode {
        push_mode(&mut resolved, parse_route_mode(single)?);
    }
    for name in modes.iter().flatten() {
        push_mode(&mut resolved, parse_route_mode(name)?);
    }

    Ok(if resolved.is_empty() {
        vec![RouteMode::Http]
    } else {
        resolved
    })
}

pub(crate) fn push_mode(resolved: &mut Vec<RouteMode>, mode: RouteMode) {
    if !resolved.contains(&mode) {
        resolved.push(mode);
    }
}

/// Rejects a backend URL that cannot work.
///
/// Two schemes are fetchable: `http://` and `https://`. The second one means
/// this process *originates* a TLS session towards the backend and verifies
/// the certificate it gets back — it still holds no certificate of its own and
/// still terminates nothing on the client's behalf. A backend that only
/// speaks TLS on the same port as its plain listener is a `passthrough`
/// route's business; a backend that is *fetched* over TLS is this.
///
/// Anything else is refused at startup rather than attempted, because a
/// request to it cannot work and the operator would rather read about it here
/// than in a 502.
pub fn validate_backend(label: &str, mode: RouteMode, backend: &str) -> anyhow::Result<()> {
    // Passthrough only needs a host and a port — the scheme carries no meaning
    // because those bytes are never interpreted — but it still has to name one.
    // Checked with the function the route will dial it with, so what starts is
    // what runs: an address that only fails at connect time turns every
    // connection into a 502 with nothing at startup to explain it.
    if mode == RouteMode::Passthrough {
        return match crate::passthrough::parse_backend_addr(backend) {
            Some((host, port)) if !host.is_empty() && port != 0 => Ok(()),
            _ => anyhow::bail!(
                "{label}: backend \"{backend}\" is not an address a passthrough route can dial; \
                 expected host:port, for example \"10.0.0.5:443\" or \"[::1]:443\""
            ),
        };
    }

    // An L4 backend is an address to dial, not a URL to fetch, so it is checked
    // against different rules than an HTTP one.
    if mode.is_l4() {
        return validate_l4_backend(label, backend);
    }

    let url = url::Url::parse(backend).map_err(|e| {
        anyhow::anyhow!(
            "{label}: backend \"{backend}\" is not a URL ({e}); expected http://host:port"
        )
    })?;

    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => anyhow::bail!(
            "{label}: backend \"{backend}\" uses {scheme}://, which is not a scheme this proxy can \
             fetch; expected http://host:port or https://host:port. A backend that serves TLS \
             only, with no plain listener beside it, belongs to a passthrough route."
        ),
    }
}

/// Rejects an L4 backend that does not name exactly one address.
///
/// Both `host:port` and `scheme://host:port` are accepted — the scheme is ignored,
/// because these bytes are never interpreted as HTTP — but the port is mandatory and a
/// path is refused. An L4 route dials its backend directly, so there is nothing to
/// guess: a bare host would have to default to some port, and every such default is
/// wrong for somebody. Failing at startup beats a tunnel that connects to the wrong
/// service.
pub(crate) fn validate_l4_backend(label: &str, backend: &str) -> anyhow::Result<()> {
    let trimmed = backend.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{label}: backend is empty; expected host:port");
    }

    let (host, port) = if trimmed.contains("://") {
        let url = url::Url::parse(trimmed).map_err(|e| {
            anyhow::anyhow!("{label}: backend \"{backend}\" is not a URL ({e}); expected host:port")
        })?;
        let host = url.host_str().unwrap_or_default().to_string();
        if host.is_empty() {
            anyhow::bail!("{label}: backend \"{backend}\" names no host; expected host:port");
        }
        // A special scheme (`http://`) fills in "/" for an empty path; a non-special one
        // (`tcp://`, `udp://`) leaves it empty. Both mean "no path".
        if !matches!(url.path(), "" | "/") {
            anyhow::bail!(
                "{label}: backend \"{backend}\" has a path, but an L4 route dials an address \
                 rather than fetching a URL; expected {host}:<port>"
            );
        }
        (host, url.port())
    } else {
        match trimmed.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (
                host.to_string(),
                port.parse::<u16>().ok().filter(|port| *port != 0),
            ),
            // A bare host, an IPv6 literal without brackets, or something that is not
            // a port at all.
            _ => (trimmed.to_string(), None),
        }
    };

    match port {
        Some(port) => {
            tracing::debug!("L4 route {label}: dials {host}:{port}");
            Ok(())
        }
        None => anyhow::bail!(
            "{label}: backend \"{backend}\" does not name a port. An L4 route dials its backend \
             directly, so the port cannot be defaulted; write it as {host}:5432"
        ),
    }
}

/// Refuses TOTP parameters the validator cannot honour as written.
///
/// `window` is the one that was quietly wrong: it is handed to the TOTP library
/// as a `u8`, so anything above 255 was truncated by the cast — `window = 300`
/// became 44, which widens a code's validity from ±5 minutes to ±22 minutes,
/// and `window = 256` became 0. The other two only failed later, inside the
/// library, at the first login and with nothing to say which knob was wrong.
pub(crate) fn validate_totp_parameters(
    time_step: u32,
    digits: u32,
    window: u32,
) -> anyhow::Result<()> {
    if time_step == 0 {
        anyhow::bail!(
            "[auth] time_step is 0: a code would cover no time at all, and the step is what \
             the counter is divided by"
        );
    }
    if !(6..=8).contains(&digits) {
        anyhow::bail!("[auth] digits is {digits}: a code is 6, 7 or 8 digits long");
    }
    if window > u8::MAX as u32 {
        anyhow::bail!(
            "[auth] window is {window}, above the {max} the TOTP library's field holds: larger \
             values were silently truncated, so 300 came out as 44",
            max = u8::MAX
        );
    }
    if window > 10 {
        // Legal, but wide enough to be worth saying out loud: `window` counts
        // steps in *both* directions, so 10 already means a code stays valid
        // for ten minutes either side of now.
        tracing::warn!(
            "[auth] window is {window}: a code stays valid for {} minutes either side of now",
            window * time_step / 60
        );
    }
    Ok(())
}
