//! The one backend dial, and the one backend address parser.
//!
//! Two paths reach a backend: the TLS passthrough ([`crate::passthrough`]) and
//! the L4 tunnel ([`crate::l4`]). Each used to carry its own copy of both, and
//! the copies had already drifted apart: the same configured backend was read
//! one way by one path and refused by the other, and one blackholed address
//! could spend the whole connect budget, so the address after it — the one
//! that would have worked — was never dialled.
//!
//! Both live here now. What the two paths genuinely want to say *differently*
//! is a parameter and not a fork: [`PortDefault`] says what a backend address
//! means when it does not name a port, and the caller says which reading it
//! means.
//!
//! # The budget
//!
//! One deadline covers the resolution and every address it names, so a backend
//! with many addresses cannot multiply the budget. Each address then gets a
//! *share* of what is left of it, so an address that blackholes — an IPv6
//! address on a network without IPv6, where the SYN goes nowhere — cannot
//! spend all of it and strand the addresses after it.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// The smallest share of the connect budget one address attempt gets.
///
/// A long list of addresses must not cut a real one off after a few
/// milliseconds. The share is a floor; the one overall deadline is what caps
/// the total.
const MIN_ADDRESS_SHARE: Duration = Duration::from_millis(250);

/// What a backend address means when it does not name a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortDefault {
    /// The address has to name its port.
    ///
    /// An L4 route dials a raw port, and there is nothing to guess: every
    /// default is wrong for somebody, and a tunnel that opens the wrong
    /// service is worse than one that fails to open.
    Required,

    /// The port comes from the scheme when the address names one, and from
    /// `bare` when it does not.
    ///
    /// This is the passthrough reading: the bytes are forwarded to a listener
    /// that terminates TLS, so `https://host` is the HTTPS port and a bare
    /// `host` is the TLS port.
    SchemeOrBare { bare: u16 },
}

/// Reads a backend address: `host:port`, `[::1]:port`, or a URL.
///
/// The port is the only thing the two callers read differently, and that is
/// what `default` is for: the passthrough may fall back to the scheme's port,
/// the L4 path may not. Everything else — the host, the brackets around an
/// IPv6 literal, the refusal of an address that names no host — is the same
/// for both, because it was the same in only one of the two copies before.
///
/// The scheme carries no meaning on either path: passthrough copies bytes and
/// never speaks TLS itself, and an L4 route dials an address rather than
/// fetching a URL. Both accept it anyway, which keeps the backend list in
/// the same shape as the HTTP routes.
pub(crate) fn parse_backend_addr(backend: &str, default: PortDefault) -> Option<(String, u16)> {
    let backend = backend.trim();
    if backend.is_empty() {
        return None;
    }

    if backend.contains("://") {
        let url = url::Url::parse(backend).ok()?;
        let host = url.host_str()?;
        if host.is_empty() {
            return None;
        }
        let port = match url.port() {
            Some(port) => port,
            // No port in the URL. The scheme's own default is what the URL
            // would have used, and it is a default only the passthrough may
            // fall back to.
            None => match default {
                PortDefault::Required => return None,
                PortDefault::SchemeOrBare { .. } => url.port_or_known_default()?,
            },
        };
        return Some((strip_ipv6_brackets(host).to_string(), port));
    }

    // A bracketed IPv6 literal: the colons inside the address come before the
    // one that separates the port, so the brackets have to go first.
    if let Some(rest) = backend.strip_prefix('[') {
        // An unclosed bracket is not a host name anyone can resolve.
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return match tail.strip_prefix(':') {
            Some(port) => Some((host.to_string(), port.parse().ok()?)),
            None => match default {
                PortDefault::Required => None,
                PortDefault::SchemeOrBare { bare } => Some((host.to_string(), bare)),
            },
        };
    }

    match backend.rsplit_once(':') {
        Some((host, port)) => {
            // An empty host is not a host: `:5432` names a port and nothing
            // else, and dialling it would look for a host called ":5432".
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port.parse().ok()?))
        }
        None => match default {
            PortDefault::Required => None,
            PortDefault::SchemeOrBare { bare } => Some((backend.to_string(), bare)),
        },
    }
}

/// Drops the brackets around an IPv6 literal.
///
/// Both forms a config can use keep them — `Url::host_str()` hands back
/// `[::1]`, and so does splitting `[::1]:443` on the colon — and leaving them
/// on makes the resolver look for a host actually called `[::1]`, which no
/// backend ever is.
fn strip_ipv6_brackets(host: &str) -> &str {
    host.trim_matches(['[', ']'])
}

/// Dials a backend within `[timeouts] connect_secs`.
///
/// One deadline for the resolution and for every address it names, so a
/// backend with many addresses cannot multiply the budget. Each address gets
/// a share of what is left of that deadline, so one that blackholes cannot
/// spend all of it.
pub(crate) async fn connect(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> anyhow::Result<TcpStream> {
    // The name is resolved through the cache, so this dial does not wait for a
    // `getaddrinfo` that the connection before it already paid for. The
    // addresses are then tried in turn, which is what
    // `TcpStream::connect((host, port))` did too.
    let deadline = Instant::now() + connect_timeout;
    let addrs = tokio::time::timeout_at(deadline, crate::dns::resolve_to(host, port))
        .await
        .map_err(|_| anyhow::anyhow!("timed out resolving backend {host}:{port}"))?
        // The resolver's own words are part of the message the log prints —
        // it prints the top-level message — and the error they came from
        // stays the source of the chain.
        .map_err(|e| {
            let message = format!("cannot resolve backend {host}:{port}: {e}");
            e.context(message)
        })?;

    connect_addrs(&addrs, deadline).await.map_err(|e| {
        let message = format!("failed to connect to backend {host}:{port}: {e}");
        e.context(message)
    })
}

/// Tries the addresses in turn, under one deadline.
///
/// The deadline is handed in rather than computed here: the resolution that
/// produced the addresses is inside the same budget, so a backend with many
/// addresses cannot multiply it.
pub(crate) async fn connect_addrs(
    addrs: &[SocketAddr],
    deadline: Instant,
) -> anyhow::Result<TcpStream> {
    connect_addrs_with(addrs, deadline, TcpStream::connect).await
}

/// Tries the addresses in turn, under one deadline and a share of it each.
///
/// `dial` is the dial one attempt makes. It is a parameter so that a test can
/// install an address that never answers: a real blackhole cannot be
/// reproduced on a build machine, and the budget rule is exactly what has to
/// be tested.
pub(crate) async fn connect_addrs_with<F, Fut>(
    addrs: &[SocketAddr],
    deadline: Instant,
    dial: F,
) -> anyhow::Result<TcpStream>
where
    F: Fn(SocketAddr) -> Fut + Send,
    Fut: Future<Output = io::Result<TcpStream>> + Send,
{
    let mut outcomes: Vec<String> = Vec::with_capacity(addrs.len());

    for (index, addr) in addrs.iter().enumerate() {
        let now = Instant::now();
        if now >= deadline {
            // The budget is spent. The addresses that are left are named in
            // the error and none of them is dialled: a connect that cannot
            // finish inside the budget is not worth a SYN.
            for addr in &addrs[index..] {
                outcomes.push(format!("{addr}: not tried (the connect budget was spent)"));
            }
            break;
        }

        let attempt_deadline = share_deadline(now, deadline, (addrs.len() - index) as u32);
        match tokio::time::timeout_at(attempt_deadline, dial(*addr)).await {
            Ok(Ok(stream)) => {
                // The tunnel carries TLS records; Nagle would only add latency
                // here.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => outcomes.push(format!("{addr}: {e}")),
            Err(_) => outcomes.push(format!("{addr}: timed out")),
        }
    }

    if outcomes.is_empty() {
        return Err(anyhow::anyhow!("there was no address to try"));
    }

    // Every address is named, not only the last one: an operator has to be
    // able to see that the address that would have worked was never reached.
    Err(anyhow::anyhow!(
        "no address answered: {}",
        outcomes.join("; ")
    ))
}

/// The deadline one address attempt gets.
///
/// An equal share of what is left of the budget, so a blackholed address can
/// only spend its own share and the addresses after it are still tried. The
/// share has a floor, so a long list of addresses cannot cut a real one off
/// after a few milliseconds; the one overall deadline is what caps the
/// total.
fn share_deadline(now: Instant, deadline: Instant, left: u32) -> Instant {
    let remaining = deadline.saturating_duration_since(now);
    let share = remaining / left.max(1);
    (now + share.max(MIN_ADDRESS_SHARE)).min(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};

    /// The passthrough reading: a URL's scheme names its port, and a bare
    /// host is the TLS port.
    const PASSTHROUGH: PortDefault = PortDefault::SchemeOrBare { bare: 443 };

    #[test]
    fn both_paths_read_the_same_address_the_same_way() {
        // Every spelling that carries its own port is read the same way by
        // both paths: one parser, one answer.
        for backend in [
            "caddy:443",
            "https://caddy:8443",
            "tcp://db.internal:5432",
            "10.0.0.5:8080",
            "[::1]:443",
            "https://[::1]:8443",
        ] {
            assert_eq!(
                parse_backend_addr(backend, PortDefault::Required),
                parse_backend_addr(backend, PASSTHROUGH),
                "{backend}",
            );
        }
    }

    #[test]
    fn the_port_default_is_the_callers_intent_and_not_an_accident() {
        // The passthrough forwards a TLS session: `https://host` is the HTTPS
        // port and a bare `host` is the TLS port.
        assert_eq!(
            parse_backend_addr("https://host", PASSTHROUGH),
            Some(("host".to_string(), 443))
        );
        assert_eq!(
            parse_backend_addr("http://host", PASSTHROUGH),
            Some(("host".to_string(), 80))
        );
        assert_eq!(
            parse_backend_addr("host", PASSTHROUGH),
            Some(("host".to_string(), 443))
        );

        // The L4 path dials a raw port, so the port has to be named: an
        // address that leaves it out is refused rather than guessed at.
        assert_eq!(
            parse_backend_addr("https://host", PortDefault::Required),
            None
        );
        assert_eq!(
            parse_backend_addr("http://host", PortDefault::Required),
            None
        );
        assert_eq!(parse_backend_addr("host", PortDefault::Required), None);
    }

    #[test]
    fn an_ipv6_literal_loses_its_brackets_on_both_paths() {
        // With the brackets left on, the resolver is asked for a host called
        // "[::1]" and every connection to this backend fails.
        for default in [PortDefault::Required, PASSTHROUGH] {
            assert_eq!(
                parse_backend_addr("[::1]:443", default),
                Some(("::1".to_string(), 443))
            );
            assert_eq!(
                parse_backend_addr("https://[::1]:8443", default),
                Some(("::1".to_string(), 8443))
            );
        }
    }

    #[test]
    fn an_address_without_a_host_is_refused() {
        for default in [PortDefault::Required, PASSTHROUGH] {
            assert_eq!(parse_backend_addr("", default), None);
            assert_eq!(parse_backend_addr("   ", default), None);
            assert_eq!(parse_backend_addr(":5432", default), None);
            assert_eq!(parse_backend_addr("caddy:notaport", default), None);
        }
    }

    /// A stream that is already open, and the address it is open to.
    ///
    /// The dial inside the test must not do any real I/O: the clock is
    /// paused, and a paused clock advances itself while the runtime waits —
    /// which would cut the attempt short before the socket was ready. The
    /// listener is handed back as well and kept alive, because a connection
    /// whose peer has gone is no longer connected.
    async fn open_stream() -> (tokio::net::TcpListener, TcpStream, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        (listener, stream, addr)
    }

    #[tokio::test(start_paused = true)]
    async fn a_blackholed_address_leaves_the_budget_for_the_next_one() {
        // The backend resolves to an IPv6 address first and an IPv4 address
        // second. On a network without IPv6 the first one blackholes, and the
        // second one — the one that would have worked — is never reached.
        let (_listener, stream, accepting) = open_stream().await;
        let blackhole: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        let dialled = Arc::new(Mutex::new(Vec::new()));
        let recorder = dialled.clone();
        // The stream the dial hands back, taken once: only the address that
        // answers is ever given one.
        let open = Arc::new(Mutex::new(Some(stream)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let started = Instant::now();

        let connected = connect_addrs_with(&[blackhole, accepting], deadline, move |addr| {
            let recorder = recorder.clone();
            let open = open.clone();
            async move {
                recorder.lock().unwrap().push(addr);
                if addr == blackhole {
                    // Never answers: the SYN goes nowhere.
                    std::future::pending::<io::Result<TcpStream>>().await
                } else {
                    let open = open.lock().unwrap().take().unwrap();
                    Ok(open)
                }
            }
        })
        .await
        .expect("the address after the blackhole should have been tried");

        assert_eq!(connected.peer_addr().unwrap(), accepting);
        assert_eq!(
            *dialled.lock().unwrap(),
            vec![blackhole, accepting],
            "the address after the blackhole has to be dialled"
        );

        // The blackhole spent its share of the budget — half of it, because
        // two addresses were left — and not the whole of it.
        let elapsed = started.elapsed();
        assert!(
            elapsed <= Duration::from_millis(5500),
            "the first address should have spent its share, not the whole budget, took {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn many_addresses_cannot_multiply_the_budget() {
        // Eight addresses, none of which answers. The whole dial is bounded by
        // the one deadline: eight addresses must not make it eight times as
        // long.
        let addrs: Vec<SocketAddr> = (0..8)
            .map(|i| SocketAddr::new(IpAddr::from([10, 0, 0, i]), 443))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        let started = Instant::now();

        let error = connect_addrs_with(&addrs, deadline, |_addr| async {
            std::future::pending::<io::Result<TcpStream>>().await
        })
        .await
        .expect_err("no address answers");

        let elapsed = started.elapsed();
        assert!(
            elapsed <= Duration::from_secs(10) + Duration::from_millis(100),
            "the dial has to end with the one deadline, took {elapsed:?}"
        );

        // Every address is named, so an operator can see which one was never
        // reached.
        for addr in &addrs {
            assert!(
                error.to_string().contains(&addr.to_string()),
                "the error should name {addr}, got {error}"
            );
        }
    }
}
