use anyhow::Result;

// The per-domain virtual IP mapping is the same one the smoltcp stack routes by
// (nexapipe-client's): an address this server hands out must be an address the
// stack can reverse-lookup, so both share one instance and one pool.
pub use nexapipe_client::virtual_ip::IpMapping;

use nexapipe_client::dns::UpstreamResolvers;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// How long one upstream is given to answer before the next is tried.
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// How many of the machine's own resolvers the upstream chain may carry.
///
/// Every one of them that does not answer costs a 1.5s window before the next is
/// tried, so an unbounded list of them would turn "the resolver is slow" into
/// "the query never finishes". Two is what a machine normally has.
pub(crate) const MAX_PREVIOUS_RESOLVERS: usize = 2;

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    pub listen_addr: String,
    pub upstream_dns: String,
    pub proxy_domains: Vec<String>,
}

/// DNS server — implements DNS hijacking
pub struct DnsServer {
    config: DnsServerConfig,
    /// The resolvers the machine was using before the hijack displaced them, in
    /// the order they are tried. Kept out of [`DnsServerConfig`] because it is
    /// not configuration: it is read off the host at the moment the tunnel comes
    /// up, and a caller that builds a config before then has none to give.
    previous_resolvers: Vec<String>,
    ip_mapping: Arc<IpMapping>,
    stopped: Arc<AtomicBool>,
}

impl DnsServer {
    pub fn new(config: DnsServerConfig, ip_mapping: Arc<IpMapping>) -> Self {
        Self {
            config,
            previous_resolvers: Vec::new(),
            ip_mapping,
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Records the resolvers the machine was using before the hijack, so that
    /// domains this proxy does not handle are still answered by whoever was
    /// authoritative for them — see [`forwardable_resolvers`].
    pub fn with_previous_resolvers(mut self, resolvers: Vec<String>) -> Self {
        self.previous_resolvers = resolvers;
        self
    }

    pub fn stopped_flag(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }

    /// Binds the DNS listening socket (eager bind).
    ///
    /// The caller must confirm the bind succeeded before pointing system DNS at
    /// `listen_addr`, otherwise system DNS would point at an address nobody listens on and
    /// break name resolution for the entire machine (which also disconnects the iroh relay).
    /// On Windows, if the TUN interface address (see `tun_proxy::tun_ip()`) is not ready yet,
    /// this returns WSAEADDRNOTAVAIL (10049).
    pub async fn bind(&self) -> Result<Arc<UdpSocket>> {
        let socket = Arc::new(UdpSocket::bind(&self.config.listen_addr).await?);
        tracing::info!("DNS server listening on: {}", self.config.listen_addr);
        Ok(socket)
    }

    /// Runs the DNS server main loop on an already bound socket.
    pub async fn run_with_socket(&self, socket: Arc<UdpSocket>) -> Result<()> {
        let proxy_domains = Arc::new(self.config.proxy_domains.clone());
        let ip_mapping = self.ip_mapping.clone();
        let stopped = self.stopped.clone();

        // The upstream resolvers, and the sockets they are asked through.
        //
        // One socket per resolver, kept for as long as this server runs: a
        // socket per query would mean a new source port for every lookup,
        // and every router between the machine and the resolver would have to
        // build a NAT mapping for it — and tear it down again as soon as the
        // answer was in.
        let upstreams = resolver_chain(&self.previous_resolvers, &self.config.upstream_dns);
        let addresses: Vec<std::net::SocketAddr> = upstreams
            .iter()
            .filter_map(|server| server.parse().ok())
            .collect();
        // The chain is tried in turn, and each one is given a window, so the
        // whole chain is given one window per member and a little over.
        let overall = UPSTREAM_TIMEOUT * addresses.len() as u32 + std::time::Duration::from_secs(1);
        let resolvers = Arc::new(UpstreamResolvers::with_timeouts(
            &addresses,
            stopped.clone(),
            UPSTREAM_TIMEOUT,
            overall,
        ));

        loop {
            if stopped.load(Ordering::Acquire) {
                tracing::info!("DNS server stopping");
                break;
            }

            let mut buf = [0u8; 4096];
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                socket.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, addr))) => {
                    let data = buf[..len].to_vec();
                    let socket = socket.clone();
                    let proxy_domains = proxy_domains.clone();
                    let ip_mapping = ip_mapping.clone();
                    let resolvers = resolvers.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_dns_query(
                            &socket,
                            &data,
                            addr,
                            &resolvers,
                            &proxy_domains,
                            &ip_mapping,
                        )
                        .await
                        {
                            tracing::debug!("DNS query handler error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    tracing::error!("DNS recv error: {}", e);
                }
                Err(_) => {
                    continue;
                }
            }
        }
        Ok(())
    }
}

/// Handles a single DNS query
async fn handle_dns_query(
    socket: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: std::net::SocketAddr,
    resolvers: &UpstreamResolvers,
    proxy_domains: &[String],
    ip_mapping: &IpMapping,
) -> Result<()> {
    if data.len() < 12 {
        return Ok(());
    }

    // Parse the DNS query. The codec is the client's, which runs a DNS server
    // of its own for the TUN: one copy of what a question is and what an
    // answer looks like, so the two cannot answer the same question
    // differently.
    let query = match nexapipe_client::dns::parse_query(data) {
        Some(q) => q,
        None => {
            tracing::debug!("Failed to parse DNS query");
            return Ok(());
        }
    };

    tracing::debug!("DNS query: {} (type {})", query.domain, query.qtype);

    // Check whether the domain is in the proxy list (suffix match on subdomains)
    if should_proxy_domain(&query.domain, proxy_domains) {
        // A gets an address from the IPv4 pool, AAAA from the IPv6 one — and the
        // IPv6 pool only exists when the TUN actually got an IPv6 address to
        // route (see routing::configure_ipv6). Without it the honest answer is
        // the empty NOERROR that sends the resolver back to A, not an address
        // that leads nowhere.
        //
        // The **class** is part of the question too, and what goes back is an IN
        // record: handing one out for a CH or ANY question answers something
        // that was not asked. Only a question in the Internet class gets an
        // address — and the client says the same thing, which is the point of
        // the codec being the client's: one rule, or two answers to one
        // question.
        let in_class = query.qclass == nexapipe_client::dns::DNS_CLASS_IN;
        let answer = match query.qtype {
            1 if in_class => Some(std::net::IpAddr::V4(ip_mapping.allocate(&query.domain))),
            28 if in_class => ip_mapping
                .allocate_v6(&query.domain)
                .map(std::net::IpAddr::V6),
            _ => None,
        };

        let response = match answer {
            Some(address) => {
                tracing::info!("DNS hijack: {} -> {}", query.domain, address);
                nexapipe_client::dns::build_response(&query, address)
            }
            None => {
                // Every other type (AAAA with no IPv6 pool, MX, ...) gets an empty NOERROR
                // reply so the query is not leaked upstream and browser resolution is not
                // disturbed.
                nexapipe_client::dns::build_empty_response(&query)
            }
        };
        socket.send_to(&response, client_addr).await?;
        return Ok(());
    }

    // Non-proxied domains: forward upstream. The machine's own resolvers come
    // first — see [`resolver_chain`] for why — and the public fallbacks close the
    // chain for when none of them answers.
    forward_to_upstream(socket, data, client_addr, resolvers).await
}

/// Of the resolvers a host reports, the ones worth forwarding a query to.
///
/// A machine's own resolvers are the only ones that can answer its
/// split-horizon and internal names, and on a host that already runs another
/// tunnel they are that tunnel's resolver — asking a public one instead routes
/// around both. What makes one *not* worth asking:
///
/// - it is an address this hijack answers on itself (`ours`), which is a loop
///   and not a lookup;
/// - it is one of the TUN addresses the hijack points system DNS at, which is
///   the same loop left over from a run that never restored;
/// - it is loopback, which on a machine running a local stub is the stub the
///   hijack itself feeds: rewriting `/etc/resolv.conf` makes dnsmasq or
///   resolved forward at the TUN, so asking it is asking ourselves;
/// - it is unspecified, or link-local (a `fe80::` address cannot be dialled
///   without the scope id this process does not know).
///
/// Deduplicated and capped at `limit`, both because a repeated or unreachable
/// address costs a 1.5s window each time it is tried.
pub(crate) fn forwardable_resolvers(
    candidates: &[String],
    ours: &[IpAddr],
    limit: usize,
) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for candidate in candidates {
        let Ok(ip) = candidate.parse::<IpAddr>() else {
            continue;
        };
        if ours.contains(&ip) || ip.is_loopback() || ip.is_unspecified() || is_link_local(&ip) {
            continue;
        }
        if crate::proxy::dns_config::is_tun_dns_address(candidate) {
            continue;
        }
        if kept.contains(candidate) {
            continue;
        }
        kept.push(candidate.clone());
        if kept.len() >= limit {
            break;
        }
    }
    kept
}

/// Whether `ip` is a link-local address: one that names a link as well as a
/// host, so dialling it needs a scope id this process does not have.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..2] == [169, 254],
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// `address` with a port, so a bare address a platform reported can be compared
/// with — and stand next to — the configured `host:port`.
fn with_default_port(address: &str) -> String {
    match address.parse::<std::net::SocketAddr>() {
        Ok(_) => address.to_string(),
        // Either a bare IPv4 address, or a bare IPv6 one that needs brackets.
        Err(_) if address.contains(':') => format!("[{address}]:53"),
        Err(_) => format!("{address}:53"),
    }
}

/// The upstreams to try, in order: the machine's own resolvers first, then the
/// configured one, then the public fallbacks.
///
/// The order is the point. A resolver this machine was already using is the one
/// whose answers are right for it — an internal zone, a split-horizon name, or
/// the fake-IP answers another tunnel hands out — and a public resolver asked
/// the same question answers NXDOMAIN for all of them. The configured upstream
/// and the fallbacks stay behind them so the chain still ends somewhere when the
/// machine's own resolvers are unreachable.
///
/// Shared with the TUN stack, which forwards along the same list — see
/// `tun_proxy::run`. Both have to ask the same servers in the same order, or
/// the same name gets two answers depending on which path carried the query.
pub(crate) fn resolver_chain(previous: &[String], configured: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let candidates = previous
        .iter()
        .map(|server| with_default_port(server))
        .chain(std::iter::once(configured.to_string()))
        .chain(FALLBACK_UPSTREAMS.iter().map(|server| server.to_string()));
    for candidate in candidates {
        if !chain.contains(&candidate) {
            chain.push(candidate);
        }
    }
    chain
}

/// Fallback upstream resolvers, tried in order when the configured upstream times out or is
/// unreachable.
/// The default 8.8.8.8 is unreachable on some networks (e.g. direct connections in mainland
/// China), which breaks iroh relay resolution ("No addressing information available"), so we
/// fall back through public resolvers that are reachable there.
pub(crate) const FALLBACK_UPSTREAMS: &[&str] = &[
    "223.5.5.5:53",       // AliDNS
    "114.114.114.114:53", // 114 DNS
    "1.1.1.1:53",         // Cloudflare
];

/// Forwards the query along the chain, returning the first successful reply.
///
/// The chain is tried in turn, and each upstream gets a window. Only a
/// response coming from the upstream we queried is accepted (spoofing
/// protection) — that is the shared resolver's own rule, and it is the one
/// this path has always had.
async fn forward_to_upstream(
    socket: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: std::net::SocketAddr,
    resolvers: &UpstreamResolvers,
) -> Result<()> {
    match resolvers.forward(data).await {
        Some(answer) => {
            socket.send_to(&answer, client_addr).await?;
        }
        None => tracing::debug!("All upstream DNS servers failed for query"),
    }
    Ok(())
}

/// A configured proxy domain reduced to the bare suffix it covers: no leading
/// `*`, no leading or trailing dot, lower case.
///
/// This is the **scope** the per-domain DNS hijack hands to the operating
/// system, not the pattern the per-query decision is made with: a file under
/// `/etc/resolver`, a systemd-resolved routing domain and an NRPT suffix rule
/// all name a *domain*, and a domain covers the name and its subdomains.
///
/// So the scope is the wider of the two, and the question "is this particular
/// name one to hand a virtual address for" is answered per query, with the
/// server's rule. A name the scope covers but the rule does not is forwarded
/// to the real resolver and resolves for real; a name the rule covers but the
/// scope does not would never arrive here, which is why the scope is derived
/// from the pattern rather than the other way round.
pub fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase()
}

/// The configured domains as a per-domain hijack, or `None` when they cannot be
/// written as one.
///
/// Such a hijack has to name every domain to the OS, so `None` is the answer for
/// a configuration containing one that cannot be named — a bare `*`, which means
/// every domain and is the global hijack this replaces, or a label with no dot,
/// which is a hostname rather than a domain. It is also the answer for no
/// domains at all, which is a proxy that resolves nothing and is left to behave
/// exactly as it does today.
///
/// All or nothing, then: a hijack covering part of the configured domains would
/// leave the rest unproxied and unreported, where a global hijack at least
/// resolves them all.
pub fn scoped_domains(proxy_domains: &[String]) -> Option<Vec<String>> {
    if proxy_domains.is_empty() {
        return None;
    }
    let mut scoped: Vec<String> = Vec::new();
    for domain in proxy_domains {
        let normalized = normalize_domain(domain);
        if !is_scoped_domain(&normalized) {
            return None;
        }
        if !scoped.contains(&normalized) {
            scoped.push(normalized);
        }
    }
    Some(scoped)
}

/// Whether a normalized suffix can be named to the OS as a domain of its own.
///
/// Kept to what a domain can contain, because on at least one platform the
/// suffix becomes a path: `/etc/resolver/<domain>`. A name that could reach
/// outside that directory is not a domain this machine ever had.
fn is_scoped_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Checks whether a domain should be proxied.
///
/// The one rule, and it is the server's: a name (`example.com`), a dotted
/// wildcard (`*.example.com`, its subdomains and not the apex) or the
/// catch-all (`*`). The same rule decides which routes the server serves and
/// which names a client puts in the tunnel, so a name this answers with a
/// virtual address is a name the server can have a route for.
///
/// It used to be DOMAIN-SUFFIX here — a bare `example.com` meant the name and
/// every subdomain — which is why this file and the client's own copy of the
/// question could answer differently for the same config.
fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    nexapipe_client::should_proxy_domain(host, proxy_domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// The address every hijack points system DNS at: `…254` of the block in use.
    fn a_tun_dns_address() -> String {
        Ipv4Addr::from(u32::from(TUN_BASE_CANDIDATES[0]) | 0x0000_00FE).to_string()
    }

    /// The whole point of the chain: the resolver the machine was already using
    /// is asked before the configured one and before any public fallback, because
    /// it is the only one that can answer that machine's own names.
    #[test]
    fn the_machines_own_resolvers_come_first() {
        let chain = resolver_chain(&["192.168.1.1".to_string()], "8.8.8.8:53");
        assert_eq!(chain[0], "192.168.1.1:53");
        assert_eq!(chain[1], "8.8.8.8:53");
        // The public fallbacks still close the chain: a machine whose own
        // resolvers are unreachable must not be left without an answer.
        assert_eq!(chain.len(), 1 + 1 + FALLBACK_UPSTREAMS.len());
    }

    /// Two machines' resolvers, then the configured one, then the fallbacks.
    #[test]
    fn every_resolver_in_the_chain_appears_once() {
        let chain = resolver_chain(
            &["192.168.1.1".to_string(), "10.0.0.1".to_string()],
            "8.8.8.8:53",
        );
        assert_eq!(
            chain,
            vec![
                "192.168.1.1:53",
                "10.0.0.1:53",
                "8.8.8.8:53",
                "223.5.5.5:53",
                "114.114.114.114:53",
                "1.1.1.1:53",
            ]
        );
    }

    /// A machine whose resolver is also the configured upstream — or one of the
    /// public fallbacks — does not get asked twice, and keeps its place at the
    /// front rather than being pushed behind the fallbacks.
    #[test]
    fn a_resolver_repeated_later_in_the_chain_is_asked_once() {
        let chain = resolver_chain(&["223.5.5.5".to_string()], "223.5.5.5:53");
        assert_eq!(
            chain,
            vec!["223.5.5.5:53", "114.114.114.114:53", "1.1.1.1:53"]
        );
    }

    /// A bare address a platform reported has to come out comparable with the
    /// configured `host:port`, or the de-duplication above never matches it.
    #[test]
    fn a_bare_address_gets_a_port_and_a_bare_ipv6_one_gets_brackets() {
        assert_eq!(with_default_port("192.168.1.1"), "192.168.1.1:53");
        assert_eq!(with_default_port("fd00::1"), "[fd00::1]:53");
        assert_eq!(with_default_port("8.8.8.8:53"), "8.8.8.8:53");
    }

    /// A resolver that answers what it is asked, and remembers where the
    /// queries came from.
    ///
    /// The answer carries the question it was asked and no records at all: the
    /// shared resolver only needs the question to check the answer against.
    struct FakeUpstream {
        address: std::net::SocketAddr,
        /// The source address of every query that arrived.
        seen: Arc<std::sync::Mutex<Vec<std::net::SocketAddr>>>,
    }

    impl FakeUpstream {
        async fn start() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
            let address = socket.local_addr().expect("the address it got");
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = seen.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(from);
                    let mut reply = buf[..n].to_vec();
                    // QR: this is an answer, not another query.
                    reply[2] |= 0x80;
                    socket.send_to(&reply, from).await.ok();
                }
            });

            Self { address, seen }
        }

        fn seen(&self) -> Vec<std::net::SocketAddr> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    /// A DNS query for `example.com` in the Internet class.
    fn a_query() -> Vec<u8> {
        a_query_in_class(1)
    }

    /// A DNS query for `example.com` in a given class.
    fn a_query_in_class(class: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet
    }

    /// The number of records in an answer.
    fn answer_count(answer: &[u8]) -> u16 {
        u16::from_be_bytes([answer[6], answer[7]])
    }

    /// The class is part of the question, and what goes back is an IN record.
    ///
    /// A question asked in another class must not be answered with one: the
    /// client refuses it, and the codec is the client's — one rule, or two
    /// answers to the same question.
    #[tokio::test]
    async fn a_question_in_another_class_is_answered_with_nothing() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("a free port"));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
        let client_addr = client.local_addr().expect("the address it got");
        let resolvers = UpstreamResolvers::new(&[], Arc::new(AtomicBool::new(false)));
        let mapping = IpMapping::new();
        let domains = vec!["example.com".to_string()];

        // The Internet class gets an address.
        handle_dns_query(
            &socket,
            &a_query(),
            client_addr,
            &resolvers,
            &domains,
            &mapping,
        )
        .await
        .expect("the query is answered");
        let mut buf = [0u8; 512];
        let (read, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("an answer arrives")
        .expect("the answer is received");
        assert_eq!(
            answer_count(&buf[..read]),
            1,
            "a question in the Internet class is answered with an address"
        );

        // Another class gets nothing.
        handle_dns_query(
            &socket,
            &a_query_in_class(3),
            client_addr,
            &resolvers,
            &domains,
            &mapping,
        )
        .await
        .expect("the query is answered");
        let mut buf = [0u8; 512];
        let (read, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("an answer arrives")
        .expect("the answer is received");
        assert_eq!(
            answer_count(&buf[..read]),
            0,
            "a question in another class is answered with nothing"
        );
    }

    /// Every query leaves from the same socket.
    ///
    /// A socket per query would mean a new source port for every lookup, and
    /// every router between the machine and the resolver would have to build a
    /// NAT mapping for it — and tear it down again as soon as the answer was
    /// in. One socket for the lot is what keeps the mapping alive.
    #[tokio::test]
    async fn every_query_leaves_from_the_same_socket() {
        let upstream = FakeUpstream::start().await;
        let resolvers =
            UpstreamResolvers::new(&[upstream.address], Arc::new(AtomicBool::new(false)));

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("a free port"));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
        let client_addr = client.local_addr().expect("the address it got");

        for _ in 0..2 {
            forward_to_upstream(&socket, &a_query(), client_addr, &resolvers)
                .await
                .expect("the query is forwarded");
        }

        let seen = upstream.seen();
        assert_eq!(seen.len(), 2, "both queries reached the resolver");
        assert_eq!(
            seen[0].port(),
            seen[1].port(),
            "both queries left from the same socket"
        );
    }

    /// Asking an address this process answers on itself is a loop, not a lookup:
    /// the query would come straight back and be forwarded again.
    #[test]
    fn our_own_addresses_are_not_forwarding_targets() {
        let ours = vec![
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 254)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let kept = forwardable_resolvers(
            &[
                "198.18.0.254".to_string(),
                "::1".to_string(),
                "192.168.1.1".to_string(),
            ],
            &ours,
            MAX_PREVIOUS_RESOLVERS,
        );
        assert_eq!(kept, vec!["192.168.1.1".to_string()]);
    }

    /// The same loop left behind by a run that never restored: system DNS still
    /// pointing at a TUN address, read back as "what this machine uses".
    #[test]
    fn a_tun_address_left_in_the_system_dns_is_not_a_forwarding_target() {
        let kept = forwardable_resolvers(&[a_tun_dns_address()], &[], MAX_PREVIOUS_RESOLVERS);
        assert!(
            kept.is_empty(),
            "{} should not be forwarded to: it is ours",
            a_tun_dns_address()
        );
    }

    /// A link-local address names a link as well as a host; without the scope id
    /// this process does not have, it cannot be dialled. Neither can 0.0.0.0.
    #[test]
    fn addresses_we_cannot_dial_are_not_forwarding_targets() {
        let kept = forwardable_resolvers(
            &[
                "fe80::1".to_string(),
                "169.254.1.1".to_string(),
                "0.0.0.0".to_string(),
                "::".to_string(),
                // What a Linux host running a local stub names in
                // /etc/resolv.conf: the stub the hijack itself feeds.
                "127.0.0.1".to_string(),
                "127.0.0.53".to_string(),
                "::1".to_string(),
                "192.168.1.1".to_string(),
            ],
            &[],
            MAX_PREVIOUS_RESOLVERS,
        );
        assert_eq!(kept, vec!["192.168.1.1".to_string()]);
    }

    /// Cap and de-duplication: every address kept is tried for 1.5s, so a long
    /// list of them would turn a slow resolver into a stalled query.
    #[test]
    fn at_most_a_handful_of_resolvers_survive_and_none_twice() {
        let candidates: Vec<String> = (0..8).map(|i| format!("10.0.0.{i}")).collect();
        let kept = forwardable_resolvers(&candidates, &[], MAX_PREVIOUS_RESOLVERS);
        assert_eq!(kept.len(), MAX_PREVIOUS_RESOLVERS);

        let repeated = vec!["10.0.0.1".to_string(), "10.0.0.1".to_string()];
        assert_eq!(
            forwardable_resolvers(&repeated, &[], MAX_PREVIOUS_RESOLVERS),
            vec!["10.0.0.1".to_string()]
        );
    }

    /// An answer this code cannot read — `networksetup` naming a service, or a
    /// platform reporting something that is not an address — is skipped rather
    /// than dialled.
    #[test]
    fn something_that_is_not_an_address_is_not_a_forwarding_target() {
        assert!(forwardable_resolvers(&["There aren't any".to_string()], &[], 2).is_empty());
    }

    /// The spellings a domain can be configured in all name the same suffix.
    #[test]
    fn the_wildcard_spellings_normalize_to_the_same_suffix() {
        for spelling in [
            "example.com",
            "*.example.com",
            ".example.com",
            "EXAMPLE.com",
            "example.com.",
        ] {
            assert_eq!(normalize_domain(spelling), "example.com");
        }
    }

    /// The per-query decision follows the server's rule, so a name this
    /// answers with a virtual address is a name the server can route.
    #[test]
    fn a_name_is_proxied_by_the_rule_the_server_routes_by() {
        // A name is that name.
        let name = vec!["example.com".to_string()];
        assert!(should_proxy_domain("example.com", &name));
        assert!(!should_proxy_domain("www.example.com", &name));

        // A dotted wildcard is the subdomains, and not the apex.
        let wildcard = vec!["*.example.com".to_string()];
        assert!(should_proxy_domain("a.b.example.com", &wildcard));
        assert!(!should_proxy_domain("example.com", &wildcard));

        // And a host that merely ends in the same letters is nobody's.
        assert!(!should_proxy_domain("notexample.com", &wildcard));
    }

    /// The scope the operating system is told about is the suffix behind the
    /// pattern, because no resolver mechanism can say "the subdomains and not
    /// the apex": a resolver file for `example.com` covers both. The scope is
    /// therefore the wider of the two, and the per-query decision above is what
    /// narrows it — a name outside the pattern is forwarded to the real
    /// resolver and resolves for real.
    #[test]
    fn the_scope_is_the_suffix_behind_the_pattern() {
        for spelling in ["example.com", "*.example.com", ".example.com"] {
            assert_eq!(normalize_domain(spelling), "example.com");
        }
    }

    /// One domain the OS cannot be told about takes the whole configuration out
    /// of the per-domain hijack. Splitting it would leave some domains unproxied
    /// and unreported, which is worse than resolving all of them globally.
    #[test]
    fn one_domain_that_cannot_be_named_takes_the_whole_set_with_it() {
        // A wildcard means every domain; a bare label is a hostname; and the
        // slash is the one that matters most — on the platform that writes a
        // file per domain, a suffix carrying one would reach outside that
        // directory, and it has to be turned down by the characters it carries
        // rather than by some other rule happening to catch it first.
        for unusable in ["*", "", "localhost", "a..b", "bad/domain.com", "-"] {
            assert_eq!(scoped_domains(&[unusable.to_string()]), None);
        }
        for unusable in ["*", "localhost", "bad/domain"] {
            assert_eq!(
                scoped_domains(&["example.com".to_string(), unusable.to_string()]),
                None
            );
        }
        assert_eq!(scoped_domains(&[]), None);
    }

    #[test]
    fn scoped_domains_keep_the_suffixes_and_drop_the_repeats() {
        assert_eq!(
            scoped_domains(&[
                "*.example.com".to_string(),
                "EXAMPLE.com".to_string(),
                "foo.io".to_string(),
            ]),
            Some(vec!["example.com".to_string(), "foo.io".to_string()])
        );
    }
}
