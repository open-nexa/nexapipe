use anyhow::Result;

// The per-domain virtual IP mapping is the same one the smoltcp stack routes by
// (nexapipe-client's): an address this server hands out must be an address the
// stack can reverse-lookup, so both share one instance and one pool.
pub use nexapipe_client::virtual_ip::IpMapping;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

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
        let upstream = self.config.upstream_dns.clone();
        let proxy_domains = Arc::new(self.config.proxy_domains.clone());
        let previous = Arc::new(self.previous_resolvers.clone());
        let ip_mapping = self.ip_mapping.clone();
        let stopped = self.stopped.clone();

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
                    let upstream = upstream.clone();
                    let proxy_domains = proxy_domains.clone();
                    let previous = previous.clone();
                    let ip_mapping = ip_mapping.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_dns_query(
                            &socket,
                            &data,
                            addr,
                            &upstream,
                            &previous,
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
    upstream: &str,
    previous: &[String],
    proxy_domains: &[String],
    ip_mapping: &IpMapping,
) -> Result<()> {
    if data.len() < 12 {
        return Ok(());
    }

    // Parse the DNS query
    let query = match parse_dns_query(data) {
        Ok(q) => q,
        Err(e) => {
            tracing::debug!("Failed to parse DNS query: {}", e);
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
        let answer = match query.qtype {
            1 => Some(std::net::IpAddr::V4(ip_mapping.allocate(&query.domain))),
            28 => ip_mapping.allocate_v6(&query.domain).map(std::net::IpAddr::V6),
            _ => None,
        };

        let response = match answer {
            Some(address) => {
                tracing::info!("DNS hijack: {} -> {}", query.domain, address);
                build_dns_response(data, &query, address)
            }
            None => {
                // Every other type (AAAA with no IPv6 pool, MX, ...) gets an empty NOERROR
                // reply so the query is not leaked upstream and browser resolution is not
                // disturbed.
                build_empty_dns_response(&query)
            }
        };
        socket.send_to(&response, client_addr).await?;
        return Ok(());
    }

    // Non-proxied domains: forward upstream. The machine's own resolvers come
    // first — see [`resolver_chain`] for why — and the public fallbacks close the
    // chain for when none of them answers.
    forward_to_upstream(socket, data, client_addr, upstream, previous).await
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
fn resolver_chain(previous: &[String], configured: &str) -> Vec<String> {
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

/// The address a socket is bound to before it dials `upstream`.
///
/// A socket can only reach an address of its own family: an IPv6 resolver
/// dialled from an IPv4 socket fails at `send_to`, so it would spend one of the
/// two slots on the machine's own resolvers and take a usable IPv4 one down
/// with it, and the failure would look like a resolver that does not answer.
fn bind_addr_for(upstream: &std::net::SocketAddr) -> &'static str {
    if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
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

/// Forwards the query along [`resolver_chain`], returning the first successful
/// reply. Each upstream gets a 1.5s window and only a response coming from the
/// upstream we queried is accepted (spoofing protection).
async fn forward_to_upstream(
    socket: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: std::net::SocketAddr,
    configured_upstream: &str,
    previous: &[String],
) -> Result<()> {
    let upstreams = resolver_chain(previous, configured_upstream);

    for upstream in &upstreams {
        let upstream_addr: std::net::SocketAddr = match upstream.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let upstream_socket = match UdpSocket::bind(bind_addr_for(&upstream_addr)).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if upstream_socket.send_to(data, upstream_addr).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(
            tokio::time::Duration::from_millis(1500),
            upstream_socket.recv_from(&mut buf),
        )
        .await
        {
            // Only accept a response from the upstream we queried, so spoofed or unrelated
            // UDP packets are never forwarded to the client
            Ok(Ok((len, src))) if src == upstream_addr => {
                socket.send_to(&buf[..len], client_addr).await?;
                return Ok(());
            }
            _ => continue, // timeout / unexpected source / error: try the next upstream
        }
    }

    tracing::debug!("All upstream DNS servers failed for query");
    Ok(())
}

/// How many compression pointers one name may follow before it is declared
/// unreadable. A real name needs one; more than that is a loop.
const MAX_DNS_POINTER_JUMPS: usize = 4;

/// Parsed DNS query
#[derive(Debug)]
struct DnsQuery {
    id: u16,
    domain: String,
    qtype: u16,
    question_section: Vec<u8>,
}

/// Parses a DNS query from a raw packet
fn parse_dns_query(data: &[u8]) -> Result<DnsQuery> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS packet too short"));
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);

    if qdcount == 0 {
        return Err(anyhow::anyhow!("No question in DNS query"));
    }

    let mut offset = 12;
    let mut labels = Vec::new();
    let question_start = offset;
    // Where the rest of the question sits once the name is over. It follows the
    // terminating zero byte for an uncompressed name, but the two pointer bytes
    // when the name jumped (RFC 1035 4.1.4): the labels those bytes point at
    // live somewhere else, and reading on from them lands in another section.
    let mut after_name: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        if offset >= data.len() {
            return Err(anyhow::anyhow!("DNS packet truncated"));
        }

        let label_len = data[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }

        // A compression pointer, not a length: the two top bits are set and the
        // rest, with the byte after, is an offset into the message. Read as a
        // length it gives a nonsense label, and from there a nonsense domain —
        // which decides whether the name is proxied.
        if label_len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(anyhow::anyhow!("DNS compression pointer truncated"));
            }
            let target = ((label_len & 0x3F) << 8) | data[offset + 1] as usize;
            if target >= data.len() {
                return Err(anyhow::anyhow!("DNS compression pointer out of bounds"));
            }
            // A pointer to another pointer forever is a loop.
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return Err(anyhow::anyhow!("DNS compression pointer loops"));
            }
            if after_name.is_none() {
                after_name = Some(offset + 2);
            }
            offset = target;
            continue;
        }

        // The two remaining label types are reserved or unused; a name that
        // uses one cannot be read as text.
        if label_len & 0xC0 != 0 {
            return Err(anyhow::anyhow!("unsupported DNS label type"));
        }

        if offset + 1 + label_len > data.len() {
            return Err(anyhow::anyhow!("DNS label out of bounds"));
        }

        let label = std::str::from_utf8(&data[offset + 1..offset + 1 + label_len])
            .map_err(|_| anyhow::anyhow!("Invalid DNS label"))?;
        labels.push(label.to_string());
        offset += 1 + label_len;
    }

    let type_at = after_name.unwrap_or(offset);
    if type_at + 4 > data.len() {
        return Err(anyhow::anyhow!("DNS query type/class truncated"));
    }

    let qtype = u16::from_be_bytes([data[type_at], data[type_at + 1]]);
    let question_end = type_at + 4;

    Ok(DnsQuery {
        id,
        domain: labels.join("."),
        qtype,
        question_section: data[question_start..question_end].to_vec(),
    })
}

/// Builds a DNS response containing one address record: A for an IPv4 address,
/// AAAA for an IPv6 one.
fn build_dns_response(query: &[u8], dns_query: &DnsQuery, ip: std::net::IpAddr) -> Vec<u8> {
    let (rtype, rdata): (u16, &[u8]) = match ip {
        std::net::IpAddr::V4(v4) => (1, &v4.octets()),
        std::net::IpAddr::V6(v6) => (28, &v6.octets()),
    };

    let mut response = Vec::with_capacity(query.len() + rdata.len() + 16);

    // Header
    response.extend_from_slice(&dns_query.id.to_be_bytes()); // ID
                                                             // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    response.extend_from_slice(&[0x81, 0x80]);
    // QDCOUNT=1
    response.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT=1
    response.extend_from_slice(&1u16.to_be_bytes());
    // NSCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes());

    // Question section (copied verbatim from the original query's question)
    response.extend_from_slice(&dns_query.question_section);

    // Answer section
    // Name pointer (points at the domain name in the question section)
    response.extend_from_slice(&[0xC0, 0x0C]);
    // TYPE=A (1) or AAAA (28)
    response.extend_from_slice(&rtype.to_be_bytes());
    // CLASS=IN
    response.extend_from_slice(&1u16.to_be_bytes());
    // TTL=60
    response.extend_from_slice(&60u32.to_be_bytes());
    // RDLENGTH=4 for A, 16 for AAAA
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    // RDATA=IP
    response.extend_from_slice(rdata);

    response
}

/// A configured proxy domain reduced to the bare suffix it matches: no leading
/// `*`, no leading or trailing dot, lower case.
///
/// Shared with the per-domain DNS hijack, which has to spell the same suffix in
/// a place the operating system reads it — a file under `/etc/resolver`, a
/// systemd-resolved routing domain. The two halves only work as long as they
/// mean the same thing: a suffix this server matches but no resolver routes is
/// a domain that silently is not proxied, and one a resolver routes but this
/// server does not match is a domain the machine can no longer resolve at all.
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

/// Checks whether a domain should be proxied (DOMAIN-SUFFIX semantics):
/// - `example.com` matches `example.com` and all of its subdomains (e.g. `fn.example.com`)
/// - the `*.example.com` / `.example.com` spellings are accepted with the same meaning
fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    for domain in proxy_domains {
        let domain_lower = normalize_domain(domain);
        if host_lower == domain_lower || host_lower.ends_with(&format!(".{}", domain_lower)) {
            return true;
        }
    }
    false
}

/// Builds an empty NOERROR reply (for non-A queries such as AAAA on hijacked domains)
fn build_empty_dns_response(dns_query: &DnsQuery) -> Vec<u8> {
    let mut response = Vec::with_capacity(dns_query.question_section.len() + 16);
    // Header: ID + QR=1, RD=1, RA=1, RCODE=0 + QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    response.extend_from_slice(&dns_query.id.to_be_bytes());
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    // Question section (copied verbatim)
    response.extend_from_slice(&dns_query.question_section);
    response
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

    /// The socket that dials an upstream has to be of the upstream's family, or
    /// every IPv6 resolver in the chain fails at `send_to` without a word.
    #[test]
    fn a_socket_is_bound_to_the_family_of_the_upstream_it_dials() {
        assert_eq!(
            bind_addr_for(&"192.168.1.1:53".parse().unwrap()),
            "0.0.0.0:0"
        );
        assert_eq!(bind_addr_for(&"[fd00::1]:53".parse().unwrap()), "[::]:0");
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

    /// The two halves of the hijack have to agree: whatever the resolver is told
    /// to route is exactly what this server answers for, and vice versa.
    #[test]
    fn a_scoped_domain_is_the_same_suffix_the_server_matches() {
        for spelling in ["example.com", "*.example.com", ".example.com"] {
            assert!(should_proxy_domain(
                "a.b.example.com",
                &[spelling.to_string()]
            ));
            assert!(should_proxy_domain("example.com", &[spelling.to_string()]));
            assert!(!should_proxy_domain(
                "notexample.com",
                &[spelling.to_string()]
            ));
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
