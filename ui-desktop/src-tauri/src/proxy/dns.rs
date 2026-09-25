use anyhow::Result;
use std::net::Ipv4Addr;

// The per-domain virtual IP mapping is the same one the smoltcp stack routes by
// (nexapipe-client's): an address this server hands out must be an address the
// stack can reverse-lookup, so both share one instance and one pool.
pub use nexapipe_client::virtual_ip::IpMapping;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

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
    ip_mapping: Arc<IpMapping>,
    stopped: Arc<AtomicBool>,
}

impl DnsServer {
    pub fn new(config: DnsServerConfig, ip_mapping: Arc<IpMapping>) -> Self {
        Self {
            config,
            ip_mapping,
            stopped: Arc::new(AtomicBool::new(false)),
        }
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
                    let ip_mapping = ip_mapping.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_dns_query(
                            &socket,
                            &data,
                            addr,
                            &upstream,
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
        let virtual_ip = ip_mapping.allocate(&query.domain);
        tracing::info!("DNS hijack: {} -> {}", query.domain, virtual_ip);

        // A records return the virtual IP; every other type (AAAA, ...) gets an empty NOERROR
        // reply so the query is not leaked upstream and browser resolution is not disturbed
        let response = if query.qtype == 1 {
            build_dns_response(data, &query, virtual_ip)
        } else {
            build_empty_dns_response(&query)
        };
        socket.send_to(&response, client_addr).await?;
        return Ok(());
    }

    // Non-proxied domains: forward upstream (falls back to other public resolvers when the
    // configured one is unreachable)
    forward_to_upstream(socket, data, client_addr, upstream).await
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

/// Forwards the query to the configured upstream and then to each fallback, returning the
/// first successful reply. Each upstream gets a 1.5s window and only a response coming from
/// the upstream we queried is accepted (spoofing protection).
async fn forward_to_upstream(
    socket: &Arc<UdpSocket>,
    data: &[u8],
    client_addr: std::net::SocketAddr,
    configured_upstream: &str,
) -> Result<()> {
    // Build a de-duplicated upstream list: user configuration first, fallbacks afterwards
    let mut upstreams: Vec<String> = Vec::new();
    if !upstreams.iter().any(|u| u == configured_upstream) {
        upstreams.push(configured_upstream.to_string());
    }
    for fb in FALLBACK_UPSTREAMS {
        if !upstreams.iter().any(|u| u == fb) {
            upstreams.push(fb.to_string());
        }
    }

    for upstream in upstreams {
        let upstream_addr: std::net::SocketAddr = match upstream.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
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

    loop {
        if offset >= data.len() {
            return Err(anyhow::anyhow!("DNS packet truncated"));
        }

        let label_len = data[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }

        if offset + 1 + label_len > data.len() {
            return Err(anyhow::anyhow!("DNS label out of bounds"));
        }

        let label = std::str::from_utf8(&data[offset + 1..offset + 1 + label_len])
            .map_err(|_| anyhow::anyhow!("Invalid DNS label"))?;
        labels.push(label.to_string());
        offset += 1 + label_len;
    }

    if offset + 4 > data.len() {
        return Err(anyhow::anyhow!("DNS query type/class truncated"));
    }

    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let question_end = offset + 4;

    Ok(DnsQuery {
        id,
        domain: labels.join("."),
        qtype,
        question_section: data[question_start..question_end].to_vec(),
    })
}

/// Builds a DNS response containing an A record
fn build_dns_response(query: &[u8], dns_query: &DnsQuery, ip: Ipv4Addr) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 16);

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
    // TYPE=A
    response.extend_from_slice(&1u16.to_be_bytes());
    // CLASS=IN
    response.extend_from_slice(&1u16.to_be_bytes());
    // TTL=60
    response.extend_from_slice(&60u32.to_be_bytes());
    // RDLENGTH=4
    response.extend_from_slice(&4u16.to_be_bytes());
    // RDATA=IP
    response.extend_from_slice(&ip.octets());

    response
}

/// Checks whether a domain should be proxied (DOMAIN-SUFFIX semantics):
/// - `example.com` matches `example.com` and all of its subdomains (e.g. `fn.example.com`)
/// - the `*.example.com` / `.example.com` spellings are accepted with the same meaning
fn should_proxy_domain(host: &str, proxy_domains: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    for domain in proxy_domains {
        let domain_lower = domain
            .trim_start_matches('*')
            .trim_start_matches('.')
            .to_lowercase();
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
