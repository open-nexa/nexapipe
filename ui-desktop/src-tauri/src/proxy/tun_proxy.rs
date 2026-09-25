//! TUN proxy — desktop side: owns the TUN device, the interface/route/system-DNS
//! configuration and the local DNS sockets.
//!
//! The TCP/IP stack itself is NOT implemented here any more: the hand-written
//! packet-level TCP state machine (no MSS segmentation, a fixed 65535 window,
//! one iroh connection per TCP flow, never returned to the pool) was replaced by
//! the netstack-smoltcp core in `nexapipe-client`'s `tun_proxy` — the same code
//! the Android client runs. This module feeds the device's IP packets into that
//! stack and back:
//!
//! ```text
//! APP → TUN device → shared TunProxy (netstack-smoltcp)
//!                      ├─ TCP: reverse-lookup the destination virtual IP
//!                      │        → l4::open_tcp(domain, port) → iroh → server route
//!                      │        (pooled connections, returned after the flow ends)
//!                      ├─ UDP: one l4::open_udp bi-stream per flow
//!                      └─ DNS (dst <dns_ip>:53): hijack, one virtual IP per domain
//!
//! DNS has two entry points on the desktop, sharing one IpMapping so an address
//! handed out by either is routable by the stack:
//!   - queries that traverse the TUN device reach the stack's UDP demultiplexer;
//!   - queries the OS local-delivers (Windows never sends packets to the
//!     machine's own address through the adapter) reach the DnsServer bound on
//!     the interface address — see `run`.
//! ```
//!
//! Virtual network (must stay in sync with the pool in `run` and the DNS answers
//! in dns.rs):
//! - x.x.x.254  = TUN device address / DNS server address (the block in use)
//! - x.x.x.2 … x.x.x.253 = virtual IPs mapped to proxied domains
//!
//! System routing: once the interface is configured as x.x.x.254/24 the kernel
//! adds a x.x.x.0/24 connected route automatically, so all traffic to the
//! virtual IPs enters the TUN device; system DNS points at x.x.x.254 (see
//! dns_config.rs, which also parks the physical adapters' IPv6 DNS on [::1]).
//!
//! Platform differences:
//! - Windows: the tun crate creates a wintun adapter; wintun.dll must be loaded first
//! - Linux:   the tun crate creates a /dev/net/tun device; any name works (≤15 chars)
//! - macOS:   the name must be utunN; if omitted the system assigns one automatically

use crate::proxy::dns::{DnsServer, DnsServerConfig};
use crate::proxy::{dns_config, routing};
use anyhow::Result;
use nexapipe_client::endpoint_group::EndpointGroup;
use nexapipe_client::tun_proxy::{TunProxy as StackProxy, TunStackConfig};
use nexapipe_client::virtual_ip::IpMapping;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tun::AbstractDevice;

/// Tried in order; the first one the host will actually let us use wins.
///
/// The head of the list deliberately lives in *reserved* ranges rather than ordinary private
/// address space: the historical default `10.0.0.0/24` is also what a great many home LANs
/// use, and a TUN block overlapping the LAN breaks routing in ways that look like "the
/// internet died". `198.18.0.0/15` (RFC 2544 benchmarking) is never handed out by any router
/// or DHCP server and is the established convention for fake-IP DNS answers — which is
/// exactly what the virtual IPs below are. The old `10.0.0.0` block stays at the tail so
/// configurations saved against it remain valid (and get retargeted into whichever block
/// actually took, see [`retarget`]).
pub const TUN_BASE_CANDIDATES: [Ipv4Addr; 6] = [
    Ipv4Addr::new(198, 18, 0, 0), // RFC 2544 benchmarking — the fake-IP convention
    Ipv4Addr::new(198, 19, 0, 0), // second half of the same /15
    Ipv4Addr::new(100, 100, 0, 0), // RFC 6598 CGNAT shared space — never a LAN subnet
    Ipv4Addr::new(172, 26, 0, 0), // private-space fallback, rarely used by routers
    Ipv4Addr::new(10, 200, 0, 0), // private-space fallback
    Ipv4Addr::new(10, 0, 0, 0),   // legacy default, kept last for old saved configs
];

/// Netmask of the TUN block — every candidate is a /24.
pub const TUN_NETMASK: &str = "255.255.255.0";

/// The block actually in use, as recorded by `routing::configure_interface`.
static TUN_BASE: std::sync::OnceLock<Ipv4Addr> = std::sync::OnceLock::new();

/// The base of the block in use. Falls back to the configured one until the interface is up.
pub fn tun_base() -> Ipv4Addr {
    *TUN_BASE.get_or_init(|| TUN_BASE_CANDIDATES[0])
}

/// Records the block `routing::configure_interface` actually managed to configure.
pub fn set_tun_base(base: Ipv4Addr) {
    let _ = TUN_BASE.set(base);
}

/// The TUN device address: the last usable host address of the block in use (…254).
pub fn tun_ip() -> String {
    Ipv4Addr::from(u32::from(tun_base()) | 0x0000_00FE).to_string()
}

/// The block in use, in CIDR form.
pub fn tun_network() -> String {
    format!("{}/24", tun_base())
}

/// Rewrites an address that still points into one of the *candidate* blocks (as it was
/// configured, before the interface existed) so it points at the same host address inside the
/// block actually in use.
///
/// Needed because the DNS address reaches the TUN proxy as a configured string, decided before
/// the interface exists and therefore before the block is known — a config saved against the
/// old `10.0.0.x` default, for instance, keeps working after the TUN moved to `198.18.0.0/24`.
/// Anything outside every candidate block is a user-chosen address and is left alone.
pub fn retarget(addr: &str) -> String {
    // Split an optional `:port` off first; a bare address is also accepted.
    let (host, port) = match addr.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(port))
        }
        _ => (addr, None),
    };

    let Ok(ip) = host.parse::<Ipv4Addr>() else {
        return addr.to_string();
    };

    let in_candidate = TUN_BASE_CANDIDATES
        .iter()
        // Every candidate is a /24, so the network part is everything but the last octet.
        .any(|base| u32::from(ip) & 0xFFFF_FF00 == u32::from(*base));
    if !in_candidate {
        return addr.to_string();
    }

    let retargeted = Ipv4Addr::from(u32::from(tun_base()) | (u32::from(ip) & 0x0000_00FF));
    match port {
        Some(port) => format!("{retargeted}:{port}"),
        None => retargeted.to_string(),
    }
}

/// Must match `TUN_MTU` in `crates/nexapipe-client/src/tun_proxy.rs` (the smoltcp stack is
/// built with it) and `tunMtu` in `ui-android/.../NexaVpnService.kt`. 1400 keeps one inner IP
/// packet inside a single QUIC datagram (~1435 usable bytes after the short header + AEAD tag);
/// at 1500 every inner segment was split across two datagrams, roughly doubling the packet
/// count and AEAD cost.
const TUN_MTU: usize = 1400;
/// Wait-loop poll interval — lets `run()` react to stop() (and to the stack dying on its own)
/// in a timely fashion.
const READ_POLL_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct TunProxyConfig {
    /// Ignored on macOS, where the system assigns the utunN name itself.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub tunnel_name: String,
    /// Address that system DNS should point at (the TUN virtual IP, usually 198.18.0.254)
    pub dns_ip: String,
    /// Local DNS server configuration (DNS hijacking)
    pub dns: DnsServerConfig,
}

pub struct TunProxy {
    config: TunProxyConfig,
    endpoint_group: Arc<EndpointGroup>,
    stopped: Arc<AtomicBool>,
    /// `true` once `run()` has fully wound down — including the system-DNS restore.
    /// Starts `true` (nothing is running); `run()` flips it to `false` on entry and a drop
    /// guard flips it back on the way out, whichever path `run()` returned by.
    teardown_done: Arc<tokio::sync::watch::Sender<bool>>,
}

impl TunProxy {
    pub fn new(config: TunProxyConfig, endpoint_group: Arc<EndpointGroup>) -> Self {
        Self {
            config,
            endpoint_group,
            stopped: Arc::new(AtomicBool::new(false)),
            teardown_done: Arc::new(tokio::sync::watch::channel(true).0),
        }
    }

    pub fn stop(&self) {
        tracing::info!("Stopping TUN proxy");
        self.stopped.store(true, Ordering::Release);
    }

    /// Sets the stop flag and waits until `run()` has finished its cleanup — which is what
    /// restores the system DNS. A bare flag-set lets the caller's process exit (a service
    /// stop is followed by the runtime being dropped) or report "stopped" to the UI while
    /// the restore has not run yet, leaving the machine with a static DNS pointing at a
    /// TUN address that no longer exists — "the internet is broken" until something resets
    /// it. Bounded, so a stuck teardown cannot wedge the caller either.
    pub async fn stop_and_wait(&self) {
        self.stop();
        let mut rx = self.teardown_done.subscribe();
        let done = async {
            loop {
                if *rx.borrow_and_update() {
                    break;
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };
        // The wait loop notices the flag within one poll; the stack shutdown joins its
        // tasks (500 ms each), and the restore itself is two PowerShell spawns. Twenty
        // seconds is generous.
        if tokio::time::timeout(std::time::Duration::from_secs(20), done)
            .await
            .is_err()
        {
            tracing::warn!(
                "TUN teardown did not finish within 20s; the system DNS restore may not have run"
            );
        }
    }

    /// Whether the current process may create a TUN device (Windows: admin / Unix: root)
    pub fn is_admin() -> bool {
        #[cfg(windows)]
        {
            std::process::Command::new("net")
                .arg("session")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
    }

    pub async fn is_available() -> bool {
        Self::is_admin()
    }

    /// Starts the TUN proxy: create device → configure address/routes → start local DNS
    /// → switch system DNS → run the smoltcp stack over the device → clean up and restore.
    ///
    /// The order matters: the local DNS server must bind to x.x.x.254:53, which is the TUN
    /// interface address, so the interface has to be configured before the DNS server is
    /// started — otherwise Windows fails the bind with WSAEADDRNOTAVAIL (10049).
    pub async fn run(&self) -> Result<()> {
        tracing::info!("Starting TUN proxy (smoltcp stack) with DNS hijacking");

        // Marks the tunnel as not-torn-down for `stop_and_wait`; the guard flips it back
        // when `run()` returns by any path — success, an early `?` bail, or a panic — so a
        // waiter never hangs on a run that died before its cleanup.
        let _ = self.teardown_done.send(false);
        let _teardown = TeardownGuard(self.teardown_done.clone());

        let device = self.create_device()?;
        let interface = device.tun_name()?;
        tracing::info!(
            "TUN device ready: {} (mtu {})",
            interface,
            device.mtu().unwrap_or(TUN_MTU as u16)
        );

        // 1. Configure the interface address / routes (idempotent) — the TUN address (see
        //    `tun_ip()`) must already exist on this host
        routing::configure_interface(&interface)?;
        routing::add_routes(&interface)?;

        // 2. One IpMapping for everything: the DNS server's answers and the stack's
        //    reverse lookups must agree, or a domain resolved through [::1] would hand
        //    out an address the stack refuses to route. The pool leaves …254 (the
        //    interface/DNS address) to the interface, exactly like the old dns.rs pool.
        let base = tun_base();
        let ip_mapping = Arc::new(IpMapping::with_range(
            Ipv4Addr::from(u32::from(base) | 0x02),
            Ipv4Addr::from(u32::from(base) | 0xFD),
        ));

        // 3. Bind the local DNS server (DNS hijacking).
        //    The bind must succeed before system DNS is pointed at the TUN address, otherwise
        //    system DNS would point at an address nobody listens on and break DNS for the
        //    entire machine (including iroh relay resolution).
        //    On Windows, binding before the interface address is ready fails with
        //    WSAEADDRNOTAVAIL (10049); we bail out here (the manager falls back to the local
        //    proxy) instead of running in a half-broken state.
        //
        //    The address is re-pointed first: it was decided from configuration, but the block
        //    the interface actually got is only known now — see [`retarget`].
        let dns_listen = retarget(&self.config.dns.listen_addr);
        let dns_ip = retarget(&self.config.dns_ip);
        let dns_server = DnsServer::new(
            DnsServerConfig {
                listen_addr: dns_listen.clone(),
                upstream_dns: self.config.dns.upstream_dns.clone(),
                proxy_domains: self.config.dns.proxy_domains.clone(),
            },
            ip_mapping.clone(),
        );
        let dns_socket = dns_server.bind().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to bind DNS server on {}: {}. Ensure the TUN interface {} is configured with {} and port 53 is free.",
                dns_listen,
                e,
                interface,
                tun_ip()
            )
        })?;
        let dns_server = Arc::new(dns_server);
        let dns_stopped = dns_server.stopped_flag();
        let dns_v4 = dns_server.clone();
        let dns_handle = tokio::spawn(async move {
            if let Err(e) = dns_v4.run_with_socket(dns_socket).await {
                tracing::error!("DNS server failed: {}", e);
            }
        });

        // The same server also listens on the IPv6 loopback: the hijack points every
        // physical adapter's static IPv6 DNS at ::1 (see dns_config). Without this, a
        // router-learned fe80::... v6 DNS races the TUN resolver and wins with an
        // NXDOMAIN for proxied domains (they do not exist publicly) — the observed
        // "proxy connects but the domain does not resolve" failure.
        let dns_v6_handle = match tokio::net::UdpSocket::bind("[::1]:53").await {
            Ok(sock) => {
                tracing::info!("DNS server also listening on: [::1]:53");
                let dns_v6 = dns_server.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = dns_v6.run_with_socket(Arc::new(sock)).await {
                        tracing::error!("DNS server (v6 loopback) failed: {}", e);
                    }
                }))
            }
            Err(e) => {
                tracing::warn!(
                    "Could not bind DNS server on [::1]:53: {} — a router-learned IPv6 DNS may win the resolution race",
                    e
                );
                None
            }
        };

        // 4. Point system DNS at the virtual IP — only after the DNS server bound successfully
        if let Err(e) = dns_config::set_system_dns(&interface, &dns_ip) {
            tracing::warn!("Failed to set system DNS: {}, DNS hijack may not work", e);
        }

        // 5. Start the smoltcp stack over the device. Each AsyncRead/AsyncWrite call
        //    on the device carries exactly one IP packet; the stack demultiplexes TCP
        //    flows (per-domain virtual IP → l4::open_tcp, connections pooled and
        //    returned), UDP flows and the DNS queries that do traverse the TUN.
        let dns_ip_v4: Ipv4Addr = retarget(&self.config.dns_ip)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid DNS IP '{}': {}", self.config.dns_ip, e))?;
        // The stack's own DNS branch forwards through the same upstream + fallback
        // chain as the local DNS server (see dns.rs).
        let mut dns_servers: Vec<SocketAddr> = Vec::new();
        for upstream in std::iter::once(self.config.dns.upstream_dns.as_str())
            .chain(crate::proxy::dns::FALLBACK_UPSTREAMS.iter().copied())
        {
            if let Ok(addr) = upstream.parse::<SocketAddr>() {
                if !dns_servers.contains(&addr) {
                    dns_servers.push(addr);
                }
            }
        }
        let (reader, writer) = tokio::io::split(device);
        let stack = StackProxy::with_io(
            reader,
            writer,
            self.endpoint_group.clone(),
            self.config.dns.proxy_domains.clone(),
            dns_servers,
            TunStackConfig {
                dns_ip: dns_ip_v4,
                // The desktop never handed out a fixed proxy address, so there is no
                // legacy payload-sniffing path — every flow goes by its own virtual IP.
                legacy_proxy_ip: None,
                ip_mapping,
            },
        );

        let mut stack = match stack {
            Ok(s) => Some(s),
            Err(e) => {
                // Fall through to the cleanup below (system DNS restore &c.) with the error.
                tracing::error!("Failed to start the TUN stack: {}", e);
                None
            }
        };
        let run_result: Result<()> = match &stack {
            Some(_) => {
                // 6. Run until stopped. The stack's own stop flag is set by every one of
                //    its tasks on exit, so a dead device tears the whole proxy down.
                loop {
                    if self.stopped.load(Ordering::Acquire) {
                        tracing::info!("TUN stopping due to stop flag");
                        break;
                    }
                    if stack.as_ref().is_some_and(|s| s.is_stopped()) {
                        tracing::warn!("TUN stack stopped on its own, winding down");
                        break;
                    }
                    tokio::time::sleep(READ_POLL_TIMEOUT).await;
                }
                Ok(())
            }
            None => Err(anyhow::anyhow!(
                "Failed to start the smoltcp TUN stack (see the log above)"
            )),
        };

        // Cleanup (best effort), in the order the parts were brought up: restore
        // system DNS, stop the local DNS server, remove the routes — all while the
        // device (still held by the stack's pumps) keeps the interface alive — and
        // only then stop the stack, which drops the device and the adapter.
        if let Err(e) = dns_config::restore_system_dns(&interface, &dns_ip) {
            tracing::warn!("Failed to restore system DNS: {}", e);
        }
        dns_stopped.store(true, Ordering::Release);
        if let Err(e) = dns_handle.await {
            tracing::debug!("DNS handle join error: {:?}", e);
        }
        if let Some(h) = dns_v6_handle {
            if let Err(e) = h.await {
                tracing::debug!("DNS v6 handle join error: {:?}", e);
            }
        }
        if let Err(e) = routing::remove_routes(&interface) {
            tracing::warn!("Failed to remove TUN routes: {}", e);
        }
        if let Some(s) = stack.take() {
            s.shutdown_async().await;
        }
        run_result
    }

    /// Creates the TUN device. On Windows this first locates wintun.dll and passes it to the
    /// tun crate explicitly (we must not rely on the system DLL search — when the search
    /// fails, wintun-bindings' load_from_path("wintun.dll") ends up verifying the signature
    /// of the exe itself and reports "The file is not signed.").
    /// On macOS no name is given and the system assigns utunN automatically.
    fn create_device(&self) -> Result<tun::AsyncDevice> {
        #[cfg(windows)]
        let wintun_path = find_wintun_path().ok_or_else(|| {
            anyhow::anyhow!(
                "wintun.dll not found. Make sure build.rs copied it next to the exe, \
                 or set the WINTUN_PATH environment variable to point at wintun.dll"
            )
        })?;
        #[cfg(windows)]
        tracing::info!("Using wintun.dll at {}", wintun_path.display());

        let mut config = tun::Configuration::default();
        // Pass the absolute wintun.dll path explicitly: avoids the wintun-bindings system
        // search + signature verification bug
        #[cfg(windows)]
        config.platform_config(|pc| {
            pc.wintun_file(wintun_path.clone());
        });
        #[cfg(not(target_os = "macos"))]
        config.tun_name(&self.config.tunnel_name);
        config.mtu(TUN_MTU as u16);
        // Address and routes are configured centrally (and idempotently) by
        // routing::configure_interface to avoid conflicting with ip/ifconfig/netsh.
        // On Windows the tun crate creates the wintun adapter directly.

        let device = tun::create_as_async(&config)?;
        Ok(device)
    }
}

/// Signals `teardown_done` when `run()` returns, by whatever path it took.
struct TeardownGuard(Arc<tokio::sync::watch::Sender<bool>>);

impl Drop for TeardownGuard {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

/// Windows: locate the absolute path of wintun.dll (lookup only, no loading).
/// Order of precedence: WINTUN_PATH injected at compile time (where build.rs copied it)
/// → exe directory → exe/wintun/bin/{arch} → bundled resources dir → runtime WINTUN_PATH.
#[cfg(windows)]
fn find_wintun_path() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = option_env!("WINTUN_PATH") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        let arch_dir = target_arch_dir();
        candidates.push(exe_dir.join("wintun.dll"));
        candidates.push(
            exe_dir
                .join("wintun")
                .join("bin")
                .join(arch_dir)
                .join("wintun.dll"),
        );
        candidates.push(
            exe_dir
                .join("resources")
                .join("wintun")
                .join("bin")
                .join(arch_dir)
                .join("wintun.dll"),
        );
    }
    if let Ok(path) = std::env::var("WINTUN_PATH") {
        candidates.push(PathBuf::from(path));
    }
    candidates.into_iter().find(|p| p.exists())
}

#[cfg(windows)]
fn target_arch_dir() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "x86")]
    {
        "x86"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "aarch64"
    )))]
    {
        "amd64"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configured address inside one candidate block is rewritten into the block actually in
    /// use, host part and port preserved — this is what keeps an old config (saved against the
    /// legacy 10.0.0.x default) working after the TUN moved.
    ///
    /// `TUN_BASE` is a `OnceLock`, i.e. set at most once per process, so the expectations are
    /// derived from [`tun_base`] instead of assuming which block a test managed to register.
    #[test]
    fn retarget_moves_candidate_block_addresses_into_the_block_in_use() {
        set_tun_base(TUN_BASE_CANDIDATES[0]);
        let base = u32::from(tun_base());
        let moved = Ipv4Addr::from(base | 0x0000_00FE);

        // Pick a candidate block that is not the one in use (always exists: there are six).
        let other = TUN_BASE_CANDIDATES
            .iter()
            .find(|candidate| u32::from(**candidate) != base)
            .expect("more than one candidate block");
        let source = Ipv4Addr::from(u32::from(*other) | 0x0000_00FE);

        assert_eq!(retarget(&format!("{source}:53")), format!("{moved}:53"));
        assert_eq!(retarget(&source.to_string()), moved.to_string());
    }

    /// A user-chosen address outside every candidate block is none of our business.
    #[test]
    fn retarget_leaves_foreign_addresses_alone() {
        assert_eq!(retarget("192.168.1.10:53"), "192.168.1.10:53");
        assert_eq!(retarget("[::1]:53"), "[::1]:53");
        assert_eq!(retarget("not-an-address"), "not-an-address");
    }
}
