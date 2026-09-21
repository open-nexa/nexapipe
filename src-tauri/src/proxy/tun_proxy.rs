//! TUN proxy — cross-platform implementation
//! (Windows: wintun / Linux: /dev/net/tun / macOS: utun).
//!
//! Data flow:
//! ```text
//! APP → TUN device → AsyncDevice::recv() → parse IP/TCP packet
//!                                            ↓
//!                    look up the domain by destination virtual IP (IpMapping)
//!                                            ↓
//!              open an iroh bi-stream, write the L4 preface (host + port),
//!              wait for the server's status byte — a refusal becomes a RST
//!                                            ↓
//!                 build TCP reply packet → AsyncDevice::send() → TUN device → APP
//! ```
//!
//! Virtual network (must stay in sync with the IpMapping allocation in dns.rs):
//! - 10.0.0.254  = TUN device address / DNS server address
//! - 10.0.0.2+   = virtual IPs mapped to proxied domains (returned by DNS hijacking)
//!
//! System routing: once the interface is configured as 10.0.0.254/24 the kernel adds a
//! 10.0.0.0/24 connected route automatically, so all traffic to the virtual IPs enters the
//! TUN device; system DNS points at 10.0.0.254 (see dns_config.rs).
//!
//! Platform differences:
//! - Windows: the tun crate creates a wintun adapter; wintun.dll must be loaded first
//! - Linux:   the tun crate creates a /dev/net/tun device; any name works (≤15 chars)
//! - macOS:   the name must be utunN; if omitted the system assigns one automatically

use crate::proxy::dns::{DnsServer, DnsServerConfig, IpMapping};
use crate::proxy::packet::{tcp_flags, Ipv4Packet, TcpPacket, IPPROTO_TCP};
use crate::proxy::{dns_config, routing};
use anyhow::Result;
use nexapipe_client::endpoint_group::EndpointGroup;
use nexapipe_client::l4::{self, L4Proto};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tun::AbstractDevice;

/// IP of the TUN device itself (also the address of the local DNS server)
pub const TUN_IP: &str = "10.0.0.254";
pub const TUN_NETMASK: &str = "255.255.255.0";
/// Virtual subnet — must match VIRTUAL_IP_START/END in dns.rs (10.0.0.2 ~ 10.0.0.253).
/// Only used by the Linux routing module; on other platforms the connected route is
/// derived automatically from the interface address.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const TUN_NETWORK: &str = "10.0.0.0/24";
/// Must match `TUN_MTU` in `crates/nexapipe-client/src/tun_proxy.rs` and `tunMtu` in
/// `ui-android/.../NexaVpnService.kt`. 1400 keeps one inner IP packet inside a single QUIC
/// datagram (~1435 usable bytes after the short header + AEAD tag); at 1500 every inner
/// segment was split across two datagrams, roughly doubling the packet count and AEAD cost.
const TUN_MTU: usize = 1400;
/// Read loop timeout — lets the loop react to stop() in a timely fashion
const READ_POLL_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq)]
enum TcpState {
    SynReceived,
    Established,
    FinWait1,
    LastAck,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ConnectionKey {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
}

struct Connection {
    state: TcpState,
    our_seq: u32,
    our_ack: u32,
    nexapipe_send: Option<iroh::endpoint::SendStream>,
    nexapipe_recv: Option<iroh::endpoint::RecvStream>,
}

#[derive(Debug, Clone)]
pub struct TunProxyConfig {
    pub tunnel_name: String,
    /// Address that system DNS should point at (the TUN virtual IP, usually 10.0.0.254)
    pub dns_ip: String,
    /// Local DNS server configuration (DNS hijacking)
    pub dns: DnsServerConfig,
}

pub struct TunProxy {
    config: TunProxyConfig,
    endpoint_group: Arc<EndpointGroup>,
    ip_mapping: Arc<IpMapping>,
    connections: Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    identification: Arc<Mutex<u16>>,
    stopped: Arc<AtomicBool>,
}

impl TunProxy {
    pub fn new(
        config: TunProxyConfig,
        endpoint_group: Arc<EndpointGroup>,
        ip_mapping: Arc<IpMapping>,
    ) -> Self {
        Self {
            config,
            endpoint_group,
            ip_mapping,
            connections: Arc::new(Mutex::new(HashMap::new())),
            identification: Arc::new(Mutex::new(0)),
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        tracing::info!("Stopping TUN proxy");
        self.stopped.store(true, Ordering::Release);
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
    /// → switch system DNS → run the packet loop → clean up and restore.
    ///
    /// The order matters: the local DNS server must bind to 10.0.0.254:53, which is the TUN
    /// interface address, so the interface has to be configured before the DNS server is
    /// started — otherwise Windows fails the bind with WSAEADDRNOTAVAIL (10049).
    pub async fn run(&self) -> Result<()> {
        tracing::info!("Starting TUN proxy with DNS hijacking");

        let device = Arc::new(self.create_device()?);
        let interface = device.tun_name()?;
        tracing::info!(
            "TUN device ready: {} (mtu {})",
            interface,
            device.mtu().unwrap_or(TUN_MTU as u16)
        );

        // 1. Configure the interface address / routes (idempotent) — 10.0.0.254 must already
        //    exist on this host
        routing::configure_interface(&interface)?;
        routing::add_routes(&interface)?;

        // 2. Bind the local DNS server (DNS hijacking).
        //    The bind must succeed before system DNS is pointed at 10.0.0.254, otherwise
        //    system DNS would point at an address nobody listens on and break DNS for the
        //    entire machine (including iroh relay resolution).
        //    On Windows, binding before the interface address is ready fails with
        //    WSAEADDRNOTAVAIL (10049); we bail out here (the manager falls back to the local
        //    proxy) instead of running in a half-broken state.
        let dns_server = DnsServer::new(self.config.dns.clone(), self.ip_mapping.clone());
        let dns_socket = dns_server.bind().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to bind DNS server on {}: {}. Ensure the TUN interface {} is configured with {} and port 53 is free.",
                self.config.dns.listen_addr,
                e,
                interface,
                TUN_IP
            )
        })?;
        let dns_stopped = dns_server.stopped_flag();
        let dns_handle = tokio::spawn(async move {
            if let Err(e) = dns_server.run_with_socket(dns_socket).await {
                tracing::error!("DNS server failed: {}", e);
            }
        });

        // 3. Point system DNS at the virtual IP — only after the DNS server bound successfully
        if let Err(e) = dns_config::set_system_dns(&interface, &self.config.dns_ip) {
            tracing::warn!("Failed to set system DNS: {}, DNS hijack may not work", e);
        }

        let result = self.run_device(&device).await;

        // Cleanup (best effort): restore system DNS, stop the local DNS server, remove routes
        if let Err(e) = dns_config::restore_system_dns(&interface, &self.config.dns_ip) {
            tracing::warn!("Failed to restore system DNS: {}", e);
        }
        dns_stopped.store(true, Ordering::Release);
        if let Err(e) = dns_handle.await {
            tracing::debug!("DNS handle join error: {:?}", e);
        }
        if let Err(e) = routing::remove_routes(&interface) {
            tracing::warn!("Failed to remove TUN routes: {}", e);
        }
        result
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

    /// Runs the packet loop: read from TUN → parse → dispatch to handle_packet.
    async fn run_device(&self, device: &Arc<tun::AsyncDevice>) -> Result<()> {
        let mut buf = vec![0u8; TUN_MTU];
        loop {
            if self.stopped.load(Ordering::Acquire) {
                tracing::info!("TUN stopping due to stop flag");
                break;
            }
            match tokio::time::timeout(READ_POLL_TIMEOUT, device.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if n == 0 {
                        break;
                    }
                    let data = buf[..n].to_vec();
                    let device = device.clone();
                    let connections = self.connections.clone();
                    let endpoint_group = self.endpoint_group.clone();
                    let ip_mapping = self.ip_mapping.clone();
                    let identification = self.identification.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_packet(
                            &data,
                            &device,
                            &connections,
                            &endpoint_group,
                            &ip_mapping,
                            &identification,
                        )
                        .await
                        {
                            tracing::debug!("Packet handling error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    tracing::error!("TUN receive error: {}", e);
                    break;
                }
                Err(_) => continue, // Timed out; loop back to check the stop flag
            }
        }
        tracing::info!("TUN proxy stopped");
        Ok(())
    }
}

async fn handle_packet(
    data: &[u8],
    device: &Arc<tun::AsyncDevice>,
    connections: &Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    endpoint_group: &Arc<EndpointGroup>,
    ip_mapping: &Arc<IpMapping>,
    identification: &Arc<Mutex<u16>>,
) -> Result<()> {
    let ip_packet = match Ipv4Packet::parse(data) {
        Some(p) => p,
        None => return Ok(()),
    };
    if ip_packet.protocol != IPPROTO_TCP {
        return Ok(());
    }
    let tcp_packet = match TcpPacket::parse(&ip_packet.payload) {
        Some(p) => p,
        None => return Ok(()),
    };
    let domain = match ip_mapping.lookup_domain(&ip_packet.dst_addr) {
        Some(d) => d,
        None => return Ok(()),
    };
    let conn_key = ConnectionKey {
        src_ip: u32::from(ip_packet.src_addr),
        src_port: tcp_packet.src_port,
        dst_ip: u32::from(ip_packet.dst_addr),
        dst_port: tcp_packet.dst_port,
    };
    handle_tcp(
        &conn_key,
        &tcp_packet,
        &ip_packet,
        &domain,
        device,
        connections,
        endpoint_group,
        identification,
    )
    .await
}

async fn handle_tcp(
    conn_key: &ConnectionKey,
    tcp: &TcpPacket,
    ip: &Ipv4Packet,
    domain: &str,
    device: &Arc<tun::AsyncDevice>,
    connections: &Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    endpoint_group: &Arc<EndpointGroup>,
    identification: &Arc<Mutex<u16>>,
) -> Result<()> {
    let is_syn = (tcp.flags & tcp_flags::SYN) != 0;
    let is_ack = (tcp.flags & tcp_flags::ACK) != 0;
    let is_fin = (tcp.flags & tcp_flags::FIN) != 0;
    let is_rst = (tcp.flags & tcp_flags::RST) != 0;
    let has_data = !tcp.payload.is_empty();

    if is_rst {
        connections.lock().remove(conn_key);
        return Ok(());
    }

    if is_syn && !is_ack {
        return handle_syn(
            conn_key,
            tcp,
            ip,
            domain,
            device,
            connections,
            endpoint_group,
            identification,
        )
        .await;
    }

    let conn_exists = connections.lock().contains_key(conn_key);
    if !conn_exists {
        return Ok(());
    }

    let conn_state = {
        let conns = connections.lock();
        conns.get(conn_key).map(|c| (c.state, c.our_seq, c.our_ack))
    };
    let (state, our_seq, _our_ack) = match conn_state {
        Some(s) => s,
        None => return Ok(()),
    };

    match state {
        TcpState::SynReceived => {
            if is_ack && !has_data {
                let mut conns = connections.lock();
                if let Some(conn) = conns.get_mut(conn_key) {
                    conn.state = TcpState::Established;
                }
            }
        }
        TcpState::Established => {
            if has_data {
                let mut send_stream = {
                    let mut conns = connections.lock();
                    conns.get_mut(conn_key).and_then(|c| c.nexapipe_send.take())
                };
                if let Some(ref mut send) = send_stream {
                    if let Err(_e) = send.write_all(&tcp.payload).await {
                        connections.lock().remove(conn_key);
                        return Ok(());
                    }
                }
                {
                    let mut conns = connections.lock();
                    if let Some(conn) = conns.get_mut(conn_key) {
                        conn.nexapipe_send = send_stream;
                    }
                }
                let new_ack = tcp.seq_num.wrapping_add(tcp.payload.len() as u32);
                let ack_packet = TcpPacket {
                    src_port: tcp.dst_port,
                    dst_port: tcp.src_port,
                    seq_num: our_seq,
                    ack_num: new_ack,
                    flags: tcp_flags::ACK,
                    window: 65535,
                    payload: Vec::new(),
                };
                let id = get_next_id(identification);
                let packet = ack_packet.build_with_ip(ip.dst_addr, ip.src_addr, id);
                send_tun_packet(device, &packet).await?;
                {
                    let mut conns = connections.lock();
                    if let Some(conn) = conns.get_mut(conn_key) {
                        conn.our_ack = new_ack;
                    }
                }
                spawn_recv_task(
                    conn_key.clone(),
                    connections.clone(),
                    ip.dst_addr,
                    ip.src_addr,
                    tcp.dst_port,
                    tcp.src_port,
                    identification.clone(),
                    device.clone(),
                    our_seq,
                    new_ack,
                );
            }
            if is_fin {
                let fin_ack = tcp.seq_num.wrapping_add(tcp.payload.len() as u32 + 1);
                let packet = TcpPacket {
                    src_port: tcp.dst_port,
                    dst_port: tcp.src_port,
                    seq_num: our_seq,
                    ack_num: fin_ack,
                    flags: tcp_flags::FIN | tcp_flags::ACK,
                    window: 65535,
                    payload: Vec::new(),
                };
                let id = get_next_id(identification);
                let data = packet.build_with_ip(ip.dst_addr, ip.src_addr, id);
                send_tun_packet(device, &data).await?;
                {
                    let mut conns = connections.lock();
                    if let Some(conn) = conns.get_mut(conn_key) {
                        conn.state = TcpState::LastAck;
                        conn.our_ack = fin_ack;
                    }
                }
            }
        }
        TcpState::LastAck => {
            if is_ack {
                connections.lock().remove(conn_key);
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_syn(
    conn_key: &ConnectionKey,
    tcp: &TcpPacket,
    ip: &Ipv4Packet,
    domain: &str,
    device: &Arc<tun::AsyncDevice>,
    connections: &Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    endpoint_group: &Arc<EndpointGroup>,
    identification: &Arc<Mutex<u16>>,
) -> Result<()> {
    // A retransmitted SYN while this handshake is still in flight must not open a
    // second tunnel: the preface round trip below can outlast the application's SYN
    // retransmit timer, and the second flow would leave the first one orphaned on the
    // server. Answer the retransmission with the SYN-ACK that was already promised.
    let pending = {
        let conns = connections.lock();
        conns.get(conn_key).map(|c| (c.state, c.our_seq))
    };
    if let Some((state, our_seq)) = pending {
        if matches!(state, TcpState::SynReceived) {
            let syn_ack = TcpPacket {
                src_port: tcp.dst_port,
                dst_port: tcp.src_port,
                seq_num: our_seq.wrapping_sub(1),
                ack_num: tcp.seq_num.wrapping_add(1),
                flags: tcp_flags::SYN | tcp_flags::ACK,
                window: 65535,
                payload: Vec::new(),
            };
            let id = get_next_id(identification);
            send_tun_packet(device, &syn_ack.build_with_ip(ip.dst_addr, ip.src_addr, id)).await?;
        }
        return Ok(());
    }

    let pooled_conn = match endpoint_group.get_connection(domain).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get nexapipe connection: {}", e);
            return send_rst(device, tcp, ip, identification).await;
        }
    };

    let conn = pooled_conn.into_inner();

    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::error!("Failed to open nexapipe stream: {}", e);
            return send_rst(device, tcp, ip, identification).await;
        }
    };

    // Announce where this connection is going with the L4 preface, and wait for the
    // server to say whether it can carry it.
    //
    // This used to write `CONNECT <domain>:<port> HTTP/1.1` as the first bytes of the
    // bi-stream. Nothing on the server understood that: the bytes went into the HTTP
    // parser, came out with an empty path, matched no route and were forwarded to
    // `default_backend`. The port was thrown away, so only 443 ever worked — and a
    // refusal looked exactly like success. `l4::handshake` is the same code the local
    // proxy's CONNECT branch uses, so the two paths cannot drift apart on the wire
    // format.
    if let Err(e) = l4::handshake(&mut send, &mut recv, L4Proto::Tcp, domain, tcp.dst_port).await {
        tracing::warn!("Cannot open a TCP tunnel to {}:{}: {}", domain, tcp.dst_port, e);
        return send_rst(device, tcp, ip, identification).await;
    }

    let our_seq = 1000u32;
    let our_ack = tcp.seq_num.wrapping_add(1);
    let syn_ack = TcpPacket {
        src_port: tcp.dst_port,
        dst_port: tcp.src_port,
        seq_num: our_seq,
        ack_num: our_ack,
        flags: tcp_flags::SYN | tcp_flags::ACK,
        window: 65535,
        payload: Vec::new(),
    };
    let id = get_next_id(identification);
    let data = syn_ack.build_with_ip(ip.dst_addr, ip.src_addr, id);
    send_tun_packet(device, &data).await?;

    let conn_data = Connection {
        state: TcpState::SynReceived,
        our_seq: our_seq.wrapping_add(1),
        our_ack,
        nexapipe_send: Some(send),
        nexapipe_recv: Some(recv),
    };
    connections.lock().insert(*conn_key, conn_data);
    Ok(())
}

fn spawn_recv_task(
    conn_key: ConnectionKey,
    connections: Arc<Mutex<HashMap<ConnectionKey, Connection>>>,
    tun_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    tun_port: u16,
    client_port: u16,
    identification: Arc<Mutex<u16>>,
    device: Arc<tun::AsyncDevice>,
    initial_seq: u32,
    initial_ack: u32,
) {
    let recv = {
        let mut conns = connections.lock();
        match conns.get_mut(&conn_key) {
            Some(conn) => conn.nexapipe_recv.take(),
            None => return,
        }
    };
    if recv.is_none() {
        return;
    }
    let mut recv = recv.unwrap();
    let mut our_seq = initial_seq;

    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    let data = &buf[..n];
                    let tcp_packet = TcpPacket {
                        src_port: tun_port,
                        dst_port: client_port,
                        seq_num: our_seq,
                        ack_num: initial_ack,
                        flags: tcp_flags::PSH | tcp_flags::ACK,
                        window: 65535,
                        payload: data.to_vec(),
                    };
                    let id = get_next_id(&identification);
                    let packet = tcp_packet.build_with_ip(tun_ip, client_ip, id);
                    if let Err(_e) = send_tun_packet(&device, &packet).await {
                        break;
                    }
                    our_seq = our_seq.wrapping_add(n as u32);
                }
                Err(_e) => break,
            }
        }
        let fin_packet = TcpPacket {
            src_port: tun_port,
            dst_port: client_port,
            seq_num: our_seq,
            ack_num: initial_ack,
            flags: tcp_flags::FIN | tcp_flags::ACK,
            window: 65535,
            payload: Vec::new(),
        };
        let id = get_next_id(&identification);
        let packet = fin_packet.build_with_ip(tun_ip, client_ip, id);
        let _ = send_tun_packet(&device, &packet).await;
        let mut conns = connections.lock();
        if let Some(conn) = conns.get_mut(&conn_key) {
            conn.state = TcpState::FinWait1;
        }
    });
}

async fn send_tun_packet(device: &Arc<tun::AsyncDevice>, data: &[u8]) -> Result<()> {
    device
        .send(data)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send TUN packet: {}", e))?;
    Ok(())
}

/// Refuse a connection the proxy cannot carry.
///
/// The application is waiting for a SYN-ACK, so without this it keeps waiting until
/// its own connect timeout — the RST is what makes it fail now, and what tells it the
/// proxy (rather than a silent black hole) declined.
async fn send_rst(
    device: &Arc<tun::AsyncDevice>,
    tcp: &TcpPacket,
    ip: &Ipv4Packet,
    identification: &Arc<Mutex<u16>>,
) -> Result<()> {
    let rst_packet = TcpPacket {
        src_port: tcp.dst_port,
        dst_port: tcp.src_port,
        seq_num: 0,
        ack_num: tcp.seq_num.wrapping_add(1),
        flags: tcp_flags::RST | tcp_flags::ACK,
        window: 0,
        payload: Vec::new(),
    };
    let id = get_next_id(identification);
    let data = rst_packet.build_with_ip(ip.dst_addr, ip.src_addr, id);
    send_tun_packet(device, &data).await
}

fn get_next_id(identification: &Arc<Mutex<u16>>) -> u16 {
    let mut id = identification.lock();
    let current = *id;
    *id = id.wrapping_add(1);
    current
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
