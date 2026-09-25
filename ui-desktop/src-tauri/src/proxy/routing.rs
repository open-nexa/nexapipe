//! Cross-platform TUN interface address and route management.
//!
//! After creating the TUN device, call `configure_interface` + `add_routes` to make the
//! virtual subnet routable; call `remove_routes` on shutdown to clean up. Every command is
//! idempotent, so running it repeatedly never fails.
//!
//! - Windows: IP Helper API (netsh is a silent no-op under LocalSystem; kept as fallback)
//! - Linux:   ip addr / ip link / ip route (the kernel adds the connected route itself;
//!   an explicit `replace` acts as a fallback)
//! - macOS:   ifconfig / route (utun interfaces need an explicit IP and route)

use anyhow::Result;
use std::process::Command;

#[cfg(windows)]
use crate::proxy::tun_proxy::{TUN_BASE_CANDIDATES, TUN_NETMASK, set_tun_base, tun_network};
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::net::UdpSocket;
#[cfg(windows)]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::proxy::tun_proxy::{set_tun_base, tun_network, TUN_BASE_CANDIDATES, TUN_NETMASK};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::{Ipv4Addr, UdpSocket};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{Duration, Instant};

/// Assigns the TUN interface IP address and brings the interface up (idempotent).
///
/// Every platform follows the same policy: walk [`TUN_BASE_CANDIDATES`] and keep the first
/// block whose address actually becomes bindable, recording it via `set_tun_base` so the rest
/// of the proxy (DNS address, virtual IP pool) derives from the block in use.
pub fn configure_interface(interface: &str) -> Result<()> {
    #[cfg(windows)]
    return configure_interface_windows(interface);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return configure_interface_unix(interface);

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        Ok(())
    }
}

/// Makes sure the route for the virtual subnet exists (idempotent). The kernel normally adds
/// the connected route once the interface address is set; on some platforms we add it
/// explicitly in case the automatic route is missing.
pub fn add_routes(interface: &str) -> Result<()> {
    #[cfg(windows)]
    {
        // Setting the interface address already added the /24 connected route
        let _ = interface;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "replace", &tun_network(), "dev", interface])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run ip route: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ip route replace failed: {}", stderr.trim());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        // Returns "File exists" when the route is already present — treat that as success
        let network = tun_network();
        let (network, _) = network
            .split_once('/')
            .expect("tun_network() is a CIDR block");
        let output = Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                network,
                "-netmask",
                TUN_NETMASK,
                "-interface",
                interface,
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run route: {}", e))?;
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("File exists")
        {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("route add failed: {}", stderr.trim())
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

/// Remove the TUN route (best effort; it disappears automatically when the device is destroyed).
pub fn remove_routes(interface: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = interface;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "del", &tun_network(), "dev", interface])
            .output();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let network = tun_network();
        let (network, _) = network
            .split_once('/')
            .expect("tun_network() is a CIDR block");
        let _ = Command::new("route")
            .args([
                "-n",
                "delete",
                "-net",
                network,
                "-netmask",
                TUN_NETMASK,
                "-interface",
                interface,
            ])
            .output();
        Ok(())
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

#[cfg(windows)]
fn configure_interface_windows(interface: &str) -> Result<()> {
    // Not one address but a list of candidate /24 blocks, tried in order.
    //
    // The block used to be fixed at 10.0.0.0/24, which is also what a great many home LANs use.
    // When the machine's own LAN already occupies it, Windows accepts the configuration and
    // then never makes the address usable: `netsh` exits 0, the bind to …254:53 fails with
    // WSAEADDRNOTAVAIL, and the whole proxy dies a couple of seconds after starting. Retrying
    // the same address cannot help, so once a block has been given a fair chance we move the
    // TUN to the next one.
    for base in TUN_BASE_CANDIDATES {
        let ip = Ipv4Addr::from(u32::from(base) | 0x0000_00FE).to_string();

        // A block that overlaps a subnet an existing adapter already sits in is unusable:
        // the connected route for it would exist on both interfaces and packets for the
        // TUN address (e.g. DNS to …254:53) would be ARP-resolved on the physical LAN,
        // where nothing answers. This is not hypothetical — 10.0.0.0/24, the first
        // candidate, is also what a great many home LANs (including this dev machine's)
        // use. Checking upfront costs one GetAdaptersAddresses call and skips the whole
        // DAD wait on a block that could never work.
        match tun_block_collides(base, interface) {
            Ok(true) => {
                tracing::warn!(
                    "Skipping TUN block {}/24: it overlaps a subnet already in use on this host",
                    base
                );
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    "Could not check whether {}/24 collides with existing subnets: {}; trying it anyway",
                    base,
                    e
                );
            }
        }

        // The address is set through the IP Helper API, not `netsh`: as a service
        // (LocalSystem) netsh exits 0 with no output and no effect, which is what made the
        // TUN address unbindable on every block. `netsh` is kept as a fallback for the cases
        // where the API refuses.
        //
        // It is assigned exactly once per block: repeating CreateUnicastIpAddressEntry every
        // few hundred milliseconds can restart duplicate address detection each time, and a
        // tentative address is not bindable — so re-creating was one way to make a block look
        // dead forever.
        let mut assigned = false;
        for attempt in 1..=3 {
            match assign_address_iphelper(interface, &ip) {
                Ok(()) => {
                    tracing::info!("IP Helper set {} on {} (attempt {})", ip, interface, attempt);
                    assigned = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "IP Helper could not set {} on {} (attempt {}): {}",
                        ip,
                        interface,
                        attempt,
                        e
                    );
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        if !assigned {
            tracing::warn!("IP Helper refused {}; falling back to netsh", ip);
            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &format!("name={}", interface),
                    "static",
                    &ip,
                    TUN_NETMASK,
                ])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to run netsh: {}", e))?;
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

            // Logged unconditionally: netsh exits 0 for a number of failures, so its
            // exit code alone cannot say whether the address was taken.
            tracing::info!(
                "netsh set address {}/{} on {}: exit {} — out: {:?} err: {:?}",
                ip,
                TUN_NETMASK,
                interface,
                output.status,
                stdout,
                stderr
            );

            if !output.status.success() {
                delete_address_iphelper(interface, &ip);
                continue;
            }
        }

        // Windows needs a moment: duplicate address detection keeps a fresh address in the
        // tentative state — present but not bindable (WSAEADDRNOTAVAIL, 10049) — for about a
        // second. Give each block up to 10 seconds; DAD states (0=invalid 1=tentative
        // 2=duplicate 3=deprecated 4=preferred) are logged so a stuck block says why.
        let mut bound = false;
        for attempt in 1..=20 {
            match bindable(&ip) {
                Ok(()) => {
                    bound = true;
                    break;
                }
                Err(e) if attempt == 1 || attempt % 4 == 0 => {
                    tracing::warn!(
                        "{} is not bindable after {}ms: {}; DAD state: {:?}",
                        ip,
                        attempt * 500,
                        e,
                        dad_state(interface, &ip)
                    );
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if bound {
            set_tun_base(base);
            if base != TUN_BASE_CANDIDATES[0] {
                tracing::warn!(
                    "Moved the TUN to {}: the configured block was already in use on this host",
                    tun_network()
                );
            }
            tracing::info!(
                "Interface {} configured with {} netmask {}",
                interface,
                ip,
                TUN_NETMASK
            );
            return Ok(());
        }
        tracing::warn!(
            "giving up on {} (DAD state: {:?}); removing it and trying the next block",
            ip,
            dad_state(interface, &ip)
        );
        delete_address_iphelper(interface, &ip);
    }

    // Last resort before giving up: say what the machine itself thinks, using a program that is
    // not the one that may have silently done nothing.
    let seen = Command::new("ipconfig").output().map(|o| {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        text.contains(interface)
    });
    anyhow::bail!(
        "Failed to give interface {} any of the candidate TUN blocks ({:?}): the TUN address is never bindable, DNS server cannot bind and routing will not work. \
         ipconfig mentions the interface: {:?}",
        interface,
        TUN_BASE_CANDIDATES,
        seen
    )
}

/// Whether `ip` can be bound to: the test the DNS server has to pass before it will start.
#[cfg(windows)]
fn bindable(ip: &str) -> std::io::Result<()> {
    // Bind a temporary UDP socket to the address (port 0, i.e. random). Success means the
    // address really is attached to a local interface; failure (usually WSAEADDRNOTAVAIL,
    // 10049) means it is not ready yet.
    UdpSocket::bind((ip, 0)).map(|_| ())
}

/// True when some adapter other than the TUN one already has a unicast IPv4 address whose
/// subnet overlaps `base`/24. Such a block cannot be used for the TUN: its connected route
/// would exist on both interfaces and traffic for the TUN address would escape onto the
/// physical LAN.
#[cfg(windows)]
fn tun_block_collides(base: Ipv4Addr, tun_interface: &str) -> Result<bool> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

    // IfOperStatusUp — down adapters keep stale DHCP addresses that route nothing.
    const IF_OPER_STATUS_UP: i32 = 1;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // IP_ADAPTER_ADDRESSES_LH starts with a ULONGLONG, so keep the buffer 8-aligned.
        let mut buf: Vec<u64> = vec![0; size.div_ceil(8) as usize];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            anyhow::bail!("GetAdaptersAddresses failed: {rc}");
        }
        let mut cur: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr().cast();
        while !cur.is_null() {
            let adapter: &IP_ADAPTER_ADDRESSES_LH = unsafe { &*cur };
            let name = if adapter.FriendlyName.is_null() {
                String::new()
            } else {
                unsafe { wide_ptr_to_string(adapter.FriendlyName) }
            };
            if name != tun_interface && adapter.OperStatus == IF_OPER_STATUS_UP {
                let mut uni = adapter.FirstUnicastAddress;
                while !uni.is_null() {
                    let u = unsafe { &*uni };
                    if !u.Address.lpSockaddr.is_null()
                        && unsafe { (*u.Address.lpSockaddr).sa_family } == AF_INET
                    {
                        let sin: *const SOCKADDR_IN = u.Address.lpSockaddr.cast();
                        // Same union-view trick as unicast_row: the dword view does not
                        // depend on how IN_ADDR's union is spelled.
                        let raw = unsafe {
                            std::ptr::read_unaligned(&(*sin).sin_addr as *const _ as *const u32)
                        };
                        let addr = Ipv4Addr::from(u32::from_be(raw));
                        // Overlap against the *wider* of the two subnets: a /8 LAN contains
                        // the whole candidate /24, a /32 host route only its own address.
                        let prefix = u.OnLinkPrefixLength.min(24);
                        if prefix > 0 {
                            let mask = u32::MAX << (32 - prefix);
                            if (u32::from(base) & mask) == (u32::from(addr) & mask) {
                                tracing::warn!(
                                    "TUN block {}/24 overlaps {}/{} on adapter {:?}",
                                    base,
                                    addr,
                                    u.OnLinkPrefixLength,
                                    name
                                );
                                return Ok(true);
                            }
                        }
                    }
                    uni = u.Next;
                }
            }
            cur = adapter.Next;
        }
        return Ok(false);
    }
    anyhow::bail!("GetAdaptersAddresses kept asking for a larger buffer");
}

/// Assigns `ip/24` to `interface` through the IP Helper API.
///
/// `netsh` is not used for this because it does nothing at all when the process is a service
/// running as LocalSystem: it exits 0 and prints nothing, and the address never appears. The
/// documented API has no such dependency on the caller's session.
#[cfg(windows)]
fn assign_address_iphelper(interface: &str, ip: &str) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::CreateUnicastIpAddressEntry;

    let addr: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|e| anyhow::anyhow!("{ip} is not an IPv4 address: {e}"))?;

    // The interface index is resolved from the friendly name ("nexa-tun"). `GetAdapterIndex`
    // looks like the obvious API for this but is not usable here: it wants the adapter's
    // *GUID* name (the `AdapterName` of `GetAdaptersAddresses`, "{…}"), and returns
    // ERROR_INVALID_PARAMETER (87) for the friendly name — which is all the `tun` crate
    // exposes. That is exactly what made every candidate block fail in the service log.
    let ifindex = adapter_index_by_friendly_name(interface)?;

    let row = unicast_row(ifindex, addr);
    unsafe {
        let rc = CreateUnicastIpAddressEntry(&row);
        match rc {
            0 => Ok(()),
            // 5010 = ERROR_OBJECT_ALREADY_EXISTS: the address is there, which is what we asked for.
            5010 => Ok(()),
            other => anyhow::bail!("CreateUnicastIpAddressEntry({ip}/{ifindex}) failed: {other}"),
        }
    }
}

/// The row shared by create/get/delete for `addr/24` on `ifindex`.
#[cfg(windows)]
fn unicast_row(
    ifindex: u32,
    addr: std::net::Ipv4Addr,
) -> windows_sys::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = ifindex;
        row.OnLinkPrefixLength = 24;

        let sin: *mut SOCKADDR_IN = &mut row.Address.Ipv4;
        (*sin).sin_family = AF_INET;
        (*sin).sin_port = 0;
        // IN_ADDR is a union of byte/word/dword views over the same four bytes; writing the
        // dword view is the one that does not depend on how the union is spelled.
        std::ptr::write_unaligned(
            &mut (*sin).sin_addr as *mut _ as *mut u32,
            u32::from(addr).to_be(),
        );
        row
    }
}

/// The duplicate-address-detection state of `ip` on `interface`, for logging.
/// `None` means the query failed (e.g. the address is not on the interface at all).
#[cfg(windows)]
fn dad_state(interface: &str, ip: &str) -> Option<i32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetUnicastIpAddressEntry;

    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let ifindex = adapter_index_by_friendly_name(interface).ok()?;
    let mut row = unicast_row(ifindex, addr);
    unsafe {
        if GetUnicastIpAddressEntry(&mut row) == 0 {
            Some(row.DadState)
        } else {
            None
        }
    }
}

/// Removes `ip` from `interface` — best effort, used when a candidate block is abandoned
/// so the next block does not inherit a tentatively-configured address.
#[cfg(windows)]
fn delete_address_iphelper(interface: &str, ip: &str) {
    use windows_sys::Win32::NetworkManagement::IpHelper::DeleteUnicastIpAddressEntry;

    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return;
    };
    let Ok(ifindex) = adapter_index_by_friendly_name(interface) else {
        return;
    };
    let row = unicast_row(ifindex, addr);
    unsafe {
        let rc = DeleteUnicastIpAddressEntry(&row);
        if rc != 0 && rc != 2 {
            // 2 = ERROR_FILE_NOT_FOUND: nothing to delete, which is fine.
            tracing::warn!("DeleteUnicastIpAddressEntry({ip}/{ifindex}) failed: {rc}");
        }
    }
}

/// Resolves an interface index from the adapter's friendly name (e.g. "nexa-tun").
///
/// The IP Helper APIs take either an index or a LUID — never the friendly name — and the
/// `tun` crate only exposes the friendly name. `GetAdapterIndex` is no alternative: it
/// expects the GUID-shaped `AdapterName` and fails with 87 for anything else.
#[cfg(windows)]
fn adapter_index_by_friendly_name(friendly: &str) -> Result<u32> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    // Skip everything the linked list carries but nobody here needs — the list still
    // contains every adapter, with or without addresses.
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        // IP_ADAPTER_ADDRESSES_LH starts with a ULONGLONG, so keep the buffer 8-aligned.
        let mut buf: Vec<u64> = vec![0; size.div_ceil(8) as usize];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            // `size` now says how much is actually needed; retry with that.
            continue;
        }
        if rc != 0 {
            anyhow::bail!("GetAdaptersAddresses failed: {rc}");
        }
        let mut cur: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr().cast();
        while !cur.is_null() {
            let adapter: &IP_ADAPTER_ADDRESSES_LH = unsafe { &*cur };
            if !adapter.FriendlyName.is_null() {
                let name = unsafe { wide_ptr_to_string(adapter.FriendlyName) };
                if name == friendly {
                    let ifindex = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                    let guid = unsafe {
                        std::ffi::CStr::from_ptr(adapter.AdapterName.cast())
                            .to_string_lossy()
                            .into_owned()
                    };
                    tracing::debug!("adapter {friendly:?} (guid {guid}) has ifindex {ifindex}");
                    return Ok(ifindex);
                }
            }
            cur = adapter.Next;
        }
        anyhow::bail!("no adapter with friendly name {friendly:?} was found");
    }
    anyhow::bail!("GetAdaptersAddresses kept asking for a larger buffer");
}

/// Reads a NUL-terminated UTF-16 string from a pointer into a `String`.
#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

// ==========================================================================
// Unix — same candidate-block policy as Windows (see configure_interface_windows):
// the address assignment is platform-specific (`ip` vs `ifconfig`), but the loop
// that walks TUN_BASE_CANDIDATES and keeps the first bindable block is shared.
// ==========================================================================

/// Walks [`TUN_BASE_CANDIDATES`] and configures the first block the host actually accepts.
///
/// The historical behaviour assigned a fixed block, which is a liability: when the machine's
/// own LAN uses the same one, the commands succeed but the address is never usable and every
/// connection dies a couple of seconds in. Retrying the same address cannot help, so once a
/// block has been given a fair chance the TUN moves to the next one.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn configure_interface_unix(interface: &str) -> Result<()> {
    // Addresses other interfaces already hold. A candidate block containing one is not ours to
    // take, and bindability probing cannot see it: the address is bindable, it is just spoken
    // for. The classic case is a coexisting fake-IP VPN — Clash/mihomo &co default to a
    // 198.18.0.1/16 fake-IP pool — whose DNS hands out addresses across the range while its own
    // interface only holds a sliver. Our /24 route is more specific than its catch-all routes,
    // so every fake IP it handed out inside our block lands in our TUN with no domain mapping
    // and is dropped, which looks exactly like "the rest of the internet died".
    let foreign = foreign_interface_addresses(interface);
    // Fake-IP tools treat 198.18.0.0/15 as one pool (the RFC 2544 convention) even though the
    // two candidates here are separate /24s: a foreign address anywhere in the /15 disqualifies
    // both, because the tool's DNS may hand out any address in the range.
    let fake_ip_claimed = foreign
        .iter()
        .any(|a| matches!(a.octets(), [198, 18..=19, _, _]));

    for base in TUN_BASE_CANDIDATES {
        if matches!(base.octets(), [198, 18 | 19, 0, 0]) && fake_ip_claimed {
            tracing::warn!(
                "skipping {base}/24: another interface holds an address in 198.18.0.0/15 — \
                 a fake-IP VPN (Clash/mihomo &co) owns that range"
            );
            continue;
        }
        if foreign
            .iter()
            .any(|a| u32::from(*a) & 0xFFFF_FF00 == u32::from(base))
        {
            tracing::warn!("skipping {base}/24: another interface already holds an address in it");
            continue;
        }

        let ip = Ipv4Addr::from(u32::from(base) | 0x0000_00FE);

        if let Err(e) = assign_interface_address(interface, &ip) {
            tracing::warn!("could not set {ip} on {interface}: {e}; trying the next block");
            continue;
        }

        if wait_bindable(&ip) {
            set_tun_base(base);
            if base != TUN_BASE_CANDIDATES[0] {
                tracing::warn!(
                    "Moved the TUN to {}: an earlier candidate block was unusable on this host",
                    tun_network()
                );
            }
            tracing::info!(
                "Interface {} configured with {} netmask {}",
                interface,
                ip,
                TUN_NETMASK
            );
            return Ok(());
        }

        tracing::warn!(
            "{ip} never became bindable on {interface}; removing it and trying the next block"
        );
        remove_interface_address(interface, &ip);
    }

    anyhow::bail!(
        "Failed to give interface {} any of the candidate TUN blocks ({:?})",
        interface,
        TUN_BASE_CANDIDATES
    )
}

/// IPv4 addresses held by interfaces other than `skip`.
///
/// An enumeration failure yields an empty list — the bindability probe still guards the basic
/// "can this address exist here" question; this check only adds the "is it already spoken for"
/// one on top.
#[cfg(target_os = "macos")]
fn foreign_interface_addresses(skip: &str) -> Vec<Ipv4Addr> {
    match Command::new("ifconfig").arg("-a").output() {
        Ok(output) => parse_ifconfig_addresses(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// IPv4 addresses held by interfaces other than `skip`. See the macOS twin for the rationale.
#[cfg(target_os = "linux")]
fn foreign_interface_addresses(skip: &str) -> Vec<Ipv4Addr> {
    match Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
    {
        Ok(output) => parse_ip_addr_addresses(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// `ifconfig -a` address lines: an unindented line names the interface, a tab-indented
/// `inet <addr> ...` line under it carries one of its addresses (`inet6` lines are excluded by
/// the trailing space in the prefix).
#[cfg(target_os = "macos")]
fn parse_ifconfig_addresses(text: &str, skip: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut current = "";
    for line in text.lines() {
        if line.starts_with('\t') || line.starts_with(' ') {
            if let Some(addr) = line
                .trim_start()
                .strip_prefix("inet ")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|a| a.parse().ok())
            {
                if current != skip {
                    out.push(addr);
                }
            }
        } else if let Some(name) = line.split(':').next() {
            current = name.trim();
        }
    }
    out
}

/// `ip -o -4 addr show` lines: `<idx>: <ifname>[@<peer>] inet <addr>/<prefix> ...`.
///
/// Two shapes have to be accepted. Modern iproute2 with `-o` puts the interface name and the
/// address on one line; older builds keep the trailing colon after the name, and plain
/// `ip addr show` splits them into an unindented `<idx>: <ifname>: <flags>` header plus indented
/// `inet ...` lines below it. Parsing only the first shape silently returned an empty list on
/// the other two, which made the candidate-block conflict check a no-op.
#[cfg(target_os = "linux")]
fn parse_ip_addr_addresses(text: &str, skip: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    // Interface the indented lines below belong to (multi-line output only).
    let mut current: Option<&str> = None;
    for line in text.lines() {
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if !indented {
            current = interface_field_name(tokens.get(1).copied());
        }
        // `inet` matched exactly, so `inet6` lines never land here.
        let Some(pos) = tokens.iter().position(|t| *t == "inet") else {
            continue;
        };
        let Some(addr) = tokens
            .get(pos + 1)
            .and_then(|a| a.split('/').next())
            .and_then(|a| a.parse().ok())
        else {
            continue;
        };
        let owner = if indented {
            current
        } else {
            interface_field_name(tokens.get(1).copied())
        };
        if owner != Some(skip) {
            out.push(addr);
        }
    }
    out
}

/// `<ifname>[@<peer>][:]` — the peer suffix and the colon some iproute2 versions print.
#[cfg(target_os = "linux")]
fn interface_field_name(token: Option<&str>) -> Option<&str> {
    token.map(|n| n.split('@').next().unwrap_or(n).trim_end_matches(':'))
}

/// Whether `ip` can be bound within a short grace period — the same test the DNS server has to
/// pass before it starts. Windows needs this window for duplicate address detection; on Unix
/// the address is normally usable immediately, so this is a short safety net only.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_bindable(ip: &Ipv4Addr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if UdpSocket::bind((*ip, 0)).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(target_os = "linux")]
fn assign_interface_address(interface: &str, ip: &Ipv4Addr) -> Result<()> {
    // `ip addr replace` is idempotent — setting the same address twice does not fail
    let cidr = format!("{ip}/24");
    let output = Command::new("ip")
        .args(["addr", "replace", &cidr, "dev", interface])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ip addr: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip addr replace failed: {}", stderr.trim());
    }

    let output = Command::new("ip")
        .args(["link", "set", "dev", interface, "up"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ip link: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip link set up failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_interface_address(interface: &str, ip: &Ipv4Addr) {
    let cidr = format!("{ip}/24");
    let _ = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", interface])
        .output();
}

#[cfg(target_os = "macos")]
fn assign_interface_address(interface: &str, ip: &Ipv4Addr) -> Result<()> {
    // ifconfig utunX inet <ip> <netmask> — running it again replaces the existing address
    // (idempotent). utun interfaces are point-to-point by nature; the explicit /24 route in
    // `add_routes` is what makes the whole block reachable, so this only has to make the
    // address exist and be bindable.
    let output = Command::new("ifconfig")
        .args([interface, "inet", &ip.to_string(), TUN_NETMASK])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ifconfig: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ifconfig inet failed: {}", stderr.trim());
    }

    let output = Command::new("ifconfig")
        .args([interface, "up"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run ifconfig up: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ifconfig up failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_interface_address(interface: &str, ip: &Ipv4Addr) {
    let _ = Command::new("ifconfig")
        .args([interface, "inet", &ip.to_string(), "remove"])
        .output();
}

#[cfg(test)]
mod tests {
    /// The conflict the candidate-block check exists for: a fake-IP VPN (Clash/mihomo) holds
    /// 198.18.0.1/30 on its utun while our default candidate block is 198.18.0.0/24.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_foreign_address_inside_a_candidate_block_is_collected() {
        let text = "\
lo0: flags=8049<LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.0.0.83 netmask 0xffffff00 broadcast 10.0.0.255
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
\tinet6 fe80::c62:9049:5746:8c61%utun8 prefixlen 64 scopeid 0x17
nexa-tun: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 198.18.0.254 netmask 0xffffff00
";
        let foreign = super::parse_ifconfig_addresses(text, "nexa-tun");
        assert!(foreign.contains(&"198.18.0.1".parse().unwrap()));
        assert!(foreign.contains(&"10.0.0.83".parse().unwrap()));
        // Our own interface is excluded, and inet6 lines are not addresses here.
        assert!(!foreign.contains(&"198.18.0.254".parse().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_foreign_address_inside_a_candidate_block_is_collected() {
        // `ip -o -4 addr show`: the interface and its address share one line, and the record is
        // continued with a trailing backslash.
        let oneline = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: enp3s0    inet 10.0.0.83/24 brd 10.0.0.255 scope global enp3s0\\       valid_lft forever preferred_lft forever
9: tun0    inet 198.18.0.1/30 scope global tun0\\       valid_lft forever preferred_lft forever
10: nexa-tun    inet 198.18.0.254/24 scope global nexa-tun\\       valid_lft forever preferred_lft forever
";
        // Plain `ip addr show`, plus the trailing colon older iproute2 keeps even under `-o`:
        // an unindented header names the interface, indented lines carry the addresses.
        let multiline = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.83/24 brd 10.0.0.255 scope global enp3s0
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 9000
    inet 198.18.0.1/30 scope global tun0
10: nexa-tun: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400
    inet 198.18.0.254/24 scope global nexa-tun
";
        for text in [oneline, multiline] {
            let foreign = super::parse_ip_addr_addresses(text, "nexa-tun");
            assert!(
                foreign.contains(&"198.18.0.1".parse().unwrap()),
                "the conflicting foreign address was not collected: {foreign:?}"
            );
            assert!(
                foreign.contains(&"10.0.0.83".parse().unwrap()),
                "an unrelated LAN address was not collected: {foreign:?}"
            );
            assert!(
                !foreign.contains(&"198.18.0.254".parse().unwrap()),
                "our own interface must be excluded: {foreign:?}"
            );
        }
    }
}
