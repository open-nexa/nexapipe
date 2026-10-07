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
use crate::proxy::tun_proxy::{set_tun_base, tun_network, TUN_BASE_CANDIDATES, TUN_NETMASK};
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

/// Assigns the TUN's IPv6 address and route (idempotent), returning whether the
/// block is usable.
///
/// Unlike the IPv4 block this is optional, and failing is a supported outcome:
/// a machine (or a service account) that will not let the interface take an
/// address keeps working over IPv4, and the DNS hijack answers AAAA with
/// nothing rather than with an address no route leads to. Callers must treat
/// `false` as "stay on IPv4", not as an error.
pub fn configure_ipv6(interface: &str) -> bool {
    #[cfg(windows)]
    return configure_ipv6_windows(interface);

    #[cfg(target_os = "linux")]
    return configure_ipv6_linux(interface);

    #[cfg(target_os = "macos")]
    return configure_ipv6_macos(interface);

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        false
    }
}

/// Removes the TUN's IPv6 address and route (best effort).
pub fn remove_ipv6(interface: &str) -> Result<()> {
    #[cfg(windows)]
    return remove_ipv6_windows(interface);

    #[cfg(target_os = "linux")]
    return remove_ipv6_linux(interface);

    #[cfg(target_os = "macos")]
    return remove_ipv6_macos(interface);

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        Ok(())
    }
}

/// `ifconfig <if> inet6 <addr> prefixlen 64` plus the /64 route — an utun
/// interface gets no connected route for an address it was only just given.
#[cfg(target_os = "macos")]
fn configure_ipv6_macos(interface: &str) -> bool {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_BASE, TUN_V6_PREFIX_LEN};

    let prefix = TUN_V6_PREFIX_LEN.to_string();
    let out = Command::new("ifconfig")
        .args([
            interface,
            "inet6",
            &tun_v6_ip().to_string(),
            "prefixlen",
            &prefix,
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                "ifconfig could not set {} on {}: {}",
                tun_v6_ip(),
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("could not run ifconfig for {}: {}", interface, e);
            return false;
        }
    }

    // "File exists" is the route already being there, which is what we asked
    // for — every command here is meant to be idempotent.
    let out = Command::new("route")
        .args([
            "-n",
            "add",
            "-inet6",
            "-net",
            &TUN_V6_BASE.to_string(),
            "-prefixlen",
            &prefix,
            "-interface",
            interface,
        ])
        .output();
    match out {
        Ok(out)
            if out.status.success()
                || String::from_utf8_lossy(&out.stderr).contains("File exists") =>
        {
            true
        }
        Ok(out) => {
            tracing::warn!(
                "route could not add {} via {}: {}",
                TUN_V6_BASE,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("could not run route for {}: {}", interface, e);
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_ipv6_macos(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_BASE, TUN_V6_PREFIX_LEN};

    let prefix = TUN_V6_PREFIX_LEN.to_string();
    let _ = Command::new("route")
        .args([
            "-n",
            "delete",
            "-inet6",
            "-net",
            &TUN_V6_BASE.to_string(),
            "-prefixlen",
            &prefix,
            "-interface",
            interface,
        ])
        .output();
    // `delete` (without `alias`) removes the address configured above; the
    // interface and its IPv4 half are untouched.
    let _ = Command::new("ifconfig")
        .args([interface, "inet6", &tun_v6_ip().to_string(), "delete"])
        .output();
    Ok(())
}

/// `ip -6 addr replace` + `ip -6 route replace`; the kernel adds the connected
/// route itself, and the explicit replace covers the cases where it does not.
#[cfg(target_os = "linux")]
fn configure_ipv6_linux(interface: &str) -> bool {
    use crate::proxy::tun_proxy::{tun_v6_ip, tun_v6_network, TUN_V6_PREFIX_LEN};

    let addr = format!("{}/{}", tun_v6_ip(), TUN_V6_PREFIX_LEN);
    let out = Command::new("ip")
        .args(["-6", "addr", "replace", &addr, "dev", interface])
        .output();
    match out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                "ip could not set {} on {}: {}",
                addr,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("could not run ip for {}: {}", interface, e);
            return false;
        }
    }

    let network = tun_v6_network();
    let out = Command::new("ip")
        .args(["-6", "route", "replace", &network, "dev", interface])
        .output();
    match out {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(
                "ip could not route {} via {}: {}",
                network,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("could not run ip route for {}: {}", interface, e);
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_ipv6_linux(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_PREFIX_LEN};

    let _ = Command::new("ip")
        .args([
            "-6",
            "addr",
            "del",
            &format!("{}/{}", tun_v6_ip(), TUN_V6_PREFIX_LEN),
            "dev",
            interface,
        ])
        .output();
    Ok(())
}

/// `New-NetIPAddress` rather than the IP Helper API the IPv4 side uses: the
/// failure this has to survive is the address already being there, which the
/// cmdlet reports as an error we can simply look up, whereas the FFI path would
/// need a second unsafe call to ask the same question.
#[cfg(windows)]
fn configure_ipv6_windows(interface: &str) -> bool {
    use crate::proxy::tun_proxy::{tun_v6_ip, TUN_V6_PREFIX_LEN};

    let addr = tun_v6_ip().to_string();
    // Already there is success — every command here is idempotent.
    let present = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "(Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv6 \
                 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq '{addr}' }} \
                 | Measure-Object).Count -gt 0"
            ),
        ])
        .output();
    if let Ok(out) = &present {
        if String::from_utf8_lossy(&out.stdout).trim() == "True" {
            return true;
        }
    }

    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "New-NetIPAddress -InterfaceAlias '{interface}' -IPAddress '{addr}' \
                 -PrefixLength {TUN_V6_PREFIX_LEN} -ErrorAction Stop"
            ),
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(
                "New-NetIPAddress could not set {} on {}: {}",
                addr,
                interface,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("could not run powershell for {}: {}", interface, e);
            false
        }
    }
}

#[cfg(windows)]
fn remove_ipv6_windows(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::tun_v6_ip;

    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv6 \
                 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq '{}' }} | \
                 Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue",
                tun_v6_ip()
            ),
        ])
        .output();
    Ok(())
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
                    tracing::info!(
                        "IP Helper set {} on {} (attempt {})",
                        ip,
                        interface,
                        attempt
                    );
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
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
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
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
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
    // The same question asked of the routing table, which is where a fake-IP tool actually
    // stakes its claim: its own interface holds a /30 while the range it answers for is routed
    // at it, so no address of ours ever lands inside an address of theirs.
    let routes = foreign_route_prefixes(interface);

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
        if let Some((network, len)) = route_claiming_block(&routes, base) {
            tracing::warn!(
                "skipping {base}/24: {network}/{len} is already routed to another interface"
            );
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

// ==========================================================================
// Routes installed by other interfaces
//
// The address check above asks "does somebody already hold an address here". A
// fake-IP tool does not have to: it puts a sliver of an address on its own
// interface — a /30 is typical — and routes a range tens of thousands of times
// wider at it, so no interface holds an address in the blocks it answers for.
// What claims the block is the route.
// ==========================================================================

/// IPv4 route prefixes installed on interfaces other than `skip`, as `(network, prefix_len)`.
///
/// An enumeration failure yields an empty list, which leaves the address check as the only
/// guard — the same trade-off [`foreign_interface_addresses`] makes.
#[cfg(target_os = "macos")]
fn foreign_route_prefixes(skip: &str) -> Vec<(Ipv4Addr, u8)> {
    match Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
        Ok(output) => parse_netstat_routes(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// IPv4 route prefixes installed on interfaces other than `skip`. See the macOS twin.
///
/// `table all` and not the default main table: a route in any other table claims its prefix
/// just as loudly while a lookup reaches it through an `ip rule`, which is how a tunnel that
/// wants to sit in front of the default route installs itself. What that adds — the host and
/// broadcast addresses of the local table — is dropped by the parser, not by luck.
#[cfg(target_os = "linux")]
fn foreign_route_prefixes(skip: &str) -> Vec<(Ipv4Addr, u8)> {
    match Command::new("ip")
        .args(["-4", "route", "show", "table", "all"])
        .output()
    {
        Ok(output) => parse_ip_route_prefixes(&String::from_utf8_lossy(&output.stdout), skip),
        Err(_) => Vec::new(),
    }
}

/// A route this wide is not a claim on an address block, it is a way of taking the default
/// route: a VPN installs `0.0.0.0/1` and `128.0.0.0/1` to sit in front of every destination
/// without overwriting the default route itself. Our /24 is more specific than either, so the
/// two coexist — counting those would disqualify every candidate block on such a host.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const CLAIM_PREFIX_FLOOR: u8 = 8;

/// The mask of the leading `len` bits. A zero-length prefix masks everything, which is the
/// default route and therefore no block in particular.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn prefix_mask(len: u8) -> u32 {
    match len {
        0 => 0,
        n if n >= 32 => u32::MAX,
        n => u32::MAX << (32 - n),
    }
}

/// The route that makes `base`/24 unusable, if any: one that overlaps it.
///
/// Overlap is decided on the *shorter* of the two prefixes. A /16 somebody else routes swallows
/// the whole candidate /24 — the fake-IP case, where a tool holds one address of its own and
/// routes a range forty thousand times wider at it. A /32 inside the block claims only its own
/// address, which is still enough: it is an address the block would have to stay silent about.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn route_claiming_block(routes: &[(Ipv4Addr, u8)], base: Ipv4Addr) -> Option<(Ipv4Addr, u8)> {
    routes.iter().copied().find(|(network, len)| {
        if *len < CLAIM_PREFIX_FLOOR {
            return false;
        }
        let shared = (*len).min(24);
        let mask = prefix_mask(shared);
        (u32::from(*network) & mask) == (u32::from(base) & mask)
    })
}

/// `netstat -rn -f inet` route lines: `Destination Gateway Flags Netif [Expire]`.
///
/// The destination is printed shortened — `10/24`, `198.18.0`, `169.254` — with the prefix
/// length implied by how many bytes are written when no `/len` follows. Two kinds of line are
/// dropped: anything flagged `L`, which is an ARP cache entry rather than a route, and the
/// default route — spelled `default`, which parses as nothing at all, but also `0/0` on a table
/// that prints it numerically, which parses into a route covering every block there is.
#[cfg(any(target_os = "macos", test))]
fn parse_netstat_routes(text: &str, skip: &str) -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Destination, Gateway, Flags, Netif — the header row falls out here, its
        // destination column being the word "Destination".
        let (Some(dest), Some(netif)) = (tokens.first().copied(), tokens.get(3).copied()) else {
            continue;
        };
        if netif == skip {
            continue;
        }
        if tokens.get(2).is_some_and(|flags| flags.contains('L')) {
            continue;
        }
        if let Some(prefix) = parse_shortened_prefix(dest).filter(|(_, len)| *len > 0) {
            out.push(prefix);
        }
    }
    out
}

/// `10/24`, `198.18.0`, `169.254`, `127`, `224.0.0/4` — the destination column of `netstat -rn`,
/// where the prefix length is explicit after a slash and otherwise the number of bytes written:
/// one byte is a /8, two a /16, three a /24, four a host route.
#[cfg(any(target_os = "macos", test))]
fn parse_shortened_prefix(field: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, explicit_len) = match field.split_once('/') {
        Some((addr, len)) => (addr, Some(len.parse::<u8>().ok()?)),
        None => (field, None),
    };
    let mut octets = [0u8; 4];
    let mut written = 0u8;
    for (i, part) in addr.split('.').enumerate() {
        if i > 3 {
            return None;
        }
        octets[i] = part.parse().ok()?;
        written += 1;
    }
    if written == 0 {
        return None;
    }
    let len = explicit_len.unwrap_or(written * 8);
    (len <= 32).then_some((Ipv4Addr::from(octets), len))
}

/// The route types `ip` prints ahead of the destination — the ones that stand for a prefix
/// rather than for an address of this host. Each of them keeps the packets its prefix names,
/// which is what makes it a claim on a block.
#[cfg(any(target_os = "linux", test))]
const IP_ROUTE_TYPES: [&str; 5] = ["blackhole", "unreachable", "prohibit", "throw", "nat"];

/// `ip -4 route show` lines: `[<type>] <prefix> [via <gw>] dev <ifname> ...`.
///
/// The default route is dropped for the same reason as on macOS: every host has one, and
/// counting it would disqualify every block. It is spelled `default` here, or `0.0.0.0/0` on a
/// table that prints it numerically; the first parses as nothing, the second is filtered by its
/// prefix length. A route with no `dev` — a blackhole, for instance — belongs to nobody, which
/// still leaves the prefix spoken for, so its type is read past rather than read as the
/// destination.
#[cfg(any(target_os = "linux", test))]
fn parse_ip_route_prefixes(text: &str, skip: &str) -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.windows(2).any(|pair| pair == ["dev", skip]) {
            continue;
        }
        // `ip` prints the type of a route that has one ahead of its prefix, and
        // those are exactly the routes with no interface to exclude: a blackhole
        // swallows the block it names as surely as a device does.
        let dest = match tokens.split_first() {
            Some((first, rest)) if IP_ROUTE_TYPES.contains(first) => match rest.first().copied() {
                Some(next) => next,
                None => continue,
            },
            Some((first, _)) => *first,
            None => continue,
        };
        let prefix = match dest.split_once('/') {
            Some((addr, len)) => len
                .parse::<u8>()
                .ok()
                .zip(addr.parse().ok())
                .map(|(len, addr)| (addr, len)),
            None => dest.parse::<Ipv4Addr>().ok().map(|addr| (addr, 32)),
        };
        if let Some(prefix) = prefix.filter(|(_, len)| *len > 0 && *len <= 32) {
            out.push(prefix);
        }
    }
    out
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
    use std::net::Ipv4Addr;

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

    /// The hole the route check closes: a fake-IP tool holds 198.18.0.1/30 on its own utun and
    /// routes 198.18/16 at it, so no interface holds an address in the /24 we would take.
    #[test]
    fn a_foreign_route_covering_a_candidate_block_is_collected_macos() {
        // `netstat -rn -f inet` as it actually prints: shortened destinations, ARP entries
        // flagged `L`, and our own interface's route sitting among them.
        let text = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.0.0.1           UGScg                 en0
0/0                10.0.0.1           UGSc                  en0
10/24              link#12            UCS                   en0      !
10.0.0.99          8c:d0:b2:19:a8:b2  UHLWI                 en0   1157
127                127.0.0.1          UCS                   lo0
169.254            link#12            UCS                   en0      !
198.18/16          utun8              USc                 utun8
198.18.0           utun8              USc               nexa-tun
224.0.0/4          link#12            UmCS                  en0      !
";
        let routes = super::parse_netstat_routes(text, "nexa-tun");
        assert!(
            routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
            "the fake-IP route was not collected: {routes:?}"
        );
        // The prefix length is read off the bytes written when no `/len` follows.
        assert!(
            routes.contains(&(Ipv4Addr::new(169, 254, 0, 0), 16)),
            "a shortened destination lost its implied prefix: {routes:?}"
        );
        assert!(routes.contains(&(Ipv4Addr::new(10, 0, 0, 0), 24)));
        // Our own interface is skipped, the ARP entry is a neighbour rather than a destination,
        // and the default route is not a claim on any block.
        assert!(
            !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
            "our own route must be excluded: {routes:?}"
        );
        assert!(
            !routes.contains(&(Ipv4Addr::new(10, 0, 0, 99), 32)),
            "an ARP entry is not a route: {routes:?}"
        );
        assert!(
            !routes.iter().any(|(_, len)| *len == 0),
            "the default route must not be collected: {routes:?}"
        );
    }

    /// Linux twin of the above: `ip -4 route show` names the prefix in full and the interface
    /// after `dev`.
    #[test]
    fn a_foreign_route_covering_a_candidate_block_is_collected_linux() {
        let text = "\
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.83 metric 100
0.0.0.0/0 via 10.0.0.1 dev eth0 proto dhcp
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.83 metric 100
10.0.0.99 dev eth0 scope link
198.18.0.0/16 dev tun0 proto kernel scope link src 198.18.0.1
198.18.0.0/24 dev nexa-tun proto kernel scope link src 198.18.0.254
";
        let routes = super::parse_ip_route_prefixes(text, "nexa-tun");
        assert!(
            routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
            "the fake-IP route was not collected: {routes:?}"
        );
        assert!(routes.contains(&(Ipv4Addr::new(10, 0, 0, 0), 24)));
        // A bare address is a host route, not a /24.
        assert!(
            routes.contains(&(Ipv4Addr::new(10, 0, 0, 99), 32)),
            "a host route lost its /32: {routes:?}"
        );
        assert!(
            !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
            "our own route must be excluded: {routes:?}"
        );
        assert!(
            !routes.iter().any(|(_, len)| *len == 0),
            "the default route must not be collected: {routes:?}"
        );
    }

    /// The two ways a route used to hide: one installed in a table other than
    /// main, reached through an `ip rule`, and one whose type `ip` prints ahead
    /// of its prefix. Both claim the block they name — a blackhole more loudly
    /// than most — and neither carries a `dev` to be excluded by.
    #[test]
    fn a_route_from_another_table_or_of_another_type_still_claims() {
        let text = "\
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.83 metric 100
blackhole 100.100.0.0/24
unreachable 198.18.0.0/16
172.26.0.0/16 dev wg0 table 51820 proto static scope link
local 10.0.0.83 dev eth0 table local proto kernel scope host src 10.0.0.83
broadcast 10.0.0.255 dev eth0 table local proto kernel scope link src 10.0.0.83
198.18.0.0/24 dev nexa-tun proto kernel scope link src 198.18.0.254
";
        let routes = super::parse_ip_route_prefixes(text, "nexa-tun");
        assert!(
            routes.contains(&(Ipv4Addr::new(100, 100, 0, 0), 24)),
            "a blackhole route was not collected: {routes:?}"
        );
        assert!(
            routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 16)),
            "an unreachable route was not collected: {routes:?}"
        );
        assert!(
            routes.contains(&(Ipv4Addr::new(172, 26, 0, 0), 16)),
            "a route from another table was not collected: {routes:?}"
        );
        assert!(
            !routes.contains(&(Ipv4Addr::new(198, 18, 0, 0), 24)),
            "our own route must be excluded: {routes:?}"
        );
        // What `table all` adds and this does not want: the host and broadcast
        // addresses of the local table, which name no block.
        assert!(
            !routes.contains(&(Ipv4Addr::new(10, 0, 0, 83), 32)),
            "a local address is not a route: {routes:?}"
        );
        assert!(
            !routes.contains(&(Ipv4Addr::new(10, 0, 0, 255), 32)),
            "a broadcast address is not a route: {routes:?}"
        );
    }

    /// A /16 somebody else routes swallows the whole candidate /24.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_route_wider_than_the_block_claims_it() {
        let routes = [(Ipv4Addr::new(198, 18, 0, 0), 16)];
        assert_eq!(
            super::route_claiming_block(&routes, Ipv4Addr::new(198, 18, 0, 0)),
            Some((Ipv4Addr::new(198, 18, 0, 0), 16))
        );
        assert_eq!(
            super::route_claiming_block(&routes, Ipv4Addr::new(100, 100, 0, 0)),
            None
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_host_route_inside_the_block_claims_it_too() {
        let routes = [(Ipv4Addr::new(100, 100, 0, 7), 32)];
        assert_eq!(
            super::route_claiming_block(&routes, Ipv4Addr::new(100, 100, 0, 0)),
            Some((Ipv4Addr::new(100, 100, 0, 7), 32))
        );
    }

    /// `0.0.0.0/1` + `128.0.0.0/1` is how a VPN takes every destination without overwriting the
    /// default route. Our /24 is more specific than either, so no block is unusable for it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn taking_every_destination_is_not_a_claim_on_any_block() {
        let routes = [
            (Ipv4Addr::new(0, 0, 0, 0), 1),
            (Ipv4Addr::new(128, 0, 0, 0), 1),
        ];
        for base in super::TUN_BASE_CANDIDATES {
            assert_eq!(
                super::route_claiming_block(&routes, base),
                None,
                "{base}/24 was claimed by a route that owns every destination"
            );
        }
    }
}
