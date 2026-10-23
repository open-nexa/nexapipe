//! The Windows half of the TUN interface and route management: the IP Helper API for the
//! IPv4 address, and PowerShell for the IPv6 one.

use super::*;

/// `New-NetIPAddress` rather than the IP Helper API the IPv4 side uses: the
/// failure this has to survive is the address already being there, which the
/// cmdlet reports as an error we can simply look up, whereas the FFI path would
/// need a second unsafe call to ask the same question.
#[cfg(windows)]
pub(super) fn configure_ipv6_windows(interface: &str) -> bool {
    use crate::proxy::tun_proxy::tun_v6_ip;

    let addr = tun_v6_ip().to_string();
    // Already there is success — every command here is idempotent.
    let present = powershell::run(&powershell::Call::new(
        powershell::has_ipv6_script(),
        interface,
        &addr,
    ));
    if let Ok(out) = &present {
        if String::from_utf8_lossy(&out.stdout).trim() == "True" {
            return true;
        }
    }

    let out = powershell::run(&powershell::Call::new(
        powershell::set_ipv6_script(),
        interface,
        &addr,
    ));
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
pub(super) fn remove_ipv6_windows(interface: &str) -> Result<()> {
    use crate::proxy::tun_proxy::tun_v6_ip;

    let _ = powershell::run(&powershell::Call::new(
        powershell::remove_ipv6_script(),
        interface,
        &tun_v6_ip().to_string(),
    ));
    Ok(())
}

#[cfg(windows)]
pub(super) fn configure_interface_windows(interface: &str) -> Result<()> {
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
            let output = hidden("netsh")
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
    let seen = hidden("ipconfig").output().map(|o| {
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
