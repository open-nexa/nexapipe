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

#[cfg(windows)]
use crate::win::hidden;
use anyhow::Result;
#[cfg(not(windows))]
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

#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod interface;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use interface::*;

#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "linux", test))]
use linux::*;

#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(any(target_os = "macos", test))]
use macos::*;

#[cfg(any(windows, test))]
mod powershell;

#[cfg(test)]
mod tests;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::*;

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
