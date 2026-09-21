//! Cross-platform TUN interface address and route management.
//!
//! After creating the TUN device, call `configure_interface` + `add_routes` to make the
//! virtual subnet routable; call `remove_routes` on shutdown to clean up. Every command is
//! idempotent, so running it repeatedly never fails.
//!
//! - Windows: netsh (the wintun adapter needs an explicit IP)
//! - Linux:   ip addr / ip link / ip route (the kernel adds the connected route itself;
//!            an explicit `replace` acts as a fallback)
//! - macOS:   ifconfig / route (utun interfaces need an explicit IP and route)

use anyhow::Result;
use std::process::Command;

#[cfg(windows)]
use crate::proxy::tun_proxy::{TUN_IP, TUN_NETMASK};
#[cfg(target_os = "macos")]
use crate::proxy::tun_proxy::{TUN_IP, TUN_NETMASK};
#[cfg(target_os = "linux")]
use crate::proxy::tun_proxy::{TUN_IP, TUN_NETWORK};
#[cfg(windows)]
use std::net::UdpSocket;
#[cfg(windows)]
use std::time::Duration;

/// Assigns the TUN interface IP address and brings the interface up (idempotent).
pub fn configure_interface(interface: &str) -> Result<()> {
    #[cfg(windows)]
    {
        configure_interface_windows(interface)
    }

    #[cfg(target_os = "linux")]
    {
        configure_interface_linux(interface)
    }

    #[cfg(target_os = "macos")]
    {
        configure_interface_macos(interface)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

/// Makes sure the route for the virtual subnet exists (idempotent). The kernel normally adds
/// the connected route once the interface address is set; on some platforms we add it
/// explicitly in case the automatic route is missing.
pub fn add_routes(interface: &str) -> Result<()> {
    #[cfg(windows)]
    {
        // `netsh set address` already added the 10.0.0.0/24 connected route
        let _ = interface;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "replace", TUN_NETWORK, "dev", interface])
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
        let output = Command::new("route")
            .args([
                "-n",
                "add",
                "-net",
                "10.0.0.0",
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
            .args(["route", "del", TUN_NETWORK, "dev", interface])
            .output();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args([
                "-n",
                "delete",
                "-net",
                "10.0.0.0",
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
    // Retry up to 5 times: when netsh reports success the address should be usable right
    // away, but in some cases Windows needs a moment before it actually attaches the address
    // to the interface — otherwise the later bind to 10.0.0.254:53 fails with
    // WSAEADDRNOTAVAIL (10049). Each attempt runs netsh, then verifies the address is
    // really bindable.
    for attempt in 1..=5 {
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &format!("name={}", interface),
                "static",
                TUN_IP,
                TUN_NETMASK,
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run netsh: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            anyhow::bail!(
                "netsh set address failed (attempt {}): {} {}",
                attempt,
                stderr,
                stdout
            );
        }

        // Verify: 10.0.0.254 must already be a locally bindable address (matching the DNS
        // server bind precondition).
        if is_local_address_bindable(TUN_IP) {
            tracing::info!(
                "Interface {} configured with {} netmask {}",
                interface,
                TUN_IP,
                TUN_NETMASK
            );
            return Ok(());
        }

        tracing::warn!(
            "netsh set address returned success but {} is not bindable yet (attempt {}), retrying...",
            TUN_IP,
            attempt
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    anyhow::bail!(
        "Failed to assign {} to interface {} after 5 attempts: the TUN address is not local, DNS server cannot bind and routing will not work",
        TUN_IP,
        interface
    )
}

#[cfg(windows)]
fn is_local_address_bindable(ip: &str) -> bool {
    // Bind a temporary UDP socket to the address (port 0, i.e. random). Success means the
    // address really is attached to a local interface; failure (usually WSAEADDRNOTAVAIL,
    // 10049) means it is not ready yet.
    UdpSocket::bind((ip, 0)).is_ok()
}

#[cfg(target_os = "linux")]
fn configure_interface_linux(interface: &str) -> Result<()> {
    // `ip addr replace` is idempotent — setting the same address twice does not fail
    let output = Command::new("ip")
        .args([
            "addr",
            "replace",
            &format!("{}/24", TUN_IP),
            "dev",
            interface,
        ])
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

#[cfg(target_os = "macos")]
fn configure_interface_macos(interface: &str) -> Result<()> {
    // ifconfig utunX inet 10.0.0.254 255.255.255.0 — running it again replaces the existing
    // address (idempotent)
    let output = Command::new("ifconfig")
        .args([interface, "inet", TUN_IP, TUN_NETMASK])
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
