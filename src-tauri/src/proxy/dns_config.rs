//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! - Windows: netsh (same as the previous implementation)
//! - Linux:   resolvectl (systemd-resolved), falling back to overwriting /etc/resolv.conf
//!            (with a backup)
//! - macOS:   networksetup (iterating over every network service)
//!
//! Note: the local DNS server (proxy/dns.rs) must be started before `set_system_dns`,
//! otherwise the switched-over system DNS queries would have nobody to answer them.

use anyhow::Result;
use std::process::Command;

/// Points system DNS at the TUN virtual IP.
pub fn set_system_dns(interface: &str, dns_ip: &str) -> Result<()> {
    // Only the Linux branch needs `interface` (resolvectl); other platforms ignore it
    #[cfg(not(target_os = "linux"))]
    let _ = interface;

    #[cfg(windows)]
    {
        set_system_dns_windows(dns_ip)
    }

    #[cfg(target_os = "linux")]
    {
        set_system_dns_linux(interface, dns_ip)
    }

    #[cfg(target_os = "macos")]
    {
        set_system_dns_macos(dns_ip)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

/// Restores the system DNS configuration (best effort).
pub fn restore_system_dns(interface: &str, dns_ip: &str) -> Result<()> {
    // Only the Linux branch needs `interface` (resolvectl revert); other platforms ignore it
    #[cfg(not(target_os = "linux"))]
    let _ = interface;

    #[cfg(windows)]
    {
        restore_system_dns_windows(dns_ip)
    }

    #[cfg(target_os = "linux")]
    {
        restore_system_dns_linux(interface, dns_ip)
    }

    #[cfg(target_os = "macos")]
    {
        restore_system_dns_macos(dns_ip)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

// ============================================================
// Windows — netsh
// ============================================================

#[cfg(windows)]
fn set_system_dns_windows(dns_ip: &str) -> Result<()> {
    // On Windows IPv6 DNS takes priority and the two families race in parallel: if the NIC
    // keeps a public IPv6 DNS server (e.g. a fe80::... link-local or an ISP-assigned one),
    // the browser may still query IPv6 DNS first even though the 10.0.0.254 IPv4 DNS is in
    // effect — the public resolver then returns NXDOMAIN and the browser reports
    // DNS_PROBE_FINISHED_NXDOMAIN.
    // So the static IPv6 DNS servers have to be cleared as well, letting queries fall back to
    // IPv4 10.0.0.254.
    //
    // Strategy, for every adapter that is Up:
    //   IPv4: statically set to dns_ip (10.0.0.254)
    //   IPv6: reset to DHCP / no static DNS (this proxy does not serve DNS over IPv6), so a
    //         public IPv6 resolver cannot answer first
    let ps_cmd = format!(
        "$adapters = Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }};\
         $adapters | Set-DnsClientServerAddress -AddressFamily IPv4 -ServerAddresses {0};\
         $adapters | Set-DnsClientServerAddress -AddressFamily IPv6 -ResetServerAddresses;",
        dns_ip
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run powershell: {}", e))?;
    if output.status.success() {
        tracing::info!(
            "System DNS IPv4={}, IPv6=DHCP (via PowerShell Set-DnsClientServerAddress)",
            dns_ip
        );
        return Ok(());
    }
    tracing::warn!(
        "PowerShell Set-DnsClientServerAddress failed (exit {:?}): stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    // Fallback: netsh sets IPv4 and resets IPv6 DNS separately
    let _ = Command::new("netsh")
        .args([
            "interface", "ip", "set", "dnsservers", "all", dns_ip, "primary",
        ])
        .output();
    let _ = Command::new("netsh")
        .args([
            "interface", "ipv6", "set", "dnsservers", "all", "dhcp",
        ])
        .output();
    tracing::info!("System DNS fallback netsh applied (IPv4 set, IPv6 reset dhcp)");
    Ok(())
}

#[cfg(windows)]
fn restore_system_dns_windows(_dns_ip: &str) -> Result<()> {
    // Symmetric to set: first use PowerShell to reset both IPv4 and IPv6 to DHCP, so that a
    // leftover static IPv6 DNS server cannot break connectivity after restoring IPv4 only.
    let ps_cmd = "$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' };\
                  $adapters | Set-DnsClientServerAddress -AddressFamily IPv4 -ResetServerAddresses;\
                  $adapters | Set-DnsClientServerAddress -AddressFamily IPv6 -ResetServerAddresses;";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run powershell: {}", e))?;
    if output.status.success() {
        tracing::info!("System DNS IPv4+IPv6 restored to DHCP via PowerShell");
        return Ok(());
    }
    tracing::warn!(
        "PowerShell restore dns failed (exit {:?}): stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    // Fallback via netsh
    let _ = Command::new("netsh")
        .args(["interface", "ip", "set", "dnsservers", "all", "dhcp"])
        .output();
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "set", "dnsservers", "all", "dhcp"])
        .output();
    tracing::info!("System DNS fallback netsh restore dhcp applied");
    Ok(())
}

// ============================================================
// Linux — resolvectl, falling back to /etc/resolv.conf
// ============================================================

#[cfg(target_os = "linux")]
const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.nexapipe.bak";

#[cfg(target_os = "linux")]
fn set_system_dns_linux(interface: &str, dns_ip: &str) -> Result<()> {
    // Prefer resolvectl (systemd-resolved)
    if let Ok(output) = Command::new("resolvectl")
        .args(["dns", interface, dns_ip])
        .output()
    {
        if output.status.success() {
            tracing::info!("resolvectl set DNS for {}: {}", interface, dns_ip);
            return Ok(());
        }
    }

    // Fallback: back up and overwrite /etc/resolv.conf
    let _ = std::fs::copy("/etc/resolv.conf", RESOLV_CONF_BACKUP);
    std::fs::write("/etc/resolv.conf", format!("nameserver {}\n", dns_ip))
        .map_err(|e| anyhow::anyhow!("Failed to write /etc/resolv.conf: {}", e))?;
    tracing::info!("Wrote /etc/resolv.conf with nameserver {}", dns_ip);
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_system_dns_linux(interface: &str, _dns_ip: &str) -> Result<()> {
    // Prefer reverting via resolvectl
    let _ = Command::new("resolvectl")
        .args(["revert", interface])
        .output();

    // Restore from the resolv.conf backup if it exists
    if let Ok(backup) = std::fs::read(RESOLV_CONF_BACKUP) {
        let _ = std::fs::write("/etc/resolv.conf", backup);
        let _ = std::fs::remove_file(RESOLV_CONF_BACKUP);
    }
    Ok(())
}

// ============================================================
// macOS — networksetup
// ============================================================

#[cfg(target_os = "macos")]
fn set_system_dns_macos(dns_ip: &str) -> Result<()> {
    let services = network_services()?;
    if services.is_empty() {
        tracing::warn!("No network services found via networksetup");
        return Ok(());
    }
    for service in &services {
        match Command::new("networksetup")
            .args(["-setdnsservers", service, dns_ip])
            .output()
        {
            Ok(o) if o.status.success() => {
                tracing::info!("Set DNS for {}: {}", service, dns_ip)
            }
            Ok(o) => tracing::warn!(
                "networksetup failed for {}: {}",
                service,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::warn!("Failed to run networksetup for {}: {}", service, e),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_system_dns_macos(_dns_ip: &str) -> Result<()> {
    let services = network_services().unwrap_or_default();
    for service in &services {
        // "Empty" restores DHCP / the system default
        let _ = Command::new("networksetup")
            .args(["-setdnsservers", service, "Empty"])
            .output();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn network_services() -> Result<Vec<String>> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| {
            anyhow::anyhow!("Failed to run networksetup -listallnetworkservices: {}", e)
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
        .map(|l| l.trim().to_string())
        .collect())
}
