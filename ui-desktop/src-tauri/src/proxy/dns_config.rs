//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! - Windows: PowerShell Set-DnsClientServerAddress (netsh fallback), verified afterwards
//! - Linux:   resolvectl (systemd-resolved), falling back to overwriting /etc/resolv.conf
//!   (with a backup)
//! - macOS:   networksetup (iterating over every network service)
//!
//! Note: the local DNS server (proxy/dns.rs) must be started before `set_system_dns`,
//! otherwise the switched-over system DNS queries would have nobody to answer them.

use anyhow::Result;
use std::process::Command;

/// Points system DNS at the TUN virtual IP.
pub fn set_system_dns(interface: &str, dns_ip: &str) -> Result<()> {
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;

    #[cfg(windows)]
    {
        set_system_dns_windows(interface, dns_ip)
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
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;

    #[cfg(windows)]
    {
        restore_system_dns_windows(interface, dns_ip)
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
// Windows — PowerShell Set-DnsClientServerAddress, netsh fallback
// ============================================================

#[cfg(windows)]
fn set_system_dns_windows(interface: &str, dns_ip: &str) -> Result<()> {
    // On Windows all configured DNS servers race in parallel (smart multi-homed name
    // resolution): if the NIC keeps a public IPv6 DNS server — typically a router-learned
    // fe80::... link-local one that `-ResetServerAddresses` cannot remove because it is not
    // static — it answers proxied domains with NXDOMAIN (they do not exist publicly) faster
    // than the TUN resolver answers, and the browser reports DNS_PROBE_FINISHED_NXDOMAIN.
    // The race is won by giving every physical adapter a *static* IPv6 DNS of ::1, which
    // replaces the learned list, and running the same local DNS server on [::1]:53.
    //
    // Strategy, for every adapter that is Up (except the TUN adapter itself):
    //   1. reset both address families to DHCP (drops any static public DNS)
    //   2. statically set the IPv4 DNS to the TUN virtual IP
    //   3. statically set the IPv6 DNS to ::1 (the local DNS server listens there)
    //   4. flush the resolver cache (earlier failures may have negative-cached the domain)
    match set_system_windows_dns_ps(interface, dns_ip) {
        Ok(dump) if dump.contains(dns_ip) => {
            if !dump.contains("::1") {
                tracing::warn!(
                    "IPv6 DNS ::1 is missing from the effective DNS — a router-learned v6 DNS may still win the race: {}",
                    dump.trim()
                );
            }
            tracing::info!(
                "System DNS set to {} (verified): {}",
                dns_ip,
                dump.trim().replace('\n', "; ")
            );
            return Ok(());
        }
        Ok(dump) => {
            tracing::warn!(
                "PowerShell Set-DnsClientServerAddress ran but {} is missing from the effective DNS: {}",
                dns_ip,
                dump.trim()
            );
        }
        Err(e) => {
            tracing::warn!("PowerShell Set-DnsClientServerAddress failed: {}", e);
        }
    }

    // Fallback: netsh sets IPv4 and resets IPv6 DNS separately. This works when running
    // elevated in process mode, but is a silent no-op under LocalSystem (exit 0, no
    // effect) — so verify the result instead of trusting the exit code.
    let _ = Command::new("netsh")
        .args([
            "interface", "ip", "set", "dnsservers", "all", dns_ip, "primary",
        ])
        .output();
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "set", "dnsservers", "all", "dhcp"])
        .output();
    if windows_dns_points_at(dns_ip) {
        tracing::info!("System DNS set to {} via netsh fallback (verified)", dns_ip);
        return Ok(());
    }
    anyhow::bail!(
        "Failed to point system DNS at the TUN resolver {} — DNS hijack is NOT in effect",
        dns_ip
    )
}

/// Runs the per-adapter DNS switch and returns a dump of the effective IPv4 DNS servers
/// ("<alias>: <addr>,..." per line) for the caller to verify against.
#[cfg(windows)]
fn set_system_windows_dns_ps(interface: &str, dns_ip: &str) -> Result<String> {
    // IMPORTANT: `Set-DnsClientServerAddress` has NO `-AddressFamily` parameter (only the
    // `Get-` cmdlet does). Passing it fails with NamedParameterNotFound — that used to send
    // us down the netsh fallback, which is a silent no-op under LocalSystem, so the DNS
    // hijack never actually happened while the log still claimed success.
    let itf = interface.replace('\'', "''");
    let ps_cmd = format!(
        "$tun = '{1}';\
         Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.Name -ne $tun }} | ForEach-Object {{\
           $a = $_;\
           try {{ $a | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop }} catch {{ Write-Warning ('reset ' + $a.Name + ': ' + $_.Exception.Message) }};\
           try {{ $a | Set-DnsClientServerAddress -ServerAddresses '{0}' -ErrorAction Stop }} catch {{ Write-Warning ('set ' + $a.Name + ': ' + $_.Exception.Message) }};\
           try {{ $a | Set-DnsClientServerAddress -ServerAddresses '::1' -ErrorAction Stop }} catch {{ Write-Warning ('set v6 ' + $a.Name + ': ' + $_.Exception.Message) }}\
         }};\
         Clear-DnsClientCache;\
         Get-DnsClientServerAddress | Where-Object {{ $_.ServerAddresses }} | ForEach-Object {{ $_.InterfaceAlias + ' [' + $_.AddressFamily + ']: ' + ($_.ServerAddresses -join ',') }}",
        dns_ip, itf
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run powershell: {}", e))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        tracing::warn!("set system DNS powershell stderr: {}", stderr.trim());
    }
    if !output.status.success() {
        anyhow::bail!(
            "Set-DnsClientServerAddress exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// True when at least one adapter's effective IPv4 DNS list contains `dns_ip`.
#[cfg(windows)]
fn windows_dns_points_at(dns_ip: &str) -> bool {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses -join ',' }",
        ])
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(dns_ip),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn restore_system_dns_windows(interface: &str, _dns_ip: &str) -> Result<()> {
    // Symmetric to set: reset both IPv4 and IPv6 to DHCP on every Up adapter (except the
    // TUN one). This drops the hijack's static IPv4 DNS *and* the static ::1 IPv6 DNS, so
    // neither a leftover static server nor a poisoned resolver cache can break connectivity
    // afterwards. Best effort — a failed restore is logged, not propagated.
    let itf = interface.replace('\'', "''");
    let ps_cmd = format!(
        "$tun = '{0}';\
         Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.Name -ne $tun }} | ForEach-Object {{\
           try {{ $_ | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop }} catch {{ Write-Warning ('reset ' + $_.Name + ': ' + $_.Exception.Message) }}\
         }};\
         Clear-DnsClientCache",
        itf
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                tracing::warn!("restore system DNS powershell stderr: {}", stderr.trim());
            }
            tracing::info!("System DNS IPv4+IPv6 restored to DHCP via PowerShell");
            return Ok(());
        }
        Ok(o) => {
            tracing::warn!(
                "PowerShell restore dns failed (exit {:?}): stdout={} stderr={}",
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => {
            tracing::warn!("Failed to run powershell for DNS restore: {}", e);
        }
    }

    // Fallback via netsh (best effort; silent no-op under LocalSystem)
    let _ = Command::new("netsh")
        .args(["interface", "ip", "set", "dnsservers", "all", "dhcp"])
        .output();
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "set", "dnsservers", "all", "dhcp"])
        .output();
    tracing::info!("System DNS fallback netsh restore dhcp applied");
    Ok(())
}

/// Resets adapters whose DNS still points at a TUN hijack that is no longer running.
///
/// The hijack normally restores the system DNS when the proxy stops, but a killed process
/// or a machine shutdown skips that — and static DNS entries survive a reboot, so the
/// machine comes back with its DNS pointing at a TUN address that does not exist (plus a
/// dead ::1) and "the internet is broken", including for this service itself (iroh cannot
/// publish to pkarr without name resolution). Called when the service starts, before
/// anything needs DNS.
///
/// An adapter counts as stale when its IPv4 DNS is one of the TUN candidate addresses —
/// nobody configures those legitimately — or its IPv6 DNS is exactly ::1 while nothing
/// listens on [::1]:53 (the hijack's marker; a real localhost resolver holds that socket).
pub fn cleanup_stale_hijack() {
    #[cfg(windows)]
    cleanup_stale_hijack_windows();
}

#[cfg(windows)]
fn cleanup_stale_hijack_windows() {
    use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
    use std::net::Ipv4Addr;

    let stale: Vec<String> = TUN_BASE_CANDIDATES
        .iter()
        .map(|base| Ipv4Addr::from(u32::from(*base) | 0x0000_00FE).to_string())
        .collect();
    let list = stale.join("','");
    let ps_cmd = format!(
        "$stale = @('{0}');\
         $v6Listener = @(Get-NetUDPEndpoint -LocalAddress ::1 -LocalPort 53 -ErrorAction SilentlyContinue).Count -gt 0;\
         $reset = @();\
         Get-DnsClientServerAddress | Where-Object {{ $_.ServerAddresses }} | ForEach-Object {{\
           $hit = $false;\
           if ($_.AddressFamily -eq 2) {{ foreach ($s in $_.ServerAddresses) {{ if ($stale -contains $s) {{ $hit = $true }} }} }};\
           if ($_.AddressFamily -eq 23 -and -not $v6Listener -and ($_.ServerAddresses -contains '::1')) {{ $hit = $true }};\
           if ($hit) {{ $reset += $_.InterfaceIndex }}\
         }};\
         $reset = @($reset | Select-Object -Unique);\
         foreach ($i in $reset) {{\
           try {{ Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses -ErrorAction Stop; Write-Output ('reset ifindex ' + $i) }} catch {{ Write-Warning ('reset ifindex ' + $i + ': ' + $_.Exception.Message) }}\
         }};\
         if ($reset.Count -gt 0) {{ Clear-DnsClientCache }};\
         Write-Output ('stale adapters reset: ' + $reset.Count)",
        list
    );
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output()
    {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                tracing::warn!("stale DNS hijack cleanup warnings: {}", stderr.trim());
            }
            tracing::info!(
                "stale DNS hijack cleanup: {}",
                String::from_utf8_lossy(&o.stdout).trim().replace('\n', "; ")
            );
        }
        Err(e) => tracing::warn!("stale DNS hijack cleanup could not run: {}", e),
    }
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
