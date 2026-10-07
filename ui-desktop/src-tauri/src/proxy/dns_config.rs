//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! - Windows: PowerShell Set-DnsClientServerAddress (netsh fallback), verified afterwards
//! - Linux:   resolvectl (systemd-resolved), falling back to overwriting /etc/resolv.conf
//!   (with a backup, which the restore puts back)
//! - macOS:   networksetup (iterating over every network service), with the pre-hijack
//!   servers kept on file so a restore can put them back
//!
//! Note: the local DNS server (proxy/dns.rs) must be started before `set_system_dns`,
//! otherwise the switched-over system DNS queries would have nobody to answer them.

use anyhow::Result;
use std::process::Command;

// The candidate blocks, and the two tests that separate a stale hijack from a live
// one, are shared by the platforms that write a DNS setting somewhere outside this
// process: macOS into the system configuration, Linux into a file. Both of them
// keep it across a reboot, which is what makes a missed restore permanent.
// One platform wider than the platform code: `is_tun_dns_address` is compiled
// under `test` everywhere, and this is what it compares against.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::net::{Ipv4Addr, UdpSocket};
// `IpAddr` is imported one platform wider: the file's parsers are compiled under
// `test` everywhere so they can be exercised on any host, and this is the type they
// parse into. The two above are needed only by the platform code itself.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::path::Path;

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
/// publish to pkarr without name resolution). Called when the service starts and when the
/// desktop app starts, before anything needs DNS.
///
/// An adapter counts as stale when its IPv4 DNS is one of the TUN candidate addresses —
/// nobody configures those legitimately — or its IPv6 DNS is exactly ::1 while nothing
/// listens on [::1]:53 (the hijack's marker; a real localhost resolver holds that socket).
///
/// On macOS and Linux the same question is asked of the system resolver, and an address
/// that is still held by an interface is left alone — see [`cleanup_stale_hijack_macos`]
/// and [`cleanup_stale_hijack_linux`].
pub fn cleanup_stale_hijack() {
    #[cfg(windows)]
    cleanup_stale_hijack_windows();

    #[cfg(target_os = "macos")]
    cleanup_stale_hijack_macos();

    #[cfg(target_os = "linux")]
    cleanup_stale_hijack_linux();
}

/// Resets network services whose DNS still points at a TUN address no interface holds.
///
/// The macOS counterpart of [`cleanup_stale_hijack_windows`], and the reason this platform
/// needed one: `networksetup` writes a static DNS into the system configuration, where it
/// survives both the process that set it and a reboot, so a run that never reached its
/// restore leaves the machine resolving against a TUN address that no longer exists — "the
/// internet is broken", with nothing left to undo it.
///
/// A service is stale when its DNS is one of the hijack's own addresses *and* that address
/// is no longer bindable: while the tunnel is up the answer is the one we asked for, and
/// resetting it would break a proxy that is running.
#[cfg(target_os = "macos")]
fn cleanup_stale_hijack_macos() {
    let services = match network_services() {
        Ok(services) => services,
        Err(e) => {
            tracing::warn!(
                "stale DNS hijack cleanup could not list the network services: {}",
                e
            );
            return;
        }
    };

    let recorded = read_dns_backup();
    let mut reset = Vec::new();
    let mut failed = Vec::new();

    for service in &services {
        let Some(servers) = dns_servers_for(service) else {
            continue;
        };
        let stale: Vec<&str> = servers
            .iter()
            .filter(|server| is_tun_dns_address(server))
            .map(String::as_str)
            .collect();
        if stale.is_empty() {
            continue;
        }
        if stale.iter().any(|address| address_is_held(address)) {
            tracing::info!(
                "{} points at {}, which an interface still holds — not a stale hijack",
                service,
                stale.join(", ")
            );
            continue;
        }

        let target = match recorded.get(service).filter(|servers| !servers.is_empty()) {
            Some(servers) => servers.clone(),
            None => vec![EMPTY.to_string()],
        };
        match set_dns_servers(service, &target) {
            Ok(()) => {
                tracing::warn!(
                    "stale DNS hijack on {}: reset {} to {:?}",
                    service,
                    stale.join(", "),
                    target
                );
                reset.push(service.clone());
            }
            // Expected when this process is not elevated: the desktop cannot change
            // system DNS by itself, and the service runs as root and will clean up on
            // its own start. Recorded all the same, because this service still needs
            // its original servers and the backup is the only record of them.
            Err(e) => {
                tracing::warn!("could not reset the stale DNS of {}: {}", service, e);
                failed.push(service.clone());
            }
        }
    }

    if reset.is_empty() {
        tracing::info!("stale DNS hijack cleanup: nothing to reset");
        return;
    }

    tracing::warn!(
        "stale DNS hijack cleanup: reset {} network service(s): {}",
        reset.len(),
        reset.join(", ")
    );

    if backup_is_spent(&reset, &failed) {
        // A later hijack has to record its own starting point.
        let _ = std::fs::remove_file(DNS_BACKUP_PATH);
    } else {
        tracing::warn!(
            "kept {}: {} could not be reset, and its original DNS is recorded nowhere else",
            DNS_BACKUP_PATH,
            failed.join(", ")
        );
    }
}

/// Whether the recorded DNS can be retired after a cleanup pass.
///
/// Only when something was actually reset *and* nothing failed. A service that
/// could not be reset still carries the hijack address, so it will be attempted
/// again — and its original servers are in no other place. Clearing the file
/// here would leave the next pass able only to hand it to DHCP.
#[cfg(target_os = "macos")]
fn backup_is_spent(reset: &[String], failed: &[String]) -> bool {
    !reset.is_empty() && failed.is_empty()
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
    // Prefer resolvectl (systemd-resolved): it leaves the machine's own resolver in
    // the loop, so only the proxied domains go through the TUN.
    match Command::new("resolvectl")
        .args(["dns", interface, dns_ip])
        .output()
    {
        Ok(output) if output.status.success() => {
            // Read back rather than trusting the exit code: a hijack that silently
            // did not take looks exactly like a proxy that cannot resolve anything,
            // and the fallback below would paper over it by rewriting a file the
            // resolver may not even be reading.
            match resolvectl_dns_for(interface) {
                Some(servers) if servers.iter().any(|server| server == dns_ip) => {
                    tracing::info!("resolvectl set DNS for {}: {}", interface, dns_ip);
                    return Ok(());
                }
                Some(servers) => tracing::warn!(
                    "resolvectl dns {} {} exited 0 but the link has {:?}",
                    interface,
                    dns_ip,
                    servers
                ),
                None => tracing::warn!(
                    "could not read back the DNS resolvectl set on {}",
                    interface
                ),
            }
        }
        Ok(output) => tracing::warn!(
            "resolvectl dns {} {}: {}",
            interface,
            dns_ip,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(_) => {
            tracing::debug!("resolvectl is not available; falling back to writing /etc/resolv.conf")
        }
    }

    // Fallback: back up and overwrite /etc/resolv.conf. The copy is the only record
    // of what the machine used before — a hand-written resolver is not something
    // NetworkManager hands out again on the next connection.
    //
    // So it must not be taken from a file this code already wrote: a restore that
    // failed to put the original back leaves the hijack in place, and copying that
    // over the backup destroys the only copy of the machine's own resolver — the
    // next restore would then put the hijack back and call it a recovery.
    let current = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    if resolv_conf_names_a_tun_address(&current) {
        tracing::warn!(
            "/etc/resolv.conf already names a TUN address; keeping the existing {}",
            RESOLV_CONF_BACKUP
        );
    } else if let Err(e) = std::fs::copy("/etc/resolv.conf", RESOLV_CONF_BACKUP) {
        tracing::warn!(
            "could not back up /etc/resolv.conf to {}: {}",
            RESOLV_CONF_BACKUP,
            e
        );
    }
    std::fs::write("/etc/resolv.conf", format!("nameserver {}\n", dns_ip))
        .map_err(|e| anyhow::anyhow!("Failed to write /etc/resolv.conf: {}", e))?;

    let written = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    if !resolv_conf_nameservers(&written)
        .iter()
        .any(|server| server == dns_ip)
    {
        anyhow::bail!(
            "/etc/resolv.conf does not name {} — DNS hijack is NOT in effect",
            dns_ip
        );
    }
    tracing::info!("Wrote /etc/resolv.conf with nameserver {}", dns_ip);
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_system_dns_linux(interface: &str, _dns_ip: &str) -> Result<()> {
    // Prefer reverting via resolvectl
    match Command::new("resolvectl")
        .args(["revert", interface])
        .output()
    {
        Ok(output) if output.status.success() => {
            tracing::info!("resolvectl reverted the DNS of {}", interface)
        }
        Ok(output) => tracing::warn!(
            "resolvectl revert {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(_) => tracing::debug!("resolvectl is not available; nothing to revert"),
    }

    // Restore from the resolv.conf backup if it exists
    match std::fs::read(RESOLV_CONF_BACKUP) {
        Ok(backup) => match std::fs::write("/etc/resolv.conf", backup) {
            Ok(()) => {
                tracing::info!("Restored /etc/resolv.conf from {}", RESOLV_CONF_BACKUP);
                // Spent: a later hijack has to record its own starting point.
                let _ = std::fs::remove_file(RESOLV_CONF_BACKUP);
            }
            Err(e) => tracing::warn!(
                "could not restore /etc/resolv.conf from {}: {}",
                RESOLV_CONF_BACKUP,
                e
            ),
        },
        Err(_) => tracing::debug!("no {} to restore /etc/resolv.conf from", RESOLV_CONF_BACKUP),
    }

    // The hijack's whole point is that the machine no longer resolves against its
    // address. One that still does is a machine left without name resolution after a
    // disconnect, so it is reported instead of being assumed away.
    let left_behind =
        resolv_conf_nameservers(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
            .into_iter()
            .filter(|server| is_tun_dns_address(server))
            .collect::<Vec<_>>();
    if !left_behind.is_empty() {
        anyhow::bail!(
            "/etc/resolv.conf still names a TUN address after the restore: {}",
            left_behind.join(", ")
        );
    }
    Ok(())
}

/// Undoes what a run that never reached its restore left behind, in the two places
/// a Linux hijack lives.
///
/// `resolvectl` state belongs to the resolved daemon, so a reboot clears it — but
/// only a reboot does, and until then every query goes to a TUN address that this
/// machine does not route any more. `/etc/resolv.conf` is a plain file, so nothing
/// short of writing it back ever clears that one: NetworkManager rewrites it when
/// the next connection comes up, and a machine that boots into the same connection
/// keeps resolving against a dead address indefinitely.
#[cfg(target_os = "linux")]
fn cleanup_stale_hijack_linux() {
    revert_stale_resolvectl_links();
    restore_stale_resolv_conf();
}

/// Reverts every link systemd-resolved still points at a TUN address nothing holds.
///
/// Only the links that exist now are asked: a setting for a link that has since gone
/// went with it, so what is left to revert is exactly what the machine is still
/// using.
#[cfg(target_os = "linux")]
fn revert_stale_resolvectl_links() {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return;
    };

    for link in entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
    {
        let Some(servers) = resolvectl_dns_for(&link) else {
            continue;
        };
        let stale: Vec<String> = servers
            .into_iter()
            .filter(|server| is_tun_dns_address(server) && !address_is_held(server))
            .collect();
        if stale.is_empty() {
            continue;
        }
        match Command::new("resolvectl").args(["revert", &link]).output() {
            Ok(output) if output.status.success() => tracing::warn!(
                "stale DNS hijack on {}: reverted {} to the resolver's own default",
                link,
                stale.join(", ")
            ),
            // Expected when this process is not root: the desktop only reaches TUN
            // mode when it was launched elevated, and an unprivileged one cannot move
            // the system resolver.
            Ok(output) => tracing::warn!(
                "could not revert the stale DNS of {}: {}",
                link,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(_) => {
                // No systemd-resolved here, so the per-link path was never the one
                // that could have left something behind.
                tracing::debug!("resolvectl is not available; skipping the per-link DNS check");
                return;
            }
        }
    }
}

/// Puts `/etc/resolv.conf` back when it still names a TUN address nothing holds.
#[cfg(target_os = "linux")]
fn restore_stale_resolv_conf() {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        return;
    };
    let stale: Vec<String> = resolv_conf_nameservers(&contents)
        .into_iter()
        .filter(|server| is_tun_dns_address(server) && !address_is_held(server))
        .collect();
    if stale.is_empty() {
        return;
    }

    // What `set_system_dns` copied before it overwrote the file — the only record of
    // a hand-picked resolver, and the reason the fallback copies rather than
    // remembering: a machine can be told to use a DNS server that nothing else knows.
    if let Ok(backup) = std::fs::read_to_string(RESOLV_CONF_BACKUP) {
        match std::fs::write("/etc/resolv.conf", &backup) {
            Ok(()) => {
                let _ = std::fs::remove_file(RESOLV_CONF_BACKUP);
                tracing::warn!(
                    "stale DNS hijack in /etc/resolv.conf: restored the file saved before it (was {})",
                    stale.join(", ")
                );
                return;
            }
            Err(e) => tracing::warn!(
                "could not restore /etc/resolv.conf from {}: {}",
                RESOLV_CONF_BACKUP,
                e
            ),
        }
    }

    // Nothing on file: drop the lines that are ours and keep everything else — a
    // `search` domain, `options`, a real resolver listed next to ours. A file this
    // code did not write is not this code's to rewrite wholesale.
    let cleaned = resolv_conf_without_nameservers(&contents, &stale);
    match std::fs::write("/etc/resolv.conf", &cleaned) {
        Ok(()) => tracing::warn!(
            "stale DNS hijack in /etc/resolv.conf: dropped {} with nothing on file to restore",
            stale.join(", ")
        ),
        Err(e) => tracing::warn!(
            "could not drop {} from /etc/resolv.conf: {}",
            stale.join(", "),
            e
        ),
    }
}

/// The DNS servers `resolvectl dns <link>` reports for a link.
///
/// `None` when the answer is not one this code understands — no resolved on this
/// machine, a command that was refused, or output in a shape it has never seen.
#[cfg(target_os = "linux")]
fn resolvectl_dns_for(link: &str) -> Option<Vec<String>> {
    let output = Command::new("resolvectl")
        .args(["dns", link])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_resolvectl_dns(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// The addresses in `resolvectl dns` output: `Link 2 (eth0): 198.18.0.254` or a bare
/// list, depending on whether the command was given a link. Taking every token that
/// reads as an address covers both without depending on how the line is punctuated,
/// and no part of the `Link …` prefix can be mistaken for one.
#[cfg(any(target_os = "linux", test))]
fn parse_resolvectl_dns(output: &str) -> Vec<String> {
    output
        .split_whitespace()
        .filter(|token| token.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

/// The `nameserver` addresses a resolv.conf names.
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_nameservers(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next()? == "nameserver").then(|| parts.next().map(str::to_string))?
        })
        .collect()
}

/// Whether `contents` already names one of the hijack's own addresses.
///
/// Guards the backup: a resolv.conf in this state is one this code wrote and
/// failed to put back, not the machine's own configuration.
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_names_a_tun_address(contents: &str) -> bool {
    resolv_conf_nameservers(contents)
        .iter()
        .any(|server| is_tun_dns_address(server))
}

/// `contents` with the `nameserver` lines naming one of `addresses` removed, and
/// every other line kept exactly as it was.
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_without_nameservers(contents: &str, addresses: &[String]) -> String {
    let mut kept = String::with_capacity(contents.len());
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let names_a_stale_server = parts.next() == Some("nameserver")
            && parts
                .next()
                .is_some_and(|address| addresses.iter().any(|stale| stale == address));
        if names_a_stale_server {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

// ============================================================
// macOS — networksetup
// ============================================================

/// What `networksetup -getdnsservers` prints for a service with no static DNS,
/// i.e. one that takes whatever DHCP hands out. The line names the service, so
/// the match is on the fixed prefix rather than on the whole sentence.
#[cfg(target_os = "macos")]
const NO_DNS_SERVERS: &str = "There aren't any DNS Servers set on";

/// The legend `-listallnetworkservices` prints ahead of the services it lists.
#[cfg(target_os = "macos")]
const DISABLED_LEGEND: &str = "denotes that a network service is disabled";

/// The argument that clears a service's DNS servers, handing it back to DHCP.
#[cfg(target_os = "macos")]
const EMPTY: &str = "Empty";

/// Where the pre-hijack DNS configuration is kept.
///
/// Under `/Library` because both processes that move system DNS are elevated: the
/// launchd service runs as root, and the desktop only reaches TUN mode when it was
/// launched with administrator rights. A per-user path would be readable by the
/// desktop and writable by nobody who needs to write it.
#[cfg(target_os = "macos")]
const DNS_BACKUP_PATH: &str = "/Library/Application Support/nexapipe/dns-backup.json";

#[cfg(target_os = "macos")]
fn set_system_dns_macos(dns_ip: &str) -> Result<()> {
    let services = network_services()?;
    if services.is_empty() {
        tracing::warn!("No network services found via networksetup");
        return Ok(());
    }

    // Recorded before the first service is touched. A process that is killed or
    // crashes between here and the teardown never runs the restore, and the next
    // start needs this file to put back whatever the machine was using — a
    // hand-picked DNS server is not something DHCP hands out again.
    save_dns_backup(&services);

    for service in &services {
        match set_dns_servers(service, &[dns_ip.to_string()]) {
            Ok(()) => tracing::info!("Set DNS for {}: {}", service, dns_ip),
            Err(e) => tracing::warn!("Could not set DNS for {}: {}", service, e),
        }
    }

    // Read back rather than trusting the exit code: `networksetup` has been seen
    // exiting 0 for a change it did not make, and a hijack that silently did not
    // happen looks exactly like a proxy that cannot resolve anything.
    let mut hijacked = 0;
    for service in &services {
        match dns_servers_for(service) {
            Some(servers) if servers.iter().any(|server| server == dns_ip) => hijacked += 1,
            Some(servers) => tracing::warn!(
                "{} does not point at {} after the switch (it has {:?})",
                service,
                dns_ip,
                servers
            ),
            None => tracing::warn!("could not read back the DNS of {}", service),
        }
    }
    if hijacked == 0 {
        anyhow::bail!(
            "no network service points at {} — DNS hijack is NOT in effect",
            dns_ip
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_system_dns_macos(dns_ip: &str) -> Result<()> {
    let services = network_services().unwrap_or_default();
    let recorded = read_dns_backup();
    let mut restored = 0;

    for service in &services {
        // An empty recorded list means "no static DNS before the hijack", and so
        // does having nothing on file — clearing hands the service back to DHCP,
        // which is still better than leaving a TUN address behind.
        let target = match recorded.get(service).filter(|servers| !servers.is_empty()) {
            Some(servers) => servers.clone(),
            None => vec![EMPTY.to_string()],
        };
        match set_dns_servers(service, &target) {
            Ok(()) => {
                tracing::info!("Restored DNS for {}: {:?}", service, target);
                restored += 1;
            }
            Err(e) => tracing::warn!("Could not restore DNS for {}: {}", service, e),
        }
    }

    // The hijack's whole point is that no service mentions its address any more.
    // One that still does is the machine left without name resolution after a
    // disconnect, so it is reported instead of being assumed away.
    let left_behind: Vec<String> = services
        .iter()
        .filter(|service| {
            dns_servers_for(service).is_some_and(|servers| {
                servers
                    .iter()
                    // `dns_ip` is the address this run hijacked, which is the one
                    // that has to be gone; the candidate addresses catch a hijack
                    // left behind by a run that used another block.
                    .any(|server| *server == dns_ip || is_tun_dns_address(server))
            })
        })
        .cloned()
        .collect();
    if !left_behind.is_empty() {
        anyhow::bail!(
            "system DNS still points at a TUN address on {} service(s) after the restore: {}",
            left_behind.len(),
            left_behind.join(", ")
        );
    }

    // Spent: a later hijack has to record its own starting point, and leaving a
    // file from a restore that only partly worked would have the next one restore
    // the wrong thing.
    if restored == services.len() && !services.is_empty() {
        let _ = std::fs::remove_file(DNS_BACKUP_PATH);
    }
    Ok(())
}

/// The DNS servers `networksetup -getdnsservers` reports for `service`.
///
/// `None` when the answer is not one this code understands — a command that was
/// refused, or output in a shape it has never seen — so that "could not read"
/// cannot be mistaken for "no DNS servers", which is a real and different answer.
#[cfg(target_os = "macos")]
fn dns_servers_for(service: &str) -> Option<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_getdnsservers(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `-getdnsservers` output into the servers it names.
///
/// An empty `Some` is the "no static DNS" answer, i.e. DHCP. Anything that is
/// neither that nor a plain list of addresses yields `None`: writing a guess back
/// over a machine's DNS is worse than leaving it alone.
#[cfg(target_os = "macos")]
fn parse_getdnsservers(output: &str) -> Option<Vec<String>> {
    let mut servers = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        // networksetup reports a refused command as `** Error: ...`.
        if line.starts_with("**") {
            return None;
        }
        if line.starts_with(NO_DNS_SERVERS) {
            return Some(Vec::new());
        }
        if line.parse::<IpAddr>().is_err() {
            return None;
        }
        servers.push(line.to_string());
    }
    Some(servers)
}

/// Sets the DNS servers of one network service; `["empty"]` clears them, which
/// is how a service is handed back to DHCP.
#[cfg(target_os = "macos")]
fn set_dns_servers(service: &str, servers: &[String]) -> Result<()> {
    let output = Command::new("networksetup")
        .arg("-setdnsservers")
        .arg(service)
        .args(servers)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run networksetup: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "networksetup -setdnsservers {} {}: {}",
            service,
            servers.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Whether `address` is one of the addresses this hijack points system DNS at.
///
/// Only the host part the hijack actually uses — …254, see `tun_ip` — counts,
/// never the whole /24 around it: `10.0.0.0/24` is both a candidate block and the
/// subnet a great many home LANs sit in, so treating every address in it as ours
/// would wipe the DNS of anyone whose router hands out 10.0.0.1.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_tun_dns_address(address: &str) -> bool {
    // Spelled out because this is compiled one platform wider than the `Ipv4Addr`
    // import: under `test` it also builds where that import does not apply.
    let Ok(ip) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    TUN_BASE_CANDIDATES
        .iter()
        .any(|base| u32::from(ip) == (u32::from(*base) | 0x0000_00FE))
}

/// Whether some interface on this host still holds `address`.
///
/// What separates a stale hijack from a live one: the tunnel is gone before its
/// restore ran, so its address is no longer bindable here, while a tunnel that is
/// still up answers and must not be "cleaned up" from under it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn address_is_held(address: &str) -> bool {
    let Ok(ip) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    UdpSocket::bind((ip, 0)).is_ok()
}

/// The pre-hijack DNS servers recorded in [`DNS_BACKUP_PATH`], per service.
#[cfg(target_os = "macos")]
fn read_dns_backup() -> BTreeMap<String, Vec<String>> {
    let Ok(contents) = std::fs::read_to_string(DNS_BACKUP_PATH) else {
        return BTreeMap::new();
    };
    serde_json::from_str(&contents).unwrap_or_default()
}

/// Records what `services` are using now, so a later restore can put it back.
///
/// A service that already points at a TUN address cannot say what it had before —
/// that is precisely the state this file exists to survive — so its recorded
/// answer is kept rather than overwritten with the hijack's own address.
#[cfg(target_os = "macos")]
fn save_dns_backup(services: &[String]) {
    let recorded = read_dns_backup();
    let mut backup = BTreeMap::new();

    for service in services {
        let clean = dns_servers_for(service)
            .filter(|servers| !servers.iter().any(|server| is_tun_dns_address(server)));
        // Unreadable, or still hijacked from a previous run: whatever is on file
        // is a better answer than anything visible right now.
        let value = match clean {
            Some(servers) => Some(servers),
            None => recorded.get(service).cloned(),
        };
        if let Some(servers) = value {
            backup.insert(service.clone(), servers);
        }
    }

    if backup.is_empty() {
        return;
    }

    let Ok(json) = serde_json::to_string_pretty(&backup) else {
        return;
    };
    if let Some(parent) = Path::new(DNS_BACKUP_PATH).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("could not create {}: {}", parent.display(), e);
            return;
        }
    }
    if let Err(e) = std::fs::write(DNS_BACKUP_PATH, json) {
        tracing::warn!(
            "could not record the pre-hijack DNS in {}: {}",
            DNS_BACKUP_PATH,
            e
        );
    }
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
    Ok(parse_network_services(&stdout))
}

/// The service names in `-listallnetworkservices` output.
///
/// The command prints a legend before the list ("An asterisk (*) denotes that a
/// network service is disabled.") and disables an entry by prefixing its *name*
/// with `*`. Filtering on a leading `*` alone therefore kept the legend and handed
/// it to `-setdnsservers` as a service name, which is where every startup's worth
/// of "networksetup failed for An asterisk (*) ..." warnings came from.
#[cfg(target_os = "macos")]
fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('*'))
        .filter(|line| !line.contains(DISABLED_LEGEND))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::{
        backup_is_spent, is_tun_dns_address, parse_getdnsservers, parse_network_services,
        NO_DNS_SERVERS,
    };

    // The resolv.conf and resolvectl readers are pure, so they are compiled under
    // `test` on every platform: the Linux code cannot be built or run here, and a
    // parser for a file this code rewrites is not something to ship unexercised.
    #[cfg(any(target_os = "linux", test))]
    use super::{
        parse_resolvectl_dns, resolv_conf_names_a_tun_address, resolv_conf_nameservers,
        resolv_conf_without_nameservers,
    };

    /// The legend `-listallnetworkservices` prints ahead of its list is not a service.
    /// Handing it to `-setdnsservers` anyway is where every startup's worth of
    /// "networksetup failed for An asterisk (*) ..." warnings came from.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_disabled_legend_is_not_a_network_service() {
        let output = "An asterisk (*) denotes that a network service is disabled.\n\
                      Thunderbolt Bridge\n\
                      *iPhone USB\n\
                      Wi-Fi\n";

        assert_eq!(
            parse_network_services(output),
            vec!["Thunderbolt Bridge".to_string(), "Wi-Fi".to_string()]
        );
    }

    /// `-getdnsservers` answers three ways and they mean three different things: a
    /// list of servers, "none configured" — which is DHCP, and a real answer — and
    /// a command that was refused. The last two must not be confused, because one
    /// says "clear it" and the other says "do not touch it".
    #[cfg(target_os = "macos")]
    #[test]
    fn getdnsservers_output_reads_as_a_list_or_as_dhcp_or_as_unknown() {
        assert_eq!(
            parse_getdnsservers("198.18.0.254\n"),
            Some(vec!["198.18.0.254".to_string()])
        );
        assert_eq!(
            parse_getdnsservers("8.8.8.8\n1.1.1.1\n"),
            Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()])
        );
        assert_eq!(
            parse_getdnsservers(&format!("{NO_DNS_SERVERS} Wi-Fi.\n")),
            Some(Vec::new())
        );
        assert_eq!(
            parse_getdnsservers("** Error: The parameters were not valid.\n"),
            None
        );
        assert_eq!(parse_getdnsservers("garbage\n"), None);
    }

    /// Only the host address the hijack actually uses counts as ours. Widening this
    /// to the candidate /24 around it would wipe the DNS of every machine whose LAN
    /// sits in 10.0.0.0/24 — one of the candidate blocks — and whose router hands
    /// out 10.0.0.1.
    #[cfg(target_os = "macos")]
    #[test]
    fn only_the_hijack_host_address_counts_as_ours() {
        assert!(is_tun_dns_address("198.18.0.254"));
        assert!(is_tun_dns_address("198.19.0.254"));
        assert!(is_tun_dns_address("10.0.0.254"));

        assert!(
            !is_tun_dns_address("198.18.0.1"),
            "a virtual IP is not a DNS server"
        );
        assert!(
            !is_tun_dns_address("10.0.0.1"),
            "a LAN router's DNS is not ours to reset"
        );
        assert!(!is_tun_dns_address("8.8.8.8"));
        assert!(!is_tun_dns_address("not-an-address"));
    }

    /// The recorded backup has to survive a round trip through the file it is kept
    /// in, and an empty list has to stay distinguishable from a missing one: the
    /// first means "clear it on restore", the second means "we never knew".
    #[cfg(target_os = "macos")]
    #[test]
    fn a_recorded_backup_round_trips_through_json() {
        let mut backup = std::collections::BTreeMap::new();
        backup.insert("Wi-Fi".to_string(), Vec::<String>::new());
        backup.insert(
            "Thunderbolt Bridge".to_string(),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        );

        let json = serde_json::to_string(&backup).expect("a map of strings serialises");
        let read: std::collections::BTreeMap<String, Vec<String>> =
            serde_json::from_str(&json).expect("and parses back");

        assert_eq!(read, backup);
        assert_eq!(read["Wi-Fi"], Vec::<String>::new());
    }

    /// A resolv.conf is more than its nameservers: `search` and `options` are part of
    /// what the machine was told to do, and dropping the address this code put there
    /// must not take them — or a real resolver listed next to it — with it.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn dropping_our_nameserver_keeps_the_rest_of_the_file() {
        let contents = "# written by hand\n\
                        search example.internal\n\
                        nameserver 198.18.0.254\n\
                        nameserver 8.8.8.8\n\
                        options edns0\n";

        assert_eq!(
            resolv_conf_nameservers(contents),
            vec!["198.18.0.254".to_string(), "8.8.8.8".to_string()]
        );
        assert_eq!(
            resolv_conf_without_nameservers(contents, &["198.18.0.254".to_string()]),
            "# written by hand\nsearch example.internal\nnameserver 8.8.8.8\noptions edns0\n"
        );
    }

    /// The backup is only ever taken from a resolv.conf the machine still owns. A
    /// file that already names one of the hijack's addresses is one this code wrote
    /// and failed to put back: copying it over the backup would destroy the only
    /// record of the machine's own resolver, and the next restore would then put the
    /// hijack back and call it a recovery.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn a_hijacked_resolv_conf_is_not_a_backup_source() {
        assert!(resolv_conf_names_a_tun_address(
            "search example.internal\nnameserver 198.18.0.254\n"
        ));
        assert!(resolv_conf_names_a_tun_address(
            "nameserver 8.8.8.8\nnameserver 198.18.0.254\n"
        ));

        assert!(
            !resolv_conf_names_a_tun_address("nameserver 8.8.8.8\noptions edns0\n"),
            "the machine's own resolver is exactly what the backup exists to keep"
        );
        assert!(!resolv_conf_names_a_tun_address("# no nameserver at all\n"));
        assert!(
            !resolv_conf_names_a_tun_address("nameserver 10.0.0.1\n"),
            "a LAN router's DNS is not a hijack"
        );
    }

    /// The recorded DNS is spent only when a cleanup pass reset something *and* left
    /// nothing behind. A service whose reset failed still carries the hijack address
    /// and will be attempted again, and its original servers are written nowhere else
    /// — deleting the file would leave the next pass able only to hand it to DHCP.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_backup_outlives_a_partial_cleanup() {
        let reset = ["Wi-Fi".to_string()];
        let failed = ["Thunderbolt Bridge".to_string()];

        assert!(
            backup_is_spent(&reset, &[]),
            "every service that was attempted came back"
        );
        assert!(
            !backup_is_spent(&reset, &failed),
            "a service that could not be reset still needs its recorded DNS"
        );
        assert!(
            !backup_is_spent(&[], &[]),
            "nothing was reset, so nothing was spent"
        );
    }

    /// `resolvectl dns` answers with a `Link …` prefix when asked about one link and
    /// with a bare list when asked about all of them. Only the addresses matter, and
    /// no part of that prefix reads as one — including the link index.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn resolvectl_dns_reads_as_addresses_in_either_shape() {
        assert_eq!(
            parse_resolvectl_dns("Link 2 (eth0): 198.18.0.254\n"),
            vec!["198.18.0.254".to_string()]
        );
        assert_eq!(
            parse_resolvectl_dns("Link 3 (wlan0): 8.8.8.8 1.1.1.1\n"),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(
            parse_resolvectl_dns("198.18.0.254\n"),
            vec!["198.18.0.254".to_string()]
        );
        assert_eq!(
            parse_resolvectl_dns("Link 2 (eth0):\n"),
            Vec::<String>::new()
        );
    }
}
