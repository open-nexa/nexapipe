//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! Two ways of doing it, tried in this order:
//!
//! - **Scoped** (per-domain): only the proxied domains resolve through the TUN, and
//!   everything else keeps resolving wherever the machine was resolving it. This is
//!   what makes running alongside another tunnel possible — the other app's names,
//!   and the machine's own internal ones, are none of our business.
//!   - macOS: a file per domain under `/etc/resolver`
//!   - Linux:  `resolvectl` routing domains on the TUN link
//! - **Global**: every query on the machine goes to the TUN resolver. The fallback,
//!   for a platform with no per-domain mechanism and for one where the scoped attempt
//!   could not be installed.
//!   - Windows: PowerShell Set-DnsClientServerAddress (netsh fallback), verified afterwards
//!   - Linux:   overwriting /etc/resolv.conf (with a backup, which the restore puts back)
//!   - macOS:   networksetup (iterating over every network service), with the pre-hijack
//!     servers kept on file so a restore can put them back
//!
//! Which one a run ended up with is returned by [`set_system_dns`] and has to be handed
//! back to [`restore_system_dns`]: each is undone where it was done, and a scoped
//! hijack leaves nothing in the places a global one writes.
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
// Imported one platform wider than the platform code that used to be its only
// reader: `is_tun_dns_address` is now a plain predicate the DNS server asks on
// every platform, and this is what it compares against.
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
// One platform wider than the platform code, for the same reason as the parsers
// below: the per-domain resolver files are written and removed by functions that
// take the directory as an argument so that a test can exercise them on a
// temporary one. Overwriting another resolver's file, or leaving our own behind,
// is not something to ship unexercised.
#[cfg(any(target_os = "macos", test))]
use std::path::{Path, PathBuf};

/// How a run pointed system DNS at the TUN resolver.
///
/// Handed back to [`restore_system_dns`], which undoes each where it was done:
/// a scoped hijack has nothing in the places a global one writes, and a global
/// one cannot be removed by deleting per-domain files that were never created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsHijack {
    /// Only the configured domains resolve through the TUN. Everything else —
    /// the machine's own internal names, and another tunnel's, if one is
    /// running — keeps resolving where it always did.
    Scoped,
    /// Every query on the machine goes to the TUN resolver.
    Global,
}

/// Points system DNS at the TUN virtual IP, and reports which kind of hijack
/// ended up in place.
///
/// Scoped where the platform can express it and the configuration can be
/// spelled as a set of domains; the global hijack otherwise. A best effort
/// either way: a run that could not install either is reported, and the caller
/// goes on without name resolution rather than refusing to start.
pub fn set_system_dns(
    interface: &str,
    dns_ip: &str,
    proxy_domains: &[String],
) -> Result<DnsHijack> {
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;

    #[cfg(windows)]
    {
        // No per-domain mechanism on this platform: the DNS client resolves
        // against whatever the adapters carry, and there is no place to say
        // "this domain, this server" that a client SKU honours. (NRPT rules
        // exist, but they are a DirectAccess feature and are not reliably
        // applied on client builds, which is not something to find out on a
        // user's machine.) Every adapter is pointed at the TUN instead, and
        // the machine's own resolvers stay reachable through the forwarding
        // chain the local server builds — see `dns::resolver_chain`.
        let _ = proxy_domains;
        set_system_dns_windows(interface, dns_ip)?;
        Ok(DnsHijack::Global)
    }

    #[cfg(target_os = "linux")]
    {
        if set_scoped_dns_linux(interface, dns_ip, proxy_domains)? {
            return Ok(DnsHijack::Scoped);
        }
        set_system_dns_linux(interface, dns_ip)?;
        Ok(DnsHijack::Global)
    }

    #[cfg(target_os = "macos")]
    {
        if set_scoped_dns_macos(dns_ip, proxy_domains)? {
            return Ok(DnsHijack::Scoped);
        }
        set_system_dns_macos(dns_ip)?;
        Ok(DnsHijack::Global)
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = proxy_domains;
        Ok(DnsHijack::Global)
    }
}

/// Restores the system DNS configuration (best effort), undoing the kind of
/// hijack [`set_system_dns`] reported it had installed.
pub fn restore_system_dns(interface: &str, dns_ip: &str, hijack: DnsHijack) -> Result<()> {
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;

    #[cfg(windows)]
    {
        let _ = hijack;
        restore_system_dns_windows(interface, dns_ip)
    }

    #[cfg(target_os = "linux")]
    {
        match hijack {
            DnsHijack::Scoped => restore_scoped_dns_linux(interface),
            DnsHijack::Global => restore_system_dns_linux(interface, dns_ip),
        }
    }

    #[cfg(target_os = "macos")]
    {
        match hijack {
            DnsHijack::Scoped => restore_scoped_dns_macos(),
            DnsHijack::Global => restore_system_dns_macos(dns_ip),
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = hijack;
        Ok(())
    }
}

/// The DNS servers the machine is resolving against right now — the ones the
/// hijack is about to displace.
///
/// Asked before [`set_system_dns`] replaces them, so the local resolver can keep
/// asking whoever was authoritative instead of skipping to a public one: a
/// machine's own resolvers are the only ones that answer its internal and
/// split-horizon names, and on a host that already runs another tunnel they are
/// that tunnel's resolver. Routing around them is what makes a second tunnel
/// look like "the internet broke" rather than "the other app stopped working".
///
/// Unfiltered: dropping the addresses that would send a query back to us is the
/// caller's job, see `dns::forwardable_resolvers`. An empty answer is a fine one
/// — "the machine has no static DNS" just leaves the chain to the configured
/// upstream and the fallbacks.
pub fn current_dns_servers() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        current_dns_servers_macos()
    }

    #[cfg(target_os = "linux")]
    {
        current_dns_servers_linux()
    }

    #[cfg(windows)]
    {
        current_dns_servers_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Vec::new()
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

/// The DNS servers every adapter is configured with, per `Get-DnsClientServerAddress`.
///
/// IPv4 only. The IPv6 lists are what the hijack overwrites with `::1` — router-
/// learned `fe80::…` addresses that name a link as well as a host, and that this
/// process cannot dial without a scope id it does not have.
#[cfg(windows)]
fn current_dns_servers_windows() -> Vec<String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses -join ',' }",
        ])
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect(),
        Err(e) => {
            tracing::debug!("Could not read the current DNS servers: {}", e);
            Vec::new()
        }
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
    // Both places a hijack lives: the network services, and the per-domain
    // resolvers a scoped one wrote. A run that never reached its restore may
    // have left either.
    remove_stale_resolver_files();

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

/// Points the configured domains at the TUN resolver through systemd-resolved's
/// per-link routing domains, and leaves every other name to whoever was already
/// answering it.
///
/// `Ok(false)` means "not installed" — no resolved on this machine, or the
/// setting did not take — which is a call to fall back rather than a failure.
/// Whatever was set is reverted first, so the fallback starts from the machine's
/// own configuration instead of from a half-installed hijack.
#[cfg(target_os = "linux")]
fn set_scoped_dns_linux(interface: &str, dns_ip: &str, proxy_domains: &[String]) -> Result<bool> {
    let Some(domains) = crate::proxy::dns::scoped_domains(proxy_domains) else {
        tracing::info!(
            "the configured domains cannot each be routed to a link of their own; \
             every query goes to the TUN instead"
        );
        return Ok(false);
    };

    // `~` marks a routing domain: resolved sends it to this link's DNS server
    // but does not add it to any search list, which is what a proxy domain wants
    // and a search suffix is not.
    let mut domain_args = vec!["domain".to_string(), interface.to_string()];
    domain_args.extend(domains.iter().map(|domain| format!("~{domain}")));

    for args in [
        vec!["dns".to_string(), interface.to_string(), dns_ip.to_string()],
        domain_args,
    ] {
        match Command::new("resolvectl").args(&args).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                tracing::warn!(
                    "resolvectl {}: {} — every query goes to the TUN instead",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                revert_resolvectl(interface);
                return Ok(false);
            }
            Err(_) => {
                tracing::debug!(
                    "resolvectl is not available; a per-domain hijack needs systemd-resolved"
                );
                return Ok(false);
            }
        }
    }

    // Out of the running for everything else. Left on, a link's DNS server is a
    // candidate for every name, which is the global hijack wearing a different
    // hat. Only worth a warning when the subcommand is missing: an older
    // resolved still routes the domains above to the TUN.
    match Command::new("resolvectl")
        .args(["default-route", interface, "no"])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => tracing::warn!(
            "resolvectl default-route {} no: {} — the TUN link may still answer names \
             outside the configured domains",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(_) => {}
    }

    // Read back rather than trusting the exit codes: a hijack that silently did
    // not take looks exactly like a proxy that resolves nothing.
    let resolver_in_place = resolvectl_dns_for(interface)
        .is_some_and(|servers| servers.iter().any(|server| server == dns_ip));
    let routed = resolvectl_domains_for(interface)
        .is_some_and(|routed| routes_every_domain(&routed, &domains));
    if !resolver_in_place || !routed {
        revert_resolvectl(interface);
        tracing::warn!(
            "the TUN link does not answer the configured domains — every query goes to the TUN instead"
        );
        return Ok(false);
    }

    tracing::info!(
        "{} configured domain(s) resolve through {} on {}; every other name keeps its own resolver",
        domains.len(),
        dns_ip,
        interface
    );
    Ok(true)
}

/// Hands a link's resolved settings back to whatever configured them.
#[cfg(target_os = "linux")]
fn revert_resolvectl(interface: &str) {
    match Command::new("resolvectl")
        .args(["revert", interface])
        .output()
    {
        Ok(output) if output.status.success() => {
            tracing::debug!("resolvectl reverted the settings of {}", interface)
        }
        Ok(output) => tracing::warn!(
            "resolvectl revert {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(_) => tracing::debug!("resolvectl is not available; nothing to revert"),
    }
}

/// Takes back the per-link routing domains a scoped hijack installed.
#[cfg(target_os = "linux")]
fn restore_scoped_dns_linux(interface: &str) -> Result<()> {
    revert_resolvectl(interface);

    // The setting belongs to the daemon, so it goes with the interface. What is
    // worth reporting is a link that still answers against a TUN address once
    // the tunnel is down.
    let left: Vec<String> = resolvectl_dns_for(interface)
        .unwrap_or_default()
        .into_iter()
        .filter(|server| is_tun_dns_address(server))
        .collect();
    if !left.is_empty() {
        anyhow::bail!(
            "{} still resolves against a TUN address after the revert: {}",
            interface,
            left.join(", ")
        );
    }
    Ok(())
}

/// The routing domains `resolvectl domain <link>` reports.
#[cfg(target_os = "linux")]
fn resolvectl_domains_for(link: &str) -> Option<Vec<String>> {
    let output = Command::new("resolvectl")
        .args(["domain", link])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_resolvectl_domains(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Whether `routed` is every one of `domains`, and not merely one of them: a
/// domain left out keeps resolving outside the proxy while the caller is told
/// the hijack is scoped, which is the one thing the fallback is for.
#[cfg(any(target_os = "linux", test))]
fn routes_every_domain(routed: &[String], domains: &[String]) -> bool {
    domains.iter().all(|domain| routed.contains(domain))
}

/// The domains in `resolvectl domain` output, without the `~` that marks them
/// as routing-only: `Link 5 (nexa0): ~example.com ~foo.io`.
#[cfg(any(target_os = "linux", test))]
fn parse_resolvectl_domains(output: &str) -> Vec<String> {
    output
        .split_whitespace()
        .filter(|token| token.starts_with('~'))
        .map(|token| token.trim_start_matches('~').to_string())
        .collect()
}

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

/// The resolvers the machine is using: what `resolvectl` reports for every link,
/// or the `nameserver` lines of resolv.conf when there is no resolved to ask.
///
/// resolv.conf is the fallback rather than the other way round because on a
/// resolved machine it is the stub (`127.0.0.53`), which forwards to the same
/// per-link settings anyway — so it only adds a hop, while on a machine without
/// resolved it is the only answer there is.
#[cfg(target_os = "linux")]
fn current_dns_servers_linux() -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    if let Ok(output) = Command::new("resolvectl").arg("dns").output() {
        if output.status.success() {
            for server in parse_resolvectl_dns(&String::from_utf8_lossy(&output.stdout)) {
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
    }
    if servers.is_empty() {
        let contents = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        for server in resolv_conf_nameservers(&contents) {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
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
// macOS — per-domain resolvers under /etc/resolver
// ============================================================

/// Where mDNSResponder looks for a resolver that owns a domain: one file per
/// domain, holding a `nameserver` line. It picks the longest matching suffix, so
/// a file named `example.com` answers every name under it — which is the same
/// DOMAIN-SUFFIX rule the proxy already matches on, spelled the way the OS reads
/// it.
///
/// Preferred over `networksetup` because it leaves the machine's DNS alone: the
/// only queries that move are the ones for the proxied domains, so an internal
/// zone, a split-horizon name, or another tunnel's resolver keeps answering as
/// it did before the tunnel came up.
#[cfg(target_os = "macos")]
const RESOLVER_DIR: &str = "/etc/resolver";

/// The line that marks a resolver file as one this code wrote.
///
/// Ownership cannot be read off the `nameserver` line. The addresses a hijack
/// hands out end in `.254`, and `10.0.0.254` — the last candidate block — is
/// also a router address, which a hand-written split-DNS rule points at just
/// as plausibly. A file naming one and carrying no marker is somebody else's,
/// and is neither overwritten nor removed: nothing here keeps a copy of what
/// it would destroy.
///
/// A comment is safe here: the parser configd reads these files with skips
/// lines starting with `;` or `#`.
#[cfg(any(target_os = "macos", test))]
const RESOLVER_MARKER: &str = "# managed by nexapipe";

/// Whether `contents` carry [`RESOLVER_MARKER`] — the only test this code
/// trusts before it overwrites or removes a resolver file.
#[cfg(any(target_os = "macos", test))]
fn is_our_resolver_file(contents: &str) -> bool {
    contents.lines().any(|line| line.trim() == RESOLVER_MARKER)
}

/// The contents of a `/etc/resolver/<domain>` file.
#[cfg(any(target_os = "macos", test))]
fn resolver_file_contents(dns_ip: &str) -> String {
    format!("{RESOLVER_MARKER}\nnameserver {dns_ip}\n")
}

/// The address a `/etc/resolver` file hands its domain to.
///
/// `None` when the file names none. Whether the file is one this code wrote is
/// a separate question, answered by [`is_our_resolver_file`].
#[cfg(any(target_os = "macos", test))]
fn resolver_nameserver(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next()? == "nameserver").then(|| parts.next().map(str::to_string))?
    })
}

/// Points the configured domains at the TUN resolver, one file per domain.
///
/// `Ok(false)` means "not installed", which is a call to fall back to the global
/// hijack rather than a failure: whatever was written up to that point is taken
/// back first, so the two cannot be in place at once.
#[cfg(target_os = "macos")]
fn set_scoped_dns_macos(dns_ip: &str, proxy_domains: &[String]) -> Result<bool> {
    let Some(domains) = crate::proxy::dns::scoped_domains(proxy_domains) else {
        tracing::info!(
            "the configured domains cannot each be given a resolver of their own; \
             every query goes to the TUN instead"
        );
        return Ok(false);
    };

    if let Err(e) = std::fs::create_dir_all(RESOLVER_DIR) {
        tracing::warn!(
            "could not create {}: {} — every query goes to the TUN instead",
            RESOLVER_DIR,
            e
        );
        return Ok(false);
    }

    let (written, someone_elses) = write_resolver_files(Path::new(RESOLVER_DIR), dns_ip, &domains);

    // Read back rather than trusting the writes: a hijack that silently did not
    // happen looks exactly like a proxy that resolves nothing.
    let in_effect = count_resolvers_in_effect(&written, dns_ip);
    if !scoped_install_is_complete(in_effect, written.len()) {
        for path in &written {
            if count_resolvers_in_effect(std::slice::from_ref(path), dns_ip) == 0 {
                tracing::warn!(
                    "{} does not name {} after the write",
                    path.display(),
                    dns_ip
                );
            }
        }
        for path in &written {
            let _ = std::fs::remove_file(path);
        }
        tracing::warn!(
            "{} of {} resolver(s) under {} took effect — every query goes to the TUN instead",
            in_effect,
            written.len(),
            RESOLVER_DIR
        );
        return Ok(false);
    }

    tracing::info!(
        "{} of {} configured domain(s) resolve through {} via {}",
        in_effect,
        domains.len(),
        dns_ip,
        RESOLVER_DIR
    );
    if !someone_elses.is_empty() {
        tracing::warn!(
            "left resolving where they were, because another resolver already owns them: {}",
            someone_elses.join(", ")
        );
    }
    Ok(true)
}

/// Writes one resolver file per domain under `dir`, and returns the paths
/// written together with the domains that were left alone.
///
/// A file already there that is not marked as ours is somebody else's: a
/// container runtime, another tunnel, a hand-written split-DNS rule.
/// Overwriting it would break whatever it is there for, so the domain keeps
/// resolving where it resolves — and the file keeps the address it named,
/// including one of the addresses a hijack of ours uses. A marked file is a
/// leftover of ours, from this run or an earlier one, and is rewritten.
#[cfg(any(target_os = "macos", test))]
fn write_resolver_files(
    dir: &Path,
    dns_ip: &str,
    domains: &[String],
) -> (Vec<PathBuf>, Vec<String>) {
    let mut written = Vec::new();
    let mut left_alone = Vec::new();
    for domain in domains {
        let path = dir.join(domain);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if !is_our_resolver_file(&contents) {
                left_alone.push(format!("{} ({:?})", domain, resolver_nameserver(&contents)));
                continue;
            }
        }
        match std::fs::write(&path, resolver_file_contents(dns_ip)) {
            Ok(()) => written.push(path),
            Err(e) => tracing::warn!("could not write {}: {}", path.display(), e),
        }
    }
    (written, left_alone)
}

/// Reads the files written above back and returns how many of them really name
/// `dns_ip`.
#[cfg(any(target_os = "macos", test))]
fn count_resolvers_in_effect(written: &[PathBuf], dns_ip: &str) -> usize {
    written
        .iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|contents| resolver_nameserver(&contents))
                .as_deref()
                == Some(dns_ip)
        })
        .count()
}

/// Whether a scoped install covers every domain it was asked to cover.
///
/// All of them or none of them: a domain whose file did not take would go on
/// resolving outside the proxy while the caller is told the hijack is scoped,
/// which is the one thing falling back to the global hijack is for.
#[cfg(any(target_os = "macos", test))]
fn scoped_install_is_complete(in_effect: usize, written: usize) -> bool {
    in_effect == written
}

/// Takes back the per-domain resolvers a scoped hijack installed.
///
/// Every file carrying [`RESOLVER_MARKER`] is ours whichever address it names,
/// including the one a run that used another block left behind. Files without
/// it are not touched, whatever they name.
#[cfg(target_os = "macos")]
fn restore_scoped_dns_macos() -> Result<()> {
    let left = remove_resolver_files(Path::new(RESOLVER_DIR), is_our_resolver_file);
    if left.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} resolver(s) under {} still point at the TUN after the restore: {}",
        left.len(),
        RESOLVER_DIR,
        left.join(", ")
    )
}

/// Removes every file under `dir` whose contents `is_ours` accepts, and
/// returns the ones that could not be removed.
///
/// `is_ours` is handed the whole file rather than its `nameserver` line because
/// what decides ownership here is the marker, not the address — see
/// [`RESOLVER_MARKER`]. Files it rejects are left untouched: a directory the
/// machine shares with other resolvers is not one this code gets to clean out.
#[cfg(any(target_os = "macos", test))]
fn remove_resolver_files(dir: &Path, is_ours: impl Fn(&str) -> bool) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut removed = 0;
    let mut left = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !is_ours(&contents) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!("could not remove {}: {}", path.display(), e);
                left.push(path.display().to_string());
            }
        }
    }
    if removed > 0 {
        tracing::info!("removed {} resolver(s) under {}", removed, dir.display());
    }
    left
}

/// Removes the per-domain resolvers a run that never reached its restore left
/// behind.
///
/// The same test as the network-service half of this cleanup separates a stale
/// hijack from a live one: a marked file pointing at an address no interface
/// holds belongs to a tunnel that is gone, and until it is removed every query
/// for that domain goes nowhere. An unmarked one is not ours however stale its
/// address looks — a router's own `10.0.0.254` is the case that matters.
#[cfg(target_os = "macos")]
fn remove_stale_resolver_files() {
    let left = remove_resolver_files(Path::new(RESOLVER_DIR), |contents| {
        is_our_resolver_file(contents)
            && resolver_nameserver(contents).is_some_and(|server| !address_is_held(&server))
    });
    if !left.is_empty() {
        tracing::warn!(
            "{} stale resolver(s) under {} could not be removed: {}",
            left.len(),
            RESOLVER_DIR,
            left.join(", ")
        );
    }
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

/// The DNS servers every network service is using, deduplicated in the order
/// the services are listed.
///
/// A service with no static DNS contributes nothing: it takes whatever DHCP
/// hands out, which is not an address this process can be told to ask.
#[cfg(target_os = "macos")]
fn current_dns_servers_macos() -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    for service in network_services().unwrap_or_default() {
        for server in dns_servers_for(&service).unwrap_or_default() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
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
pub(crate) fn is_tun_dns_address(address: &str) -> bool {
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
    use super::{backup_is_spent, parse_getdnsservers, parse_network_services, NO_DNS_SERVERS};

    // The resolv.conf and resolvectl readers are pure, so they are compiled under
    // `test` on every platform: the Linux code cannot be built or run here, and a
    // parser for a file this code rewrites is not something to ship unexercised.
    #[cfg(any(target_os = "linux", test))]
    use super::{
        parse_resolvectl_dns, parse_resolvectl_domains, resolv_conf_names_a_tun_address,
        resolv_conf_nameservers, resolv_conf_without_nameservers, routes_every_domain,
    };

    // Same for the per-domain resolver file: what this code writes has to be
    // what it reads back, or a restore would leave its own files behind.
    #[cfg(any(target_os = "macos", test))]
    use super::{
        RESOLVER_MARKER, count_resolvers_in_effect, is_our_resolver_file, is_tun_dns_address,
        remove_resolver_files, resolver_file_contents, resolver_nameserver,
        scoped_install_is_complete, write_resolver_files,
    };
    #[cfg(any(target_os = "macos", test))]
    use crate::proxy::tun_proxy::TUN_BASE_CANDIDATES;
    #[cfg(any(target_os = "macos", test))]
    use std::net::Ipv4Addr;
    #[cfg(any(target_os = "macos", test))]
    use std::path::PathBuf;

    /// A scratch directory for the resolver-file tests: the real one is
    /// `/etc/resolver`, which a test may neither need nor be allowed to touch.
    #[cfg(any(target_os = "macos", test))]
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nexapipe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory under the temp directory");
        dir
    }

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

    /// The Linux twin of `a_partial_install_is_not_a_scoped_one`: a link given
    /// two domains and routing one of them has not routed them.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn a_link_routing_one_domain_has_not_routed_them_all() {
        let domains = vec!["example.com".to_string(), "foo.io".to_string()];
        let routed = vec!["example.com".to_string(), "foo.io".to_string()];
        assert!(routes_every_domain(&routed, &domains));
        assert!(!routes_every_domain(&["example.com".to_string()], &domains));
        assert!(!routes_every_domain(&[], &domains));
        assert!(routes_every_domain(&[], &[]));
    }

    /// `~` is what makes a domain routing-only: resolved sends it to that link's
    /// DNS server without putting it in any search list.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn the_routing_domains_a_link_was_given() {
        assert_eq!(
            parse_resolvectl_domains("Link 5 (nexa0): ~example.com ~foo.io\n"),
            vec!["example.com".to_string(), "foo.io".to_string()]
        );
        // A link given none looks like the line above with nothing after it.
        assert_eq!(
            parse_resolvectl_domains("Link 5 (nexa0):\n"),
            Vec::<String>::new()
        );
    }

    /// What the scoped hijack writes has to be what its restore reads: a file
    /// this code cannot recognise as its own is one it would leave behind.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn a_resolver_file_is_read_back_as_our_own() {
        let contents = resolver_file_contents("198.18.0.254");
        assert_eq!(
            resolver_nameserver(&contents).as_deref(),
            Some("198.18.0.254")
        );
        assert!(is_our_resolver_file(&contents));

        // The marker is the whole test: without it the same file is a stranger.
        assert!(contents.starts_with(RESOLVER_MARKER));
        assert!(!is_our_resolver_file("nameserver 198.18.0.254\n"));
        assert!(!is_our_resolver_file(""));
    }

    /// A file that names no resolver is not ours, and neither is one whose
    /// `nameserver` belongs to somebody else — the second one matters more: it
    /// is recognised, and for that reason left exactly as it is.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn only_a_file_naming_a_resolver_is_claimed() {
        assert_eq!(resolver_nameserver(""), None);
        assert_eq!(
            resolver_nameserver("# a comment\nsearch example.com\n"),
            None
        );
        assert_eq!(
            resolver_nameserver("nameserver 172.17.0.1\n").as_deref(),
            Some("172.17.0.1")
        );
    }

    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn every_domain_gets_a_file_naming_our_resolver() {
        let dir = scratch_dir("resolver-write");
        let (written, left_alone) = write_resolver_files(
            &dir,
            "198.18.0.254",
            &["example.com".to_string(), "foo.io".to_string()],
        );
        assert_eq!(written.len(), 2);
        assert!(left_alone.is_empty());
        assert_eq!(count_resolvers_in_effect(&written, "198.18.0.254"), 2);

        // The read-back is what the install checks, so it has to tell the two
        // apart: a file naming somebody else's address is not in effect.
        assert_eq!(count_resolvers_in_effect(&written, "1.1.1.1"), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole point of the per-domain hijack over the global one: whatever
    /// another resolver already owns stays exactly as it is, and survives the
    /// teardown too.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn a_resolver_somebody_else_owns_is_left_alone() {
        let dir = scratch_dir("resolver-theirs");
        let theirs = dir.join("example.com");
        std::fs::write(&theirs, "nameserver 172.17.0.1\n").unwrap();

        let (written, left_alone) =
            write_resolver_files(&dir, "198.18.0.254", &["example.com".to_string()]);
        assert!(written.is_empty());
        assert_eq!(left_alone.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "nameserver 172.17.0.1\n"
        );

        assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
        assert!(theirs.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scoped install that reached only some of the domains is not a scoped
    /// install: the rest would keep resolving outside the proxy while the caller
    /// is told they do not.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn a_partial_install_is_not_a_scoped_one() {
        assert!(scoped_install_is_complete(2, 2));
        // Nothing asked for, nothing missing.
        assert!(scoped_install_is_complete(0, 0));
        assert!(!scoped_install_is_complete(2, 3));
        assert!(!scoped_install_is_complete(0, 3));
    }

    /// Why ownership cannot be read off the address: `10.0.0.254` is the last of
    /// the candidate blocks and it is also a router address, so a split-DNS rule
    /// for an internal zone can name it without having anything to do with this
    /// proxy. Such a file is neither rewritten nor removed, and this directory is
    /// not the only place it can be at risk — the startup cleanup looks here too.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn an_unmarked_file_naming_a_hijack_address_is_left_alone() {
        let dir = scratch_dir("resolver-unmarked");
        let theirs = dir.join("corp.example");
        std::fs::write(&theirs, "nameserver 10.0.0.254\n").unwrap();
        assert!(is_tun_dns_address("10.0.0.254"));

        let (written, left_alone) =
            write_resolver_files(&dir, "198.18.0.254", &["corp.example".to_string()]);
        assert!(written.is_empty());
        assert_eq!(left_alone.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "nameserver 10.0.0.254\n"
        );

        // Both shapes of removal: the restore's, and the stale cleanup's, which
        // would otherwise match this address and find no interface holding it.
        assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
        assert!(
            remove_resolver_files(&dir, |contents| {
                is_our_resolver_file(contents)
                    && resolver_nameserver(contents).is_some_and(|server| server == "10.0.0.254")
            })
            .is_empty()
        );
        assert!(theirs.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Our own leftovers are not somebody else's: a run that used another block
    /// — or died before its restore — leaves a file naming an address no tunnel
    /// holds, and that one is rewritten and removed.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn a_resolver_left_by_an_earlier_run_is_taken_back() {
        let dir = scratch_dir("resolver-ours");
        let stale = dir.join("example.com");
        let other_block =
            Ipv4Addr::from(u32::from(TUN_BASE_CANDIDATES[1]) | 0x0000_00FE).to_string();
        // Marked, because the run that left it wrote it: the marker is the only
        // thing that still says so once the address belongs to no live tunnel.
        std::fs::write(&stale, resolver_file_contents(&other_block)).unwrap();
        assert!(is_tun_dns_address(&other_block));

        let (written, left_alone) =
            write_resolver_files(&dir, "198.18.0.254", &["example.com".to_string()]);
        assert_eq!(written.len(), 1);
        assert!(left_alone.is_empty());

        assert!(remove_resolver_files(&dir, is_our_resolver_file).is_empty());
        assert!(!stale.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
