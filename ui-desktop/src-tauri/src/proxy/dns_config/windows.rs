//! The Windows half of the system DNS configuration: NRPT rules for the scoped
//! strategy, and the adapter's own DNS servers for the global one.

//! The pure parts of it — the rule reader, the scripts it writes — are compiled
//! under `test` on every platform, because the machine that has to read them
//! back is not the one the tests run on.

#[cfg(windows)]
use crate::win::hidden;

// The shared half of the configuration. The pure parsers of this platform are
// compiled under `test` on every platform, and on some of those the shared
// half is not what they use — so the glob is unused there, which is not a
// mistake worth a warning.
#[allow(unused_imports)]
use super::*;

/// Marks an NRPT rule as one this process wrote.
///
/// Put in the rule's comment so `Get-DnsClientNrptRule` on the machine says
/// which rules are ours. Not what the code recognises them by: a comment is a
/// string an administrator or a policy can rewrite, and what makes a rule ours
/// is that it names the TUN resolver, an address nobody configures by hand
/// (see `crate::proxy::tun_proxy::TUN_BASE_CANDIDATES`).
#[cfg(any(windows, test))]
pub(super) const NRPT_COMMENT: &str = "nexapipe";

/// The namespaces one configured domain needs in the NRPT.
///
/// Two, because the NRPT reads a leading dot as a suffix and no dot as an
/// exact name: `example.com` alone leaves `www.example.com` resolving outside
/// the proxy, and `.example.com` alone is a *suffix* rule, which the name
/// `example.com` itself does not end in. Writing both is the only spelling
/// that covers a domain and everything under it either way the client reads it.
#[cfg(any(windows, test))]
pub(super) fn nrpt_namespaces(domains: &[String]) -> Vec<String> {
    let mut namespaces = Vec::with_capacity(domains.len() * 2);
    for domain in domains {
        namespaces.push(domain.clone());
        namespaces.push(format!(".{domain}"));
    }
    namespaces
}

/// One NRPT rule, as the PowerShell below prints it: what it covers, and who
/// it asks. Nothing else is needed — a rule is removed by name, and the name
/// is asked for again at that point rather than carried around.
#[cfg(any(windows, test))]
pub(super) struct NrptRule {
    namespaces: Vec<String>,
    servers: Vec<String>,
}

/// Reads a dump of the NRPT: one rule per line, `<namespaces>|<servers>`,
/// each a comma-separated list.
///
/// A rule the dump leaves half-empty still parses: an exemption rule carries no
/// servers at all, and it is not ours, but it has to be skipped rather than end
/// the parse. So does an empty dump, which is what a machine with no NRPT
/// rules prints — and which must not read as one nameless rule.
#[cfg(any(windows, test))]
pub(super) fn parse_nrpt_rules(output: &str) -> Vec<NrptRule> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (namespaces, servers) = line.split_once('|')?;
            Some(NrptRule {
                namespaces: namespaces
                    .split(',')
                    .map(|namespace| namespace.trim().to_string())
                    .collect(),
                servers: servers
                    .split(',')
                    .map(|server| server.trim().to_string())
                    .collect(),
            })
        })
        .collect()
}

/// The namespaces the NRPT routes to `dns_ip`.
///
/// Matched exactly, and not by substring: `110.7.0.254` contains `10.7.0.254`
/// and is a different resolver on a different network.
#[cfg(any(windows, test))]
pub(super) fn nrpt_namespaces_for(rules: &[NrptRule], dns_ip: &str) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| rule.servers.iter().any(|server| server == dns_ip))
        .flat_map(|rule| rule.namespaces.iter().cloned())
        .collect()
}

/// Runs a PowerShell script with no console window and returns its stdout.
///
/// A non-zero exit is an error: what these scripts have to say they say on
/// stdout, and one that failed has nothing there. Stderr is only a warning —
/// the scripts report per rule that could not be added or removed, which is a
/// partial result worth logging, not a failure of the whole command.
#[cfg(windows)]
pub(super) fn windows_ps(script: &str) -> Result<String> {
    let output = hidden("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run powershell: {}", e))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        tracing::warn!("powershell stderr: {}", stderr.trim());
    }
    if !output.status.success() {
        anyhow::bail!(
            "powershell exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The script that adds one rule per namespace and dumps the table back.
///
/// `Get-DnsClientNrptRule` rather than `Get-DnsClientNrptPolicy` for the
/// read-back, because a rule is removed by name and only the former reports
/// it: the same dump has to serve as the list a restore or a cleanup would
/// delete from.
#[cfg(any(windows, test))]
pub(super) fn nrpt_add_script(namespaces: &[String], dns_ip: &str) -> String {
    // `dns::scoped_domains` has already kept these to what a domain can
    // contain, so none of them can end the single quotes they go into.
    let list = namespaces
        .iter()
        .map(|namespace| format!("'{namespace}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "$namespaces = @({list});\
         foreach ($namespace in $namespaces) {{\
           try {{ Add-DnsClientNrptRule -Namespace $namespace -NameServers '{ip}' -Comment '{comment}' -ErrorAction Stop }} \
           catch {{ Write-Warning ('add ' + $namespace + ': ' + $_.Exception.Message) }}\
         }};\
         Clear-DnsClientCache;\
         Get-DnsClientNrptRule | ForEach-Object {{ ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }}",
        list = list,
        ip = dns_ip,
        comment = NRPT_COMMENT,
    )
}

/// The script that dumps the NRPT policy the client will actually apply.
///
/// `-Effective` rather than the rule table: what the table holds and what the
/// client resolves against are two things on a machine whose NRPT comes from a
/// domain policy, and only the effective policy says which. It is printed in the
/// same `<namespaces>|<servers>` shape as the rules, so the same parser reads
/// it — but a policy is not removable by name, which is why [`nrpt_add_script`]
/// still reads the rules for the restore to delete from.
#[cfg(any(windows, test))]
pub(super) fn nrpt_effective_script() -> String {
    "Get-DnsClientNrptPolicy -Effective | ForEach-Object { ($_.Namespace -join ',') + '|' + \
     ($_.NameServers -join ',') }"
        .to_string()
}

/// The script that removes every rule naming `dns_ip` — or carrying our
/// comment, for one whose server an earlier version wrote differently — and
/// dumps what is left.
#[cfg(any(windows, test))]
pub(super) fn nrpt_remove_script(dns_ip: &str) -> String {
    format!(
        "$ours = @(Get-DnsClientNrptRule | Where-Object {{ ($_.NameServers -contains '{ip}') -or ($_.Comment -eq '{comment}') }});\
         foreach ($rule in $ours) {{\
           try {{ Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop; Write-Output ('removed ' + ($rule.Namespace -join ',')) }} \
           catch {{ Write-Warning ('remove ' + $rule.Name + ': ' + $_.Exception.Message) }}\
         }};\
         Clear-DnsClientCache;\
         Get-DnsClientNrptRule | ForEach-Object {{ ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }}",
        ip = dns_ip,
        comment = NRPT_COMMENT,
    )
}

/// Points the configured domains at the TUN resolver with one NRPT rule each,
/// and leaves every other name to the DNS servers the adapters carry.
///
/// This is the Windows shape of what `/etc/resolver` does on macOS and a
/// routing domain does on Linux, and it is what the global hijack cannot be: a
/// name that matches no rule is resolved against the adapters, which still
/// carry whatever this machine was using before the tunnel came up — its own
/// internal resolvers, and another tunnel's, if one is running. No adapter is
/// touched, so there is no IPv6 race to lose either.
///
/// `Ok(false)` means "not installed", which is a failure and not a downgrade:
/// the caller refuses the scoped strategy rather than reaching for the global
/// one. Whatever was added up to that point is taken back first, so the
/// machine's own resolver is left in place — and taken back *for certain*,
/// because the global restore resets the adapters and leaves the table alone.
/// A rule that survives this keeps its domains pointed at a resolver nothing
/// answers from once the tunnel is down.
#[cfg(windows)]
pub(super) fn set_scoped_dns_windows(dns_ip: &str, proxy_domains: &[String]) -> Result<bool> {
    let Some(domains) = crate::proxy::dns::scoped_domains(proxy_domains) else {
        tracing::info!(
            "the configured domains cannot each be given a rule of their own; \
             the scoped DNS strategy could not be installed"
        );
        return Ok(false);
    };
    let namespaces = nrpt_namespaces(&domains);

    // Read back rather than trust the exit code, which is what the doubt about
    // this mechanism comes down to: NRPT settings live in the registry and a
    // machine that takes them from a domain policy ignores the local ones
    // entirely. A rule that is in the table but not in force looks exactly like
    // a proxy that resolves nothing.
    let dump = match windows_ps(&nrpt_add_script(&namespaces, dns_ip)) {
        Ok(dump) => dump,
        Err(e) => {
            tracing::warn!(
                "Add-DnsClientNrptRule failed: {} — the scoped DNS strategy could not be \
                 installed",
                e
            );
            clean_nrpt_rules(dns_ip)?;
            return Ok(false);
        }
    };
    let routed = nrpt_namespaces_for(&parse_nrpt_rules(&dump), dns_ip);
    if !routes_every_domain(&routed, &namespaces) {
        tracing::warn!(
            "{} of {} namespace(s) route to {} — the scoped DNS strategy could not be \
             installed: {}",
            routed.len(),
            namespaces.len(),
            dns_ip,
            dump.trim().replace('\n', "; ")
        );
        clean_nrpt_rules(dns_ip)?;
        return Ok(false);
    }

    // The rules are in the table, but the table is not the whole answer: a
    // machine whose NRPT comes from a domain policy ignores the local rules, so
    // a rule that is installed is not one that is in force. What the client
    // will actually do is the *effective* policy, and that is a separate read.
    match windows_ps(&nrpt_effective_script()) {
        Ok(policy) => {
            let effective = nrpt_namespaces_for(&parse_nrpt_rules(&policy), dns_ip);
            if !routes_every_domain(&effective, &namespaces) {
                tracing::warn!(
                    "{} of {} namespace(s) are routed to {} by the effective NRPT policy — \
                     the scoped DNS strategy could not be installed: {}",
                    effective.len(),
                    namespaces.len(),
                    dns_ip,
                    policy.trim().replace('\n', "; ")
                );
                clean_nrpt_rules(dns_ip)?;
                return Ok(false);
            }
        }
        Err(e) => {
            tracing::warn!(
                "the effective NRPT policy could not be read: {} — the scoped DNS strategy \
                 could not be installed",
                e
            );
            clean_nrpt_rules(dns_ip)?;
            return Ok(false);
        }
    }

    tracing::info!(
        "{} configured domain(s) resolve through {} via the NRPT; every other name \
         keeps the resolvers the adapters carry",
        domains.len(),
        dns_ip
    );
    Ok(true)
}

/// Removes the NRPT rules that name `dns_ip`, and reports any that stayed.
///
/// Rules outlive the process that wrote them — they are registry entries, and
/// they survive a reboot — so this is what a scoped restore runs, and one of
/// the two things the startup cleanup does. A rule left behind keeps its
/// domains resolving against a TUN address nothing answers from, which is
/// worse than no hijack at all: those names fail outright.
#[cfg(windows)]
pub(super) fn remove_nrpt_rules(dns_ip: &str) -> Result<()> {
    let dump = windows_ps(&nrpt_remove_script(dns_ip))?;
    let left = nrpt_namespaces_for(&parse_nrpt_rules(&dump), dns_ip);
    if left.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} namespace(s) still route to {} after the NRPT rules were removed: {}",
        left.len(),
        dns_ip,
        left.join(", ")
    )
}

/// Takes back the rules [`remove_nrpt_rules`] would, and says so when any
/// stayed.
///
/// The one attempt is not enough to trust: a rule can be held by a policy that
/// has not reapplied yet, or by a table another process is writing. So it is
/// tried twice, and a table that is still not clean afterwards is an error
/// rather than a silent fallback — see [`set_scoped_dns_windows`], where a rule
/// that survives keeps its domains pointed at a resolver nothing answers from
/// once the tunnel is down.
#[cfg(windows)]
pub(super) fn clean_nrpt_rules(dns_ip: &str) -> Result<()> {
    match remove_nrpt_rules(dns_ip) {
        Ok(()) => Ok(()),
        Err(first) => {
            tracing::warn!(
                "the NRPT rules naming {} are still there: {}",
                dns_ip,
                first
            );
            remove_nrpt_rules(dns_ip)
        }
    }
}

#[cfg(windows)]
pub(super) fn set_system_dns_windows(interface: &str, dns_ip: &str) -> Result<()> {
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
    let _ = hidden("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dnsservers",
            "all",
            dns_ip,
            "primary",
        ])
        .output();
    let _ = hidden("netsh")
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
pub(super) fn set_system_windows_dns_ps(interface: &str, dns_ip: &str) -> Result<String> {
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
    let output = hidden("powershell")
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
pub(super) fn windows_dns_points_at(dns_ip: &str) -> bool {
    let output = hidden("powershell")
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
pub(super) fn current_dns_servers_windows() -> Vec<String> {
    let output = hidden("powershell")
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
pub(super) fn restore_system_dns_windows(interface: &str, _dns_ip: &str) -> Result<()> {
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
    let output = hidden("powershell")
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
    let _ = hidden("netsh")
        .args(["interface", "ip", "set", "dnsservers", "all", "dhcp"])
        .output();
    let _ = hidden("netsh")
        .args(["interface", "ipv6", "set", "dnsservers", "all", "dhcp"])
        .output();
    tracing::info!("System DNS fallback netsh restore dhcp applied");
    Ok(())
}

#[cfg(windows)]
pub(super) fn cleanup_stale_hijack_windows() {
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
         $nrpt = @(Get-DnsClientNrptRule | Where-Object {{\
           $hit = $false;\
           foreach ($s in $_.NameServers) {{ if ($stale -contains $s) {{ $hit = $true }} }};\
           $hit\
         }});\
         foreach ($r in $nrpt) {{\
           try {{ Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction Stop; Write-Output ('removed nrpt rule ' + ($r.Namespace -join ',')) }} catch {{ Write-Warning ('remove nrpt ' + $r.Name + ': ' + $_.Exception.Message) }}\
         }};\
         if (($reset.Count + $nrpt.Count) -gt 0) {{ Clear-DnsClientCache }};\
         Write-Output ('stale adapters reset: ' + $reset.Count);\
         Write-Output ('stale NRPT rules removed: ' + $nrpt.Count)",
        list
    );
    match hidden("powershell")
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
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .replace('\n', "; ")
            );
        }
        Err(e) => tracing::warn!("stale DNS hijack cleanup could not run: {}", e),
    }
}
