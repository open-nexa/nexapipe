//! The Linux half of the system DNS configuration: `resolvectl` routing domains
//! for the scoped strategy, and `/etc/resolv.conf` for the global one.

//! The parsers of what `resolvectl` and `resolv.conf` say are compiled under
//! `test` on every platform, because the Linux code cannot be built or run on
//! the machine the tests run on, and a parser for a file this code rewrites is
//! not something to ship unexercised.

#[cfg(target_os = "linux")]
use std::process::Command;

// The shared half of the configuration. The pure parsers of this platform are
// compiled under `test` on every platform, and on some of those the shared
// half is not what they use — so the glob is unused there, which is not a
// mistake worth a warning.
#[allow(unused_imports)]
use super::*;

#[cfg(target_os = "linux")]
pub(super) const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.nexapipe.bak";

/// The routing domain that claims every name on a link, and the two shapes it
/// has: `~.` is what `resolvectl` is given — routing-only, so no search list
/// gains a root entry — and `.` is what [`parse_resolvectl_domains`] hands
/// back once the marker is off, which is the shape a read-back compares in.
#[cfg(any(target_os = "linux", test))]
pub(super) const DEFAULT_ROUTE_DOMAIN: &str = ".";

/// Points the configured domains at the TUN resolver through systemd-resolved's
/// per-link routing domains, and leaves every other name to whoever was already
/// answering it.
///
/// `Ok(false)` means "not installed" — no resolved on this machine, or the
/// setting did not take — which is a call to fall back rather than a failure.
/// Whatever was set is reverted first, so the fallback starts from the machine's
/// own configuration instead of from a half-installed hijack.
#[cfg(target_os = "linux")]
pub(super) fn set_scoped_dns_linux(
    interface: &str,
    dns_ip: &str,
    proxy_domains: &[String],
) -> Result<bool> {
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
pub(super) fn revert_resolvectl(interface: &str) {
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
pub(super) fn restore_scoped_dns_linux(interface: &str) -> Result<()> {
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
pub(super) fn resolvectl_domains_for(link: &str) -> Option<Vec<String>> {
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

/// The sources other than `link` that are themselves a DNS route for some
/// domain, as `resolvectl domain` reports them when it is given no link: every
/// link the machine has, plus the `Global` line.
///
/// A root route does not make this link the only one resolving asks. It keeps
/// the longest matching suffix, so a `~corp.example` on the office uplink still
/// takes every name under it — and takes those names to its own resolver,
/// which answers with the real address the tunnel exists to replace.
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_resolvectl_competing_routes(
    output: &str,
    link: &str,
) -> Vec<(String, Vec<String>)> {
    output
        .lines()
        .filter_map(|line| {
            let (source, domains) = line.split_once(':')?;
            let source = source.trim();
            // `Link 5 (nexa0)` names the link in parentheses; `Link 5` alone
            // covers a caller that addressed it by index.
            if source.contains(&format!("({link})")) || source.starts_with(&format!("Link {link} "))
            {
                return None;
            }
            // Only `~` domains route. A search domain affects how a bare name
            // is completed, not who is asked.
            let domains: Vec<String> = domains
                .split_whitespace()
                .filter(|token| token.starts_with('~'))
                .map(|token| token.trim_start_matches('~').to_string())
                .collect();
            if domains.is_empty() {
                return None;
            }
            Some((source.to_string(), domains))
        })
        .collect()
}

/// Every source other than `link` that routes some domain today, or `None` when
/// they could not be read. Not knowing is not evidence that they are quiet.
#[cfg(target_os = "linux")]
pub(super) fn competing_routes_for(link: &str) -> Option<Vec<(String, Vec<String>)>> {
    let output = Command::new("resolvectl").arg("domain").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_resolvectl_competing_routes(
        &String::from_utf8_lossy(&output.stdout),
        link,
    ))
}

/// The domains in `resolvectl domain` output, without the `~` that marks them
/// as routing-only: `Link 5 (nexa0): ~example.com ~foo.io`.
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_resolvectl_domains(output: &str) -> Vec<String> {
    output
        .split_whitespace()
        .filter(|token| token.starts_with('~'))
        .map(|token| token.trim_start_matches('~').to_string())
        .collect()
}

#[cfg(target_os = "linux")]
pub(super) fn set_system_dns_linux(interface: &str, dns_ip: &str) -> Result<()> {
    // Prefer resolvectl (systemd-resolved) to rewriting /etc/resolv.conf: the link
    // keeps the machine's own resolver configuration for the restore to hand back.
    // The TUN resolver answers the proxied domains itself and forwards the rest
    // upstream, so it can own every query while the tunnel is up.
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
                    match set_resolvectl_default_route_domain(interface) {
                        Ok(()) => {
                            // Routing every query here and being the only
                            // resolver asked are two claims. They come apart the
                            // moment another link routes some name more
                            // specifically, and "the proxy is up" is what the
                            // tray shows while that name quietly goes outside
                            // it — so say which of the two it is.
                            match competing_routes_for(interface) {
                                Some(routes) if !routes.is_empty() => {
                                    let others = routes
                                        .iter()
                                        .map(|(source, domains)| {
                                            format!("{source} routes {}", domains.join(", "))
                                        })
                                        .collect::<Vec<_>>()
                                        .join("; ");
                                    tracing::warn!(
                                        "routed every query to {} on {}, but resolved keeps the \
                                         longest match, so these keep their own resolver: {}",
                                        dns_ip,
                                        interface,
                                        others
                                    );
                                }
                                Some(_) => tracing::info!(
                                    "routed every query to {} on {}, and no other link routes \
                                     anything more specifically",
                                    dns_ip,
                                    interface
                                ),
                                None => tracing::warn!(
                                    "routed every query to {} on {}, but the other links' routing \
                                     domains could not be read back — one of them may still own \
                                     some names",
                                    dns_ip,
                                    interface
                                ),
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!(
                                "resolvectl could not route every query to {}: {}; \
                                 falling back to writing /etc/resolv.conf",
                                interface,
                                e
                            );
                            // The `dns` step did land, and a resolver left on the
                            // link is a second owner of the names the file below
                            // is about to claim: resolved fans a query out to
                            // every link that is a DNS route and keeps the first
                            // answer, so the TUN would win some names and not
                            // others with nobody to say which. Hand the link
                            // back, so the file is the only hijack in place —
                            // and so the fallback starts from the machine's own
                            // resolver rather than from half of ours.
                            revert_resolvectl(interface);
                        }
                    }
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
pub(super) fn restore_system_dns_linux(interface: &str, _dns_ip: &str) -> Result<()> {
    // Prefer reverting via resolvectl: one `revert` drops the DNS server and the
    // `~.` route that made it the only one.
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
pub(super) fn cleanup_stale_hijack_linux() {
    revert_stale_resolvectl_links();
    restore_stale_resolv_conf();
}

/// Reverts every link systemd-resolved still points at a TUN address nothing holds.
///
/// Only the links that exist now are asked: a setting for a link that has since gone
/// went with it, so what is left to revert is exactly what the machine is still
/// using.
#[cfg(target_os = "linux")]
pub(super) fn revert_stale_resolvectl_links() {
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
pub(super) fn restore_stale_resolv_conf() {
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
pub(super) fn resolvectl_dns_for(link: &str) -> Option<Vec<String>> {
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
pub(super) fn current_dns_servers_linux() -> Vec<String> {
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
pub(super) fn parse_resolvectl_dns(output: &str) -> Vec<String> {
    output
        .split_whitespace()
        .filter(|token| token.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

/// Makes `link` the DNS route for every name, not merely one more upstream.
///
/// `resolvectl dns` alone leaves the TUN resolver competing with whatever the
/// other links carry: systemd-resolved fans a query out to every link that is a
/// DNS route and keeps the first answer, so on a machine with more than one uplink
/// a proxied domain resolves to its real address as often as to the virtual one —
/// and the real address is exactly the one the tunnel exists to replace. `~.`
/// routes every query here instead, which is what the /etc/resolv.conf fallback
/// does with a file.
#[cfg(target_os = "linux")]
pub(super) fn set_resolvectl_default_route_domain(link: &str) -> Result<()> {
    // The marker is part of the token: resolved reads `~.` as "route the root
    // domain here" and a bare `.` as an ordinary search domain.
    let domain = format!("~{DEFAULT_ROUTE_DOMAIN}");
    let output = Command::new("resolvectl")
        .args(["domain", link, &domain])
        .output()
        .map_err(|e| anyhow::anyhow!("resolvectl domain {} {}: {}", link, domain, e))?;
    if !output.status.success() {
        anyhow::bail!(
            "resolvectl domain {} {}: {}",
            link,
            domain,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    match resolvectl_domains_for(link) {
        Some(domains) if domains.iter().any(|d| d == DEFAULT_ROUTE_DOMAIN) => Ok(()),
        Some(domains) => anyhow::bail!(
            "resolvectl domain {} {} exited 0 but the link has {:?}",
            link,
            domain,
            domains
        ),
        None => anyhow::bail!("could not read back the routing domain set on {}", link),
    }
}

/// The `nameserver` addresses a resolv.conf names.
#[cfg(any(target_os = "linux", test))]
pub(super) fn resolv_conf_nameservers(contents: &str) -> Vec<String> {
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
pub(super) fn resolv_conf_names_a_tun_address(contents: &str) -> bool {
    resolv_conf_nameservers(contents)
        .iter()
        .any(|server| is_tun_dns_address(server))
}

/// `contents` with the `nameserver` lines naming one of `addresses` removed, and
/// every other line kept exactly as it was.
#[cfg(any(target_os = "linux", test))]
pub(super) fn resolv_conf_without_nameservers(contents: &str, addresses: &[String]) -> String {
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
