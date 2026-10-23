//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! Three ways of doing it, and **which one is done is the operator's decision**, spelled by
//! [`DnsStrategy`]:
//!
//! - **Scoped** (per-domain): only the proxied domains resolve through the TUN, and
//!   everything else keeps resolving wherever the machine was resolving it. This is
//!   what makes running alongside another tunnel possible — the other app's names,
//!   and the machine's own internal ones, are none of our business. The default.
//!   - macOS:   a file per domain under `/etc/resolver`
//!   - Linux:   `resolvectl` routing domains on the TUN link
//!   - Windows: NRPT rules (PowerShell `Add-DnsClientNrptRule`), read back afterwards
//! - **Global**: every query on the machine goes to the TUN resolver.
//!   - Windows: PowerShell Set-DnsClientServerAddress (netsh fallback), verified afterwards
//!   - Linux:   overwriting /etc/resolv.conf (with a backup, which the restore puts back)
//!   - macOS:   networksetup (iterating over every network service), with the pre-hijack
//!     servers kept on file so a restore can put them back
//! - **None**: the machine's DNS is left exactly as it is. The local DNS server still
//!   runs, so a PAC file or a hosts entry can point at it.
//!
//! The strategy is never quietly downgraded. A machine that cannot be scoped — one
//! whose domain policy overrides the local NRPT rules, or one whose configured domain
//! list cannot be named to the operating system at all — **fails** under the scoped
//! strategy and says so, rather than having its whole DNS replaced behind the user's
//! back. The global strategy is one click away for the machine that needs it.
//!
//! Which one a run ended up with is returned by [`set_system_dns`] and has to be handed
//! back to [`restore_system_dns`]: each is undone where it was done, and a scoped
//! hijack leaves nothing in the places a global one writes.
//!
//! A hijack that *fails* carries what it had already installed with it — see
//! [`DnsHijackFailure`] — because the global paths change the machine before they read
//! it back, and a read-back that does not show the TUN address leaves the machine
//! pointing at an address that will never come up.
//!
//! Note: the local DNS server (proxy/dns.rs) must be started before `set_system_dns`,
//! otherwise the switched-over system DNS queries would have nobody to answer them.

use anyhow::Result;

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

// The three halves of the configuration. Each one is compiled only where it
// applies — except for the pure parts of each, which are compiled under `test`
// on every platform: the machine that has to read them back is not the one the
// tests run on.
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(any(windows, test))]
mod windows;

#[cfg(any(target_os = "linux", test))]
use linux::*;
#[cfg(any(target_os = "macos", test))]
use macos::*;
#[cfg(any(windows, test))]
use windows::*;

/// What the operator asked the machine's DNS to do.
///
/// The strategy is chosen by the person who set the app up, not by whatever the
/// platform happened to allow. Two machines that could both be scoped, one
/// choosing the global strategy and one not, differ in ways nobody can see
/// afterwards — so the choice is made where it can be seen, and it is not
/// changed afterwards by the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsStrategy {
    /// Only the configured domains resolve through the TUN. Everything else
    /// keeps resolving where it always did. The default, and the one that
    /// leaves the machine's own names alone.
    #[default]
    Scoped,
    /// Every query on the machine goes to the TUN resolver.
    Global,
    /// The machine's DNS is not touched at all. The local DNS server still
    /// runs, so a PAC file or a hosts entry can point at it.
    None,
}

impl DnsStrategy {
    /// The spelling in the configuration and in the settings page.
    pub fn name(&self) -> &'static str {
        match self {
            DnsStrategy::Scoped => "scoped",
            DnsStrategy::Global => "global",
            DnsStrategy::None => "none",
        }
    }

    /// Reads the spelling.
    ///
    /// A value that is present but unknown is **refused**, the way the rest of
    /// the settings are: this one says what happens to the machine's DNS, and
    /// a typo must not be read as "leave it alone" or "replace all of it" —
    /// those are two very different machines.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "scoped" => Ok(DnsStrategy::Scoped),
            "global" => Ok(DnsStrategy::Global),
            "none" => Ok(DnsStrategy::None),
            other => anyhow::bail!(
                "unknown DNS strategy {other:?}; expected \"scoped\", \"global\" or \"none\""
            ),
        }
    }
}

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
    /// The machine's DNS was not touched, so there is nothing to undo.
    None,
}

/// A hijack that failed, and what it left behind.
///
/// "It failed" and "nothing happened" are two different things, and the
/// difference is the whole point of this type: the global paths change the
/// machine *first* and read it back afterwards — the Windows one resets and
/// re-points every adapter and then asks whether the TUN address is among
/// them, the macOS one writes every service and then asks whether any of them
/// points at the TUN address. A read-back that does not show the address is a
/// failure that leaves the machine pointing at a TUN address which will never
/// come up: no name resolution on that adapter or service, until something
/// else fixes it.
///
/// So the failure carries the hijack that was installed — at least in part —
/// and the caller undoes it with that.
#[derive(Debug)]
pub struct DnsHijackFailure {
    /// The kind of hijack that was installed, at least in part.
    pub hijack: DnsHijack,
    /// What went wrong.
    pub error: anyhow::Error,
}

/// Points system DNS at the TUN virtual IP the way `strategy` says, and reports
/// which kind of hijack ended up in place.
///
/// The strategy is the operator's decision and it is the only one: a machine
/// that cannot be scoped **fails** under the scoped strategy, and the error
/// says what to do about it. It used to fall through to the global hijack
/// instead, which meant the machine's whole DNS was replaced whenever the
/// per-domain mechanism was unavailable or the configured list could not be
/// named — and nobody was told.
///
/// An empty domain list is not a failure: there is nothing to scope, so
/// nothing is installed and the machine's DNS stays where it was. A proxy that
/// proxies no domain resolves nothing either way.
///
/// A failure carries the hijack that was installed — at least in part — so that
/// the caller can take it back: see [`DnsHijackFailure`] and
/// [`undo_failed_hijack`].
pub fn set_system_dns(
    interface: &str,
    dns_ip: &str,
    proxy_domains: &[String],
    strategy: DnsStrategy,
) -> Result<DnsHijack, DnsHijackFailure> {
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`,
    // and only the three platform branches need `dns_ip`. The other platforms are a
    // compilation check, not a deployment target — but they have to compile.
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let _ = dns_ip;

    match strategy {
        // The machine's DNS is not the app's to change. The local DNS server
        // still runs, so a PAC file or a hosts entry can point at it.
        DnsStrategy::None => Ok(DnsHijack::None),

        // Asked for by name: every query on the machine goes to the TUN.
        DnsStrategy::Global => {
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
                Ok(DnsHijack::Global)
            }
        }

        // Asked for by name, and never quietly downgraded.
        DnsStrategy::Scoped => {
            // Nothing to scope: there is no domain to name to the operating
            // system, so nothing is installed and the machine's DNS stays
            // where it was. A proxy that proxies no domain resolves nothing
            // either way — and the tunnel still runs.
            if proxy_domains.is_empty() {
                return Ok(DnsHijack::None);
            }

            // The list has to be nameable before anything is tried: a
            // configuration the operating system cannot be told about is not a
            // platform failure, and the two need different answers.
            if crate::proxy::dns::scoped_domains(proxy_domains).is_none() {
                return Err(DnsHijackFailure {
                    // Nothing was installed: the machine's DNS was left alone.
                    hijack: DnsHijack::None,
                    error: anyhow::anyhow!(
                        "the scoped DNS strategy has nothing to install: {} cannot each be named \
                         to the operating system. A bare \"*\" means every domain and is what the \
                         global strategy is for, and a name without a dot is a host rather than a \
                         domain. The machine's DNS was left alone.",
                        describe_domains(proxy_domains)
                    ),
                });
            }

            #[cfg(windows)]
            {
                // Per-domain first, like the other two platforms: the NRPT names a
                // resolver for a namespace, and a name that matches no rule is resolved
                // against the adapters — which still carry the DNS this machine was
                // using, so nothing outside the configured domains moves. Rules are
                // verified by reading them back, because a machine that takes its NRPT
                // from a domain policy ignores the local ones entirely, and that is not
                // something to discover by having the proxy resolve nothing.
                match set_scoped_dns_windows(dns_ip, proxy_domains) {
                    Ok(true) => return Ok(DnsHijack::Scoped),
                    // The platform took back what it had installed.
                    Ok(false) => {}
                    // The rules are still in the table — the cleanup could not
                    // remove them — so there is something to take back, and the
                    // restore is what takes it back.
                    Err(e) => {
                        return Err(DnsHijackFailure {
                            hijack: DnsHijack::Scoped,
                            error: e,
                        })
                    }
                }
            }
            #[cfg(target_os = "linux")]
            {
                match set_scoped_dns_linux(interface, dns_ip, proxy_domains) {
                    Ok(true) => return Ok(DnsHijack::Scoped),
                    Ok(false) => {}
                    Err(e) => {
                        return Err(DnsHijackFailure {
                            hijack: DnsHijack::Scoped,
                            error: e,
                        })
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                match set_scoped_dns_macos(dns_ip, proxy_domains) {
                    Ok(true) => return Ok(DnsHijack::Scoped),
                    Ok(false) => {}
                    Err(e) => {
                        return Err(DnsHijackFailure {
                            hijack: DnsHijack::Scoped,
                            error: e,
                        })
                    }
                }
            }
            Err(DnsHijackFailure {
                // The platform took back whatever it had installed, so the
                // machine's DNS is where it was and there is nothing to undo.
                hijack: DnsHijack::None,
                error: anyhow::anyhow!(
                    "the scoped DNS strategy could not be installed on this machine: {}. The \
                     machine's DNS was left alone; the global strategy is what replaces it, and it \
                     is a setting away.",
                    scoped_failure_reason()
                ),
            })
        }
    }
}

/// Undoes a hijack that failed after it had already changed the machine.
///
/// The failure carries the hijack that was installed — see [`DnsHijackFailure`] —
/// and this is where that hijack is handed back to the restore.
///
/// Split out so that *which* hijack has to be undone is a decision of this
/// module, and a test of it runs wherever the tests run; the undoing itself
/// stays the platform's, which is what `restore` is.
pub fn undo_failed_hijack(
    failure: &DnsHijackFailure,
    restore: impl FnOnce(DnsHijack) -> Result<()>,
) -> Result<()> {
    match failure.hijack {
        // Nothing was installed, so there is nothing to undo — and undoing is
        // not free: the restore rewrites the machine's DNS configuration.
        DnsHijack::None => Ok(()),
        hijack => restore(hijack),
    }
}

/// The configured domains, as short a list as says it.
fn describe_domains(domains: &[String]) -> String {
    let shown: Vec<&str> = domains.iter().map(|d| d.as_str()).take(5).collect();
    if domains.len() > shown.len() {
        format!(
            "{} of the {} configured domains (\"{}\", …)",
            shown.len(),
            domains.len(),
            shown.join("\", \"")
        )
    } else {
        format!("the configured domains (\"{}\")", shown.join("\", \""))
    }
}

/// Why the per-domain mechanism did not take, per platform.
///
/// The installers have already said what they saw; this says what it means
/// here, so the message a user reads names the thing they would have to
/// change.
#[cfg(windows)]
fn scoped_failure_reason() -> &'static str {
    "the NRPT rules could not be installed, or were read back as not in force — a machine that takes its rules from a domain policy ignores the local ones"
}

#[cfg(target_os = "linux")]
fn scoped_failure_reason() -> &'static str {
    "systemd-resolved could not route the configured domains to the tunnel's link"
}

#[cfg(target_os = "macos")]
fn scoped_failure_reason() -> &'static str {
    "the per-domain resolver files could not be written under /etc/resolver"
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn scoped_failure_reason() -> &'static str {
    "this platform has no per-domain DNS mechanism"
}

/// Whether anything still resolves against the address this run hijacked.
///
/// Read back before undoing a global hijack. The attempt behind that undo can
/// have failed before it reached the machine — and undoing is not a no-op:
/// writing every service back from a backup an earlier run left behind, or
/// reverting a link's own DNS along with ours, changes settings this run never
/// touched. So the question is not "did the hijack succeed" but "is it there",
/// which is also what covers a hijack that partly landed before it failed.
///
/// `dns_ip` is matched exactly and not widened to the candidate blocks: one of
/// those is a router's own address, and counting a machine that was given it by
/// hand as hijacked would rewrite a setting nobody asked about. What an earlier
/// run left behind at another block is the startup cleanup's business, see
/// `cleanup_stale_hijack`.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn hijack_is_in_effect(observed: &[Vec<String>], dns_ip: &str) -> bool {
    observed
        .iter()
        .any(|servers| servers.iter().any(|server| server == dns_ip))
}

/// How much of the machine a restore is allowed to touch.
///
/// The two differ in one question: does the read-back show the hijack?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreScope {
    /// Undo the hijack only if it is still in effect.
    ///
    /// The right question for a run that installed a hijack and took it back on
    /// purpose: undoing is not free — the global restore writes every service
    /// back from a backup — and a run that never got the machine to change has
    /// nothing to undo.
    IfInEffect,
    /// Undo it whether or not the read-back shows it.
    ///
    /// For a hijack that failed *after* it had already changed the machine: the
    /// read-back is exactly what failed, so asking it again answers the same
    /// way — and the machine is left pointing at a TUN address that will never
    /// come up.
    Unconditional,
}

/// Restores the system DNS configuration (best effort), undoing the kind of
/// hijack [`set_system_dns`] reported it had installed.
///
/// `scope` says how much the restore is allowed to touch: see
/// [`RestoreScope`]. A hijack that failed halfway is undone unconditionally —
/// the read-back that failed is the very thing that would say it is not in
/// effect.
pub fn restore_system_dns(
    interface: &str,
    dns_ip: &str,
    hijack: DnsHijack,
    scope: RestoreScope,
) -> Result<()> {
    // Only the Linux (resolvectl) and Windows (adapter exclusion) branches need `interface`,
    // and only the three platform branches need `dns_ip`. The other platforms are a
    // compilation check, not a deployment target — but they have to compile.
    #[cfg(not(any(windows, target_os = "linux")))]
    let _ = interface;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let _ = dns_ip;
    // The scope is a question only where the restore asks whether the hijack
    // is still in effect; the Windows one hands the adapters back to DHCP
    // either way.
    #[cfg(windows)]
    let _ = scope;

    #[cfg(windows)]
    {
        match hijack {
            DnsHijack::Scoped => remove_nrpt_rules(dns_ip),
            // The machine's DNS was not touched, so there is nothing to undo.
            DnsHijack::None => Ok(()),
            // Rules are taken back here too, and not only in the branch above:
            // a run that installed rules and then fell through to the global
            // hijack — or one that inherited rules a process left behind before
            // it ever got to record what it did — is restored by this path, and
            // resetting the adapters does not touch the table.
            DnsHijack::Global => {
                if let Err(e) = remove_nrpt_rules(dns_ip) {
                    tracing::warn!(
                        "the NRPT rules naming {} could not be removed: {}",
                        dns_ip,
                        e
                    );
                }
                restore_system_dns_windows(interface, dns_ip)
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        match hijack {
            DnsHijack::Scoped => restore_scoped_dns_linux(interface),
            DnsHijack::None => Ok(()),
            DnsHijack::Global => {
                let observed = [
                    resolvectl_dns_for(interface).unwrap_or_default(),
                    resolv_conf_nameservers(
                        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
                    ),
                ];
                if scope == RestoreScope::Unconditional || hijack_is_in_effect(&observed, dns_ip) {
                    restore_system_dns_linux(interface, dns_ip)
                } else {
                    tracing::info!(
                        "nothing resolves against {} — this run installed no hijack to undo, \
                         and restoring is not a no-op here: it reverts the link's own DNS too",
                        dns_ip
                    );
                    Ok(())
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match hijack {
            DnsHijack::Scoped => restore_scoped_dns_macos(),
            DnsHijack::None => Ok(()),
            DnsHijack::Global => {
                let observed: Vec<Vec<String>> = network_services()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|service| dns_servers_for(service))
                    .collect();
                if scope == RestoreScope::Unconditional || hijack_is_in_effect(&observed, dns_ip) {
                    restore_system_dns_macos(dns_ip)
                } else {
                    tracing::info!(
                        "no network service points at {} — this run installed no hijack to undo, \
                         and restoring would write every service from a backup an earlier run \
                         may have left behind",
                        dns_ip
                    );
                    Ok(())
                }
            }
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
/// — a machine whose resolvers cannot be read just leaves the chain to the
/// configured upstream and the fallbacks.
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

/// The pre-hijack resolvers this program already has on file: what an earlier
/// run recorded before it moved the system DNS, kept in
/// [`DNS_BACKUP_PATH`] on macOS and in [`RESOLV_CONF_BACKUP`] on Linux.
///
/// A second source rather than a correction to [`current_dns_servers`], and the
/// reason is the case the live read cannot answer: a run that was killed before
/// its restore leaves the machine pointing at a TUN address, so asking the
/// system what it resolves against now returns the hijack itself — which the
/// caller filters out, and the chain then starts at the public resolvers. The
/// file is the only surviving record of what that machine was actually using.
///
/// Tried behind the live read, so it only contributes when those did not fill
/// the slots on their own. A stale entry costs one 1.5s window when it does not
/// answer, which is cheaper than answering an internal name from a public one.
/// Windows keeps no such record — its restore hands adapters back to DHCP — so
/// it has nothing to contribute.
pub fn recorded_dns_servers() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let mut servers: Vec<String> = Vec::new();
        for recorded in read_dns_backup().values() {
            for server in recorded {
                if !servers.contains(server) {
                    servers.push(server.clone());
                }
            }
        }
        servers
    }

    #[cfg(target_os = "linux")]
    {
        resolv_conf_nameservers(&std::fs::read_to_string(RESOLV_CONF_BACKUP).unwrap_or_default())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
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
/// An NRPT rule naming one of those addresses is stale for the same reason and is
/// removed too — a rule is a registry entry, so it survives the reboot as well, and it
/// keeps its domains resolving against a TUN address nothing answers from.
///
/// The same question is asked on every platform — is the address still in use? — and
/// only the way it is answered differs: macOS and Linux ask the system resolver whether
/// an interface still holds the address ([`cleanup_stale_hijack_macos`],
/// [`cleanup_stale_hijack_linux`]), while Windows asks whether the tunnel's DNS server
/// is still listening on it ([`cleanup_stale_hijack_windows`]). The decision itself is
/// shared — see [`stale_adapter_indexes`] — so an adapter whose address a live tunnel
/// still holds is left alone everywhere.
pub fn cleanup_stale_hijack() {
    #[cfg(windows)]
    cleanup_stale_hijack_windows();

    #[cfg(target_os = "macos")]
    cleanup_stale_hijack_macos();

    #[cfg(target_os = "linux")]
    cleanup_stale_hijack_linux();
}

/// Whether `routed` is every one of `domains`, and not merely one of them: a
/// domain left out keeps resolving outside the proxy while the caller is told
/// the hijack is scoped, which is the one thing the fallback is for.
#[cfg(any(target_os = "linux", windows, test))]
fn routes_every_domain(routed: &[String], domains: &[String]) -> bool {
    domains.iter().all(|domain| routed.contains(domain))
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

/// The IPv6 loopback — the address the local DNS server also listens on, and
/// the marker the IPv6 half of a hijack leaves behind.
#[cfg(any(windows, test))]
pub(crate) const LOCALHOST_V6: &str = "::1";

/// One adapter's DNS configuration, as the stale-hijack cleanup sees it.
///
/// The shape is the Windows one — an adapter, addressed by its interface index
/// — because that is the platform whose cleanup had no liveness guard. The
/// decision built on it is shared, so it can be exercised on any host.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterDns {
    /// The adapter's interface index — how a reset addresses it.
    pub(crate) index: u32,
    /// The DNS servers configured on it, over both address families.
    pub(crate) servers: Vec<String>,
}

/// The adapters whose DNS still points at a hijack that is no longer running.
///
/// `in_use` answers the one question that separates a stale hijack from a live
/// one: is that address still in use? It is asked per address, because the
/// answer is per address — one tunnel holds one address.
///
/// Two things have to hold for an adapter to be reset:
///
/// - it names one of the TUN candidate addresses (`…254` of a candidate block),
///   which is what a hijack leaves behind and nobody configures by hand; or
///   it names `::1`, which is the IPv6 half of the hijack — the local DNS
///   server listens on `[::1]:53` for as long as a tunnel is up;
/// - and that address is not in use.
///
/// The second half is what keeps a live tunnel out of it. Resetting the
/// adapters of a tunnel that is still up leaves the tunnel up and the machine's
/// DNS somewhere else: the proxied domains resolve at their real addresses and
/// the traffic leaves in the clear — the exact failure the DNS strategy was
/// introduced to prevent.
#[cfg(any(windows, test))]
pub(crate) fn stale_adapter_indexes(
    adapters: &[AdapterDns],
    in_use: impl Fn(&str) -> bool,
) -> Vec<u32> {
    adapters
        .iter()
        .filter(|adapter| adapter_dns_is_stale(&adapter.servers, &in_use))
        .map(|adapter| adapter.index)
        .collect()
}

/// Whether one adapter's DNS is a stale hijack.
///
/// The IPv4 half and the IPv6 half are the same question asked of two
/// addresses: does this adapter name an address a hijack uses, and is that
/// address still in use?
#[cfg(any(windows, test))]
fn adapter_dns_is_stale(servers: &[String], in_use: impl Fn(&str) -> bool) -> bool {
    let mut stale = false;
    for server in servers {
        let ours = server == LOCALHOST_V6 || is_tun_dns_address(server);
        if ours && !in_use(server) {
            stale = true;
        }
    }
    stale
}

#[cfg(test)]
mod tests {
    use super::{undo_failed_hijack, DnsHijack, DnsHijackFailure, DnsStrategy};

    // The cleanup's decision, and the pieces it is built from. Compiled under
    // `test` on every platform: the machine that has to answer the liveness
    // question is not the one the tests run on.
    #[cfg(any(windows, test))]
    use super::{stale_adapter_indexes, AdapterDns, LOCALHOST_V6};

    /// The three spellings there are, and nothing else.
    ///
    /// A strategy that is not known must not be read as one of them: the
    /// setting says what happens to the machine's name resolution, and "leave
    /// it alone" and "replace all of it" are two very different machines.
    #[test]
    fn a_dns_strategy_is_read_from_its_spelling() {
        assert_eq!(DnsStrategy::parse("scoped").unwrap(), DnsStrategy::Scoped);
        assert_eq!(DnsStrategy::parse("global").unwrap(), DnsStrategy::Global);
        assert_eq!(DnsStrategy::parse("none").unwrap(), DnsStrategy::None);
        // Case and surrounding space are the reader's business, not the user's.
        assert_eq!(
            DnsStrategy::parse("  Scoped ").unwrap(),
            DnsStrategy::Scoped
        );
    }

    /// A spelling nobody knows is refused, and the message says what there is.
    #[test]
    fn an_unknown_dns_strategy_is_refused() {
        let error = DnsStrategy::parse("everything").expect_err("a typo is refused");
        let message = error.to_string();
        assert!(message.contains("everything"), "{message}");
        assert!(message.contains("scoped"), "{message}");
        assert!(message.contains("global"), "{message}");
        assert!(message.contains("none"), "{message}");
    }

    /// The default is the strategy that leaves the machine's own names alone.
    #[test]
    fn the_default_dns_strategy_is_scoped() {
        assert_eq!(DnsStrategy::default(), DnsStrategy::Scoped);
    }

    /// Each strategy spells itself back the way it is written.
    #[test]
    fn a_dns_strategy_spells_itself_back() {
        assert_eq!(DnsStrategy::Scoped.name(), "scoped");
        assert_eq!(DnsStrategy::Global.name(), "global");
        assert_eq!(DnsStrategy::None.name(), "none");
    }

    /// "None" means the machine's DNS was not touched, and there is nothing to
    /// undo — which is what the restore path has to know.
    ///
    /// Exercised on every platform, because the point of the strategy is that
    /// it does not reach the platform at all: no scoped rules, no global
    /// hijack, nothing to restore.
    #[test]
    fn the_none_strategy_installs_nothing() {
        let hijack = super::set_system_dns(
            "does-not-matter",
            "198.18.0.254",
            &["example.com".to_string()],
            DnsStrategy::None,
        )
        .expect("the none strategy cannot fail");
        assert_eq!(hijack, DnsHijack::None);
    }

    /// An empty domain list is not a failure: there is nothing to scope, so
    /// nothing is installed and the machine's DNS stays where it was.
    ///
    /// The scoped strategy is the default, and a proxy with no domain
    /// configured is a proxy that resolves nothing — the tunnel still runs.
    /// What it must not do is fail the run: the scoped attempt has nothing to
    /// install, and a run that says "it could not be installed" is a run that
    /// refuses a tunnel over a domain list that was empty to begin with.
    #[test]
    fn the_scoped_strategy_with_no_domains_installs_nothing() {
        let hijack =
            super::set_system_dns("does-not-matter", "198.18.0.254", &[], DnsStrategy::Scoped)
                .expect("an empty domain list is not a failure");
        assert_eq!(hijack, DnsHijack::None);
    }

    #[cfg(target_os = "macos")]
    use super::{backup_is_spent, parse_getdnsservers, parse_network_services, NO_DNS_SERVERS};

    // Compiled under `test` on every platform, like the resolv.conf readers: it
    // is a pure parser for a command this machine cannot otherwise exercise, and
    // the whole point of it is the case this machine cannot produce.
    #[cfg(any(target_os = "macos", test))]
    use super::parse_scutil_dns;

    // The resolv.conf and resolvectl readers are pure, so they are compiled under
    // `test` on every platform: the Linux code cannot be built or run here, and a
    // parser for a file this code rewrites is not something to ship unexercised.
    #[cfg(any(target_os = "linux", test))]
    use super::{
        parse_resolvectl_competing_routes, parse_resolvectl_dns, parse_resolvectl_domains,
        resolv_conf_names_a_tun_address, resolv_conf_nameservers, resolv_conf_without_nameservers,
        routes_every_domain, DEFAULT_ROUTE_DOMAIN,
    };

    // The NRPT reader is pure, and the machine that has to read it back is not
    // the one the tests run on: a rule that is in the table but does not name
    // our resolver is the difference between a scoped hijack and a global one.
    #[cfg(any(windows, test))]
    use super::{
        nrpt_add_script, nrpt_effective_script, nrpt_namespaces, nrpt_namespaces_for,
        nrpt_remove_script, parse_nrpt_rules,
    };

    // The Windows cleanup reads the machine in two steps — what is on it, and
    // what is still in use — and decides in the shared code. Both halves are
    // pure, so they are compiled under `test` on every platform.
    #[cfg(any(windows, test))]
    use super::{
        cleanup_apply_script, cleanup_collect_script, parse_cleanup_state, stale_nrpt_rules,
        CleanupRule,
    };

    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    use super::hijack_is_in_effect;
    // Same for the per-domain resolver file: what this code writes has to be
    // what it reads back, or a restore would leave its own files behind.
    #[cfg(any(target_os = "macos", test))]
    use super::{
        count_resolvers_in_effect, is_our_resolver_file, is_tun_dns_address, remove_resolver_files,
        resolver_file_contents, resolver_nameserver, scoped_install_is_complete,
        scoped_install_tally, write_resolver_files, RESOLVER_MARKER,
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

    /// `scutil --dns` is read for one reason: on a machine that takes whatever
    /// DHCP hands out, it is the only thing that names the router's DNS. A
    /// resolver block the command prints without a nameserver — the mDNS one
    /// always is — contributes nothing rather than poisoning the list.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_reads_the_resolvers_in_effect_and_skips_the_ones_naming_none() {
        let output = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  order    : 300000
";
        assert_eq!(
            parse_scutil_dns(output),
            vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    /// A resolver that answers for one name is not an upstream.
    ///
    /// `scutil` prints a block for every `/etc/resolver/<domain>` on the
    /// machine — what a VPN client, Docker or dnsmasq leaves there — and each
    /// one carries a `domain :` line. Asking one of those a public name is not
    /// a slow answer but a wrong one: a live resolver answers NXDOMAIN and the
    /// chain takes the first reply it gets, and a dead one costs 1.5s.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_leaves_out_the_resolvers_that_answer_for_one_domain() {
        let output = "\
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1

resolver #2
  domain   : corp.example
  nameserver[0] : 10.8.0.1
  flags    : Scoped

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
";
        assert_eq!(
            parse_scutil_dns(output),
            vec!["192.168.1.1".to_string()],
            "only the resolver that answers every name is an upstream"
        );
    }

    /// A block is only decidable once its last line has been read, so a
    /// `domain :` at the end of one still drops the nameserver at its start.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_drops_a_block_whose_domain_line_comes_last() {
        let output = "\
resolver #1
  nameserver[0] : 10.8.0.1
  domain   : corp.example

resolver #2
  nameserver[0] : 192.168.1.1
";
        assert_eq!(parse_scutil_dns(output), vec!["192.168.1.1".to_string()]);
    }

    /// The "for scoped queries" section repeats the global one, and so does
    /// every interface that was given the same servers: the chain tries one
    /// address at a time and pays 1.5s for each that does not answer, so the
    /// repeats have to collapse rather than fill both slots with one resolver.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_names_each_resolver_once_across_the_sections_that_repeat_it() {
        let output = "\
DNS configuration

resolver #1
  nameserver[0] : 192.168.1.1

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
";
        assert_eq!(parse_scutil_dns(output), vec!["192.168.1.1".to_string()]);
    }

    /// A nameserver line is only ever taken as an address: an IPv6 one carries
    /// colons of its own, so the split has to be on the first colon — the one
    /// after the index — and not on any of the ones inside the address.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_reads_an_ipv6_nameserver_whole() {
        assert_eq!(
            parse_scutil_dns("resolver #1\n  nameserver[0] : 2001:db8::1\n"),
            vec!["2001:db8::1".to_string()]
        );
    }

    /// Output this code has never seen — a refused command, or a shape that
    /// changed — is not a resolver. Guessing an address and forwarding a
    /// machine's queries to it is worse than having no answer.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn scutil_dns_output_naming_no_address_reads_as_no_resolvers() {
        assert!(parse_scutil_dns("").is_empty());
        assert!(parse_scutil_dns("** Error: command not recognized.\n").is_empty());
        assert!(parse_scutil_dns("  nameserver[0] : not-an-address\n").is_empty());
    }

    /// One rule per line, `<namespaces>|<servers>`, which is what the two NRPT
    /// scripts print. PowerShell ends these lines with CRLF, and a rule can name
    /// more than one server — the read-back has to survive both before it is
    /// trusted to say whether the hijack is in place.
    #[cfg(any(windows, test))]
    #[test]
    fn nrpt_rules_read_back_as_the_namespaces_they_route_and_who_they_ask() {
        let rules =
            parse_nrpt_rules("example.com|10.7.0.254\r\n.foo.io|10.7.0.254,192.168.1.1\r\n");
        assert_eq!(
            nrpt_namespaces_for(&rules, "10.7.0.254"),
            vec!["example.com".to_string(), ".foo.io".to_string()]
        );
    }

    /// A rule that names another resolver is not one of ours, and neither is an
    /// exemption rule, which carries no server at all. `110.7.0.254` is the
    /// address the exact match is worth writing: it contains this one, and it is
    /// somebody else's resolver.
    #[cfg(any(windows, test))]
    #[test]
    fn an_nrpt_rule_naming_another_resolver_is_not_ours() {
        let rules =
            parse_nrpt_rules("example.com|110.7.0.254\r\n.corp.example.com|\r\nnas|10.7.0.254");
        assert_eq!(
            nrpt_namespaces_for(&rules, "10.7.0.254"),
            vec!["nas".to_string()]
        );
    }

    /// A machine with no NRPT rules prints nothing at all, which has to read as
    /// "no rules" rather than as one rule covering no namespace.
    #[cfg(any(windows, test))]
    #[test]
    fn an_empty_nrpt_dump_reads_as_no_rules() {
        assert!(parse_nrpt_rules("").is_empty());
        assert!(parse_nrpt_rules("\r\n").is_empty());
        assert!(nrpt_namespaces_for(&parse_nrpt_rules(""), "10.7.0.254").is_empty());
    }

    /// The two commands a Windows machine will run and this one cannot. Pinned
    /// because a broken escape — a `{{` that survives into the script — reaches
    /// that machine as a PowerShell syntax error, and there is no other way to
    /// see it coming from here.
    #[cfg(any(windows, test))]
    #[test]
    fn nrpt_scripts_are_pinned() {
        assert_eq!(
            nrpt_add_script(&nrpt_namespaces(&["example.com".to_string()]), "10.7.0.254"),
            "$namespaces = @('example.com','.example.com');\
             foreach ($namespace in $namespaces) {\
             try { Add-DnsClientNrptRule -Namespace $namespace -NameServers '10.7.0.254' -Comment 'nexapipe' -ErrorAction Stop } \
             catch { Write-Warning ('add ' + $namespace + ': ' + $_.Exception.Message) }\
             };\
             Clear-DnsClientCache;\
             Get-DnsClientNrptRule | ForEach-Object { ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }"
        );
        assert_eq!(
            nrpt_remove_script("10.7.0.254"),
            "$ours = @(Get-DnsClientNrptRule | Where-Object { ($_.NameServers -contains '10.7.0.254') -or ($_.Comment -eq 'nexapipe') });\
             foreach ($rule in $ours) {\
             try { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop; Write-Output ('removed ' + ($rule.Namespace -join ',')) } \
             catch { Write-Warning ('remove ' + $rule.Name + ': ' + $_.Exception.Message) }\
             };\
             Clear-DnsClientCache;\
             Get-DnsClientNrptRule | ForEach-Object { ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }"
        );
    }

    /// The policy the client applies is read back in the shape the rule parser
    /// already understands: a rule can be in the table and not in force, and the
    /// two dumps have to be read by the same code or the comparison is between
    /// different things.
    #[cfg(any(windows, test))]
    #[test]
    fn the_effective_nrpt_policy_is_read_back_as_namespaces_and_servers() {
        assert_eq!(
            nrpt_effective_script(),
            "Get-DnsClientNrptPolicy -Effective | ForEach-Object { ($_.Namespace -join ',') + '|' \
             + ($_.NameServers -join ',') }"
        );

        let rules = parse_nrpt_rules("example.com,.example.com|10.7.0.254\n.corp|10.8.0.1\n");
        assert_eq!(
            nrpt_namespaces_for(&rules, "10.7.0.254"),
            vec!["example.com".to_string(), ".example.com".to_string()]
        );
        assert!(
            nrpt_namespaces_for(&rules, "10.7.0.253").is_empty(),
            "a policy that names another server routes nothing of ours"
        );
    }

    /// The apex and everything under it, as two rules. One namespace alone is
    /// the half a scoped hijack fails on: `.example.com` is a suffix rule, which
    /// the name `example.com` does not end in.
    #[cfg(any(windows, test))]
    #[test]
    fn nrpt_namespaces_cover_a_domain_and_everything_under_it() {
        assert_eq!(
            nrpt_namespaces(&["example.com".to_string()]),
            vec!["example.com".to_string(), ".example.com".to_string()]
        );
        assert!(nrpt_namespaces(&[]).is_empty());
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

    /// The exclusive-route read-back compares what `resolvectl domain` printed
    /// against [`DEFAULT_ROUTE_DOMAIN`], so the two have to agree on the shape:
    /// the `~` that makes it routing-only is not part of what the parser keeps.
    /// A parser that starts keeping it would turn a working hijack into one that
    /// silently falls back to rewriting /etc/resolv.conf.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn the_default_route_domain_reads_back_as_the_root() {
        assert_eq!(
            parse_resolvectl_domains("Link 5 (nexa-tun): ~.\n"),
            vec![DEFAULT_ROUTE_DOMAIN.to_string()]
        );
        // The token it is written as, and the one it is read back as.
        assert_eq!(DEFAULT_ROUTE_DOMAIN, ".");
        assert_eq!(format!("~{DEFAULT_ROUTE_DOMAIN}"), "~.");
    }

    /// Routing every query to this link and being the only resolver asked are
    /// two claims, and only one of them follows from `~.`: resolved keeps the
    /// longest matching suffix, so a `~corp.example` on another link keeps
    /// answering those names with the addresses the tunnel exists to replace.
    /// Calling the hijack exclusive while that is true is how a name walks out
    /// through the proxy's front door without anybody seeing it leave.
    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn a_more_specific_route_elsewhere_keeps_its_own_resolver() {
        let output = "\
Global:
Link 2 (eth0): corp.example
Link 5 (nexa0): ~.
Link 7 (wg0): ~corp.example ~corp.internal
";
        assert_eq!(
            parse_resolvectl_competing_routes(output, "nexa0"),
            vec![(
                "Link 7 (wg0)".to_string(),
                vec!["corp.example".to_string(), "corp.internal".to_string()]
            )]
        );

        // The route this hijack installs is never a competing one.
        assert!(parse_resolvectl_competing_routes(output, "wg0")
            .iter()
            .all(|(source, _)| source != "Link 7 (wg0)"));

        // A search domain is not a route: it decides how a bare name is
        // completed, not who is asked, so eth0 above counts for nothing.
        assert_eq!(
            parse_resolvectl_competing_routes("Link 2 (eth0): corp.example\n", "nexa0"),
            Vec::new()
        );

        // The global list routes too, and belongs to no link.
        assert_eq!(
            parse_resolvectl_competing_routes(
                "Global: ~corp.example\nLink 5 (nexa0): ~.\n",
                "nexa0"
            ),
            vec![("Global".to_string(), vec!["corp.example".to_string()])]
        );

        // Addressed by index rather than by name.
        assert_eq!(
            parse_resolvectl_competing_routes("Link 5 (nexa0): ~.\n", "5"),
            Vec::new()
        );

        // Nothing routes anywhere else, so the hijack really is the only one.
        assert_eq!(
            parse_resolvectl_competing_routes("Link 5 (nexa0): ~.\n", "nexa0"),
            Vec::new()
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
        // Two domains asked for and no file written — every write failed. Nothing
        // to score against is not the same as everything having taken effect.
        assert!(!scoped_install_is_complete(0, 2));
    }

    /// Scored against what the install set out to write, so a write that failed
    /// counts as a domain that did not take rather than disappearing from the
    /// score. Too long to be a filename is how a write fails here.
    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn an_install_is_scored_against_the_domains_it_meant_to_write() {
        let dir = scratch_dir("resolver-tally");
        let too_long = format!("{}.com", "a".repeat(300));

        let install = scoped_install_tally(&dir, "198.18.0.254", &[too_long]);
        assert!(install.written.is_empty());
        assert_eq!(install.in_effect, 0);
        assert_eq!(install.meant_to_write, 1);
        assert!(!scoped_install_is_complete(
            install.in_effect,
            install.meant_to_write
        ));

        let ok = scoped_install_tally(
            &dir,
            "198.18.0.254",
            &["example.com".to_string(), "foo.io".to_string()],
        );
        assert_eq!(ok.meant_to_write, 2);
        assert_eq!(ok.in_effect, 2);
        assert!(scoped_install_is_complete(ok.in_effect, ok.meant_to_write));

        // A domain another resolver owns is subtracted rather than counted as a
        // refusal: reaching for the global hijack would not win that domain back
        // — the file outranks it — and would take the rest of the machine's DNS
        // with it.
        std::fs::write(dir.join("corp.example"), "nameserver 172.17.0.1\n").unwrap();
        let mixed = scoped_install_tally(
            &dir,
            "198.18.0.254",
            &["example.com".to_string(), "corp.example".to_string()],
        );
        assert_eq!(mixed.owned_by_someone_else.len(), 1);
        assert_eq!(mixed.meant_to_write, 1);
        assert_eq!(mixed.in_effect, 1);
        assert!(scoped_install_is_complete(
            mixed.in_effect,
            mixed.meant_to_write
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Why the global restore asks before it writes. An attempt that never
    /// reached the machine has nothing to undo, and undoing is not free: every
    /// service gets written, from a backup an earlier run may have left behind.
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    #[test]
    fn undoing_a_hijack_depends_on_what_is_in_effect() {
        let none: [Vec<String>; 0] = [];
        assert!(!hijack_is_in_effect(&none, "198.18.0.254"));

        let some = [
            vec!["192.168.1.1".to_string()],
            vec!["198.18.0.254".to_string()],
        ];
        assert!(hijack_is_in_effect(&some, "198.18.0.254"));

        // `10.0.0.254` is one of the candidate blocks and a router address. It is
        // not this run's hijack, and treating it as one is what the restore would
        // have to rewrite — see the startup cleanup for the other blocks.
        assert!(!hijack_is_in_effect(
            &[vec!["10.0.0.254".to_string()]],
            "198.18.0.254"
        ));
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
        assert!(remove_resolver_files(&dir, |contents| {
            is_our_resolver_file(contents)
                && resolver_nameserver(contents).is_some_and(|server| server == "10.0.0.254")
        })
        .is_empty());
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

    /// A hijack that failed after it had already changed the machine is taken
    /// back — with the hijack that was installed, because that is the only
    /// thing that knows where to take it back from.
    ///
    /// The failure is what carries it. The global paths change the machine
    /// before they read it back, so "it failed" does not mean "nothing
    /// happened", and a caller that had nothing but the error had nothing to
    /// undo: the machine kept a static DNS pointing at a TUN address that
    /// never comes up.
    #[test]
    fn a_hijack_that_failed_after_it_changed_the_machine_is_undone() {
        let failure = DnsHijackFailure {
            hijack: DnsHijack::Global,
            error: anyhow::anyhow!("the read-back did not show the TUN address"),
        };

        let mut undone: Option<DnsHijack> = None;
        undo_failed_hijack(&failure, |hijack| {
            undone = Some(hijack);
            Ok(())
        })
        .expect("undoing a hijack that was installed cannot fail here");

        assert_eq!(
            undone,
            Some(DnsHijack::Global),
            "the restore has to be called with the hijack that was installed"
        );
    }

    /// A scoped hijack that failed is taken back the same way: the rules or
    /// the resolver files it wrote are still there, and only the scoped
    /// restore knows how to remove them.
    #[test]
    fn a_scoped_hijack_that_failed_is_undone_as_a_scoped_one() {
        let failure = DnsHijackFailure {
            hijack: DnsHijack::Scoped,
            error: anyhow::anyhow!("the rules could not be removed"),
        };

        let mut undone: Option<DnsHijack> = None;
        undo_failed_hijack(&failure, |hijack| {
            undone = Some(hijack);
            Ok(())
        })
        .expect("undoing a hijack that was installed cannot fail here");

        assert_eq!(undone, Some(DnsHijack::Scoped));
    }

    /// A hijack that failed before it changed anything is not undone: there is
    /// nothing to take back, and the restore is not free — it rewrites the
    /// machine's DNS configuration.
    #[test]
    fn a_hijack_that_failed_before_it_changed_anything_is_not_undone() {
        let failure = DnsHijackFailure {
            hijack: DnsHijack::None,
            error: anyhow::anyhow!("the configured domains cannot each be named"),
        };

        let mut called = false;
        undo_failed_hijack(&failure, |_hijack| {
            called = true;
            Ok(())
        })
        .expect("there is nothing to undo, so nothing can fail");

        assert!(
            !called,
            "nothing was installed, so there is nothing to take back"
        );
    }

    /// The liveness guard the Windows cleanup was missing: an adapter whose
    /// TUN address a tunnel still holds is not a leftover, and resetting it
    /// would leave the tunnel up and the machine's DNS somewhere else — the
    /// proxied domains would resolve at their real addresses and the traffic
    /// would leave in the clear.
    #[test]
    fn an_adapter_whose_tun_address_is_still_in_use_is_not_reset() {
        let adapters = vec![AdapterDns {
            index: 7,
            servers: vec!["198.18.0.254".to_string()],
        }];
        let in_use = |address: &str| address == "198.18.0.254";

        assert!(
            stale_adapter_indexes(&adapters, in_use).is_empty(),
            "a live tunnel's DNS is not a stale hijack"
        );
    }

    /// The other half: an address nothing holds is a leftover, and the
    /// adapter carrying it is reset.
    #[test]
    fn an_adapter_whose_tun_address_is_not_in_use_is_reset() {
        let adapters = vec![AdapterDns {
            index: 7,
            servers: vec!["198.18.0.254".to_string()],
        }];
        let in_use = |_: &str| false;

        assert_eq!(stale_adapter_indexes(&adapters, in_use), vec![7]);
    }

    /// Only the addresses of a hijack are ever reset: an adapter carrying the
    /// machine's own DNS is not ours to touch, and the IPv6 marker is a
    /// leftover only while nothing holds `[::1]:53`.
    #[test]
    fn only_the_addresses_of_a_hijack_are_ever_reset() {
        let adapters = vec![
            AdapterDns {
                index: 7,
                servers: vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()],
            },
            AdapterDns {
                index: 8,
                servers: vec![LOCALHOST_V6.to_string()],
            },
        ];

        // Nothing is in use: the first adapter is not ours at all, the second
        // one carries the IPv6 marker of a hijack that is gone.
        let in_use = |_: &str| false;
        assert_eq!(stale_adapter_indexes(&adapters, in_use), vec![8]);

        // With the local resolver still listening on [::1]:53, the marker
        // belongs to a live tunnel and the adapter is left alone.
        let in_use = |address: &str| address == LOCALHOST_V6;
        assert!(stale_adapter_indexes(&adapters, in_use).is_empty());
    }

    /// What the Windows cleanup reads off the machine: the adapters and their
    /// DNS servers, the rules, and the addresses a tunnel still holds.
    ///
    /// The same adapter is reported once per address family, and the decision
    /// is about the adapter rather than the family — so the two rows have to
    /// end up as one.
    #[cfg(any(windows, test))]
    #[test]
    fn the_cleanup_dump_reads_as_the_adapters_the_rules_and_what_is_still_in_use() {
        let dump = "\
adapter|12|198.18.0.254\n\
adapter|12|::1\n\
adapter|15|192.168.1.1\n\
nrpt|{rule}|example.com,.example.com|198.18.0.254\n\
live|198.18.0.254\n";
        let state = parse_cleanup_state(dump);

        assert_eq!(state.adapters.len(), 2);
        assert_eq!(state.adapters[0].index, 12);
        assert_eq!(
            state.adapters[0].servers,
            vec!["198.18.0.254".to_string(), "::1".to_string()]
        );
        assert_eq!(state.adapters[1].index, 15);
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].name, "{rule}");
        assert_eq!(
            state.rules[0].namespaces,
            vec!["example.com".to_string(), ".example.com".to_string()]
        );
        assert_eq!(state.rules[0].servers, vec!["198.18.0.254".to_string()]);
        assert_eq!(state.in_use, vec!["198.18.0.254".to_string()]);
    }

    /// The guard, from what the machine says to what is done with it: an
    /// adapter whose TUN address a tunnel still holds is left alone, and one
    /// whose address nothing holds is reset.
    #[cfg(any(windows, test))]
    #[test]
    fn the_cleanup_leaves_the_adapters_of_a_live_tunnel_alone() {
        let live = parse_cleanup_state(
            "adapter|12|198.18.0.254\nadapter|15|198.18.0.254\nlive|198.18.0.254\n",
        );
        let held = |address: &str| live.in_use.iter().any(|live| live == address);
        assert!(
            stale_adapter_indexes(&live.adapters, held).is_empty(),
            "a tunnel that is up keeps its DNS"
        );

        // The same machine without the listener: both adapters are leftovers.
        let stale = parse_cleanup_state("adapter|12|198.18.0.254\nadapter|15|198.18.0.254\n");
        let nothing_held = |_: &str| false;
        assert_eq!(
            stale_adapter_indexes(&stale.adapters, nothing_held),
            vec![12, 15]
        );
    }

    /// A rule that routes to an address a live tunnel holds is not stale:
    /// removing it would take a live tunnel's names out of the proxy.
    #[cfg(any(windows, test))]
    #[test]
    fn an_nrpt_rule_of_a_live_tunnel_is_not_removed() {
        let rules = vec![
            CleanupRule {
                name: "live".to_string(),
                namespaces: vec!["example.com".to_string()],
                servers: vec!["198.18.0.254".to_string()],
            },
            CleanupRule {
                name: "stale".to_string(),
                namespaces: vec!["foo.io".to_string()],
                servers: vec!["198.19.0.254".to_string()],
            },
        ];

        let in_use = |address: &str| address == "198.18.0.254";
        let stale = stale_nrpt_rules(&rules, in_use);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].name, "stale");
    }

    /// The two scripts the Windows cleanup runs: one that reports what is on
    /// the machine, one that carries the decision out.
    ///
    /// Pinned, because a broken escape reaches that machine as a PowerShell
    /// syntax error, and there is no other way to see it coming from here.
    /// The liveness question is in the first one: the tunnel's DNS server, on
    /// the TUN address and on the IPv6 loopback.
    #[cfg(any(windows, test))]
    #[test]
    fn the_cleanup_scripts_are_pinned() {
        let collect = cleanup_collect_script();
        // The liveness question: the socket that holds the address — the
        // tunnel's DNS server, on the TUN address and on the IPv6 loopback.
        assert!(collect.contains("Get-NetUDPEndpoint -LocalAddress $a -LocalPort 53"));
        assert!(collect.contains("$watched = @('198.18.0.254'"));
        assert!(collect.contains(",'::1');"));
        assert!(collect.contains("'adapter|' + $_.InterfaceIndex"));
        assert!(collect.contains("'nrpt|' + $_.Name"));

        let apply = cleanup_apply_script(&[12], &["{rule}".to_string()]);
        assert!(apply.contains("$reset = @(12)"));
        assert!(
            apply.contains("Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses")
        );
        assert!(apply.contains("$rules = @('{rule}')"));
        assert!(apply.contains("Remove-DnsClientNrptRule -Name $r"));
    }
}
