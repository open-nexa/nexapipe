//! The install path: pointing the machine's DNS at the TUN resolver.
//!
//! The strategy decides what is installed and the platform code carries it
//! out; what is here is the decision itself and the two ways it can fail
//! — before anything was installed, and after.

use super::*;

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

/// Whether `routed` is every one of `domains`, and not merely one of them: a
/// domain left out keeps resolving outside the proxy while the caller is told
/// the hijack is scoped, which is the one thing the fallback is for.
#[cfg(any(target_os = "linux", windows, test))]
pub(super) fn routes_every_domain(routed: &[String], domains: &[String]) -> bool {
    domains.iter().all(|domain| routed.contains(domain))
}
