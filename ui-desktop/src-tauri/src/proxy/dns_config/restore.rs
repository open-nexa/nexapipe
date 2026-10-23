//! The restore path: taking the machine's DNS back.
//!
//! How much of the machine a restore may touch is the caller's decision,
//! and whether the hijack is still in effect is what the restore asks
//! before it writes anything.

use super::*;

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
pub(super) fn hijack_is_in_effect(observed: &[Vec<String>], dns_ip: &str) -> bool {
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
