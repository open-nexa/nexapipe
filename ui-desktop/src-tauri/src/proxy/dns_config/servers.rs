//! The resolvers the machine is asked against.
//!
//! Two sources: what the machine resolves against right now, and what an
//! earlier run recorded before it moved the system DNS.

use super::*;

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
