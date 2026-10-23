//! The liveness decision: is the address a hijack points at still in use?
//!
//! It is what separates a hijack that outlived its tunnel from one that a
//! live tunnel still holds — and the second one must never be cleaned up.

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

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::net::{Ipv4Addr, UdpSocket};

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
pub(super) fn address_is_held(address: &str) -> bool {
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
