//! The interface setup the Unix half shares: the walk over the candidate blocks and the
//! check for a block somebody else has already claimed.

use super::*;

#[cfg(target_os = "linux")]
use super::linux::{
    assign_interface_address, foreign_interface_addresses, foreign_route_prefixes,
    remove_interface_address,
};
#[cfg(target_os = "macos")]
use super::macos::{
    assign_interface_address, foreign_interface_addresses, foreign_route_prefixes,
    remove_interface_address,
};

// ==========================================================================
// Unix — same candidate-block policy as Windows (see configure_interface_windows):
// the address assignment is platform-specific (`ip` vs `ifconfig`), but the loop
// that walks TUN_BASE_CANDIDATES and keeps the first bindable block is shared.
// ==========================================================================

/// Walks [`TUN_BASE_CANDIDATES`] and configures the first block the host actually accepts.
///
/// The historical behaviour assigned a fixed block, which is a liability: when the machine's
/// own LAN uses the same one, the commands succeed but the address is never usable and every
/// connection dies a couple of seconds in. Retrying the same address cannot help, so once a
/// block has been given a fair chance the TUN moves to the next one.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn configure_interface_unix(interface: &str) -> Result<()> {
    // Addresses other interfaces already hold. A candidate block containing one is not ours to
    // take, and bindability probing cannot see it: the address is bindable, it is just spoken
    // for. The classic case is a coexisting fake-IP VPN — Clash/mihomo &co default to a
    // 198.18.0.1/16 fake-IP pool — whose DNS hands out addresses across the range while its own
    // interface only holds a sliver. Our /24 route is more specific than its catch-all routes,
    // so every fake IP it handed out inside our block lands in our TUN with no domain mapping
    // and is dropped, which looks exactly like "the rest of the internet died".
    let foreign = foreign_interface_addresses(interface);
    // Fake-IP tools treat 198.18.0.0/15 as one pool (the RFC 2544 convention) even though the
    // two candidates here are separate /24s: a foreign address anywhere in the /15 disqualifies
    // both, because the tool's DNS may hand out any address in the range.
    let fake_ip_claimed = foreign
        .iter()
        .any(|a| matches!(a.octets(), [198, 18..=19, _, _]));
    // The same question asked of the routing table, which is where a fake-IP tool actually
    // stakes its claim: its own interface holds a /30 while the range it answers for is routed
    // at it, so no address of ours ever lands inside an address of theirs.
    let routes = foreign_route_prefixes(interface);

    for base in TUN_BASE_CANDIDATES {
        if matches!(base.octets(), [198, 18 | 19, 0, 0]) && fake_ip_claimed {
            tracing::warn!(
                "skipping {base}/24: another interface holds an address in 198.18.0.0/15 — \
                 a fake-IP VPN (Clash/mihomo &co) owns that range"
            );
            continue;
        }
        if foreign
            .iter()
            .any(|a| u32::from(*a) & 0xFFFF_FF00 == u32::from(base))
        {
            tracing::warn!("skipping {base}/24: another interface already holds an address in it");
            continue;
        }
        if let Some((network, len)) = route_claiming_block(&routes, base) {
            tracing::warn!(
                "skipping {base}/24: {network}/{len} is already routed to another interface"
            );
            continue;
        }

        let ip = Ipv4Addr::from(u32::from(base) | 0x0000_00FE);

        if let Err(e) = assign_interface_address(interface, &ip) {
            tracing::warn!("could not set {ip} on {interface}: {e}; trying the next block");
            continue;
        }

        if wait_bindable(&ip) {
            set_tun_base(base);
            if base != TUN_BASE_CANDIDATES[0] {
                tracing::warn!(
                    "Moved the TUN to {}: an earlier candidate block was unusable on this host",
                    tun_network()
                );
            }
            tracing::info!(
                "Interface {} configured with {} netmask {}",
                interface,
                ip,
                TUN_NETMASK
            );
            return Ok(());
        }

        tracing::warn!(
            "{ip} never became bindable on {interface}; removing it and trying the next block"
        );
        remove_interface_address(interface, &ip);
    }

    anyhow::bail!(
        "Failed to give interface {} any of the candidate TUN blocks ({:?})",
        interface,
        TUN_BASE_CANDIDATES
    )
}

// ==========================================================================
// Routes installed by other interfaces
//
// The address check above asks "does somebody already hold an address here". A
// fake-IP tool does not have to: it puts a sliver of an address on its own
// interface — a /30 is typical — and routes a range tens of thousands of times
// wider at it, so no interface holds an address in the blocks it answers for.
// What claims the block is the route.
// ==========================================================================

/// A route this wide is not a claim on an address block, it is a way of taking the default
/// route: a VPN installs `0.0.0.0/1` and `128.0.0.0/1` to sit in front of every destination
/// without overwriting the default route itself. Our /24 is more specific than either, so the
/// two coexist — counting those would disqualify every candidate block on such a host.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const CLAIM_PREFIX_FLOOR: u8 = 8;

/// The mask of the leading `len` bits. A zero-length prefix masks everything, which is the
/// default route and therefore no block in particular.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn prefix_mask(len: u8) -> u32 {
    match len {
        0 => 0,
        n if n >= 32 => u32::MAX,
        n => u32::MAX << (32 - n),
    }
}

/// The route that makes `base`/24 unusable, if any: one that overlaps it.
///
/// Overlap is decided on the *shorter* of the two prefixes. A /16 somebody else routes swallows
/// the whole candidate /24 — the fake-IP case, where a tool holds one address of its own and
/// routes a range forty thousand times wider at it. A /32 inside the block claims only its own
/// address, which is still enough: it is an address the block would have to stay silent about.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(super) fn route_claiming_block(
    routes: &[(Ipv4Addr, u8)],
    base: Ipv4Addr,
) -> Option<(Ipv4Addr, u8)> {
    routes.iter().copied().find(|(network, len)| {
        if *len < CLAIM_PREFIX_FLOOR {
            return false;
        }
        let shared = (*len).min(24);
        let mask = prefix_mask(shared);
        (u32::from(*network) & mask) == (u32::from(base) & mask)
    })
}

/// Whether `ip` can be bound within a short grace period — the same test the DNS server has to
/// pass before it starts. Windows needs this window for duplicate address detection; on Unix
/// the address is normally usable immediately, so this is a short safety net only.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_bindable(ip: &Ipv4Addr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if UdpSocket::bind((*ip, 0)).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
