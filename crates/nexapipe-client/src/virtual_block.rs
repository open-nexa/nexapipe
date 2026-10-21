//! The block of addresses the tunnel claims, and the pools inside it.
//!
//! # One address space on both clients
//!
//! The desktop picks its block from a list of candidates and keeps the first the
//! host will let it use, because a TUN block that overlaps the LAN breaks
//! routing in ways that look like "the internet died". Android hard-coded
//! `10.0.1.0/24`, which a great many home routers use — so on those networks
//! the tunnel swallowed the router's own addresses, and the device could not
//! reach the machine that was serving it.
//!
//! Both clients now take the same list and the same rules, and the block that
//! is in use is **one value** rather than a constant compiled into each side.
//! That matters because the two halves have to agree: the Kotlin side configures
//! the VPN's addresses and routes, and the Rust side hands out the per-domain
//! addresses inside the same block. A disagreement is a tunnel that comes up and
//! carries nothing.
//!
//! # Who decides
//!
//! The host, not this module. It cannot know whether a block collides with the
//! network the machine is on, and that is the only question the candidate list
//! exists to answer — so the host walks the list, asks the operating system
//! what it can bind, and says which block it took with [`set`]. This module
//! holds the answer and derives everything else from it.
//!
//! # The addresses inside a block
//!
//! These follow the Android client's layout — the client that configures the
//! platform's VPN and so has to name every address it installs:
//!
//! | Address | What it is |
//! |---|---|
//! | `.1` | the TUN interface |
//! | `.2` | the DNS server the system resolver is pointed at |
//! | `.3` | the legacy virtual proxy address (TCP only; payload sniffing) |
//! | `.16` … `.254` | the per-domain addresses handed out by [`crate::virtual_ip`] |
//!
//! The desktop keeps a layout of its own — the interface at the top of the
//! block, the pool right below it — because its DNS server answers on the
//! interface address itself; see
//! `ui-desktop/src-tauri/src/proxy/tun_proxy.rs`. What the two share is the
//! block: the list of candidates, and the one value that says which of them
//! is in use.
//!
//! The IPv6 half is `fd00:{b0}:{b1}:{b2}::/64`, where `{b0}:{b1}:{b2}` are the
//! three bytes of the IPv4 block: `10.0.1.0/24` gives `fd00:10:0:1::/64`,
//! which is what Android used, and `198.18.0.0/24` gives
//! `fd00:198:18:0::/64`, which is the desktop's block. The two families read
//! as one block, and the v6 pool follows the v4 one for the same reason.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;

/// The candidate blocks, in the order they are tried.
///
/// The head of the list deliberately lives in *reserved* ranges rather than
/// ordinary private address space: the historical default `10.0.0.0/24` is
/// also what a great many home LANs use, and a TUN block overlapping the LAN
/// breaks routing in ways that look like "the internet died". `198.18.0.0/15`
/// (RFC 2544 benchmarking) is never handed out by any router or DHCP server
/// and is the established convention for fake-IP DNS answers — which is exactly
/// what the virtual addresses below are. The old `10.0.0.0` block stays at the
/// tail so configurations saved against it remain valid.
pub const TUN_BASE_CANDIDATES: [Ipv4Addr; 6] = [
    Ipv4Addr::new(198, 18, 0, 0), // RFC 2544 benchmarking — the fake-IP convention
    Ipv4Addr::new(198, 19, 0, 0), // second half of the same /15
    Ipv4Addr::new(100, 100, 0, 0), // RFC 6598 CGNAT shared space — never a LAN subnet
    Ipv4Addr::new(172, 26, 0, 0), // private-space fallback, rarely used by routers
    Ipv4Addr::new(10, 200, 0, 0), // private-space fallback
    Ipv4Addr::new(10, 0, 0, 0),   // legacy default, kept last for old saved configs
];

/// The block in use.
///
/// The first candidate until the host says otherwise, which is the same block
/// the desktop starts from — so a host that never asks still gets a block no
/// router hands out.
static CURRENT: RwLock<Ipv4Addr> = RwLock::new(TUN_BASE_CANDIDATES[0]);

/// The block in use.
pub fn current() -> Ipv4Addr {
    *CURRENT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Sets the block the tunnel claims.
///
/// Anything is accepted: the block is the host's decision, and a host that
/// wants a range of its own is answering a question this module cannot.
///
/// The address is taken as the block's *network* address — the block is a /24,
/// so the address that names it is the one with the low byte clear. A caller
/// that hands over an address inside the block gets the block, not that
/// address.
pub fn set(base: Ipv4Addr) {
    let network = Ipv4Addr::from(u32::from(base) & 0xFFFF_FF00);
    *CURRENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = network;
}

/// The block in use, as a CIDR block.
pub fn network() -> String {
    format!("{}/24", current())
}

/// The DNS server address in the block: `.2`.
///
/// The system resolver is pointed at this one, and it is the address the
/// queries arrive at.
pub fn dns_ip() -> Ipv4Addr {
    offset(current(), 2)
}

/// The legacy virtual proxy address: `.3`.
///
/// The address every proxied domain used to resolve to. Still answered, for
/// TCP only, because an application may hold a stale DNS answer.
pub fn legacy_proxy_ip() -> Ipv4Addr {
    offset(current(), 3)
}

/// The first address handed out of the pool: `.16`.
pub fn pool_first() -> Ipv4Addr {
    offset(current(), 16)
}

/// The last address handed out of the pool: `.254`.
///
/// The top of the block is left alone the same way `.255` is — the interface's
/// own address is at the bottom, and a pool that could hand out the block's
/// broadcast address is asking for confusion.
pub fn pool_last() -> Ipv4Addr {
    offset(current(), 254)
}

/// The TUN interface address: `.1`.
pub fn interface_ip() -> Ipv4Addr {
    offset(current(), 1)
}

/// The IPv6 block: `fd00:{b0}:{b1}:{b2}::/64`.
///
/// A ULA (`fd00::/8`) rather than a global address: it is never routed on the
/// public internet, so a leak of one of these addresses — a DNS answer that
/// escapes the tunnel, a log line — is a dead end.
///
/// The three segments are the *decimal digits* of the IPv4 block's first three
/// bytes, read as hexadecimal — which is what both clients have always done.
/// `10.0.1.0/24` gives `fd00:10:0:1::/64` (Android's historical block) and
/// `198.18.0.0/24` gives `fd00:198:18:0::/64` (the desktop's), so the rule
/// reproduces every block either client used, and the two families read as one
/// block.
pub fn ipv6_block() -> Ipv6Addr {
    let base = current().octets();
    Ipv6Addr::new(
        0xfd00,
        decimal_digits_as_hex(base[0]),
        decimal_digits_as_hex(base[1]),
        decimal_digits_as_hex(base[2]),
        0,
        0,
        0,
        0,
    )
}

/// The TUN interface's IPv6 address: `::1`.
///
/// The IPv4 side gives the interface the first address of the block (`.1`), and
/// this is the same address in the IPv6 half.
pub fn ipv6_interface_ip() -> Ipv6Addr {
    let mut octets = ipv6_block().octets();
    octets[15] = 0x01;
    Ipv6Addr::from(octets)
}

/// A byte's decimal digits, read as a hexadecimal number.
///
/// `10` becomes `0x10` and `198` becomes `0x198` — the digits are the ones
/// the IPv4 address is written with, and they are read as the digits of the
/// IPv6 segment. It reads oddly, and it is deliberate: it is what both
/// clients' hand-written blocks did, so a block this derives is the block
/// those constants described.
fn decimal_digits_as_hex(value: u8) -> u16 {
    u16::from_str_radix(&value.to_string(), 16).unwrap_or(0)
}

/// The first address handed out of the IPv6 pool: `::10`.
///
/// The sixteenth address, mirroring the IPv4 pool's `.16` — written in
/// hexadecimal, as IPv6 notation has it.
pub fn ipv6_pool_first() -> Ipv6Addr {
    let mut octets = ipv6_block().octets();
    octets[15] = 0x10;
    Ipv6Addr::from(octets)
}

/// The last address handed out of the IPv6 pool: `::fffe`.
pub fn ipv6_pool_last() -> Ipv6Addr {
    let mut octets = ipv6_block().octets();
    // `::fffe` is the last sixteen bits, not the last byte: the pool ends
    // two below the top of the /64.
    octets[14] = 0xff;
    octets[15] = 0xfe;
    Ipv6Addr::from(octets)
}

/// The address `n` into the block.
///
/// The block is a /24, so the low byte is the offset and the rest stays put.
fn offset(base: Ipv4Addr, n: u8) -> Ipv4Addr {
    let mut octets = base.octets();
    octets[3] = octets[3].wrapping_add(n);
    Ipv4Addr::from(octets)
}

/// The block and the addresses inside it, as the answer the native side sends:
/// `key=value` pairs joined by `;`.
///
/// The shape of it is a contract between the two halves of the tunnel: Kotlin
/// configures the VPN's addresses and routes from this answer, and the Rust
/// side hands out the per-domain addresses from the same block. A key that
/// means one thing on one side and another on the other is a VPN configured
/// with addresses the tunnel does not use.
pub fn encoded() -> String {
    format!(
        "base={};network={};interface={};dns={};proxy={};ipv6={};ipv6Interface={}",
        current(),
        network(),
        interface_ip(),
        dns_ip(),
        legacy_proxy_ip(),
        ipv6_block(),
        ipv6_interface_ip(),
    )
}

/// The lock every test that reads or writes the block takes.
///
/// The block is process-wide, so a test that changed it would otherwise be
/// read by the next one: a test running while another was halfway through
/// would see a block nobody asked for.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The block, for the duration of a test.
    fn the_block() -> std::sync::MutexGuard<'static, ()> {
        test_lock()
    }

    /// The list is the desktop's, in the same order: a block that a router
    /// hands out is at the tail, and the ones no router hands out are at the
    /// head.
    #[test]
    fn the_candidates_are_the_reserved_ranges_first() {
        let _guard = the_block();
        assert_eq!(TUN_BASE_CANDIDATES[0], Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(TUN_BASE_CANDIDATES[1], Ipv4Addr::new(198, 19, 0, 0));
        assert_eq!(
            *TUN_BASE_CANDIDATES.last().unwrap(),
            Ipv4Addr::new(10, 0, 0, 0),
            "the legacy block stays last"
        );
    }

    /// The block is named by its network address, so an address inside it
    /// names the block rather than itself.
    #[test]
    fn a_block_is_named_by_its_network_address() {
        let _guard = the_block();
        set(Ipv4Addr::new(198, 18, 0, 7));
        assert_eq!(current(), Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(network(), "198.18.0.0/24");
        assert_eq!(dns_ip(), Ipv4Addr::new(198, 18, 0, 2));
    }

    /// Everything inside a block is derived from it, so a block and its pools
    /// can never disagree about which addresses they are.
    #[test]
    fn every_address_is_derived_from_the_block() {
        let _guard = the_block();
        set(Ipv4Addr::new(198, 18, 0, 0));

        assert_eq!(interface_ip(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(dns_ip(), Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(legacy_proxy_ip(), Ipv4Addr::new(198, 18, 0, 3));
        assert_eq!(pool_first(), Ipv4Addr::new(198, 18, 0, 16));
        assert_eq!(pool_last(), Ipv4Addr::new(198, 18, 0, 254));
    }

    /// The IPv6 block follows the IPv4 one, and it reproduces the blocks both
    /// clients used before it was derived: the digits of the IPv4 address, read
    /// as the digits of the IPv6 segment.
    #[test]
    fn the_ipv6_block_follows_the_ipv4_one() {
        let _guard = the_block();
        set(Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(
            ipv6_block(),
            Ipv6Addr::new(0xfd00, 0x0010, 0, 1, 0, 0, 0, 0),
            "Android's historical block"
        );

        set(Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(
            ipv6_block(),
            Ipv6Addr::new(0xfd00, 0x0198, 0x0018, 0, 0, 0, 0, 0),
            "the desktop's historical block"
        );
    }

    /// Every candidate block has to produce a block of its own, and none of
    /// them may collide: two of them mapping onto the same ULA would put two
    /// tunnels' addresses in the same space.
    #[test]
    fn every_candidate_has_a_block_of_its_own() {
        let _guard = the_block();
        let mut seen = std::collections::HashSet::new();
        for base in TUN_BASE_CANDIDATES {
            set(base);
            assert!(
                seen.insert(ipv6_block()),
                "{} maps onto a block another candidate already used",
                base
            );
        }
    }

    /// The IPv6 pool mirrors the IPv4 one: `::10` is the sixteenth address,
    /// written in hexadecimal.
    #[test]
    fn the_ipv6_pool_mirrors_the_ipv4_one() {
        let _guard = the_block();
        set(Ipv4Addr::new(10, 0, 1, 0));

        assert_eq!(
            ipv6_pool_first(),
            Ipv6Addr::new(0xfd00, 0x0010, 0, 1, 0, 0, 0, 0x10)
        );
        assert_eq!(
            ipv6_pool_last(),
            Ipv6Addr::new(0xfd00, 0x0010, 0, 1, 0, 0, 0, 0xfffe)
        );
        assert_eq!(
            ipv6_interface_ip(),
            Ipv6Addr::new(0xfd00, 0x0010, 0, 1, 0, 0, 0, 0x01)
        );
    }

    /// The answer the native side sends is a contract with the Kotlin side: the
    /// same keys, in the same order, spelled the same way.
    #[test]
    fn the_encoded_answer_names_every_address() {
        let _guard = the_block();
        set(Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(
            encoded(),
            "base=198.18.0.0;network=198.18.0.0/24;interface=198.18.0.1;dns=198.18.0.2;\
             proxy=198.18.0.3;ipv6=fd00:198:18::;ipv6Interface=fd00:198:18::1"
        );
    }

    /// The pools have to be inside the block: an address outside it would be
    /// answered by the network rather than by the tunnel.
    #[test]
    fn the_pools_are_inside_the_block() {
        let _guard = the_block();
        for base in TUN_BASE_CANDIDATES {
            set(base);
            assert_eq!(pool_first().octets()[..3], base.octets()[..3]);
            assert_eq!(pool_last().octets()[..3], base.octets()[..3]);
        }
    }
}
