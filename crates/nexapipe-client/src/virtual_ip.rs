//! Virtual IP ↔ domain mapping for the TUN device.
//!
//! # Why a mapping and not the payload
//!
//! The tunnel used to send every connection to one virtual proxy address and
//! recover the destination from the payload: SNI out of a TLS `ClientHello`,
//! `Host` out of an HTTP request. That only works while the first bytes of a
//! connection are one of those two things, and it never worked for UDP at all —
//! a datagram to `10.0.1.3:3478` says nothing about whose traffic it is. A raw
//! TCP protocol (a database wire protocol, MQTT, a game) has no host name in it
//! either. And the port was never on the wire, so every flow looked like 443.
//!
//! So the DNS answers handed to the application carry a distinct address per
//! domain instead:
//!
//! ```text
//! dns.example.com   -> 10.0.1.16
//! turn.example.com  -> 10.0.1.17
//! ```
//!
//! The address is inside the TUN route (`10.0.1.0/24`), so the packets come
//! back to us, and the reverse lookup answers "which domain" — which is what
//! picks the route on the server. The port is then carried by the flow's own
//! packet rather than guessed.
//!
//! # The address range
//!
//! `.16` … `.254`. The addresses below `.16` belong to the Kotlin side of the
//! VPN: `.1` is the TUN interface, `.2` the DNS server the system resolver
//! points at, `.3` the legacy virtual proxy address. Every address handed out
//! here stays inside the single route the VPN installs, so nothing has to be
//! renegotiated with the platform when a domain is resolved.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// First address handed out.
const VIRTUAL_IP_FIRST: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 16);

/// Last address handed out — the top of `10.0.1.0/24`.
const VIRTUAL_IP_LAST: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 254);

/// Size of the address pool (`.16` … `.254` inclusive).
pub const VIRTUAL_IP_COUNT: usize = 239;

/// Which domain an address belongs to, and back again.
///
/// Both directions are kept because both are needed: the forward one so a
/// domain keeps the address it already handed out (the application may hold a
/// connection on it), the reverse one because that is the only thing a packet
/// carries.
#[derive(Debug)]
pub struct IpMapping {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// The direction the packet path needs.
    ip_to_domain: HashMap<u32, String>,
    /// The direction that keeps a domain's address stable across queries.
    domain_to_ip: HashMap<String, u32>,
    /// When each address was last asked for, on a clock that only ever moves
    /// forward. Every flow that reaches an address goes through
    /// [`IpMapping::lookup_domain`], so "not asked for in a long time" is the
    /// closest thing this mapping has to "nothing is using it".
    used_at: HashMap<u32, u64>,
    /// The clock behind [`Self::used_at`].
    clock: u64,
    /// Next address to hand out; wraps around the pool.
    next: u32,
    /// First address of the pool (wrap-around lower bound).
    first: u32,
    /// Last address of the pool (wrap-around upper bound).
    last: u32,
}

impl Inner {
    /// Number of addresses in the pool, both bounds included.
    fn pool_len(&self) -> usize {
        (self.last - self.first + 1) as usize
    }

    /// Records that `ip` is being used right now.
    fn touch(&mut self, ip: u32) {
        self.clock += 1;
        self.used_at.insert(ip, self.clock);
    }

    /// The address that has been quiet for the longest.
    ///
    /// Only asked for when the pool is full, which is a few hundred addresses
    /// at most, so the scan is cheaper than keeping the addresses sorted.
    fn quietest_address(&self) -> u32 {
        self.ip_to_domain
            .keys()
            .copied()
            .min_by_key(|ip| self.used_at.get(ip).copied().unwrap_or(0))
            .unwrap_or(self.first)
    }
}

impl Default for IpMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl IpMapping {
    /// The Android layout: `10.0.1.16` … `10.0.1.254` (see the module docs).
    pub fn new() -> Self {
        Self::with_range(VIRTUAL_IP_FIRST, VIRTUAL_IP_LAST)
    }

    /// A pool between `first` and `last` (inclusive).
    ///
    /// The desktop TUN lives on a block that is only known once the interface is
    /// up (`…254` is the interface/DNS address there), so it builds its pool from
    /// that block — `…2` … `…253` — instead of the Android fixed one.
    pub fn with_range(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        Self {
            inner: Mutex::new(Inner {
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
                used_at: HashMap::new(),
                clock: 0,
                next: u32::from(first),
                first: u32::from(first),
                last: u32::from(last),
            }),
        }
    }

    /// The address `domain` resolves to, allocating one on first use.
    ///
    /// A domain that already has an address keeps it: the application may be
    /// holding a connection open against it, and moving the address would break
    /// that connection's replies.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let key = normalise(domain);
        let mut inner = self.locked();

        if let Some(&ip) = inner.domain_to_ip.get(&key) {
            inner.touch(ip);
            return Ipv4Addr::from(ip);
        }

        // Before the pool is full the cursor always points at a free address,
        // because it only ever moves forward. Once it is full, take the
        // quietest address rather than whatever the cursor happens to have
        // reached: evicting a name that still has flows on the address is what
        // makes those flows' packets answer to the new name — traffic from one
        // domain arriving on another's route.
        let ip = if inner.ip_to_domain.len() < inner.pool_len() {
            let ip = inner.next;
            inner.next = if ip >= inner.last {
                inner.first
            } else {
                ip + 1
            };
            ip
        } else {
            inner.quietest_address()
        };

        if let Some(previous) = inner.ip_to_domain.insert(ip, key.clone()) {
            inner.domain_to_ip.remove(&previous);
        }
        inner.domain_to_ip.insert(key, ip);
        inner.touch(ip);

        Ipv4Addr::from(ip)
    }

    /// The domain an address was handed out for, or `None` for an address this
    /// mapping never issued (which includes `.1`/`.2`/`.3`, the fixed ones).
    ///
    /// Also what marks the address as still in use: every flow has to look its
    /// destination up here, so an address that keeps being asked for is not one
    /// to hand to somebody else.
    pub fn lookup_domain(&self, ip: &Ipv4Addr) -> Option<String> {
        let mut inner = self.locked();
        let address = u32::from(*ip);
        let domain = inner.ip_to_domain.get(&address).cloned();
        if domain.is_some() {
            inner.touch(address);
        }
        domain
    }

    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.locked().domain_to_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock still holds a consistent table, so recovering from one is
    /// better than taking the whole tunnel down: every critical section here is
    /// a handful of `HashMap` calls and nothing that can panic in between, so
    /// there is no half-applied update for the poison flag to protect us from.
    fn locked(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Fold a name to the form both maps are keyed on.
///
/// DNS names are case-insensitive and a fully qualified name may carry a
/// trailing dot; `Example.COM.` and `example.com` are the same name and must not
/// get two addresses.
fn normalise(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_same_name_always_gets_the_same_address() {
        let mapping = IpMapping::new();
        let first = mapping.allocate("dns.example.com");
        assert_eq!(mapping.allocate("dns.example.com"), first);
        // Case and the trailing dot are spelling, not identity.
        assert_eq!(mapping.allocate("DNS.Example.com."), first);
        assert_eq!(mapping.len(), 1);
    }

    #[test]
    fn different_names_get_different_addresses() {
        let mapping = IpMapping::new();
        let a = mapping.allocate("a.test");
        let b = mapping.allocate("b.test");
        assert_ne!(a, b);
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn the_reverse_lookup_is_the_inverse_of_allocate() {
        let mapping = IpMapping::new();
        for name in ["a.test", "b.test", "c.test"] {
            let ip = mapping.allocate(name);
            assert_eq!(mapping.lookup_domain(&ip).as_deref(), Some(name));
        }
    }

    #[test]
    fn an_address_we_never_handed_out_maps_to_nothing() {
        let mapping = IpMapping::new();
        mapping.allocate("a.test");
        // The three fixed addresses the Kotlin side owns, plus a free slot.
        for ip in [
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 2),
            Ipv4Addr::new(10, 0, 1, 3),
            Ipv4Addr::new(10, 0, 1, 200),
            Ipv4Addr::new(8, 8, 8, 8),
        ] {
            assert_eq!(mapping.lookup_domain(&ip), None, "{ip}");
        }
    }

    #[test]
    fn every_address_stays_inside_the_tun_route() {
        // The VPN installs exactly one route (10.0.1.0/24). An address outside
        // it would be sent to the physical network instead of to us, so the
        // whole pool has to be inside it.
        let mapping = IpMapping::new();
        let mut seen = HashSet::new();
        for i in 0..VIRTUAL_IP_COUNT {
            let ip = mapping.allocate(&format!("host{i}.test"));
            let octets = ip.octets();
            assert_eq!(&octets[..3], &[10, 0, 1], "{ip} is outside 10.0.1.0/24");
            assert!(
                (16..=254).contains(&octets[3]),
                "{ip} does not belong to the pool"
            );
            assert!(seen.insert(ip), "{ip} was handed out twice");
        }
        assert_eq!(seen.len(), VIRTUAL_IP_COUNT);
    }

    #[test]
    fn a_custom_pool_stays_inside_its_own_bounds() {
        // The desktop layout: …2 … …253 inside whatever block the TUN got.
        let first = Ipv4Addr::new(10, 44, 0, 2);
        let last = Ipv4Addr::new(10, 44, 0, 253);
        let mapping = IpMapping::with_range(first, last);

        let a = mapping.allocate("a.test");
        let b = mapping.allocate("b.test");
        assert_eq!(a, first);
        assert_eq!(b, Ipv4Addr::new(10, 44, 0, 3));

        // The wrap-around respects the custom bounds, not the Android ones:
        // the pool holds 252 addresses, so filling the remaining 250 brings the
        // cursor back to the first one.
        for i in 0..250 {
            mapping.allocate(&format!("host{i}.test"));
        }
        assert_eq!(mapping.allocate("late.test"), first);
    }

    /// The reason recycling looks at last use rather than the cursor: the
    /// address the cursor reaches may still be carrying traffic, and its flows
    /// would then be answered as the domain that took it over.
    #[test]
    fn recycling_takes_the_address_nothing_has_used_lately() {
        let mapping =
            IpMapping::with_range(Ipv4Addr::new(10, 0, 1, 16), Ipv4Addr::new(10, 0, 1, 17));
        let busy = mapping.allocate("busy.test");
        let quiet = mapping.allocate("quiet.test");

        // `busy.test` keeps opening flows; `quiet.test` resolved once and has
        // not been heard from since.
        for _ in 0..3 {
            assert_eq!(mapping.lookup_domain(&busy).as_deref(), Some("busy.test"));
        }

        let third = mapping.allocate("third.test");
        assert_eq!(third, quiet, "the quiet address is the one recycled");
        assert_eq!(mapping.lookup_domain(&busy).as_deref(), Some("busy.test"));
    }

    #[test]
    fn running_out_of_addresses_recycles_instead_of_breaking_the_lookup() {
        let mapping = IpMapping::new();
        let first = mapping.allocate("first.test");
        // Fill the rest of the pool, so the cursor is now back at the start.
        for i in 0..VIRTUAL_IP_COUNT - 1 {
            mapping.allocate(&format!("host{i}.test"));
        }
        assert_eq!(mapping.len(), VIRTUAL_IP_COUNT);

        let recycled = mapping.allocate("late.test");
        assert_eq!(recycled, first, "the pool should wrap around");

        // The address now belongs to exactly one name. `first.test` was evicted
        // rather than left pointing at an address it no longer owns.
        assert_eq!(
            mapping.lookup_domain(&recycled).as_deref(),
            Some("late.test")
        );
        assert_eq!(mapping.len(), VIRTUAL_IP_COUNT);
        assert_ne!(mapping.allocate("first.test"), recycled);
    }
}
