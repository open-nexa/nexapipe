//! Virtual IP ↔ domain mapping for the TUN device.
//!
//! # Why a mapping and not the payload
//!
//! The tunnel used to send every connection to one virtual proxy address and
//! recover the destination from the payload: SNI out of a TLS `ClientHello`,
//! `Host` out of an HTTP request. That only works while the first bytes of a
//! connection are one of those two things, and it never worked for UDP at all —
//! a datagram to the legacy proxy address says nothing about whose traffic it
//! is. A raw TCP protocol (a database wire protocol, MQTT, a game) has no host
//! name in it either. And the port was never on the wire, so every flow looked
//! like 443.
//!
//! So the DNS answers handed to the application carry a distinct address per
//! domain instead:
//!
//! ```text
//! dns.example.com   -> 198.18.0.16          (A)
//! dns.example.com   -> fd00:198:18::10      (AAAA)
//! ```
//!
//! The address is inside the TUN route — the block the tunnel claims, and the
//! IPv6 half that follows it — so the packets come back to us, and the reverse
//! lookup answers "which domain" — which is what picks the route on the
//! server. The port is then carried by the flow's own packet rather than
//! guessed.
//!
//! # The address range
//!
//! IPv4: `.16` … `.254` of the block in use. The addresses below `.16` belong
//! to the Kotlin side of the VPN: `.1` is the TUN interface, `.2` the DNS server
//! the system resolver points at, `.3` the legacy virtual proxy address. The
//! block itself is the host's decision — see [`crate::virtual_block`].
//!
//! IPv6: `::10` … `::fffe` in the block the TUN holds, with `::1` left to the
//! interface for the same reason. `::10` is the sixteenth address, the same one
//! the IPv4 pool starts at — IPv6 notation is hexadecimal, so it is written
//! `10` and not `16`. Both ranges stay inside the routes the VPN
//! installs, so nothing has to be renegotiated with the platform when a domain
//! is resolved.
//!
//! # Two families, two pools
//!
//! A domain needs both an A and an AAAA answer — a resolver that got an empty
//! AAAA falls back to A, but one that got an address will try it — so one
//! domain holds one address per family, and a pool is per family: handing an
//! IPv4 address out of the IPv6 pool (or the other way round) is not possible,
//! and neither is evicting an address of one family to make room in the other.
//!
//! # Recycling
//!
//! The pool is finite, so once it is full an address is handed to a new
//! domain. Which address that is matters: the DNS answer that named it may
//! still be cached, and an answer that changed hands under a cached resolver
//! sends the old domain's next connection to the new domain's route — the
//! tunnel answers it to the new domain.
//!
//! So an address is only taken once the answer that named it has expired —
//! [`ADDRESS_TTL`], the TTL the answers carry — and among the addresses that
//! are free the quietest wins. The two rules are not the same rule, and the
//! difference is the whole point: an idle flow is the *quietest* address there
//! is (nothing arrives on it, so it looks unused), so "take the quietest" is
//! what hands a live connection's address to another domain. The age of the
//! answer is what says whether an address may be taken at all.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

/// First address handed out.
///
/// Derived from the block in use rather than written down: the pool has to be
/// inside the block the tunnel claims, and the block is the host's decision.
/// See [`crate::virtual_block`].
fn virtual_ip_first() -> Ipv4Addr {
    crate::virtual_block::pool_first()
}

/// Last address handed out — the top of the block in use.
fn virtual_ip_last() -> Ipv4Addr {
    crate::virtual_block::pool_last()
}

/// Size of the address pool (`.16` … `.254` inclusive).
pub const VIRTUAL_IP_COUNT: usize = 239;

/// How long an address stays bound to the domain it was handed out for.
///
/// This is the TTL of the DNS answers the TUN hands out (see [`crate::dns`]):
/// a resolver may hold the answer for that long, and the answer is what says
/// "this address is this domain". An address is therefore not handed to
/// another domain before the answer that named it has expired — otherwise the
/// old domain's next connection is opened on the new domain's route.
///
/// The number lives here and the answer's own TTL lives in the DNS module, so
/// a test pins the two together: they have to be the same, or the address may
/// change hands while a resolver still holds the answer that named it.
pub const ADDRESS_TTL: Duration = Duration::from_secs(60);

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
    v4: Pool,
    /// Absent when the TUN has no IPv6 block: on the desktop the address is
    /// configured per platform and may fail, and an AAAA answer we cannot route
    /// is worse than the empty answer that makes the resolver use A.
    v6: Option<Pool>,
}

/// What the pool knows about one address it has handed out.
#[derive(Debug)]
struct Address {
    /// The domain the address was handed out for.
    domain: Arc<str>,
    /// The clock of the last use.
    ///
    /// The quietest address is the one used least recently — which is not the
    /// same as the one no flow is on: an idle flow is the quietest there is.
    used: u64,
    /// When the DNS answer that named this address expires.
    ///
    /// The answer may be cached for that long, and the address belongs to the
    /// domain it names for as long as the answer may be held.
    expires_at: Instant,
}

/// One family's addresses.
///
/// The addresses are held as the integers they are, widened to `u128`: that is
/// the one width both families fit in, and it keeps the cursor, the wrap-around
/// and the eviction scan in one place rather than written twice.
#[derive(Debug)]
struct Pool {
    /// The direction the packet path needs: the domain an address was handed
    /// out for, when it was last used, and when the answer that named it
    /// expires.
    ///
    /// **One map, not two.** The clock used to live in a map of its own, and
    /// the eviction scan then had to look every address up in it — a hash
    /// lookup per address, for a scan that runs on every allocation once the
    /// pool is full. With the clock beside the name, the scan is a walk over
    /// values that are already in hand.
    ip_to_domain: HashMap<u128, Address>,
    /// The direction that keeps a domain's address stable across queries.
    domain_to_ip: HashMap<Arc<str>, u128>,
    /// The clock behind the "last used" in [`Self::ip_to_domain`]. Per pool: it
    /// only ever orders addresses against each other, and those are always in
    /// the same pool.
    clock: u64,
    /// Next address to hand out; wraps around the pool.
    next: u128,
    /// First address of the pool (wrap-around lower bound).
    first: u128,
    /// Last address of the pool (wrap-around upper bound).
    last: u128,
}

impl Pool {
    fn new(first: u128, last: u128) -> Self {
        Self {
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
            clock: 0,
            next: first,
            first,
            last,
        }
    }

    /// Number of addresses in the pool, both bounds included.
    fn pool_len(&self) -> u128 {
        self.last.saturating_sub(self.first) + 1
    }

    /// Records that `ip` is being used right now.
    fn touch(&mut self, ip: u128) {
        self.clock += 1;
        if let Some(address) = self.ip_to_domain.get_mut(&ip) {
            address.used = self.clock;
        }
    }

    /// Records that `ip` was handed out in a DNS answer just now.
    ///
    /// The answer is what the application — and every resolver between it and
    /// us — holds: it says "this address is this domain". For as long as it
    /// may be cached, the address belongs to the domain it names.
    fn answer(&mut self, ip: u128, now: Instant) {
        if let Some(address) = self.ip_to_domain.get_mut(&ip) {
            address.expires_at = now + ADDRESS_TTL;
        }
    }

    /// The address that may be handed to a new domain.
    ///
    /// An address whose answer has not expired yet is not a candidate at all:
    /// a resolver may still be holding that answer, and the old domain's next
    /// connection would then be opened on the new domain's route.
    ///
    /// Among the addresses that are free, the quietest wins — the one whose
    /// flows have been the least busy. The address breaks a tie, so the same
    /// pool always recycles the same one.
    ///
    /// When no answer has expired — the pool filled inside one TTL — the
    /// quietest address is taken anyway: the pool has to serve the name, and
    /// that is the address with the least traffic on it.
    fn recyclable_address(&self, now: Instant) -> u128 {
        let mut quietest: Option<(u64, u128)> = None;
        let mut free: Option<(u64, u128)> = None;

        for (ip, address) in &self.ip_to_domain {
            if quietest.is_none_or(|(used, held)| (address.used, *ip) < (used, held)) {
                quietest = Some((address.used, *ip));
            }
            if address.expires_at > now {
                continue;
            }
            if free.is_none_or(|(used, held)| (address.used, *ip) < (used, held)) {
                free = Some((address.used, *ip));
            }
        }

        free.or(quietest).map(|(_, ip)| ip).unwrap_or(self.first)
    }

    /// The address for `domain`, allocating one on first use.
    fn alloc(&mut self, domain: &str) -> u128 {
        let key = crate::domains::fold_domain(domain);
        let now = Instant::now();

        // A domain that already has an address keeps it: the application may be
        // holding a connection open against it, and moving the address would
        // break that connection's replies.
        if let Some(&ip) = self.domain_to_ip.get(key.as_str()) {
            self.touch(ip);
            // The answer is being handed out again, so the hold starts again.
            self.answer(ip, now);
            return ip;
        }

        // Before the pool is full the cursor always points at a free address,
        // because it only ever moves forward. Once it is full, take an address
        // that may be taken — one whose answer has expired. Evicting a name
        // that still has flows on the address is what makes those flows'
        // packets answer to the new name — traffic from one domain arriving
        // on another's route.
        let ip = if (self.ip_to_domain.len() as u128) < self.pool_len() {
            let ip = self.next;
            self.next = if ip >= self.last { self.first } else { ip + 1 };
            ip
        } else {
            self.recyclable_address(now)
        };

        // The name is shared rather than copied: a lookup hands out a reference
        // to it, and the reference count is what the copy used to be.
        let key: Arc<str> = Arc::from(key.as_str());
        if let Some(previous) = self.ip_to_domain.insert(
            ip,
            Address {
                domain: key.clone(),
                used: 0,
                expires_at: now + ADDRESS_TTL,
            },
        ) {
            self.domain_to_ip.remove(&previous.domain);
        }
        self.domain_to_ip.insert(key, ip);
        self.touch(ip);

        ip
    }

    /// The domain `ip` was handed out for, or `None` for an address this pool
    /// never issued.
    fn lookup(&mut self, ip: u128) -> Option<Arc<str>> {
        let address = self.ip_to_domain.get_mut(&ip)?;
        self.clock += 1;
        address.used = self.clock;
        Some(address.domain.clone())
    }

    fn len(&self) -> usize {
        self.domain_to_ip.len()
    }
}

impl Default for IpMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl IpMapping {
    /// The pool of the block in use: `.16` … `.254` (see the module docs),
    /// with no IPv6 pool until one is added by [`Self::with_ipv6`].
    pub fn new() -> Self {
        Self::with_range(virtual_ip_first(), virtual_ip_last())
    }

    /// A pool between `first` and `last` (inclusive).
    ///
    /// The desktop TUN lives on a block that is only known once the interface is
    /// up (`…254` is the interface/DNS address there), so it builds its pool from
    /// that block — `…2` … `…253` — instead of the Android fixed one.
    pub fn with_range(first: Ipv4Addr, last: Ipv4Addr) -> Self {
        Self {
            inner: Mutex::new(Inner {
                v4: Pool::new(u32::from(first) as u128, u32::from(last) as u128),
                v6: None,
            }),
        }
    }

    /// Adds an IPv6 pool between `first` and `last` (inclusive).
    ///
    /// Without one, [`Self::allocate_v6`] answers `None` and the caller answers
    /// the AAAA query with an empty response, which is what the resolver needs
    /// in order to fall back to A.
    pub fn with_ipv6(mut self, first: Ipv6Addr, last: Ipv6Addr) -> Self {
        self.inner.get_mut().unwrap_or_else(|p| p.into_inner()).v6 =
            Some(Pool::new(u128::from(first), u128::from(last)));
        self
    }

    /// Whether an IPv6 pool exists — i.e. whether AAAA can be answered at all.
    pub fn has_ipv6(&self) -> bool {
        self.locked().v6.is_some()
    }

    /// The IPv4 address `domain` resolves to, allocating one on first use.
    ///
    /// A domain that already has an address keeps it: the application may be
    /// holding a connection open against it, and moving the address would break
    /// that connection's replies.
    ///
    /// The answer this address comes with may be cached for [`ADDRESS_TTL`],
    /// and the address is not handed to another domain before it expires.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        Ipv4Addr::from(self.locked().v4.alloc(domain) as u32)
    }

    /// The IPv6 address `domain` resolves to, or `None` when this mapping has no
    /// IPv6 pool to hand one out from.
    pub fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        let mut inner = self.locked();
        let pool = inner.v6.as_mut()?;
        Some(Ipv6Addr::from(pool.alloc(domain)))
    }

    /// The domain an IPv4 address was handed out for, or `None` for an address
    /// this mapping never issued (which includes `.1`/`.2`/`.3`, the fixed
    /// ones).
    ///
    /// Also what marks the address as busy: every flow has to look its
    /// destination up here, so an address that keeps being asked for is not
    /// one to hand to somebody else. That is the traffic signal, though, and
    /// traffic is not what says whether the address may be handed out — an
    /// idle flow looks idle. That is the answer's expiry
    /// ([`ADDRESS_TTL`]), and it is what the recycling follows.
    ///
    /// **The name is shared, not copied.** A lookup happens for every datagram
    /// a flow sends, and a copy of the name is a heap allocation each time.
    /// The [`Arc`] is what the mapping hands out instead: the name is written
    /// once, and a lookup is a reference count.
    pub fn lookup_domain(&self, ip: &Ipv4Addr) -> Option<Arc<str>> {
        self.locked().v4.lookup(u32::from(*ip) as u128)
    }

    /// The IPv6 twin of [`Self::lookup_domain`].
    pub fn lookup_domain_v6(&self, ip: &Ipv6Addr) -> Option<Arc<str>> {
        let mut inner = self.locked();
        let pool = inner.v6.as_mut()?;
        pool.lookup(u128::from(*ip))
    }

    /// Number of live mappings, both families counted.
    pub fn len(&self) -> usize {
        let inner = self.locked();
        inner.v4.len() + inner.v6.as_ref().map_or(0, Pool::len)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;

    impl IpMapping {
        /// Makes the answer that named `ip` look as if it had expired.
        ///
        /// The rule the recycling follows is a wall-clock one, and a test
        /// cannot wait a minute to watch it happen: the answer is moved back
        /// rather than the clock moved forward.
        fn expire(&self, ip: Ipv4Addr) {
            let mut inner = self.locked();
            let address = inner
                .v4
                .ip_to_domain
                .get_mut(&(u32::from(ip) as u128))
                .expect("the address was handed out");
            // A monotonic clock that cannot go back a second is a clock that
            // started less than a second ago: the answer is then already in
            // the past, which is what the test wanted anyway.
            address.expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    /// A DNS question for `name`, as it goes on the wire.
    fn question_for(name: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: recursion desired
        packet.extend_from_slice(&1u16.to_be_bytes()); // one question
        packet.extend_from_slice(&0u16.to_be_bytes()); // no answers
        packet.extend_from_slice(&0u16.to_be_bytes()); // no authority records
        packet.extend_from_slice(&0u16.to_be_bytes()); // no additional records
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // the name ends here
        packet.extend_from_slice(&crate::dns::DNS_TYPE_A.to_be_bytes());
        packet.extend_from_slice(&crate::dns::DNS_CLASS_IN.to_be_bytes());
        packet
    }

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

    /// The name is shared, not copied.
    ///
    /// A lookup happens for every datagram a flow sends, so a copy of the name
    /// is a heap allocation each time. What the mapping hands out instead is a
    /// reference to the one name it wrote — and this is what says so: two
    /// lookups of the same address are the same name, not two names that
    /// happen to be equal.
    #[test]
    fn a_name_is_shared_rather_than_copied() {
        let mapping = IpMapping::new();
        let ip = mapping.allocate("shared.test");

        let first = mapping.lookup_domain(&ip).expect("the address is ours");
        let second = mapping.lookup_domain(&ip).expect("the address is ours");

        assert!(
            Arc::ptr_eq(&first, &second),
            "the two lookups hand out the same name"
        );
        assert_eq!(first.as_ref(), "shared.test");
    }

    #[test]
    fn an_address_we_never_handed_out_maps_to_nothing() {
        // The block is the host's decision, so the fixed addresses the Kotlin
        // side owns are the ones of the block in use — and the lock is the
        // block's own, or another test could change it under this one.
        let _guard = crate::virtual_block::test_lock();
        let mapping = IpMapping::new();
        mapping.allocate("a.test");
        // The three fixed addresses the Kotlin side owns, plus a free slot.
        for ip in [
            crate::virtual_block::interface_ip(),
            crate::virtual_block::dns_ip(),
            crate::virtual_block::legacy_proxy_ip(),
            crate::virtual_block::pool_last(),
            Ipv4Addr::new(8, 8, 8, 8),
        ] {
            assert_eq!(mapping.lookup_domain(&ip), None, "{ip}");
        }
    }

    #[test]
    fn every_address_stays_inside_the_tun_route() {
        // The VPN installs exactly one route — the block in use. An address
        // outside it would be sent to the physical network instead of to us,
        // so the whole pool has to be inside it.
        //
        // The lock is the block's own: it is process-wide, and another test
        // that changes it would otherwise be read here.
        let _guard = crate::virtual_block::test_lock();
        let block = crate::virtual_block::current().octets();
        let mapping = IpMapping::new();
        let mut seen = HashSet::new();
        for i in 0..VIRTUAL_IP_COUNT {
            let ip = mapping.allocate(&format!("host{i}.test"));
            let octets = ip.octets();
            assert_eq!(
                &octets[..3],
                &block[..3],
                "{ip} is outside the block in use"
            );
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

    /// An address whose answer may still be cached keeps its domain.
    ///
    /// The answer is what the application holds: it says "this address is
    /// this domain". An address that changes hands while that answer is
    /// cached sends the old domain's next connection to the new domain's
    /// route — the tunnel answers it to the new domain.
    #[test]
    fn an_address_within_its_ttl_is_not_recycled() {
        let mapping =
            IpMapping::with_range(Ipv4Addr::new(10, 0, 1, 16), Ipv4Addr::new(10, 0, 1, 17));
        let held = mapping.allocate("held.test");
        let free = mapping.allocate("free.test");

        // The answer that named `free` has expired; the one that named `held`
        // has not, so a resolver may still be holding it.
        mapping.expire(free);

        // The pool is full now, so the next name takes an address — and it
        // takes the one whose answer expired, not the quieter one whose
        // answer a resolver may still be holding.
        let third = mapping.allocate("third.test");
        assert_eq!(third, free, "the address whose answer expired is recycled");
        assert_eq!(
            mapping.lookup_domain(&held).as_deref(),
            Some("held.test"),
            "the address whose answer is still cached keeps its domain"
        );
    }

    /// The quietest address is not the one to take while its answer is
    /// cached.
    ///
    /// An idle flow is the quietest address there is — nothing arrives on it,
    /// so it looks unused — so "take the quietest" is what hands a live
    /// connection's address to another domain. Whether the answer that named
    /// the address has expired is what says whether it may be taken at all.
    #[test]
    fn a_busy_address_whose_answer_expired_is_taken_before_a_quiet_one() {
        let mapping =
            IpMapping::with_range(Ipv4Addr::new(10, 0, 1, 16), Ipv4Addr::new(10, 0, 1, 17));
        let quiet = mapping.allocate("quiet.test");
        let busy = mapping.allocate("busy.test");

        // `busy.test` keeps opening flows; `quiet.test` resolved once and has
        // not been heard from since.
        for _ in 0..3 {
            assert_eq!(mapping.lookup_domain(&busy).as_deref(), Some("busy.test"));
        }
        // The answer that named `busy` has expired; the one that named
        // `quiet` has not.
        mapping.expire(busy);

        let third = mapping.allocate("third.test");
        assert_eq!(third, busy, "the address whose answer expired is recycled");
        assert_eq!(
            mapping.lookup_domain(&quiet).as_deref(),
            Some("quiet.test"),
            "the address whose answer is still cached keeps its domain"
        );
    }

    /// An answer handed out again holds the address for another TTL.
    ///
    /// The answer is what a resolver caches, so the hold follows the answer
    /// and not the address: a domain that is resolved over and over keeps its
    /// address for as long as it keeps being resolved.
    #[test]
    fn an_address_answered_again_is_held_for_another_ttl() {
        let mapping =
            IpMapping::with_range(Ipv4Addr::new(10, 0, 1, 16), Ipv4Addr::new(10, 0, 1, 17));
        let first = mapping.allocate("first.test");
        mapping.allocate("second.test");
        // The answer that named `first` has expired, so the address may be
        // taken.
        mapping.expire(first);

        // But the domain is resolved again, and the answer is handed out
        // again: the hold starts again.
        assert_eq!(mapping.allocate("first.test"), first);

        // The pool is full, so the next name takes an address — and it may not
        // take this one, whose answer was just handed out.
        let third = mapping.allocate("third.test");
        assert_ne!(
            third, first,
            "the address was answered again, so it is held"
        );
        assert_eq!(
            mapping.lookup_domain(&first).as_deref(),
            Some("first.test"),
            "the address keeps its domain"
        );
    }

    /// The address is held for as long as the answer that named it may be
    /// cached — so the two have to be the same number.
    ///
    /// The TTL is written into the answer by the DNS module and the hold time
    /// is written down here; this test is what keeps the two copies in step.
    #[test]
    fn the_address_is_held_for_as_long_as_the_answer_may_be_cached() {
        let query = question_for("held.test");
        let parsed = crate::dns::parse_query(&query).expect("the question parses");
        let answer = crate::dns::build_response(&parsed, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 16)));

        // The answer repeats the question and then the record: a name
        // pointer, the type, the class, and the TTL.
        let ttl_at = 12 + (query.len() - 12) + 2 + 2 + 2;
        let ttl = u32::from_be_bytes(
            answer[ttl_at..ttl_at + 4]
                .try_into()
                .expect("the TTL is four bytes"),
        );
        assert_eq!(ttl, ADDRESS_TTL.as_secs() as u32);
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

    // ------------------------------------------------------------------
    // IPv6
    // ------------------------------------------------------------------

    /// The pool the Android TUN uses for AAAA answers, and the IPv6 half of
    /// the block in use it comes from.
    ///
    /// The IPv6 half follows the block, which the host decides, so a helper
    /// that wrote it down would test a layout the TUN does not run with. The
    /// lock is the block's own, or another test could move the block between
    /// the two pools — and the two are read together for the same reason.
    fn ipv6_mapping() -> (IpMapping, Ipv6Addr) {
        let _guard = crate::virtual_block::test_lock();
        let block = crate::virtual_block::ipv6_block();
        let mapping = IpMapping::new().with_ipv6(
            crate::virtual_block::ipv6_pool_first(),
            crate::virtual_block::ipv6_pool_last(),
        );
        (mapping, block)
    }

    #[test]
    fn without_an_ipv6_pool_there_is_no_aaaa_answer() {
        // The desktop case: the address could not be configured, so the
        // resolver has to be told "no address of that type" rather than be
        // handed one nothing routes.
        let mapping = IpMapping::new();
        assert!(!mapping.has_ipv6());
        assert_eq!(mapping.allocate_v6("a.test"), None);
        assert_eq!(mapping.lookup_domain_v6(&Ipv6Addr::LOCALHOST), None);
    }

    #[test]
    fn the_two_families_do_not_share_addresses() {
        let (mapping, _) = ipv6_mapping();
        assert!(mapping.has_ipv6());

        let v4 = mapping.allocate("a.test");
        let v6 = mapping.allocate_v6("a.test").expect("an IPv6 pool exists");

        // One name, one address per family — and neither family's answer is
        // mistaken for the other's by the reverse lookup.
        assert_eq!(mapping.lookup_domain(&v4).as_deref(), Some("a.test"));
        assert_eq!(mapping.lookup_domain_v6(&v6).as_deref(), Some("a.test"));
        assert_ne!(v4, Ipv4Addr::UNSPECIFIED);
        assert!(v6.octets().starts_with(&[0xfd, 0x00]));
    }

    #[test]
    fn ipv6_addresses_stay_inside_the_tun_route() {
        // The route the VPN installs is the IPv6 half of the block in use, so
        // the addresses have to be inside that half — and the half follows
        // the block, which the host decides.
        let (mapping, block) = ipv6_mapping();
        let mut seen = HashSet::new();
        for i in 0..1000 {
            let ip = mapping.allocate_v6(&format!("host{i}.test")).unwrap();
            // The VPN installs one /64 route; an address outside it would leave
            // through the physical network instead of coming back to us.
            assert_eq!(
                &ip.octets()[..8],
                &block.octets()[..8],
                "{ip} is outside the IPv6 half of the block in use"
            );
            assert!(seen.insert(ip), "{ip} was handed out twice");
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn an_ipv6_pool_that_runs_out_recycles_like_the_ipv4_one() {
        let mapping = IpMapping::new().with_ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x10),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x11),
        );
        let first = mapping.allocate_v6("first.test").unwrap();
        let second = mapping.allocate_v6("second.test").unwrap();
        assert_ne!(first, second);

        // `second.test` keeps opening flows; `first.test` resolved once and has
        // not been heard from since.
        for _ in 0..3 {
            assert_eq!(
                mapping.lookup_domain_v6(&second).as_deref(),
                Some("second.test")
            );
        }

        // Both slots are taken, so the next name evicts the quiet one.
        let third = mapping.allocate_v6("third.test").unwrap();
        assert_eq!(third, first);
        assert_eq!(
            mapping.lookup_domain_v6(&second).as_deref(),
            Some("second.test")
        );
        assert_eq!(
            mapping.lookup_domain_v6(&third).as_deref(),
            Some("third.test")
        );
    }
}
