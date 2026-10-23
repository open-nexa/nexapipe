//! The DNS server the TUN answers through.
//!
//! The device asks its resolver a question; this is the resolver. A name the
//! proxy is configured for gets a virtual address, and everything else is
//! asked of the real resolvers — with the answers kept for as long as their
//! own records say they are good.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

use crate::domains::should_proxy_domain;
use crate::virtual_ip::IpMapping;

#[cfg(feature = "jni")]
use crate::jni_log;

/// Desktop/server builds log through `tracing`; builds without either the `jni`
/// or the `tracing` feature get a no-op.
#[cfg(all(not(feature = "jni"), feature = "tracing"))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        ::tracing::debug!($($arg)*)
    };
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
macro_rules! jni_log {
    ($($arg:tt)*) => {
        if false {
            let _ = ::std::format_args!($($arg)*);
        }
    };
}

use super::{
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, UpstreamResolvers, build_empty_response,
    build_response, parse_query,
};

// DNS handling — ported from the Kotlin NexaVpnService.
// ============================================================

/// Handle a DNS query and return the DNS response payload.
///
/// - Proxied domain → allocate a virtual address for it and return that as an A record.
/// - iroh infrastructure domain → forward to the real DNS (not proxied inside the TUN).
/// - Other domain → forward to the real DNS and return the response as-is.
///
/// Note: do NOT hijack the system's captive-portal validation domains (connectivitycheck.gstatic.com,
/// etc.) to a private virtual IP. Android's NetworkMonitor treats "validation domain resolves to a
/// private IP" as "no internet" (DNS returned private IP = no internet), which shows a WiFi
/// exclamation mark in the status bar. Let them use the real DNS and reach the physical network,
/// matching the behavior when the VPN is off.
///
/// The mapping has to be the one the stack routes by: an address handed out
/// here has to be an address the stack can reverse-lookup, or the connection
/// that follows the answer has nowhere to go.
///
/// Public because it is the client's whole DNS surface — the TUN asks through
/// it, and so does anything that wants the same answer the device would get.
pub async fn handle_dns_query(
    query: &[u8],
    proxy_domains: &[String],
    resolvers: &UpstreamResolvers,
    ip_mapping: &IpMapping,
) -> Option<Vec<u8>> {
    let parsed = match parse_query(query) {
        Some(q) => q,
        None => return None,
    };
    let domain = parsed.domain.as_str();
    let (qtype, qclass) = (parsed.qtype, parsed.qclass);
    if domain.is_empty() {
        return None;
    }

    let domain_lower = domain.to_lowercase();

    // iroh infrastructure domains are not proxied through the TUN — iroh's own traffic goes via addDisallowedApplication.
    let is_iroh = domain_lower.ends_with(".iroh.link") || domain_lower.ends_with(".n0.iroh.link");

    let is_proxy = !is_iroh && should_proxy_domain(domain, proxy_domains);

    if is_proxy {
        // Only an A or an AAAA query **in the Internet class** gets an address,
        // and each only from the pool of its own family: a rack of virtual IPv4
        // addresses cannot answer an AAAA query with the truth, and it cannot
        // answer a question asked in another class either — what would be
        // written back is an IN record, so handing one out for a CH or ANY
        // question answers something that was not asked. Anything else gets an
        // empty NOERROR and the application falls back to the type it can use.
        // Just as important, none of them consumes an address for a name
        // nothing may ever connect to.
        if qclass != DNS_CLASS_IN || (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
            return Some(build_empty_response(&parsed));
        }

        let answer = match qtype {
            DNS_TYPE_A => Some(IpAddr::V4(ip_mapping.allocate(domain))),
            DNS_TYPE_AAAA => {
                // `None` when the TUN has no IPv6 block to route — the
                // desktop's interface may have refused the address. An empty
                // answer is then the honest one: the resolver falls back to A,
                // whereas an address nothing routes is a connection that hangs.
                let v6 = ip_mapping.allocate_v6(domain);
                if v6.is_none() {
                    jni_log!("[tun-proxy] DNS: no IPv6 pool, answering AAAA with nothing");
                }
                v6.map(IpAddr::V6)
            }
            _ => None,
        };
        let Some(answer) = answer else {
            return Some(build_empty_response(&parsed));
        };

        // The name is deliberately left out: this runs for every name the
        // device resolves, so logging it turns logcat into a record of where
        // the user goes. What debugging needs is the decision, not the name.
        jni_log!("[tun-proxy] DNS: proxying a query -> {}", answer);
        Some(build_response(&parsed, answer))
    } else {
        // Forward to the real DNS.
        jni_log!("[tun-proxy] DNS: forwarding a query (qtype={})", qtype);
        forward_dns_query(query, domain, qtype, qclass, resolvers).await
    }
}

/// Forward a DNS query to the real DNS server and return the response as-is.
///
/// A name that was resolved recently is answered from a cache instead, for as
/// long as the answer's own records say it is good — see [`remember_answer`].
/// The transaction ID of the query asking now is written into the answer before
/// it goes out.
///
/// The question is passed in rather than parsed here: the caller has already
/// parsed it, and parsing a DNS message is not free.
pub async fn forward_dns_query(
    query: &[u8],
    domain: &str,
    qtype: u16,
    qclass: u16,
    resolvers: &UpstreamResolvers,
) -> Option<Vec<u8>> {
    // Every name the device looks up comes through here, and a lookup the
    // resolver has already answered does not need another round trip to a
    // server — which on a phone is a radio wake-up, not a LAN packet.
    let key = CacheKey {
        name: Arc::from(domain.to_lowercase()),
        qtype,
        qclass,
        resolvers: resolvers.scope().clone(),
    };
    if let Some(answer) = cached_answer(&key, query) {
        return Some(answer);
    }

    let answer = resolvers.forward(query).await;

    if let Some(answer) = &answer {
        remember_answer(key, answer);
    }

    answer
}

// ============================================================
// DNS answer cache
// ============================================================

/// How long an answer may be kept whose records say it never expires. Bounded
/// because one that never expires would pin an address to a name for as long as
/// the process lives.
///
/// There is deliberately **no lower bound**. A `0` TTL is not "a very short
/// TTL" but the server asking that the record be re-fetched (RFC 1035 3.2.1), so
/// [`cacheable_for`] refuses to keep it rather than inventing a floor of one
/// second — a floor would be answering with something we were told not to
/// answer with.
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(300);

/// Answers kept before the oldest are dropped to make room. A phone resolves a
/// few dozen names; this is a few hundred, so a busy app cannot grow it.
const DNS_CACHE_MAX_ENTRIES: usize = 512;

/// What an answer belongs to, and therefore what it may be served for.
///
/// Everything here is part of the question asked: **name**, **type** and
/// **class**, plus **who answered it**. Leaving the class out meant a query in
/// one class was served from another class's entry; leaving the resolvers out
/// meant changing the DNS servers in the configuration kept serving what the
/// previous ones had said.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Lower-cased, because DNS names are case-insensitive.
    ///
    /// Shared rather than copied: the key is cloned on every lookup, and a
    /// name is a handful of bytes that every query would otherwise copy.
    name: Arc<str>,
    qtype: u16,
    qclass: u16,
    /// The resolvers this answer came from, in the order they were configured.
    ///
    /// Shared for the same reason as the name: the scope is the same for every
    /// query, so there is no reason to rebuild it for each of them.
    resolvers: Arc<str>,
}

struct CachedAnswer {
    response: Vec<u8>,
    expires_at: tokio::time::Instant,
}

static DNS_CACHE: std::sync::LazyLock<Mutex<HashMap<CacheKey, CachedAnswer>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock_cache() -> MutexGuard<'static, HashMap<CacheKey, CachedAnswer>> {
    DNS_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The answer already held for `key`, with the transaction ID of the query
/// asking now and each record's TTL cut down to what is left of it.
///
/// `None` when there is none, or when the one there has expired.
fn cached_answer(key: &CacheKey, query: &[u8]) -> Option<Vec<u8>> {
    cached_answer_at(key, query, tokio::time::Instant::now())
}

/// [`cached_answer`] with the clock handed in, so a test can ask what is served
/// an hour into a sixty-second expiry without waiting an hour.
fn cached_answer_at(key: &CacheKey, query: &[u8], now: tokio::time::Instant) -> Option<Vec<u8>> {
    let cache = lock_cache();
    let entry = cache.get(key)?;
    if entry.expires_at <= now {
        return None;
    }

    // The answer was fetched with a different ID, and a resolver drops a reply
    // whose ID does not match the question it sent — so without this a cached
    // answer looks to the application exactly like no answer at all.
    let mut response = entry.response.clone();
    if response.len() >= 2 && query.len() >= 2 {
        response[0] = query[0];
        response[1] = query[1];
    }

    // What each record carries out is the part of its TTL that is still left,
    // not the whole it started with. Rewriting only the transaction ID meant a
    // 300-second answer fetched 290 seconds ago went out with 300 seconds on
    // the clock again: the *cache entry* expired on time, but the record it
    // handed out outlived itself by as long as anybody kept asking.
    let remaining = entry.expires_at.saturating_duration_since(now).as_secs();
    set_answer_ttls(&mut response, remaining.min(u32::MAX as u64) as u32);

    Some(response)
}

/// Stores `response` for `key`, for as long as its own records say it is good.
fn remember_answer(key: CacheKey, response: &[u8]) {
    let Some(ttl) = answer_ttl(response) else {
        // Nothing to keep: an answer with no records, or one the server
        // refused, is either a negative answer (which a resolver may want to
        // re-ask at any moment) or unreadable.
        return;
    };

    let mut cache = lock_cache();
    let now = tokio::time::Instant::now();

    // The sweep walks the whole table, so it happens only when the table is
    // full. An entry that has expired is never served anyway — the lookup
    // checks the expiry — so nothing is lost by letting it sit there until
    // there is a reason to look.
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        cache.retain(|_, entry| entry.expires_at > now);

        // No room and nothing expired: the whole table is dropped rather than
        // picking a victim one record at a time, which for a cache this size is
        // not worth the bookkeeping.
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
    }

    cache.insert(
        key,
        CachedAnswer {
            response: response.to_vec(),
            expires_at: now + ttl,
        },
    );
}

/// The offset of every answer record's TTL within `response`.
///
/// The one walk through the answer section, shared by everything that has to
/// read or write those four bytes. Keeping two copies of it is how a TTL ages
/// in one place and not the other.
fn answer_ttl_offsets(response: &[u8]) -> Option<Vec<usize>> {
    if response.len() < 12 {
        return None;
    }

    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;
    if answers == 0 {
        return None;
    }

    // Skip the header and the question — one name plus QTYPE and QCLASS.
    let mut pos = skip_dns_name(response, 12)? + 4;

    let mut offsets = Vec::with_capacity(answers);
    for _ in 0..answers {
        pos = skip_dns_name(response, pos)?;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        if pos + 10 > response.len() {
            return None;
        }
        offsets.push(pos + 4);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    Some(offsets)
}

/// How long the records in `response` may be served from the cache: the
/// shortest TTL among the answers, since one expired record makes the answer
/// wrong. `None` when the response has no answers to read a TTL from, is an
/// error, or asked not to be cached.
fn answer_ttl(response: &[u8]) -> Option<Duration> {
    if response.len() < 12 {
        return None;
    }

    // RCODE is the low four bits of the flags: anything but 0 is a refusal or
    // a failure, which is not something to keep answering with.
    if response[3] & 0x0F != 0 {
        return None;
    }

    let shortest = answer_ttl_offsets(response)?
        .into_iter()
        .map(|offset| read_u32(response, offset))
        .min()?;

    cacheable_for(shortest)
}

/// How long an answer whose shortest record TTL is `ttl` may be kept.
///
/// `None` for a zero TTL: RFC 1035 says that means do not cache, and the cache
/// has no business turning "ask again every time" into a second of authority.
fn cacheable_for(ttl: u32) -> Option<Duration> {
    if ttl == 0 {
        return None;
    }
    Some(Duration::from_secs(
        (ttl as u64).min(DNS_CACHE_MAX_TTL.as_secs()),
    ))
}

/// Writes `ttl` into every answer record of `response`, in place.
fn set_answer_ttls(response: &mut [u8], ttl: u32) {
    let Some(offsets) = answer_ttl_offsets(response) else {
        return;
    };
    for offset in offsets {
        if offset + 4 <= response.len() {
            response[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
    }
}

/// The `u32` at `pos`, or 0 when the packet is too short to hold one.
fn read_u32(payload: &[u8], pos: usize) -> u32 {
    if pos + 4 <= payload.len() {
        u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ])
    } else {
        0
    }
}

/// The offset just past the name starting at `pos`, following a compression
/// pointer if the name ends in one.
fn skip_dns_name(payload: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *payload.get(pos)? as usize;
        match len {
            0 => return Some(pos + 1),
            // A pointer ends the name, and is two bytes long.
            0xC0.. => return Some(pos + 2),
            _ => pos += 1 + len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver_scope;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// The resolvers every test answer claims to have come from. What matters
    /// is only that they are the same two strings on both sides of a test.
    const RESOLVERS: &str = "1.1.1.1:53";

    fn key(name: &str) -> CacheKey {
        key_in(name, DNS_CLASS_IN)
    }

    fn key_in(name: &str, qclass: u16) -> CacheKey {
        CacheKey {
            name: Arc::from(name),
            qtype: 1,
            qclass,
            resolvers: Arc::from(RESOLVERS),
        }
    }

    /// Puts an answer in the cache with an expiry of its own choosing, so a
    /// test can stand an hour into a sixty-second answer without waiting.
    fn remember_answer_until(key: CacheKey, response: &[u8], expires_at: tokio::time::Instant) {
        lock_cache().insert(
            key,
            CachedAnswer {
                response: response.to_vec(),
                expires_at,
            },
        );
    }

    /// The TTL the first answer record carries, read back out of it.
    fn served_ttl(response: &[u8]) -> Option<u32> {
        let first = *answer_ttl_offsets(response)?.first()?;
        Some(read_u32(response, first))
    }

    /// `example.com` in wire form: one length byte per label, then the
    /// terminator. Shared so the tests below ask about one name.
    fn wire_name() -> Vec<u8> {
        vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]
    }

    /// A query packet: 12 bytes of header, then the question.
    fn query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        packet
    }

    /// A query asking A, in a class that is not `IN`. Answering this out of the
    /// IN entry for the same name is what the key used to allow.
    fn query_in_class(name: &[u8], qclass: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        packet.extend_from_slice(&qclass.to_be_bytes());
        packet
    }
    /// pointer to the `example.com` written further along. The pointer ends the
    /// name where it stands, so QTYPE follows its two bytes — not the labels it
    /// points at.
    fn query_with_partly_compressed_name(qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&[0x03, b'w', b'w', b'w']); // offset 12..16
        packet.extend_from_slice(&[0xC0, 24]); // pointer at 16..18 -> offset 24
        packet.extend_from_slice(&qtype.to_be_bytes()); // 18..20
        packet.extend_from_slice(&1u16.to_be_bytes()); // 20..22
        packet.extend_from_slice(&[0, 0]); // 22..24, filler
        packet.extend_from_slice(&[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        packet.extend_from_slice(&[0x03, b'c', b'o', b'm', 0x00]);
        packet
    }

    #[test]
    fn reads_an_uncompressed_name() {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let parsed = parse_query(&query(&name, 1)).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.qclass, DNS_CLASS_IN);
    }

    /// The bug: read as a length, the pointer's 0xC0 became a 192-byte label
    /// (out of bounds, so `None`) or, with a smaller value, a garbage one — and
    /// the routing decision that follows the name was silently wrong.
    #[test]
    fn follows_a_compression_pointer_to_the_rest_of_the_name() {
        let parsed = parse_query(&query_with_partly_compressed_name(1)).unwrap();
        assert_eq!(parsed.domain, "www.example.com");
        assert_eq!(parsed.qtype, 1);
    }

    /// QTYPE follows the pointer, not the labels it points at: reading on from
    /// the pointed-to name's terminator would land in the tail of the packet.
    #[test]
    fn reads_the_qtype_where_the_pointer_ended() {
        let parsed = parse_query(&query_with_partly_compressed_name(28)).unwrap();
        assert_eq!(parsed.qtype, 28);
    }

    #[test]
    fn refuses_a_pointer_that_loops() {
        // 0xC00C points at offset 12, which is this very pointer.
        let name = [0xC0, 0x0C];
        assert!(parse_query(&query(&name, 1)).is_none());
    }

    #[test]
    fn refuses_a_pointer_outside_the_packet() {
        let name = [0x03, b'a', b'b', b'c', 0xC0, 0xF0];
        assert!(parse_query(&query(&name, 1)).is_none());
    }

    /// An answer with two A records: the same header and question, then two
    /// records whose TTLs differ, so the cache has to keep the shorter one.
    fn answer(ttls: &[u32]) -> Vec<u8> {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let mut packet = vec![0xAA, 0xBB, 0x81, 0x80, 0x00, 0x01];
        packet.extend_from_slice(&(ttls.len() as u16).to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT + ARCOUNT
        packet.extend_from_slice(&name);
        packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

        for ttl in ttls {
            packet.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to the question
            packet.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
            packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
            packet.extend_from_slice(&ttl.to_be_bytes());
            packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
            packet.extend_from_slice(&[10, 0, 0, 1]); // RDATA
        }
        packet
    }

    #[test]
    fn the_cache_keeps_the_shortest_ttl_in_the_answer() {
        assert_eq!(
            answer_ttl(&answer(&[300, 60])),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            answer_ttl(&answer(&[60, 300])),
            Some(Duration::from_secs(60))
        );
    }

    /// A zero TTL is not "a very short TTL" but the server asking that the
    /// record be re-fetched, so nothing is kept for it.
    #[test]
    fn a_zero_ttl_is_not_cached_at_all() {
        assert_eq!(answer_ttl(&answer(&[0])), None);
        assert_eq!(cacheable_for(0), None);
    }

    /// An answer that claims never to expire would pin a name to an address for
    /// as long as the process lives, so the ceiling still holds.
    #[test]
    fn a_ttl_that_never_expires_is_bounded() {
        assert_eq!(
            answer_ttl(&answer(&[u32::MAX])),
            Some(Duration::from_secs(300))
        );
    }

    /// Nothing to keep: an answer with no records, or one the server refused.
    #[test]
    fn an_answer_with_no_records_is_not_cached() {
        assert_eq!(answer_ttl(&answer(&[])), None);

        let mut refused = answer(&[60]);
        refused[3] = 0x83; // RCODE = NXDOMAIN
        assert_eq!(answer_ttl(&refused), None);
    }

    /// The answer is fetched once and served to many queries, each with its own
    /// transaction ID — a resolver drops a reply whose ID does not match the
    /// question it sent.
    #[test]
    fn a_cached_answer_is_served_with_the_asking_query_id() {
        let name = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let fetched = query(&name, 1); // ID 0x1234
        let asking = {
            let mut other = fetched.clone();
            other[0] = 0xAB;
            other[1] = 0xCD;
            other
        };

        remember_answer(key("id.example.com"), &answer(&[60]));

        let served = cached_answer(&key("id.example.com"), &asking)
            .expect("the answer was remembered with a 60s TTL");
        assert_eq!(&served[..2], &[0xAB, 0xCD]);

        // A different record type is a different question, even for one name.
        assert!(
            cached_answer(
                &CacheKey {
                    qtype: 28,
                    ..key("id.example.com")
                },
                &asking
            )
            .is_none()
        );
    }

    /// The key used to be a name and a type, so a query in another class was
    /// answered out of the `IN` entry for that name.
    #[test]
    fn a_query_in_another_class_is_not_answered_from_the_in_entry() {
        let asking = query_in_class(&wire_name(), 3); // CH

        remember_answer(key("class.example.com"), &answer(&[60]));

        assert!(cached_answer(&key("class.example.com"), &query(&wire_name(), 1)).is_some());
        assert!(
            cached_answer(&key_in("class.example.com", 3), &asking).is_none(),
            "no entry exists for this name in class CH"
        );
    }

    /// Changing the DNS servers changes who answers, so it must stop serving
    /// what the previous ones said — including a different operator's answer
    /// for the same name.
    #[test]
    fn an_answer_is_only_served_to_the_resolvers_that_produced_it() {
        let asking = query(&wire_name(), 1);

        remember_answer(key("resolvers.example.com"), &answer(&[60]));

        let elsewhere = CacheKey {
            resolvers: resolver_scope(&["9.9.9.9:53".parse().unwrap()]),
            ..key("resolvers.example.com")
        };
        assert!(cached_answer(&elsewhere, &asking).is_none());
    }

    /// A cached answer hands out the part of its TTL that is left, not the whole
    /// it started with. Rewriting only the transaction ID meant a 300s answer
    /// fetched 290s ago went out with 300s on the clock again, so the record
    /// outlived the cache entry holding it.
    #[test]
    fn a_record_ages_the_ttl_it_hands_out() {
        let expires_at = tokio::time::Instant::now() + Duration::from_secs(60);
        remember_answer_until(key("aging.example.com"), &answer(&[60]), expires_at);

        // Asked five seconds in: fifty-five of the sixty are still on it.
        let asking = query(&wire_name(), 1);
        let fresh = cached_answer_at(
            &key("aging.example.com"),
            &asking,
            expires_at - Duration::from_secs(55),
        )
        .expect("five seconds into a sixty-second answer");
        assert_eq!(served_ttl(&fresh), Some(55));

        // Asked again three quarters of the way through: for want of this, the
        // fifteen seconds that were left used to go out as sixty again.
        let stale = cached_answer_at(
            &key("aging.example.com"),
            &asking,
            expires_at - Duration::from_secs(15),
        )
        .expect("fifteen seconds left of a sixty-second answer");
        assert_eq!(served_ttl(&stale), Some(15));

        // Past the expiry nothing is served, however much TTL the record has.
        assert!(
            cached_answer_at(&key("aging.example.com"), &asking, expires_at).is_none(),
            "an expired entry answers nothing"
        );
    }

    /// Every record is aged, not the first: the answer handed out claims two
    /// addresses for the name, and both have to come down together.
    #[test]
    fn aging_rewrites_every_record_not_the_first() {
        let mut response = answer(&[300, 300]);
        set_answer_ttls(&mut response, 7);

        assert_eq!(
            answer_ttl_offsets(&response)
                .expect("two records")
                .iter()
                .map(|offset| read_u32(&response, *offset))
                .collect::<Vec<_>>(),
            vec![7, 7]
        );
    }

    // ------------------------------------------------------------------
    // A / AAAA
    // ------------------------------------------------------------------

    /// The mapping the Android TUN runs with: an IPv4 pool and an IPv6 one.
    ///
    /// Both pools are the ones of the block in use — the Android TUN takes
    /// them from the shared block — so a helper that wrote them down would
    /// test a layout the TUN does not run with. The lock is the block's own,
    /// or another test could move the block between the two.
    fn dual_stack_mapping() -> IpMapping {
        let _guard = crate::virtual_block::test_lock();
        IpMapping::new().with_ipv6(
            crate::virtual_block::ipv6_pool_first(),
            crate::virtual_block::ipv6_pool_last(),
        )
    }

    /// What `handle_dns_query` answered: the number of records and, for the one
    /// it wrote, its type and its RDATA.
    async fn answered(qtype: u16, mapping: &IpMapping) -> (u16, Option<(u16, Vec<u8>)>) {
        let query = query(&wire_name(), qtype);
        // No upstream: a proxied name is never forwarded.
        let resolvers = UpstreamResolvers::new(&[], Arc::new(AtomicBool::new(false)));
        let response = handle_dns_query(&query, &["example.com".to_string()], &resolvers, mapping)
            .await
            .expect("a proxied query is answered");

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return (0, None);
        }
        // Straight after the question: the name pointer, then TYPE, CLASS, TTL,
        // RDLENGTH and the address itself.
        let answer = query.len() + 2;
        let rtype = u16::from_be_bytes([response[answer], response[answer + 1]]);
        let rdlength = u16::from_be_bytes([response[answer + 8], response[answer + 9]]) as usize;
        let rdata = response[answer + 10..answer + 10 + rdlength].to_vec();
        (ancount, Some((rtype, rdata)))
    }

    #[tokio::test]
    async fn an_a_query_is_answered_from_the_ipv4_pool() {
        let mapping = dual_stack_mapping();
        let (ancount, record) = answered(1, &mapping).await;
        assert_eq!(ancount, 1);
        let (rtype, rdata) = record.expect("one record");
        assert_eq!(rtype, DNS_TYPE_A);
        assert_eq!(rdata.len(), 4, "an A record carries four bytes");
        assert_eq!(
            mapping.lookup_domain(&std::net::Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3]
            )),
            Some(std::sync::Arc::from("example.com")),
            "the answer has to route: the stack looks the destination up here"
        );
    }

    #[tokio::test]
    async fn an_aaaa_query_is_answered_from_the_ipv6_pool() {
        let mapping = dual_stack_mapping();
        let (ancount, record) = answered(DNS_TYPE_AAAA, &mapping).await;
        assert_eq!(ancount, 1);
        let (rtype, rdata) = record.expect("one record");
        assert_eq!(rtype, DNS_TYPE_AAAA);
        assert_eq!(rdata.len(), 16, "an AAAA record carries sixteen bytes");

        let mut octets = [0u8; 16];
        octets.copy_from_slice(&rdata);
        let address = std::net::Ipv6Addr::from(octets);
        assert_eq!(
            mapping.lookup_domain_v6(&address),
            Some(std::sync::Arc::from("example.com")),
            "the same reverse lookup the packet path uses"
        );
    }

    /// The point of the empty answer: a resolver that is told "no address of
    /// this type" falls back to A, while one that is handed an address nothing
    /// routes hangs on a connection it cannot open.
    #[tokio::test]
    async fn an_aaaa_query_is_answered_with_nothing_without_an_ipv6_pool() {
        // The desktop case: the interface refused the IPv6 address, so the TUN
        // has no route for one.
        let mapping = IpMapping::new();
        assert_eq!(answered(DNS_TYPE_AAAA, &mapping).await, (0, None));
    }

    #[tokio::test]
    async fn a_type_with_no_address_gets_the_same_empty_answer() {
        let mapping = dual_stack_mapping();
        // MX (15): the mapping has addresses, but none of that type.
        assert_eq!(answered(15, &mapping).await, (0, None));
    }

    /// The two families answer independently: a name that resolved over IPv4
    /// still gets its own IPv6 address, and neither allocation disturbs the
    /// other's.
    #[tokio::test]
    async fn the_two_families_are_allocated_independently() {
        let mapping = dual_stack_mapping();
        let (_, a) = answered(1, &mapping).await;
        let (_, aaaa) = answered(DNS_TYPE_AAAA, &mapping).await;
        let (rtype_a, rdata_a) = a.expect("an A record");
        let (rtype_aaaa, rdata_aaaa) = aaaa.expect("an AAAA record");
        assert_eq!(rtype_a, DNS_TYPE_A);
        assert_eq!(rtype_aaaa, DNS_TYPE_AAAA);
        assert_ne!(rdata_a.len(), rdata_aaaa.len());
        assert_eq!(mapping.len(), 2, "one mapping per family for one name");
    }
}
