//! The upstream DNS resolvers, and the sockets they are asked through.
//!
//! A device asks the same names over and over — the system's resolver retries,
//! every application looks up the same CDNs — and each of those lookups used to
//! **build a new UDP socket**. On a phone that is the expensive part: a new
//! source port for every query means a new entry in the NAT table of every
//! router between the device and the resolver, and the entry is torn down again
//! as soon as the answer is in. A resolver that answers from the same socket
//! keeps the mapping, and the mapping is the whole reason a phone's DNS traffic
//! costs what it costs.
//!
//! So the sockets here live as long as the resolvers do, and the queries share
//! them.
//!
//! # Sharing a socket means demultiplexing by transaction ID
//!
//! The 16-bit transaction ID is what ties an answer to its question. When a
//! socket is used for one query at a time, the ID can be the application's own
//! and the answer is simply the next datagram to arrive. When it is used for
//! many queries at once, the ID has to be **ours**: two applications on the
//! device may pick the same ID for different questions at the same moment, and
//! a shared socket cannot tell those two answers apart.
//!
//! So every query that goes upstream is given an ID of our own, and the answer
//! is put back into the shape the application expects — with the application's
//! own ID — before it goes out. This is what a forwarding resolver does
//! (RFC 1035 §4.2.2 requires only that the answer carry the ID of the query
//! it answers, and the application's ID is restored before it ever sees it).
//!
//! # The answer still has to answer
//!
//! An ID that came from us is not proof that the datagram is an answer: a
//! socket that is not connected accepts datagrams from anybody, and on a path
//! where DNS is interfered with a forged reply can arrive before the real one.
//! So the question the answer carries is compared with the question that was
//! asked, and an answer to another question is dropped and the wait goes on.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;

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

/// How long one upstream is given to answer before the next one is tried.
pub const PER_SERVER_TIMEOUT: Duration = Duration::from_millis(800);

/// The whole chain is given this long, whatever it is made of.
pub const OVERALL_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// The wire format
//
// The question a client asks and the answer this proxy gives it. It was
// written down twice — once here for the TUN's own DNS server, and once in the
// desktop app, which runs a DNS server of its own — and the two copies were
// free to disagree about what a question is and what an answer looks like.
// One copy, and both sides link it.
// ---------------------------------------------------------------------------

/// The only QCLASS this proxy answers: everything it serves — a virtual
/// address, or a record forwarded from a real resolver — belongs to it.
pub const DNS_CLASS_IN: u16 = 1;

/// The two QTYPEs this proxy answers itself: A and AAAA.
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;

/// How many compression pointers one name may follow before the name is
/// declared unreadable. A real name needs one; more than that is a loop.
const MAX_DNS_POINTER_JUMPS: usize = 4;

/// A DNS query, parsed.
///
/// The parts an answer needs: the name that was asked for, the type and class
/// of the question, and the question section verbatim — a response echoes the
/// question back, and a name written with a compression pointer in it cannot
/// be rebuilt from the labels alone.
#[derive(Debug, Clone)]
pub struct Query {
    /// The transaction ID the answer has to carry.
    pub id: u16,
    /// The name the question asks for.
    pub domain: String,
    /// The question type: [`DNS_TYPE_A`] and [`DNS_TYPE_AAAA`] are the ones
    /// answered here.
    pub qtype: u16,
    /// The question class: [`DNS_CLASS_IN`] is the one answered here.
    pub qclass: u16,
    /// The question section, verbatim.
    pub question: Vec<u8>,
}

/// Parse a DNS query.
///
/// `None` when the packet is not a question this proxy can read: too short,
/// no question in it, a name that cannot be read as text, a compression
/// pointer that loops, or a type and class that are cut off.
pub fn parse_query(payload: &[u8]) -> Option<Query> {
    if payload.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // The Question section's domain name, as length-prefixed labels.
    let mut pos = 12;
    let question_start = pos;
    let mut labels: Vec<&str> = Vec::new();
    let mut jumps = 0usize;
    // Where QTYPE sits once the name is over. It follows the terminating zero
    // byte for an uncompressed name, but the two pointer bytes when the name
    // jumped (RFC 1035 4.1.4): the labels those bytes point at live somewhere
    // else entirely, and reading on from there would land inside another
    // section.
    let mut after_name: Option<usize> = None;

    while pos < payload.len() {
        let len = payload[pos] as usize;

        if len == 0 {
            pos += 1; // Skip the null terminator.
            break;
        }

        // A compression pointer (RFC 1035 4.1.4): the two top bits are set and
        // the rest, with the byte after, is an offset into the message — an
        // earlier label list that this name continues with. Reading it as a
        // length gives a nonsense label, and from there a nonsense domain: what
        // decides whether the name is proxied was silently wrong. Rare in a
        // query, legal, and some stacks do it.
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= payload.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | payload[pos + 1] as usize;
            if offset >= payload.len() {
                return None;
            }
            // A pointer that points at another pointer forever is a loop; stop
            // after a few hops rather than spin.
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return None;
            }
            if after_name.is_none() {
                after_name = Some(pos + 2);
            }
            pos = offset;
            continue;
        }

        // The remaining two label types (0x40, 0x80) are reserved or unused;
        // a name using one cannot be read as text.
        if len & 0xC0 != 0 {
            return None;
        }

        // Prevent out-of-bounds access.
        if pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label);
        pos += 1 + len;
    }

    let qtype_pos = after_name.unwrap_or(pos);
    // QTYPE first, then QCLASS — two pairs that sit together after the name.
    // The class is read rather than assumed: an answer cached for `IN` must not
    // answer a query made in another class, and a key without it cannot tell
    // those apart. Both have to be there: a question whose type is cut off is
    // not a question this proxy can answer.
    if qtype_pos + 4 > payload.len() {
        return None;
    }

    Some(Query {
        id,
        domain: labels.join("."),
        qtype: u16::from_be_bytes([payload[qtype_pos], payload[qtype_pos + 1]]),
        qclass: u16::from_be_bytes([payload[qtype_pos + 2], payload[qtype_pos + 3]]),
        question: payload[question_start..qtype_pos + 4].to_vec(),
    })
}

/// Build a response resolving the queried name to `addr`.
///
/// The record type follows the address: an IPv4 address answers an A query
/// with 4 bytes of RDATA, an IPv6 address answers an AAAA query with 16.
/// Anything else — an AAAA question answered from the IPv4 pool, an MX, a type
/// this proxy has no address for — gets an empty answer (ANCOUNT=0) so the
/// client falls back to a query it can use.
pub fn build_response(parsed: &Query, addr: IpAddr) -> Vec<u8> {
    let (rtype, rdata): (u16, &[u8]) = match (addr, parsed.qtype) {
        (IpAddr::V4(ip), DNS_TYPE_A) => (DNS_TYPE_A, &ip.octets()),
        (IpAddr::V6(ip), DNS_TYPE_AAAA) => (DNS_TYPE_AAAA, &ip.octets()),
        _ => return build_empty_response(parsed),
    };

    let mut response = Vec::with_capacity(parsed.question.len() + rdata.len() + 16);

    // Header
    response.extend_from_slice(&parsed.id.to_be_bytes()); // ID
    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    response.extend_from_slice(&[0x81, 0x80]);
    // QDCOUNT=1
    response.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT=1
    response.extend_from_slice(&1u16.to_be_bytes());
    // NSCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes());
    // ARCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes());

    // Question section (copied verbatim from the original query's question)
    response.extend_from_slice(&parsed.question);

    // Answer section
    // Name pointer (points at the domain name in the question section)
    response.extend_from_slice(&[0xC0, 0x0C]);
    // TYPE=A (1) or AAAA (28)
    response.extend_from_slice(&rtype.to_be_bytes());
    // CLASS=IN
    response.extend_from_slice(&1u16.to_be_bytes());
    // TTL=60
    response.extend_from_slice(&60u32.to_be_bytes());
    // RDLENGTH=4 for A, 16 for AAAA
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    // RDATA=IP
    response.extend_from_slice(rdata);

    response
}

/// Build a response that answers the question and carries no records.
///
/// For a question this proxy does not answer itself: an AAAA question asked
/// of a machine with no IPv6 block, a type that is not an address at all, or a
/// question asked in a class this proxy does not serve.
pub fn build_empty_response(parsed: &Query) -> Vec<u8> {
    let mut response = Vec::with_capacity(parsed.question.len() + 16);
    // Header: ID + QR=1, RD=1, RA=1, RCODE=0 + QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    response.extend_from_slice(&parsed.id.to_be_bytes());
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    // Question section (copied verbatim)
    response.extend_from_slice(&parsed.question);
    response
}

/// How often a reader looks at the stop flag while it waits for a datagram.
const STOP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The size of the buffer an answer is read into.
///
/// A DNS answer is a kilobyte at most in practice; 4096 is what the rest of
/// the client reads a datagram into.
const REPLY_BUFFER: usize = 4096;

/// The upstream resolvers a query can be forwarded to, each with a socket of its
/// own that lives as long as the resolver does.
///
/// Built once, when the proxy comes up, and shared by every query afterwards.
#[derive(Clone)]
pub struct UpstreamResolvers {
    inner: Arc<Inner>,
}

struct Inner {
    /// The resolvers, in the order they are asked.
    resolvers: Vec<Arc<Resolver>>,
    /// The scope an answer belongs to: the servers it came from.
    scope: Arc<str>,
    /// How long one resolver is given to answer.
    per_server: Duration,
    /// How long the whole chain is given.
    overall: Duration,
}

impl UpstreamResolvers {
    /// Binds one socket per server, IPv4 servers first.
    ///
    /// A server whose socket cannot be bound is **skipped**, not fatal: today
    /// the same thing happens per query (the bind fails, the server is tried
    /// next), and a machine whose IPv6 resolver cannot be reached must still
    /// resolve names through its IPv4 one.
    ///
    /// `stopped` is the flag the proxy sets when it shuts down. The readers
    /// behind these sockets end within a second of it being set.
    ///
    /// Needs a runtime context: the sockets are registered with it, and the
    /// readers are tasks of it.
    pub fn new(servers: &[SocketAddr], stopped: Arc<AtomicBool>) -> Self {
        // IPv4 first: a phone's IPv6 path is the one more likely to be a
        // dead end, and asking it first would spend a timeout on it.
        let mut ordered: Vec<SocketAddr> = servers.to_vec();
        ordered.sort_by_key(|server| !server.is_ipv4() as u8);
        Self::with_timeouts(&ordered, stopped, PER_SERVER_TIMEOUT, OVERALL_TIMEOUT)
    }

    /// [`UpstreamResolvers::new`] with the timeouts the caller wants, and the
    /// order the caller gave.
    ///
    /// The two windows are the ones the chain has always had: how long one
    /// resolver may take before the next is tried, and how long the whole
    /// chain may take. A caller whose chain is longer, or whose resolvers are
    /// further away, needs different numbers.
    ///
    /// The order is left alone: a chain is ordered for a reason. The desktop
    /// asks the machine's own resolvers first, then its configured one, then
    /// the public fallbacks, because only the machine's own resolver knows its
    /// split-horizon and internal names. Sorting it by address family would
    /// put a public IPv4 fallback ahead of an IPv6 resolver that knows them.
    pub fn with_timeouts(
        servers: &[SocketAddr],
        stopped: Arc<AtomicBool>,
        per_server: Duration,
        overall: Duration,
    ) -> Self {
        let mut resolvers = Vec::new();
        for &server in servers {
            match Resolver::bind(server) {
                Ok(resolver) => {
                    let resolver = Arc::new(resolver);
                    spawn_reader(resolver.clone(), stopped.clone());
                    resolvers.push(resolver);
                }
                Err(e) => {
                    jni_log!("[dns] no socket for the resolver {server}: {e}");
                }
            }
        }

        Self {
            inner: Arc::new(Inner {
                resolvers,
                scope: resolver_scope(servers),
                per_server,
                overall,
            }),
        }
    }

    /// The resolvers an answer belongs to.
    ///
    /// An answer from one set of resolvers must never be reachable through the
    /// name of another, so the set is part of the cache key.
    pub fn scope(&self) -> &Arc<str> {
        &self.inner.scope
    }

    /// How many resolvers can be asked.
    pub fn len(&self) -> usize {
        self.inner.resolvers.len()
    }

    /// Whether there is a resolver to ask at all.
    pub fn is_empty(&self) -> bool {
        self.inner.resolvers.is_empty()
    }

    /// Asks the resolvers in order until one of them answers.
    ///
    /// The order and the timeouts are the ones the per-query sockets had:
    /// each resolver gets [`PER_SERVER_TIMEOUT`], and the whole chain gets
    /// [`OVERALL_TIMEOUT`].
    pub async fn forward(&self, query: &[u8]) -> Option<Vec<u8>> {
        if self.inner.resolvers.is_empty() {
            jni_log!("[dns] no upstream resolver to ask");
            return None;
        }

        let answer = tokio::time::timeout(self.inner.overall, async {
            for resolver in &self.inner.resolvers {
                if let Some(answer) = resolver.query(query, self.inner.per_server).await {
                    return Some(answer);
                }
            }
            None
        })
        .await;

        match answer {
            Ok(Some(answer)) => Some(answer),
            Ok(None) => {
                jni_log!(
                    "[dns] no resolver answered ({} asked)",
                    self.inner.resolvers.len()
                );
                None
            }
            Err(_) => {
                jni_log!(
                    "[dns] the resolvers did not answer within {}s",
                    self.inner.overall.as_secs()
                );
                None
            }
        }
    }
}

/// The resolvers an answer belongs to, joined in configuration order.
///
/// Not hashed: an answer from one resolver set must never be reachable through
/// the name of another, and a hash collision would be the cache's bug all over
/// again. A handful of strings in a 512-entry table costs nothing.
pub fn resolver_scope(servers: &[SocketAddr]) -> Arc<str> {
    let joined = servers
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(",");
    Arc::from(joined)
}

/// One upstream resolver, and the socket every query to it goes through.
struct Resolver {
    server: SocketAddr,
    socket: Arc<UdpSocket>,
    /// The queries waiting for an answer, by the ID we gave them.
    waiting: std::sync::Mutex<HashMap<u16, Pending>>,
    /// The next ID to hand out.
    next_id: AtomicU16,
    /// The next query's number.
    ///
    /// Wider than the ID on purpose: the IDs wrap, and a query that is still
    /// waiting can share its ID with a much later one.
    next_token: AtomicU64,
}

/// A query that is out and waiting for its answer.
struct Pending {
    /// The ID the application's query carried, put back into the answer.
    original_id: [u8; 2],
    /// The question that was asked, so a reply to another question is not
    /// believed.
    question: Vec<u8>,
    /// Which query this is.
    ///
    /// The ID alone is not enough to name it: the IDs are 16 bits wide and
    /// wrap, so a query that is still waiting can share its ID with a much
    /// later one. The token is not.
    token: u64,
    /// Where the answer goes.
    reply: oneshot::Sender<Vec<u8>>,
}

impl Resolver {
    /// Binds the socket this resolver asks through.
    ///
    /// The socket is **not** connected: a connected socket only accepts
    /// datagrams from the peer it is connected to, and a resolver that answers
    /// from another address would be ignored. The source address is checked
    /// instead, in [`Resolver::deliver`].
    fn bind(server: SocketAddr) -> std::io::Result<Self> {
        // Bind by address family: an IPv4 resolver cannot be reached from an
        // IPv6 socket, and the other way round.
        let bind_addr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;

        Ok(Self {
            server,
            socket: Arc::new(socket),
            waiting: std::sync::Mutex::new(HashMap::new()),
            next_id: AtomicU16::new(0),
            next_token: AtomicU64::new(0),
        })
    }

    /// Sends `query` and waits for the answer.
    ///
    /// The ID the query goes out with is ours, not the application's: see the
    /// module's header for why. The answer comes back with the application's
    /// ID, so the caller sees what it expects.
    async fn query(self: &Arc<Self>, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let (id, token, reply) = self.register(query);
        // Removes the entry when this future ends, whatever ends it: the
        // answer arriving, the timeout, or the whole chain being cancelled.
        let _pending = PendingGuard {
            resolver: self.clone(),
            id,
            token,
        };

        let mut outgoing = query.to_vec();
        // The transaction ID is two bytes, most significant first: the same
        // order it had when it came in.
        outgoing[0] = (id >> 8) as u8;
        outgoing[1] = id as u8;
        if self.socket.send_to(&outgoing, self.server).await.is_err() {
            return None;
        }

        match tokio::time::timeout(timeout, reply).await {
            Ok(Ok(answer)) => Some(answer),
            _ => None,
        }
    }

    /// Puts `query` on the list of questions waiting for an answer, and returns
    /// the ID it was given and where its answer goes.
    fn register(&self, query: &[u8]) -> (u16, u64, oneshot::Receiver<Vec<u8>>) {
        let (reply, waiting_for) = oneshot::channel();
        let mut waiting = self.waiting.lock().unwrap_or_else(|e| e.into_inner());

        // An ID that is already out must not be handed out again: the answer
        // to the first question would wake the wrong waiter.
        let id = loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if !waiting.contains_key(&id) {
                break id;
            }
        };

        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        waiting.insert(
            id,
            Pending {
                original_id: [query[0], query[1]],
                question: query.to_vec(),
                token,
                reply,
            },
        );

        (id, token, waiting_for)
    }

    /// Hands an answer to the query it belongs to.
    ///
    /// A datagram that came from another address, or that answers another
    /// question, is dropped: the wait goes on.
    fn deliver(&self, mut answer: Vec<u8>) {
        if answer.len() < 12 {
            return;
        }
        // QR: a query is the wrong kind of packet to be answering with.
        if answer[2] & 0x80 == 0 {
            return;
        }
        let id = u16::from_be_bytes([answer[0], answer[1]]);

        let mut waiting = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pending) = waiting.get(&id) else {
            // Nobody is waiting for this one: a late answer to a query that
            // timed out, or a datagram that is not ours.
            return;
        };
        if !answers_the_question(&answer, &pending.question) {
            return;
        }
        let Some(pending) = waiting.remove(&id) else {
            return;
        };
        drop(waiting);

        // The application's ID goes back in, so the answer it receives is the
        // answer to the question it asked.
        answer[0] = pending.original_id[0];
        answer[1] = pending.original_id[1];
        let _ = pending.reply.send(answer);
    }
}

/// Removes a query from the list of questions waiting for an answer.
///
/// The answer arriving removes it too; this is for the other ways a query can
/// end — the timeout, a failed send, the whole chain being cancelled — so a
/// question that was never answered does not stay in the table for ever.
struct PendingGuard {
    resolver: Arc<Resolver>,
    id: u16,
    token: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        let mut waiting = self
            .resolver
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Only this query's own entry: the ID may have been handed to a later
        // query in the meantime.
        if waiting
            .get(&self.id)
            .is_some_and(|pending| pending.token == self.token)
        {
            waiting.remove(&self.id);
        }
    }
}

/// Reads the answers to the queries that went out through one resolver.
fn spawn_reader(resolver: Arc<Resolver>, stopped: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; REPLY_BUFFER];
        while !stopped.load(Ordering::Acquire) {
            // A timeout rather than a plain read, so the stop flag is seen
            // even when no datagram ever arrives.
            let Ok(received) =
                tokio::time::timeout(STOP_POLL_INTERVAL, resolver.socket.recv_from(&mut buf)).await
            else {
                continue;
            };
            let Ok((n, from)) = received else {
                // The socket is broken; nothing will answer through it again.
                break;
            };
            if from != resolver.server {
                // Somebody else's packet. The socket is not connected, so
                // anything can arrive on it.
                continue;
            }
            resolver.deliver(buf[..n].to_vec());
        }
    });
}

/// Whether `answer` answers the question `query` asked.
///
/// The name is compared without regard to case — DNS names are case-insensitive
/// — and the type and the class have to match exactly: an answer for one class
/// is not an answer for another whose name and type happen to match.
fn answers_the_question(answer: &[u8], query: &[u8]) -> bool {
    // QR: a query is the wrong kind of packet to be answering with.
    if answer.len() < 12 || answer[2] & 0x80 == 0 {
        return false;
    }
    let Some((answer_name, answer_rest)) = question_of(answer) else {
        return false;
    };
    let Some((name, rest)) = question_of(query) else {
        return false;
    };
    answer_name.eq_ignore_ascii_case(name) && answer_rest == rest
}

/// The question a message asks: the name, the type and the class.
///
/// The question is the first thing in the message, and a compression pointer
/// can only point backwards, so a message carries its question as plain bytes
/// — the same bytes the query had.
fn question_of(message: &[u8]) -> Option<(&[u8], &[u8])> {
    if message.len() < 12 {
        return None;
    }
    // More than one question is not something this client asks or answers; a
    // message with none is not a message that answers anything.
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    if qdcount != 1 {
        return None;
    }

    let start = 12;
    let mut offset = start;
    loop {
        let Some(&label_len) = message.get(offset) else {
            return None;
        };
        offset += 1;
        if label_len == 0 {
            break;
        }
        // A pointer, not a length: the two top bits are set. The question is
        // the first thing in the message, so it cannot be one.
        if label_len & 0xC0 != 0 {
            return None;
        }
        offset += label_len as usize;
        if offset > message.len() {
            return None;
        }
    }

    // The type and the class follow the name.
    let end = offset + 4;
    if end > message.len() {
        return None;
    }
    Some((&message[start..offset], &message[offset..end]))
}

#[cfg(test)]
mod tests {
    use super::{UpstreamResolvers, answers_the_question, question_of, resolver_scope};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// `example.com` in wire form: one length byte per label, then the
    /// terminator.
    fn wire_name() -> Vec<u8> {
        vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]
    }

    /// `other.test` in wire form.
    fn other_name() -> Vec<u8> {
        vec![
            0x05, b'o', b't', b'h', b'e', b'r', 0x04, b't', b'e', b's', b't', 0x00,
        ]
    }

    /// A query packet: 12 bytes of header, then the question.
    fn query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    /// The same, with the header's QR bit set: an answer rather than a query.
    fn answer(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut packet = query(name, qtype);
        packet[2] |= 0x80;
        packet
    }

    /// The name in a message's question, read back as text.
    fn question_name(message: &[u8]) -> String {
        let mut labels = Vec::new();
        let mut offset = 12;
        loop {
            let len = message[offset] as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            labels.push(String::from_utf8_lossy(&message[offset..offset + len]).into_owned());
            offset += len;
        }
        labels.join(".")
    }

    /// A resolver that answers what it is asked, and remembers where the
    /// queries came from.
    ///
    /// The answer carries the question it was asked and **no records at all**:
    /// an answer with no records has no TTL, and the client keeps no answer it
    /// has no TTL for — so every query really goes out, which is what these
    /// tests are about.
    struct FakeUpstream {
        address: SocketAddr,
        /// The source address of every query that arrived, with the ID it
        /// carried.
        seen: Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    }

    impl FakeUpstream {
        /// A resolver that answers every question it is asked.
        async fn start() -> Self {
            Self::spawn(false).await
        }

        /// A resolver whose answers carry an ID nobody is waiting for.
        async fn start_answering_with_a_wrong_id() -> Self {
            Self::spawn(true).await
        }

        async fn spawn(wrong_id: bool) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
            let address = socket.local_addr().expect("the address it got");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                    let query = &buf[..n];
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((from, u16::from_be_bytes([query[0], query[1]])));

                    let mut reply = query.to_vec();
                    // QR: this is an answer, not another query.
                    reply[2] |= 0x80;
                    if wrong_id {
                        // An ID nobody is waiting for: a datagram from
                        // somewhere else, arriving on this socket.
                        reply[0] ^= 0xff;
                        reply[1] ^= 0xff;
                    }
                    socket.send_to(&reply, from).await.ok();
                }
            });

            Self { address, seen }
        }

        /// Where every query came from, and the ID it carried.
        fn seen(&self) -> Vec<(SocketAddr, u16)> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    /// The resolvers under test, with nothing to stop them.
    fn resolvers_for(address: SocketAddr) -> UpstreamResolvers {
        UpstreamResolvers::new(&[address], Arc::new(AtomicBool::new(false)))
    }

    /// The socket is the point.
    ///
    /// A query that built a socket of its own would come from a new source
    /// port every time, and every router between the device and the resolver
    /// would have to keep a mapping for it — a mapping it tears down again as
    /// soon as the answer is in. The same socket for every query is what keeps
    /// the mapping alive.
    #[tokio::test]
    async fn every_query_leaves_from_the_same_socket() {
        let upstream = FakeUpstream::start().await;
        let resolvers = resolvers_for(upstream.address);

        let first = resolvers.forward(&query(&wire_name(), 1)).await;
        let second = resolvers.forward(&query(&wire_name(), 1)).await;

        assert!(first.is_some(), "the first query is answered");
        assert!(second.is_some(), "the second query is answered");

        let seen = upstream.seen();
        assert_eq!(seen.len(), 2, "both queries reached the resolver");
        assert_eq!(
            seen[0].0.port(),
            seen[1].0.port(),
            "both queries left from the same socket"
        );
    }

    /// Two applications on the device may pick the same transaction ID for
    /// different questions at the same moment. The answers must still reach
    /// the questions they answer.
    #[tokio::test]
    async fn two_queries_with_the_same_id_get_their_own_answers() {
        let upstream = FakeUpstream::start().await;
        let resolvers = resolvers_for(upstream.address);

        let mut first = query(&wire_name(), 1);
        let mut second = query(&other_name(), 1);
        // The same ID, the way two applications that know nothing about each
        // other would pick one.
        first[0] = 0x12;
        first[1] = 0x34;
        second[0] = 0x12;
        second[1] = 0x34;

        let (first_answer, second_answer) =
            tokio::join!(resolvers.forward(&first), resolvers.forward(&second));

        let first_answer = first_answer.expect("the first query is answered");
        let second_answer = second_answer.expect("the second query is answered");

        assert_eq!(
            question_name(&first_answer),
            "example.com",
            "the first query got the answer to the first question"
        );
        assert_eq!(
            question_name(&second_answer),
            "other.test",
            "the second query got the answer to the second question"
        );
        assert_eq!(
            &first_answer[0..2],
            &[0x12, 0x34],
            "the first answer carries the ID the application asked with"
        );
        assert_eq!(
            &second_answer[0..2],
            &[0x12, 0x34],
            "the second answer carries the ID the application asked with"
        );
    }

    /// The ID that goes upstream is the client's, not the application's: the
    /// application's is only good while it is the only query on the wire.
    #[tokio::test]
    async fn the_id_that_goes_upstream_is_the_clients_own() {
        let upstream = FakeUpstream::start().await;
        let resolvers = resolvers_for(upstream.address);

        let mut asked = query(&wire_name(), 1);
        asked[0] = 0xab;
        asked[1] = 0xcd;

        let answer = resolvers.forward(&asked).await.expect("an answer");

        assert_eq!(
            &answer[0..2],
            &[0xab, 0xcd],
            "the application's ID is back in the answer"
        );
        let seen = upstream.seen();
        assert_eq!(seen.len(), 1, "the query reached the resolver");
        assert_ne!(
            seen[0].1, 0xabcd,
            "the ID that went upstream is not the application's"
        );
    }

    /// An answer that belongs to nobody is not taken: the wait goes on, and
    /// the query ends in nothing rather than in a wrong answer.
    #[tokio::test]
    async fn an_answer_with_an_id_nobody_waits_for_is_not_taken() {
        let upstream = FakeUpstream::start_answering_with_a_wrong_id().await;
        let resolvers = resolvers_for(upstream.address);

        let answer = resolvers.forward(&query(&wire_name(), 1)).await;

        assert!(answer.is_none(), "the forged answer is not taken");
    }

    #[test]
    fn the_question_is_the_name_the_type_and_the_class() {
        let packet = query(&wire_name(), 1);
        let (name, rest) = question_of(&packet).expect("the question is there");
        assert_eq!(name, &wire_name()[..]);
        assert_eq!(rest, &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn a_message_with_no_question_has_none() {
        assert!(question_of(&[0u8; 12]).is_none());
    }

    #[test]
    fn an_answer_to_the_question_is_taken() {
        assert!(answers_the_question(
            &answer(&wire_name(), 1),
            &query(&wire_name(), 1)
        ));
    }

    #[test]
    fn an_answer_to_another_name_is_not_taken() {
        let other = vec![0x03, b'f', b'o', b'o', 0x00];
        assert!(!answers_the_question(
            &answer(&other, 1),
            &query(&wire_name(), 1)
        ));
    }

    #[test]
    fn an_answer_to_another_type_is_not_taken() {
        assert!(!answers_the_question(
            &answer(&wire_name(), 28),
            &query(&wire_name(), 1)
        ));
    }

    /// A query is not an answer, whatever else it is.
    #[test]
    fn a_query_is_not_an_answer() {
        assert!(!answers_the_question(
            &query(&wire_name(), 1),
            &query(&wire_name(), 1)
        ));
    }

    /// The name is compared without regard to case: DNS names are
    /// case-insensitive, and a resolver that echoes the name in its own case
    /// has answered.
    #[test]
    fn the_name_is_compared_without_regard_to_case() {
        let mut shouted = wire_name();
        shouted[1] = b'E';
        assert!(answers_the_question(
            &answer(&shouted, 1),
            &query(&wire_name(), 1)
        ));
    }

    #[test]
    fn the_scope_names_the_resolvers_it_was_built_from() {
        let servers: Vec<SocketAddr> = vec!["1.1.1.1:53".parse().unwrap()];
        assert_eq!(&*resolver_scope(&servers), "1.1.1.1:53");
    }

    #[test]
    fn no_resolvers_is_an_empty_set() {
        let resolvers = UpstreamResolvers::new(&[], Arc::new(AtomicBool::new(false)));
        assert!(resolvers.is_empty());
        assert_eq!(resolvers.len(), 0);
    }

    /// The order a caller gives is the order it is asked in, family and all:
    /// the desktop's chain puts the machine's own resolvers before the public
    /// fallbacks because only the former know its internal names.
    #[tokio::test]
    async fn with_timeouts_keeps_the_order_it_is_given() {
        let servers: Vec<SocketAddr> =
            vec!["[::1]:53".parse().unwrap(), "127.0.0.1:53".parse().unwrap()];
        let resolvers = UpstreamResolvers::with_timeouts(
            &servers,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(50),
            Duration::from_millis(100),
        );
        let asked: Vec<SocketAddr> = resolvers
            .inner
            .resolvers
            .iter()
            .map(|resolver| resolver.server)
            .collect();
        assert_eq!(asked, servers);
    }

    /// The local proxy's own entry point still asks IPv4 first: a phone's IPv6
    /// path is the one more likely to be a dead end.
    #[tokio::test]
    async fn new_asks_ipv4_servers_first() {
        let servers: Vec<SocketAddr> =
            vec!["[::1]:53".parse().unwrap(), "127.0.0.1:53".parse().unwrap()];
        let resolvers = UpstreamResolvers::new(&servers, Arc::new(AtomicBool::new(false)));
        let asked: Vec<SocketAddr> = resolvers
            .inner
            .resolvers
            .iter()
            .map(|resolver| resolver.server)
            .collect();
        assert_eq!(
            asked,
            vec!["127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap()]
        );
    }
}
