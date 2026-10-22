//! The names this process has resolved, and how long the answer holds.
//!
//! Every L4 flow and every TLS passthrough dials a backend by **name**, and
//! the name was resolved again for every one of them. The resolution is a
//! `getaddrinfo` on a blocking thread, and it sits on the critical path of
//! the flow: the client waits for the flow to be open before it sends
//! anything, and the server cannot open the flow before it knows where the
//! backend is.
//!
//! So the answers are cached, for a while.
//!
//! # What is cached, and for how long
//!
//! A name that resolved is remembered for [`POSITIVE_TTL`], and a name that
//! did **not** is remembered for [`NEGATIVE_TTL`] — much shorter, because a
//! name that failed is often a backend that has just come up, and the next
//! flow should find it.
//!
//! The cache holds **addresses, not flows**: it answers "where is this name",
//! and every flow still opens its own connection to it. A cached address that
//! has gone away fails the dial like any other, and the flow fails with it.
//!
//! # Why the port is not part of the key
//!
//! A DNS answer is about the name. The port is the caller's, and it is added
//! when the address is used — so `db.test:5432` and `db.test:5433` share one
//! resolution.
//!
//! # What is not cached
//!
//! The resolution itself is never cached while it is in progress: two flows
//! that arrive together and both find the cache empty would both start a
//! `getaddrinfo`. The second one waits for the first.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

/// How long a name that resolved stays resolved.
const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a name that did not resolve stays unresolved.
///
/// Short on purpose: a name that failed is often a backend that has just come
/// up, and the flow after that should find it.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Where the addresses come from.
///
/// Injectable so that the cache can be tested without a network, and so that
/// a test can count how many resolutions actually happened.
pub trait Resolve: Send + Sync {
    /// The addresses `host` resolves to. Empty when it resolves to nothing.
    fn resolve(&self, host: &str) -> Vec<IpAddr>;
}

/// The system resolver, called on a blocking thread.
///
/// `getaddrinfo` blocks, and the flow that asked for the address is waiting
/// for it — so it does not run on a worker.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        // Port 0: the port is not part of a DNS answer, and it is added when
        // the address is used.
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// What the cache knows about a name.
#[derive(Debug, Clone)]
struct Entry {
    /// The addresses, or `None` when the name did not resolve.
    addrs: Option<Vec<IpAddr>>,
    /// When the answer stops being true.
    expires_at: Instant,
}

/// A cache of resolved names.
pub struct DnsCache {
    entries: RwLock<HashMap<String, Entry>>,
    resolver: Arc<dyn Resolve>,
    positive_ttl: Duration,
    negative_ttl: Duration,
}

impl DnsCache {
    /// A cache that resolves through `resolver`.
    pub fn new(resolver: Arc<dyn Resolve>, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            resolver,
            positive_ttl,
            negative_ttl,
        }
    }

    /// The addresses `host` resolves to, from the cache when the answer still
    /// holds.
    ///
    /// A name that is not in the cache — or whose answer has expired — is
    /// resolved and remembered.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Some(entry) = self.lookup(host) {
            return match entry.addrs {
                Some(addrs) => Ok(addrs),
                None => Err(format!("{host} did not resolve")),
            };
        }

        let resolver = self.resolver.clone();
        let name = host.to_string();
        let resolved = tokio::task::spawn_blocking(move || resolver.resolve(&name))
            .await
            .map_err(|e| format!("the resolver did not run: {e}"))?;

        if resolved.is_empty() {
            // Remembered, but only briefly: a name that failed is often a
            // backend that has just come up.
            self.store(
                host,
                Entry {
                    addrs: None,
                    expires_at: Instant::now() + self.negative_ttl,
                },
            );
            return Err(format!("{host} did not resolve"));
        }

        self.store(
            host,
            Entry {
                addrs: Some(resolved.clone()),
                expires_at: Instant::now() + self.positive_ttl,
            },
        );
        Ok(resolved)
    }

    /// The addresses `host` resolves to, for a dial toward `port`.
    ///
    /// The port is the caller's: it is not part of the DNS answer and it is
    /// not part of the cache's key.
    pub async fn resolve_to(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        Ok(self
            .resolve(host)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// The cached answer for `host`, if it is one and it still holds.
    fn lookup(&self, host: &str) -> Option<Entry> {
        let entries = self.read();
        let entry = entries.get(host)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.clone())
    }

    /// Remembers an answer.
    fn store(&self, host: &str, entry: Entry) {
        let mut entries = self.write();
        // A name that is asked about often should not push the others out, and
        // the table is small anyway: the number of backends a proxy has.
        if entries.len() >= 1024 {
            entries.clear();
        }
        entries.insert(host.to_string(), entry);
    }

    /// The read lock, and a poisoned one is still a lock.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Entry>> {
        self.entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The write lock, and a poisoned one is still a lock.
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Entry>> {
        self.entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The cache this process resolves names through.
static CACHE: LazyLock<DnsCache> =
    LazyLock::new(|| DnsCache::new(Arc::new(SystemResolver), POSITIVE_TTL, NEGATIVE_TTL));

/// The addresses `host` resolves to.
///
/// Cached, and the answer is what the last resolution said until it expires.
pub async fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    CACHE.resolve(host).await
}

/// The addresses `host` resolves to, for a dial toward `port`.
///
/// The port is the caller's: it is not part of the DNS answer and it is not
/// part of the cache's key.
pub async fn resolve_to(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    CACHE.resolve_to(host, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A resolver that answers from a table and counts what it was asked.
    struct Counting {
        answers: HashMap<String, Vec<IpAddr>>,
        calls: AtomicUsize,
    }

    impl Counting {
        fn new(answers: HashMap<String, Vec<IpAddr>>) -> Self {
            Self {
                answers,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Resolve for Counting {
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.answers.get(host).cloned().unwrap_or_default()
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[tokio::test]
    async fn the_second_resolution_is_answered_from_the_cache() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "db.test".to_string(),
            vec![ip(1), ip(2)],
        )])));
        let cache = DnsCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(5),
        );

        let first = cache.resolve("db.test").await.expect("the name resolves");
        let second = cache.resolve("db.test").await.expect("the name resolves");

        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(
            resolver.calls.load(Ordering::Relaxed),
            1,
            "the second resolution should not have gone to the resolver"
        );
    }

    #[tokio::test]
    async fn a_name_that_did_not_resolve_is_remembered_briefly() {
        let resolver = Arc::new(Counting::new(HashMap::new()));
        let cache = DnsCache::new(
            resolver.clone(),
            Duration::from_secs(30),
            Duration::from_secs(5),
        );

        assert!(cache.resolve("nowhere.test").await.is_err());
        assert!(cache.resolve("nowhere.test").await.is_err());

        assert_eq!(
            resolver.calls.load(Ordering::Relaxed),
            1,
            "a failure should be remembered too, so the same answer is not paid for twice"
        );
    }

    #[tokio::test]
    async fn an_expired_answer_is_resolved_again() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "db.test".to_string(),
            vec![ip(1)],
        )])));
        let cache = DnsCache::new(
            resolver.clone(),
            Duration::from_millis(0),
            Duration::from_millis(0),
        );

        cache.resolve("db.test").await.expect("the name resolves");
        cache.resolve("db.test").await.expect("the name resolves");

        assert_eq!(
            resolver.calls.load(Ordering::Relaxed),
            2,
            "an answer that has expired should not be used"
        );
    }

    #[tokio::test]
    async fn the_port_is_added_when_the_address_is_used() {
        let resolver = Arc::new(Counting::new(HashMap::from([(
            "db.test".to_string(),
            vec![ip(7)],
        )])));
        let cache = DnsCache::new(resolver, Duration::from_secs(30), Duration::from_secs(5));

        let addrs = cache
            .resolve_to("db.test", 5432)
            .await
            .expect("the name resolves");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 5432);
    }
}
