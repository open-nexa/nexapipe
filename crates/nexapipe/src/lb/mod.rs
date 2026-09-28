use rand;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
}

#[derive(Debug, Clone)]
pub struct BackendStatus {
    url: String,
    healthy: bool,
    last_check: Option<std::time::Instant>,
    consecutive_failures: usize,
}

impl BackendStatus {
    pub fn new(url: String) -> Self {
        BackendStatus {
            url,
            healthy: true,
            last_check: None,
            consecutive_failures: 0,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    pub fn mark_healthy(&mut self) {
        self.healthy = true;
        self.consecutive_failures = 0;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
        self.consecutive_failures += 1;
        self.last_check = Some(std::time::Instant::now());
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }
}

#[derive(Debug, Clone)]
pub struct BackendPool {
    backends: Vec<Arc<RwLock<BackendStatus>>>,
    strategy: LoadBalancingStrategy,
    round_robin_index: Arc<RwLock<usize>>,
}

impl BackendPool {
    pub fn new(backends: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        let backend_statuses = backends
            .into_iter()
            .map(|url| Arc::new(RwLock::new(BackendStatus::new(url))))
            .collect();

        BackendPool {
            backends: backend_statuses,
            strategy,
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn select_backend(&self) -> String {
        let mut healthy_backends = Vec::new();
        for (i, b) in self.backends.iter().enumerate() {
            if b.read().await.is_healthy() {
                healthy_backends.push(i);
            }
        }

        if healthy_backends.is_empty() {
            // Still handed out, and deliberately: a route whose backends are all
            // down keeps answering 502 rather than going dark, and the client
            // gets an error it can act on instead of a hang. Callers that need
            // to tell this from a healthy pool ask `healthy_count`.
            tracing::warn!("No healthy backends available, falling back to all backends");
            return if let Some(b) = self.backends.first() {
                b.read().await.url.clone()
            } else {
                String::new()
            };
        }

        let idx = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                let idx = healthy_backends[*index % healthy_backends.len()];
                *index = (*index + 1) % healthy_backends.len();
                idx
            }
            LoadBalancingStrategy::Random => {
                let rand_idx = (rand::random::<u64>() % healthy_backends.len() as u64) as usize;
                healthy_backends[rand_idx]
            }
        };

        let selected = &self.backends[idx];
        let url = selected.read().await.url.clone();
        tracing::debug!("Selected backend: {} (strategy={:?})", url, self.strategy);
        url
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn strategy(&self) -> LoadBalancingStrategy {
        self.strategy
    }

    pub async fn backends(&self) -> Vec<String> {
        let mut result = Vec::new();
        for b in &self.backends {
            result.push(b.read().await.url.clone());
        }
        result
    }

    /// How many backends are healthy right now.
    ///
    /// `select_backend` never returns nothing — a pool with no healthy backend
    /// still hands one out, so a dead route answers 502 instead of going dark —
    /// so this is the only way a caller can tell that case from a pool that is
    /// actually serving traffic.
    pub async fn healthy_count(&self) -> usize {
        let mut count = 0;
        for backend in &self.backends {
            if backend.read().await.is_healthy() {
                count += 1;
            }
        }
        count
    }

    pub async fn set_backend_health(&self, url: &str, healthy: bool) {
        // Every entry carrying this URL, not the first: a pool is allowed to
        // name the same backend twice, and stopping at the first left the rest
        // healthy forever — so the pool reported a backend as up while half its
        // entries were down and the balancer kept picking them.
        let mut matched = false;
        for backend in &self.backends {
            let mut status = backend.write().await;
            if status.url != url {
                continue;
            }
            matched = true;
            if healthy {
                status.mark_healthy();
            } else {
                status.mark_unhealthy();
            }
            tracing::debug!(
                "Backend {} health status: {} (failures: {})",
                url,
                healthy,
                status.consecutive_failures()
            );
        }

        if !matched {
            tracing::debug!("set_backend_health: no backend named {url} in this pool");
        }
    }

    pub async fn get_backend_statuses(&self) -> Vec<(String, bool)> {
        let mut result = Vec::new();
        for b in &self.backends {
            let status = b.read().await;
            result.push((status.url.clone(), status.healthy));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(backends: &[&str]) -> BackendPool {
        BackendPool::new(
            backends.iter().map(|b| b.to_string()).collect(),
            LoadBalancingStrategy::RoundRobin,
        )
    }

    #[tokio::test]
    async fn every_entry_carrying_a_url_is_marked_not_just_the_first() {
        let pool = pool(&["http://a:80", "http://a:80"]);
        assert_eq!(pool.healthy_count().await, 2);

        pool.set_backend_health("http://a:80", false).await;

        assert_eq!(
            pool.get_backend_statuses().await,
            vec![
                ("http://a:80".to_string(), false),
                ("http://a:80".to_string(), false),
            ],
            "the second entry stayed healthy, so the balancer kept picking a backend the pool had already given up on"
        );
        assert_eq!(pool.healthy_count().await, 0);
    }

    #[tokio::test]
    async fn a_pool_with_no_healthy_backend_says_so_and_still_answers() {
        let pool = pool(&["http://a:80", "http://b:80"]);
        pool.set_backend_health("http://a:80", false).await;
        pool.set_backend_health("http://b:80", false).await;

        // select_backend still hands one out — a route with a dead backend
        // answers 502 rather than going dark — so the count is the only way to
        // tell this pool from one that is serving traffic.
        assert_eq!(pool.healthy_count().await, 0);
        assert!(
            !pool.select_backend().await.is_empty(),
            "a pool with no healthy backend still has to name one"
        );
    }
}
