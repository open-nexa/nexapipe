use crate::http::HttpClient;
use crate::lb::BackendPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, sleep};

pub struct HealthChecker {
    backend_pool: Arc<BackendPool>,
    client: Arc<HttpClient>,
    interval: Duration,
    timeout: Duration,
    failure_threshold: usize,
    health_path: String,
    /// Shared with the config watcher so `[health_check] enabled` can be
    /// switched while the process runs: a probe already spawned outlives the
    /// reload that would otherwise have to cancel it, so it is paused instead.
    enabled: Arc<AtomicBool>,
    /// Consecutive failed probes per backend, kept here because a `BackendPool`
    /// only stores the outcome. A backend leaves the pool once this reaches
    /// `failure_threshold` and returns on the first probe that succeeds.
    failures: Mutex<HashMap<String, usize>>,
}

impl HealthChecker {
    pub fn new(
        backend_pool: Arc<BackendPool>,
        client: Arc<HttpClient>,
        interval: Duration,
        timeout: Duration,
        failure_threshold: usize,
        health_path: &str,
        enabled: Arc<AtomicBool>,
    ) -> Self {
        HealthChecker {
            backend_pool,
            client,
            interval,
            timeout,
            failure_threshold: failure_threshold.max(1),
            health_path: health_path.to_string(),
            failures: Mutex::new(HashMap::new()),
            enabled,
        }
    }

    pub async fn run(self) {
        tracing::info!(
            "Health checker started with interval={:?}, timeout={:?}, threshold={}",
            self.interval,
            self.timeout,
            self.failure_threshold
        );

        loop {
            // Paused, not cancelled: the task is owned by nobody after spawn,
            // so `[health_check] enabled = false` on a reload stops the probing
            // without having to reach into every checker.
            if self.enabled.load(Ordering::Relaxed) {
                self.check_all_backends().await;
            }
            sleep(self.interval).await;
        }
    }

    async fn check_all_backends(&self) {
        let backends = self.backend_pool.backends().await;
        for url in backends {
            let is_healthy = self.check_backend(&url).await;
            let failures = self.record_result(&url, is_healthy);
            let statuses = self.backend_pool.get_backend_statuses().await;
            let current_healthy = statuses
                .into_iter()
                .find(|(u, _)| u == &url)
                .map(|(_, h)| h);

            if is_healthy {
                if current_healthy == Some(false) {
                    tracing::info!("Backend {} recovered, marking healthy", url);
                    self.backend_pool.set_backend_health(&url, true).await;
                }
                continue;
            }

            // One failed probe proves little, so the count, not the failure,
            // is what empties the pool.
            if failures < self.failure_threshold {
                tracing::debug!(
                    "Backend {} health check failed ({}/{})",
                    url,
                    failures,
                    self.failure_threshold
                );
                continue;
            }

            if current_healthy != Some(false) {
                tracing::warn!(
                    "Backend {} failed {} consecutive health checks, marking unhealthy",
                    url,
                    failures
                );
                self.backend_pool.set_backend_health(&url, false).await;
            }
        }
    }

    /// Counts consecutive failures for one backend and returns the new count.
    /// A success resets it, so a backend that flaps once is not punished for a
    /// failure that happened an hour ago.
    fn record_result(&self, url: &str, healthy: bool) -> usize {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if healthy {
            failures.remove(url);
            0
        } else {
            let count = failures.get(url).copied().unwrap_or(0) + 1;
            failures.insert(url.to_string(), count);
            count
        }
    }

    async fn check_backend(&self, url: &str) -> bool {
        let health_url = format!("{}{}", url, self.health_path);

        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&health_url)
            .header("host", "health-check")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();

        match tokio::time::timeout(self.timeout, self.client.request(request)).await {
            Ok(Ok(response)) => {
                let status = response.status();
                // Treat 2xx and 404 as healthy: some backends don't implement
                // a dedicated health endpoint and return 404 for unknown paths,
                // which still indicates the server is up and responding.
                let healthy = status.is_success() || status.as_u16() == 404;
                // Per-result details stay at debug: the check runs on every tick, so a backend
                // that is down would otherwise log this once per interval. The state changes
                // that actually matter are logged in `check_all_backends`.
                if healthy {
                    tracing::debug!("Backend {} health check passed: {}", url, status);
                } else {
                    tracing::debug!("Backend {} health check failed: {}", url, status);
                }
                healthy
            }
            Ok(Err(e)) => {
                tracing::debug!("Backend {} health check error: {}", url, e);
                false
            }
            Err(_) => {
                tracing::debug!("Backend {} health check timed out", url);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http;
    use crate::lb::LoadBalancingStrategy;
    use std::sync::atomic::AtomicBool;

    /// A port nothing listens on: the probe fails immediately, with no network
    /// and no server to stand up.
    const DEAD_BACKEND: &str = "http://127.0.0.1:1";

    fn checker(
        pool: Arc<BackendPool>,
        threshold: usize,
        enabled: Arc<AtomicBool>,
    ) -> HealthChecker {
        HealthChecker::new(
            pool,
            Arc::new(http::create_http_client()),
            Duration::from_millis(10),
            Duration::from_millis(200),
            threshold,
            "/health",
            enabled,
        )
    }

    fn pool() -> Arc<BackendPool> {
        Arc::new(BackendPool::new(
            vec![DEAD_BACKEND.to_string()],
            LoadBalancingStrategy::RoundRobin,
        ))
    }

    async fn healthy(pool: &BackendPool, url: &str) -> bool {
        pool.get_backend_statuses()
            .await
            .into_iter()
            .find(|(u, _)| u == url)
            .map(|(_, h)| h)
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn one_failed_probe_never_takes_a_backend_out() {
        let pool = pool();
        let checker = checker(pool.clone(), 3, Arc::new(AtomicBool::new(true)));

        checker.check_all_backends().await;

        assert!(
            healthy(&pool, DEAD_BACKEND).await,
            "a single failed probe must not empty the pool"
        );
    }

    #[tokio::test]
    async fn the_threshold_is_what_takes_a_backend_out() {
        let pool = pool();
        let checker = checker(pool.clone(), 2, Arc::new(AtomicBool::new(true)));

        checker.check_all_backends().await;
        assert!(healthy(&pool, DEAD_BACKEND).await);

        checker.check_all_backends().await;
        assert!(
            !healthy(&pool, DEAD_BACKEND).await,
            "two consecutive failures reached the threshold"
        );
    }

    #[tokio::test]
    async fn disabling_the_check_leaves_the_pool_alone() {
        let pool = pool();
        let enabled = Arc::new(AtomicBool::new(false));
        let checker = checker(pool.clone(), 1, enabled.clone());

        // Through `run`, because that is where the switch lives — the loop never
        // returns, so it is spawned rather than awaited.
        tokio::spawn(async move { checker.run().await });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            healthy(&pool, DEAD_BACKEND).await,
            "a disabled checker must not probe at all"
        );

        // What a reload that turns `[health_check] enabled` back on does.
        enabled.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !healthy(&pool, DEAD_BACKEND).await,
            "enabling the check starts probing again"
        );
    }
}
