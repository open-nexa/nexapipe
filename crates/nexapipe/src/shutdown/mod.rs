use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::signal;

pub struct ShutdownSignal {
    shutdown_requested: AtomicBool,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    pub fn new() -> Self {
        ShutdownSignal {
            shutdown_requested: AtomicBool::new(false),
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested
            .store(true, std::sync::atomic::Ordering::Relaxed);
        tracing::info!("Shutdown requested");
    }
}

#[cfg(unix)]
pub async fn wait_for_shutdown_signal(shutdown_signal: Arc<ShutdownSignal>) {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM signal");
            shutdown_signal.request_shutdown();
        }
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT signal");
            shutdown_signal.request_shutdown();
        }
    }
}

#[cfg(windows)]
pub async fn wait_for_shutdown_signal(shutdown_signal: Arc<ShutdownSignal>) {
    match signal::ctrl_c().await {
        Ok(()) => {
            tracing::info!("Received Ctrl+C signal");
            shutdown_signal.request_shutdown();
        }
        Err(e) => {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
        }
    }
}

pub type SharedShutdownSignal = Arc<ShutdownSignal>;

/// Work the process is still holding, so a shutdown can wait for it instead of
/// guessing with a sleep.
///
/// Connections, not requests: a WebSocket session or a long L4 flow is one unit
/// for as long as it lives, and draining means letting those finish rather than
/// cutting them at an arbitrary second.
#[derive(Debug, Default)]
pub struct InFlight {
    count: AtomicUsize,
}

impl InFlight {
    pub fn new() -> Self {
        InFlight::default()
    }

    /// Registers one unit of work. The returned guard decrements when dropped,
    /// so a task that returns early, is cancelled or panics cannot leak a count
    /// and strand the shutdown.
    pub fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        InFlightGuard {
            in_flight: self.clone(),
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Waits for the count to reach zero, giving up after `limit` so a stuck
    /// peer cannot hold the process open forever.
    pub async fn wait_until_idle(&self, limit: std::time::Duration) {
        let deadline = tokio::time::Instant::now() + limit;

        loop {
            if self.count() == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    "Giving up on draining after {:?} with {} connection(s) still open",
                    limit,
                    self.count()
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Kept alive for as long as the work it stands for; see [`InFlight::enter`].
pub struct InFlightGuard {
    in_flight: Arc<InFlight>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.count.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long a shutdown waits for open connections before it stops waiting.
/// Long enough for an in-flight response, short enough that `systemctl stop`
/// does not hang.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_count_follows_the_guards() {
        let in_flight = Arc::new(InFlight::new());
        assert_eq!(in_flight.count(), 0);

        let a = in_flight.enter();
        let b = in_flight.enter();
        assert_eq!(in_flight.count(), 2);

        drop(a);
        assert_eq!(in_flight.count(), 1);
        drop(b);
        assert_eq!(in_flight.count(), 0);
    }

    #[tokio::test]
    async fn a_dropped_task_does_not_strand_the_shutdown() {
        let in_flight = Arc::new(InFlight::new());

        // Stands in for a connection task cancelled mid-request: the guard has
        // to run its `Drop` even then, or the drain waits for a connection that
        // no longer exists.
        let guard = in_flight.enter();
        drop(guard);

        in_flight
            .wait_until_idle(std::time::Duration::from_millis(50))
            .await;
        assert_eq!(in_flight.count(), 0);
    }

    #[tokio::test]
    async fn draining_gives_up_instead_of_hanging() {
        let in_flight = Arc::new(InFlight::new());
        let _stuck = in_flight.enter();

        // A peer that never closes must not hold the process open.
        let started = tokio::time::Instant::now();
        in_flight
            .wait_until_idle(std::time::Duration::from_millis(300))
            .await;

        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(in_flight.count(), 1);
    }
}
