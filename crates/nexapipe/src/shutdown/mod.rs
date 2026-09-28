use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::signal;

pub struct ShutdownSignal {
    shutdown_requested: AtomicBool,
    /// Tells every loop waiting for shutdown that it was asked for, so they
    /// stop then instead of noticing it on their next poll.
    ///
    /// A `watch` rather than a `Notify`: `notify_waiters()` only reaches
    /// waiters that are already parked, and a waiter parks on its *first
    /// poll*, not when the future is created — so a request landing between
    /// "am I shutting down?" and "park me" would wake nobody, and the loop
    /// would sit there until a connection happened to arrive. `watch` carries
    /// the value itself, so a waiter that arrives late still sees it.
    requested: tokio::sync::watch::Sender<bool>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (requested, _) = tokio::sync::watch::channel(false);
        ShutdownSignal {
            shutdown_requested: AtomicBool::new(false),
            requested,
        }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resolves as soon as shutdown is requested, and immediately if it already
    /// was.
    ///
    /// Made for the `select!` in an accept loop, where the flag alone is not
    /// enough: it would have to be polled on a timer, and shutdown would then
    /// wait for the next tick.
    ///
    /// Safe to call any number of times and from any number of loops: each
    /// call subscribes its own receiver, so one request wakes all of them.
    pub async fn requested(&self) {
        // `subscribe()` marks the current value as seen, so a request that has
        // already happened is read in `borrow_and_update()` and one that
        // happens later is caught by `changed()`. Neither can slip between the
        // two steps.
        let mut requested = self.requested.subscribe();
        if *requested.borrow_and_update() {
            return;
        }
        // Ends with an error only when the sender is dropped, which for a
        // `ShutdownSignal` is the end of the process anyway.
        let _ = requested.changed().await;
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // `send_modify` and not `send`: `send` refuses to update the value
        // when nobody is subscribed yet, and the loops subscribe when they
        // start waiting — so a request made before the first one did would
        // leave the flag at `false` and the waiter would park forever.
        self.requested.send_modify(|requested| *requested = true);
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

    /// A request that lands before the wait must still be seen: a waiter that
    /// subscribes after the fact would otherwise stay parked forever, and the
    /// process would never shut down.
    #[tokio::test]
    async fn a_request_made_before_the_wait_still_wakes_it() {
        let signal = ShutdownSignal::new();
        signal.request_shutdown();

        tokio::time::timeout(std::time::Duration::from_secs(2), signal.requested())
            .await
            .expect("a shutdown requested before the wait was never seen");
    }

    /// Every loop that waits has to be woken, not one of them: the accept loop,
    /// the HTTP server and the local proxy all sit on the same signal.
    #[tokio::test]
    async fn one_request_wakes_every_waiter() {
        let signal = Arc::new(ShutdownSignal::new());

        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let signal = signal.clone();
                tokio::spawn(async move { signal.requested().await })
            })
            .collect();

        // Let all three reach their wait before the request goes out.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        signal.request_shutdown();

        for waiter in waiters {
            tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
                .await
                .expect("a waiter was never woken")
                .expect("the waiter panicked");
        }
    }

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
