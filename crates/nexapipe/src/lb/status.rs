/// What is known about a backend that is **not** on the request's path.
///
/// The address and the health flag are not here: both are read on every
/// request, so they sit on the entry beside this, where reading them needs
/// no lock at all. What is left is the bookkeeping — when the backend was
/// last probed and how many times in a row it has failed — which is read by
/// the operator's view and by nobody on the hot path.
#[derive(Debug, Clone, Default)]
pub struct BackendStatus {
    last_check: Option<std::time::Instant>,
    consecutive_failures: usize,
}

impl BackendStatus {
    /// The backend is up.
    pub fn mark_healthy(&mut self) {
        self.consecutive_failures = 0;
        self.last_check = Some(std::time::Instant::now());
    }

    /// The backend is down.
    pub fn mark_unhealthy(&mut self) {
        self.consecutive_failures += 1;
        self.last_check = Some(std::time::Instant::now());
    }

    /// How many times in a row it has failed.
    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    /// When it was last probed.
    pub fn last_check(&self) -> Option<std::time::Instant> {
        self.last_check
    }
}
