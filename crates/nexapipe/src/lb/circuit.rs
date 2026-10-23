/// Where a backend's circuit stands.
///
/// Two states, not three: a circuit is closed (traffic flows, failures are
/// counted) or open (the backend is out of rotation until the cooldown
/// passes). The trial request that the cooldown allows is not a state of its
/// own — it is a closed circuit that re-opens on the first failure instead of
/// on the fifth, which is the same rule with one fewer step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Closed,
    Open,
}

#[derive(Debug)]
pub(super) struct CircuitState {
    pub(super) phase: Phase,
    /// Consecutive failures, reset by a success.
    pub(super) failures: usize,
    /// When the circuit opened, for the cooldown.
    pub(super) opened_at: Option<std::time::Instant>,
}

impl CircuitState {
    pub(super) fn new() -> Self {
        CircuitState {
            phase: Phase::Closed,
            failures: 0,
            opened_at: None,
        }
    }
}
