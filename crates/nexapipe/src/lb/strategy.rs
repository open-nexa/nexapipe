#[derive(Debug, Clone, Copy)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    /// Fewest requests outstanding to this backend wins; see
    /// [`BackendPool::select_backend`] for what "outstanding" counts and what
    /// happens to the ties.
    ///
    /// [`BackendPool::select_backend`]: crate::lb::BackendPool::select_backend
    LeastConn,
}
