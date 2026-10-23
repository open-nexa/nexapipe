//! The load balancer: which backend a flow goes to, and what happens when one
//! of them stops answering.

// The file is one thing, and it is four: the pool with the entries in it and
// the lease it hands out, the strategies the pool picks by, the circuit that
// takes a failing backend out of rotation, and the bookkeeping beside an
// entry that says how it has been doing.
mod circuit;
mod pool;
mod status;
mod strategy;

#[cfg(test)]
mod tests;

pub use pool::{BackendLease, BackendPool};
pub use status::BackendStatus;
pub use strategy::LoadBalancingStrategy;
