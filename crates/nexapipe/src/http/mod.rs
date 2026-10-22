//! The HTTP half of the proxy: what a request is, and what is done with it.

// The five halves of it: the clients the backends are reached through, the
// bodies, the response and the failure, the forwarding, and the hand-written
// parser the tunnel path needs.
mod body;
mod client;
mod forward;
mod legacy;
mod response;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport;

pub use body::*;
pub use client::*;
pub use forward::*;
pub use legacy::*;
pub use response::*;
