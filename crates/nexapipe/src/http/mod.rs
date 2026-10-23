//! The HTTP half of the proxy: what a request is, and what is done with it.

// The six halves of it: the clients the backends are reached through, the
// bodies, the reader a request's body is shared through, the response and the
// failure, the forwarding, and the hand-written parser the tunnel path needs.
mod body;
mod client;
mod forward;
mod legacy;
mod reader;
mod response;
pub mod server;
mod websocket;

// The tests of the HTTP half: the ones that need nothing but the code, and
// the ones that need a backend that speaks TLS.
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;

pub use body::*;
pub use client::*;
pub use forward::*;
pub use legacy::*;
pub use response::*;
