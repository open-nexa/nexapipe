//! The tunnel path, served by hyper's own HTTP/1 codec.
//!
//! # What this is
//!
//! The tunnel path used to read the request head off the iroh stream by hand,
//! parse it by hand, read the body by hand, and write the answer by hand —
//! the status line, the headers, the framing, all of it assembled into a
//! buffer and pushed at the socket. Hyper does all of that, and does it the
//! way every other HTTP server does it, so the bytes on the wire are the bytes
//! a client expects from any other server.
//!
//! What is **not** hyper's is in here: which route serves a name, whether
//! this peer may use it, which backend it goes to, how a failure is retried,
//! what the access log says. Those are this project's rules, and they are the
//! same rules they were before.
//!
//! # How the two protocols get here
//!
//! A connection that named its protocol with ALPN says what it carries:
//! `nexapipe/http` is HTTP and `nexapipe/l4` is a tunnel. Nothing is sniffed
//! and nothing is read twice.
//!
//! A connection that named the old ALPN does not say, so the first byte is
//! read to find out: `0x05` is an L4 preface, `0x16` is a TLS hello, and
//! anything else is a request line. That one byte is **handed back** to hyper
//! with the rest of the stream, so hyper reads the head from the beginning
//! and nothing is lost or parsed twice.
//!
//! That is the one thing the ALPN change bought: the protocol is known
//! before a byte is read, so the codec does not have to guess.

use std::sync::Arc;

use crate::auth::ClientAcl;
use crate::conn::peers::PeerIdentity;
use crate::http::client::BackendClients;
use crate::routes::RoutingTable;

mod body;
mod forward;
mod report;
mod request;
mod serve;

#[cfg(test)]
mod tests;

pub use body::{BodyFailure, IncomingBody, LentBody, RequestBody};
pub use hyper::body::{Frame, Incoming};
pub use report::{AccessReport, CountedBody};
pub use serve::serve;

pub(in crate::http) use self::forward::forward;

/// The largest request head hyper will buffer.
///
/// The hand-written parser refused a head over 64 KiB, and it refused it
/// *before* forwarding anything: a head that large is not a request, and a
/// peer that sends one is not one to be given a backend.
pub const MAX_HEAD: usize = 64 * 1024;

/// What the service needs to answer a request.
///
/// Everything here is the tunnel path's own rules. The connection's peer and
/// its credentials travel with the request because the service runs once per
/// request, on a connection that may carry several.
///
/// It is cloned per request rather than shared: the id of a request is the
/// id of that request, and a connection may carry several.
#[derive(Clone)]
pub struct Context {
    /// The routes, and the timeouts they carry.
    pub config: Arc<RoutingTable>,
    /// The clients the backends are reached through.
    pub clients: Arc<BackendClients>,
    /// Where the connection came from, for the access log.
    pub peer: String,
    /// Who may use which route. `None` when there is no allow list.
    pub acl: Option<Arc<ClientAcl>>,
    /// The id of this request, for the access log and the `x-request-id` header.
    ///
    /// **The id of the request, not of the connection.** The connection's own
    /// context starts with the id of the stream, and the service hands each
    /// request a context of its own with the id of that request in it — hyper
    /// serves keep-alive requests on one stream, so an id that belonged to the
    /// connection would belong to every request on it.
    pub request_id: String,
    /// Who the connection authenticated as, for the access log.
    pub who: PeerIdentity,
}
