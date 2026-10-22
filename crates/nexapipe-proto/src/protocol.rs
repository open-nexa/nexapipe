//! Choosing the protocol at the handshake.
//!
//! # What this is for
//!
//! A connection used to carry everything: an HTTP request, an L4 tunnel and a
//! TLS session all went over the same QUIC connection, and the server told
//! them apart by **the first byte of each stream** — `0x05` is an L4
//! preface, `0x16` is a TLS ClientHello, anything else is an HTTP request
//! line.
//!
//! That works, and it is what the server still does for a client that asks
//! for [`ALPN_LEGACY`]. But it makes the server **sniff**: the first bytes
//! have to be read before the connection's purpose is known, and a codec
//! that wants the whole head — [`hyper`](https://docs.rs/hyper) — cannot
//! have it without the bytes being read and handed back.
//!
//! Choosing the protocol with ALPN says the same thing at the handshake,
//! where it belongs, and the server knows what a connection is before a
//! single byte of it is read.
//!
//! # The cost
//!
//! A protocol is per **connection**, so a client that speaks more than one
//! protocol holds a connection for each. That is the trade: one handshake
//! more, and one connection's buffers more, against a server that knows
//! what it is serving.
//!
//! # The old one
//!
//! [`ALPN_LEGACY`] is what the client used before this, and it keeps
//! working: a connection negotiated with it is served the way it always
//! was, by the first byte of each stream. It is not removed — a client
//! that predates this cannot be made to speak a protocol it does not know.

/// The ALPN of a connection that carries HTTP requests.
pub const ALPN_HTTP: &[u8] = b"nexapipe/http";

/// The ALPN of a connection that carries L4 tunnels.
pub const ALPN_L4: &[u8] = b"nexapipe/l4";

/// The ALPN of a connection that carries a TLS session, terminated by the
/// backend.
pub const ALPN_TLS: &[u8] = b"nexapipe/tls";

/// What a connection carries.
///
/// The three named protocols are chosen at the handshake; [`Protocol::Legacy`]
/// is the one where the first byte of each stream decides, and it is what
/// every client spoke before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// HTTP requests.
    Http,
    /// L4 tunnels: a TCP or UDP stream to a backend, framed by the preface
    /// in [`crate::preface`].
    L4,
    /// A TLS session, terminated by the backend and routed on its SNI.
    Tls,
    /// The first byte of each stream decides.
    ///
    /// This is the **generic** name, and it is what a client that names no
    /// protocol in particular gets: the server serves it the way it always
    /// did, by reading the first byte of each stream.
    Legacy,
}

impl Protocol {
    /// The ALPN this protocol is spoken with.
    ///
    /// [`Protocol::Legacy`] speaks the old one, because that is what a
    /// connection that says nothing else is served as.
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Protocol::Http => ALPN_HTTP,
            Protocol::L4 => ALPN_L4,
            Protocol::Tls => ALPN_TLS,
            // The generic name: the first byte of each stream decides, which
            // is what a connection that named nothing in particular is served
            // as.
            Protocol::Legacy => crate::ALPN_NEXAPIPE,
        }
    }

    /// The protocol an ALPN names, if it names one.
    ///
    /// `None` for an ALPN this build does not know: the connection is
    /// refused rather than served as something it is not.
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            ALPN_HTTP => Some(Protocol::Http),
            ALPN_L4 => Some(Protocol::L4),
            ALPN_TLS => Some(Protocol::Tls),
            crate::ALPN_NEXAPIPE => Some(Protocol::Legacy),
            _ => None,
        }
    }

    /// The name of the protocol, for a log line.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::L4 => "l4",
            Protocol::Tls => "tls",
            Protocol::Legacy => "legacy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_round_trips_through_its_alpn() {
        for protocol in [
            Protocol::Http,
            Protocol::L4,
            Protocol::Tls,
            Protocol::Legacy,
        ] {
            assert_eq!(
                Protocol::from_alpn(protocol.alpn()),
                Some(protocol),
                "{} does not survive its own ALPN",
                protocol.name()
            );
        }
    }

    #[test]
    fn an_alpn_nobody_claimed_names_no_protocol() {
        assert_eq!(Protocol::from_alpn(b"nexapipe/nonsense"), None);
        assert_eq!(Protocol::from_alpn(b""), None);
    }

    /// The generic name is the generic one: it is the name a client that
    /// names no protocol in particular gets, and it is served the way it
    /// always was.
    #[test]
    fn the_generic_name_is_the_generic_one() {
        assert_eq!(Protocol::Legacy.alpn(), b"nexapipe");
    }
}
