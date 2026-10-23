//! One stream of a connection, and what it carries.
//!
//! A connection carries several streams, and each one says what it is: the
//! first byte of an HTTP request, the preface of an L4 tunnel, the hello of a
//! TLS session. A connection that named its protocol with ALPN said so at the
//! handshake; the old one does not, so the byte is read to find out — and
//! handed back when it turns out to be part of a request.

use crate::auth::ClientAcl;
use crate::http::BackendClients;
use crate::l4;
use crate::passthrough;
use crate::routes::RoutingTable;

use nexapipe_proto::protocol::Protocol;

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use super::peers::PeerIdentity;

/// Finds the end of a header block, scanning from `from`.
///
/// `from` is what keeps a head that arrives in many small reads off O(n²):
/// the bytes before it were already scanned on an earlier read, so without it
/// every read rescanned the whole buffer, and a head delivered one segment at
/// a time cost a full pass per segment.
pub(crate) fn find_headers_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| from + pos)
}

/// The two deadlines an iroh stream starts with.
///
/// The first byte says which protocol a stream carries, and the wait for it
/// is not the HTTP head's: `header_secs` bounds an HTTP request head, and a
/// TLS or L4 client that is slow to speak must not be cut off by it. Those two
/// protocols have their own budgets, and a client on them never sends a
/// request head at all.
///
/// Until the byte arrives the protocol is unknown, so the wait is the longer
/// of the two budgets — the head's, because an HTTP client may take that long
/// to start, and the hello's, because a TLS client may take that long and is
/// not an HTTP client at all. The head itself is still bounded by
/// `header_secs` from the moment the stream opened, so a client that trickles
/// a head renews nothing.
pub(super) struct StreamBudgets {
    /// The whole request head, from the moment the stream opened.
    pub(super) head: tokio::time::Instant,
    /// The first byte, which says which protocol this stream carries.
    pub(super) identify: tokio::time::Instant,
    /// When the stream opened, so the budgets can be reported in seconds.
    pub(super) open: tokio::time::Instant,
}

impl StreamBudgets {
    pub(super) fn new(deadlines: &crate::deadline::Deadlines, open: tokio::time::Instant) -> Self {
        Self {
            head: open + deadlines.header,
            identify: open + deadlines.header.max(deadlines.tls_hello),
            open,
        }
    }

    /// How long the first byte may take.
    pub(super) fn identify_budget(&self) -> std::time::Duration {
        self.identify - self.open
    }

    /// How long the head may take, from the moment the stream opened.
    pub(super) fn head_budget(&self) -> std::time::Duration {
        self.head - self.open
    }

    /// How much of the head's budget is left.
    ///
    /// The head is bounded from the moment the stream opened, not from the
    /// moment the head was read: a peer that dribbles a head renews nothing.
    /// So whatever the first bytes took is taken off the budget the codec
    /// gets, and the two add up to the same bound the hand-written reader
    /// applied.
    fn head_left(&self) -> std::time::Duration {
        self.head_budget().saturating_sub(self.open.elapsed())
    }
}

/// What a stream turned out to carry.
///
/// The decision is the first byte's — unless the connection already said. A
/// connection that named its protocol with ALPN is not asked: it said, and
/// the server does not have to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamKind {
    /// An L4 tunnel: the client sent the preface, and the bytes go to the
    /// tunnel.
    L4,
    /// A TLS session: the client sent a ClientHello, and the bytes go to the
    /// passthrough, which routes on SNI.
    Tls,
    /// A request: the bytes are a request head, and they go to the codec.
    Request,
}

/// What a stream carries, decided by the protocol the connection named and by
/// the first bytes it sent.
///
/// The named protocols are taken at their word: an L4 connection is a tunnel, a
/// TLS connection is a TLS session, and an HTTP connection is a request — even
/// when the bytes say otherwise, because a connection that named its protocol
/// is not going to be sent something else.
///
/// The old ALPN says nothing, so the first byte says it: `0x05` is an L4
/// preface, `0x16` is a TLS hello, and anything else is a request.
pub(super) fn classify(protocol: Protocol, first: &[u8]) -> StreamKind {
    match protocol {
        Protocol::L4 => StreamKind::L4,
        Protocol::Tls => StreamKind::Tls,
        Protocol::Http => StreamKind::Request,
        Protocol::Legacy => match first.first() {
            Some(byte) if l4::is_l4_stream(*byte) => StreamKind::L4,
            Some(byte) if passthrough::is_tls_handshake(*byte) => StreamKind::Tls,
            _ => StreamKind::Request,
        },
    }
}

/// Reads the first bytes of a stream off it.
///
/// One read, and only one: enough to say which protocol the stream carries,
/// and — for the protocols that carry a preface of their own — enough to
/// hand on.
///
/// Generic over the reader so that the whole path can be driven from a test
/// with a `duplex` pair, the way the L4 preface is: the rules decided here are
/// worth more than the I/O around them, and the I/O is the part that is hard
/// to reproduce on demand.
///
/// The bytes are **handed on**, not consumed. A request's first byte is part
/// of the request, so the codec that reads the head has to see it — which is
/// why the request path hands them back before the rest of the stream.
pub(super) async fn read_first_bytes<R>(
    recv: &mut R,
    budgets: &StreamBudgets,
) -> Result<Option<Vec<u8>>, anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let read = tokio::time::timeout_at(budgets.identify, recv.read(&mut buf)).await;
    match read {
        // Zero bytes is the end of the stream, which is the reader's way of
        // saying the peer is gone. There is nobody to answer.
        Ok(Ok(0)) => Ok(None),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow::anyhow!(
            "no first byte within {}s",
            budgets.identify_budget().as_secs()
        )),
    }
}

// One more argument than clippy allows, and bundling them into a struct would
// just move the list somewhere else while making every call site build one. The
// id is last because it is the newest thing this stream carries.
#[allow(clippy::too_many_arguments)]
pub async fn handle_bidi_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    // The routes and the clients are shared rather than borrowed: the HTTP
    // path hands them to a service that runs for as long as the connection
    // does, and the connection may carry several requests.
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    limiter: &Arc<l4::FlowLimiter>,
    peer: &str,
    acl: Option<Arc<ClientAcl>>,
    request_id: &str,
    // Who the connection authenticated as, for the access log. Empty with 2FA
    // off, and for a library embedder that never built an `AuthState`, which is
    // what the access log prints nothing for.
    who: PeerIdentity,
    // What the connection carries, from the handshake. A connection that
    // named its protocol does not have to be sniffed.
    protocol: Protocol,
) -> anyhow::Result<()> {
    let mut recv = recv;

    // A phase deadline over the whole head, taken once and never renewed: a
    // peer that drips one byte before each expiry renews nothing. The bound is
    // `[timeouts] header_secs` through the routes.
    let timeouts = config.timeouts();
    let open = tokio::time::Instant::now();
    let budgets = StreamBudgets::new(&timeouts.deadlines, open);

    // A connection that named its protocol with ALPN said what it carries:
    // `nexapipe/http` is HTTP, and hyper serves it without the first byte
    // being read to find out. Nothing is sniffed, nothing is read twice, and
    // nothing is handed back.
    if protocol == Protocol::Http {
        let ctx = Arc::new(crate::http::server::Context {
            config,
            clients,
            peer: peer.to_string(),
            acl,
            request_id: request_id.to_string(),
            who,
        });
        return crate::http::server::serve(send, recv, Vec::new(), timeouts.deadlines.header, ctx)
            .await;
    }

    // The connection did not say what it carries, so the first bytes are read
    // to find out: `0x05` is an L4 preface, `0x16` is a TLS hello, and
    // anything else is a request.
    let first = match read_first_bytes(&mut recv, &budgets).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // The peer went away before it said anything. There is nobody to
            // answer, and what arrived is not a request.
            tracing::debug!("Stream from {} ended before it said what it carries", peer);
            return Ok(());
        }
        Err(e) => {
            tracing::warn!("No first bytes from {}: {}", peer, e);
            return Err(e);
        }
    };

    // An L4 tunnel says so in its first byte, so it is recognised rather than
    // sniffed. This has to happen before the request path: a preface is not a
    // request line, and the client may send its first payload in the same
    // segment, which the bytes already hold and must hand over intact.
    //
    // **The connection said which it is**, so the first byte is only read
    // when it has to be — on a connection that named the old ALPN and is
    // served the way it always was.
    match classify(protocol, &first) {
        StreamKind::L4 => {
            return l4::handle_iroh_stream(
                send,
                recv,
                first,
                &config,
                limiter,
                peer,
                acl.as_deref(),
                request_id,
                Some(&who),
            )
            .await;
        }

        // TLS is terminated by the backend, so a ClientHello is not a request:
        // hand the raw bytes (and both halves of the stream) to the
        // passthrough path, which routes on SNI.
        StreamKind::Tls => {
            return passthrough::handle_iroh_stream(send, recv, first, &config, acl.as_deref())
                .await;
        }

        StreamKind::Request => {}
    }

    // A request. The bytes that were read are part of it, so they are handed
    // back and hyper reads the head from the beginning — nothing is parsed
    // twice and nothing is lost.
    //
    // The head's budget is what is left of it: the head is bounded from the
    // moment the stream opened, and the first bytes have already taken some
    // of that.
    let head_timeout = budgets.head_left();
    let ctx = Arc::new(crate::http::server::Context {
        config,
        clients,
        peer: peer.to_string(),
        acl,
        request_id: request_id.to_string(),
        who,
    });
    crate::http::server::serve(send, recv, first, head_timeout, ctx).await
}
