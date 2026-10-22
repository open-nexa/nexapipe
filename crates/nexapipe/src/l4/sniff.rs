//! What the first bytes of a flow say about it.
//!
//! The L4 tunnel carries bytes, so the access log for one of its flows used to
//! say only what the tunnel did with them. But the bytes at the head of a flow
//! usually say what the flow *is*: a `ClientHello` names the host it is going
//! to, a request line says what is being asked for, and a status line says
//! what the origin answered.
//!
//! This module reads those bytes without taking anything away from them. The
//! reader here is a pass-through: it observes what goes through it and hands
//! the same bytes on, so a flow costs one memcpy of its first bytes and
//! nothing else — no wait for the client to speak, no extra round trip, no
//! deadline that a slow peer can trip.
//!
//! # It reads, it does not act
//!
//! Everything here comes from the client's own bytes. The name in a
//! `ClientHello` is the client's word, and the route was already chosen by the
//! preface that named the host — so nothing in this module can move a byte to
//! a different backend, and nothing in it can widen what a client is allowed
//! to reach. It exists to make the access log say what happened, not to decide
//! what happens.
//!
//! # What it can and cannot read
//!
//! Two things, and nothing else:
//!
//! * a TLS handshake, for the name it asks for — the same parse the
//!   passthrough path uses, so the two agree on what a name is;
//! * a plaintext HTTP exchange, for the request line and the status.
//!
//! Everything else — SSH, a database protocol, a game — is left alone. The
//! first line of such a protocol does not look like a request line, and the
//! sniffer says so rather than guessing.
//!
//! # What it holds
//!
//! The head of the flow, and only until it has been read: a handshake is a few
//! hundred bytes and a request line is shorter, and the buffer is released as
//! soon as the answer is known. A flow that says nothing recognizable is
//! given up on at the cap, so a peer that keeps talking cannot make the
//! buffer follow the flow.

use crate::log::FlowDetail;
use crate::passthrough::{TLS_HANDSHAKE, extract_sni};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most the sniffer will hold for one side of a flow.
///
/// A `ClientHello` is a few hundred bytes and a request line is shorter; this
/// is the point past which the bytes cannot be a handshake this proxy would
/// read, and the buffer stops there rather than following a peer that keeps
/// talking. The same cap the passthrough path uses for a handshake.
const MAX_SNIFF: usize = 16 * 1024;

/// Which side of a flow a reader sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The client: the side that asks for things.
    Client,
    /// The backend: the side that answers.
    Backend,
}

/// What the client's first bytes turned out to be.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum ClientVerdict {
    /// Not enough bytes yet to say.
    #[default]
    Undecided,
    /// A TLS handshake, and the name it asked for — if it asked for one.
    Tls(Option<String>),
    /// A plaintext HTTP request line.
    Http {
        method: String,
        target: String,
        version: String,
    },
    /// Something this proxy does not read.
    Other,
}

/// What the backend's first bytes turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BackendVerdict {
    /// Not enough bytes yet to say.
    #[default]
    Undecided,
    /// The status the origin answered with.
    Status(u16),
    /// Something this proxy does not read.
    Other,
}

/// How far the line scan has got, and what it has cost.
///
/// The scan does not start over between chunks: the bytes before `from` have
/// been looked at and held no line, and looking at them again would make the
/// cost of a flow quadratic in its bytes. A peer that opens a flow with
/// something this proxy does not read — an SSH banner, a database greeting —
/// and then dribbles it out one byte at a time would make every byte rescan
/// everything buffered so far, up to the cap.
///
/// The answer is the same whatever the chunking: the bytes before `from` held
/// no line, so the line is either in the part already scanned — in which case
/// it would have been found — or it starts in the new part.
#[derive(Debug, Default, Clone, Copy)]
struct Scan {
    /// The offset the next scan starts at.
    from: usize,
    /// How many bytes the scan has looked at, over the whole flow.
    ///
    /// It is here so that a test can say the work is linear rather than
    /// quadratic: the alternative is a test that measures time, and a test
    /// that measures time fails on a loaded machine.
    examined: usize,
}

/// The client's side of the observation.
#[derive(Debug, Default)]
struct ClientSniff {
    bytes: Vec<u8>,
    verdict: ClientVerdict,
    scan: Scan,
}

/// The backend's side of the observation.
#[derive(Debug, Default)]
struct BackendSniff {
    bytes: Vec<u8>,
    verdict: BackendVerdict,
    scan: Scan,
}

/// Watches the two ends of one flow and says what they said.
///
/// Shared by the two readers of a flow, because the verdict is a fact about
/// the flow and not about either end of it: the client says what it wants and
/// the backend says what came back, and only the two together are the answer.
#[derive(Debug, Default)]
pub(crate) struct FlowSniffer {
    client: Mutex<ClientSniff>,
    backend: Mutex<BackendSniff>,
    /// Set once a side has decided, so the reader stops asking.
    ///
    /// A lock would say the same thing, but this is read on every chunk of a
    /// flow that may last hours, and an atomic load is the price of that.
    client_done: AtomicBool,
    backend_done: AtomicBool,
}

impl FlowSniffer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Shows the sniffer the bytes that went one way.
    pub(crate) fn feed(&self, side: Side, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match side {
            Side::Client => self.feed_client(bytes),
            Side::Backend => self.feed_backend(bytes),
        }
    }

    fn feed_client(&self, bytes: &[u8]) {
        if self.client_done.load(Ordering::Relaxed) {
            return;
        }
        // The three fields are taken apart rather than reached through the
        // guard: the decision needs the bytes and the scan position at the
        // same time, and a guard hands out borrows of the whole thing.
        let mut guard = self.lock_client();
        let ClientSniff {
            bytes: buffered,
            verdict,
            scan,
        } = &mut *guard;
        if !matches!(*verdict, ClientVerdict::Undecided) {
            return;
        }
        append_bounded(buffered, bytes);
        *verdict = decide_client(buffered, scan);
        if !matches!(*verdict, ClientVerdict::Undecided) {
            self.client_done.store(true, Ordering::Relaxed);
            // The answer is known and the bytes behind it are not needed any
            // more: a flow that lasts an hour must not hold the head of its
            // first packet for the whole hour.
            buffered.clear();
        }
    }

    fn feed_backend(&self, bytes: &[u8]) {
        if self.backend_done.load(Ordering::Relaxed) {
            return;
        }
        let mut guard = self.lock_backend();
        let BackendSniff {
            bytes: buffered,
            verdict,
            scan,
        } = &mut *guard;
        if !matches!(*verdict, BackendVerdict::Undecided) {
            return;
        }
        append_bounded(buffered, bytes);
        *verdict = decide_backend(buffered, scan);
        if !matches!(*verdict, BackendVerdict::Undecided) {
            self.backend_done.store(true, Ordering::Relaxed);
            buffered.clear();
        }
    }

    /// What the flow said, once it has said it.
    ///
    /// `None` for a flow that said nothing this proxy can read — which is most
    /// of them, and is not a failure: an operator who wants to know what a
    /// tunnel carried asks the client.
    pub(crate) fn verdict(&self) -> Option<FlowDetail> {
        let client = self.lock_client();
        match &client.verdict {
            ClientVerdict::Tls(sni) => Some(FlowDetail::Tls { sni: sni.clone() }),
            ClientVerdict::Http {
                method,
                target,
                version,
            } => {
                // The status comes from the other end, and it is only an answer
                // if the origin answered: a flow that broke before the response
                // head arrived has no status, which is not the same as a 404.
                let backend = self.lock_backend();
                let status = match backend.verdict {
                    BackendVerdict::Status(code) => Some(code),
                    _ => None,
                };
                Some(FlowDetail::Http {
                    method: method.clone(),
                    target: target.clone(),
                    version: version.clone(),
                    status,
                })
            }
            _ => None,
        }
    }

    /// How much the client side is holding, for the tests that say it must not
    /// keep holding.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.lock_client().bytes.len()
    }

    /// How many bytes the line scan has looked at, over the whole flow.
    ///
    /// For the test that says the sniffer's work is linear in the bytes it is
    /// shown, and not quadratic.
    #[cfg(test)]
    pub(crate) fn examined(&self) -> usize {
        let client = self.lock_client();
        let backend = self.lock_backend();
        client.scan.examined + backend.scan.examined
    }

    fn lock_client(&self) -> std::sync::MutexGuard<'_, ClientSniff> {
        self.client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_backend(&self) -> std::sync::MutexGuard<'_, BackendSniff> {
        self.backend
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Appends what fits, and stops at the cap.
///
/// The bytes that do not fit are the ones a peer sent after the point where
/// the answer was already decided; keeping them would make the buffer follow
/// the flow rather than bound it.
fn append_bounded(buffer: &mut Vec<u8>, bytes: &[u8]) {
    let room = MAX_SNIFF.saturating_sub(buffer.len());
    if room == 0 {
        return;
    }
    buffer.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// What the client's first bytes are.
///
/// Decided from the buffer alone, so the same bytes always give the same
/// answer whether they arrived in one chunk or in thirty.
fn decide_client(bytes: &[u8], scan: &mut Scan) -> ClientVerdict {
    let Some(first) = bytes.first() else {
        return ClientVerdict::Undecided;
    };

    if *first == TLS_HANDSHAKE {
        // A TLS record: the length is in its header, and the name is inside
        // it, so the whole record is the unit that has to arrive before the
        // name can be read. Until then the answer is "not yet".
        let Some(end) = record_end(bytes) else {
            return ClientVerdict::Undecided;
        };
        if end > MAX_SNIFF {
            return ClientVerdict::Other;
        }
        if bytes.len() < end {
            return ClientVerdict::Undecided;
        }
        // The same parse the passthrough path uses, so the two never disagree
        // about what a name is.
        return ClientVerdict::Tls(extract_sni(&bytes[..end]));
    }

    // Not TLS. The only other thing this proxy reads is a plaintext HTTP
    // request, and it starts with a request line.
    let Some(line) = first_line(bytes, scan) else {
        return if bytes.len() >= MAX_SNIFF {
            ClientVerdict::Other
        } else {
            ClientVerdict::Undecided
        };
    };
    match parse_request_line(line) {
        Some((method, target, version)) => ClientVerdict::Http {
            method,
            target,
            version,
        },
        None => ClientVerdict::Other,
    }
}

/// What the backend's first bytes are.
///
/// Only a status line counts. The backend of an HTTP flow answers with one,
/// and the backend of anything else answers with whatever that protocol is.
fn decide_backend(bytes: &[u8], scan: &mut Scan) -> BackendVerdict {
    let Some(line) = first_line(bytes, scan) else {
        return if bytes.len() >= MAX_SNIFF {
            BackendVerdict::Other
        } else {
            BackendVerdict::Undecided
        };
    };
    match parse_status_line(line) {
        Some(status) => BackendVerdict::Status(status),
        None => BackendVerdict::Other,
    }
}

/// End offset of the first TLS record, once its 5-byte header is available.
fn record_end(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 {
        return None;
    }
    Some(5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]])))
}

/// The first line of the buffer, without its line ending.
///
/// `None` while the line has not arrived yet.
fn first_line<'a>(bytes: &'a [u8], scan: &mut Scan) -> Option<&'a [u8]> {
    let from = scan.from.min(bytes.len());
    match bytes[from..].iter().position(|byte| *byte == b'\n') {
        Some(offset) => {
            let end = from + offset;
            scan.examined += offset + 1;
            scan.from = end + 1;
            let line = &bytes[..end];
            // The ending may be CRLF or a bare LF; both are one line.
            Some(match line.last() {
                Some(b'\r') => &line[..line.len() - 1],
                _ => line,
            })
        }
        None => {
            // No line yet, and the bytes that are here have been looked at.
            // The next chunk starts where this one ended.
            scan.examined += bytes.len() - from;
            scan.from = bytes.len();
            None
        }
    }
}

/// Reads a request line: a method, a target and a version.
///
/// All three, and only these three. A protocol that opens with two words — an
/// SMTP `EHLO`, a database greeting — is not an HTTP request, and a line
/// with more than three words is not a request line either.
fn parse_request_line(line: &[u8]) -> Option<(String, String, String)> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((method.to_string(), target.to_string(), version.to_string()))
}

/// Reads a status line: a version and a code.
fn parse_status_line(line: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    let status = code.parse::<u16>().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    Some(status)
}

/// A reader that shows what goes through it to a [`FlowSniffer`].
///
/// The bytes are handed on unchanged and the write half is the inner stream's,
/// so a flow that is being observed is a flow that behaves exactly like one
/// that is not.
pub(crate) struct SniffReader<R> {
    inner: R,
    sniffer: Arc<FlowSniffer>,
    side: Side,
}

impl<R> SniffReader<R> {
    pub(crate) fn new(inner: R, sniffer: Arc<FlowSniffer>, side: Side) -> Self {
        SniffReader {
            inner,
            sniffer,
            side,
        }
    }
}

impl<R> AsyncRead for SniffReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                this.sniffer.feed(this.side, &buf.filled()[before..after]);
            }
        }
        result
    }
}

impl<R> AsyncWrite for SniffReader<R>
where
    R: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The sniffer's work is linear in the bytes it is shown.
    ///
    /// A peer that opens a flow with something this proxy does not read — an
    /// SSH banner, a database greeting — and then dribbles it out one byte at
    /// a time used to make every byte rescan everything buffered so far, up to
    /// the cap: quadratic in the bytes of the flow, on the thread that copies
    /// them.
    ///
    /// The verdict only becomes "something else" once the buffer reaches the
    /// cap, so the buffer keeps growing and keeps being rescanned.
    #[test]
    fn a_flow_that_arrives_one_byte_at_a_time_costs_what_it_is_worth() {
        let sniffer = FlowSniffer::new();
        // A greeting with no line in it, so the scan never finds one and the
        // buffer keeps growing to the cap.
        let bytes = vec![b'x'; MAX_SNIFF];

        for byte in &bytes {
            sniffer.feed(Side::Client, std::slice::from_ref(byte));
        }

        let examined = sniffer.examined();
        assert!(
            examined <= bytes.len() * 2,
            "the scan looked at {examined} bytes for {} bytes of flow",
            bytes.len()
        );
    }

    /// The same on the other side of the flow.
    ///
    /// The backend's first bytes are read the same way — a status line, or
    /// whatever that protocol is — so the same cost applies to it.
    #[test]
    fn a_backend_that_answers_one_byte_at_a_time_costs_what_it_is_worth() {
        let sniffer = FlowSniffer::new();
        let bytes = vec![b'y'; MAX_SNIFF];

        for byte in &bytes {
            sniffer.feed(Side::Backend, std::slice::from_ref(byte));
        }

        let examined = sniffer.examined();
        assert!(
            examined <= bytes.len() * 2,
            "the scan looked at {examined} bytes for {} bytes of flow",
            bytes.len()
        );
    }

    /// A flow that arrives in one piece costs the same as one that arrives a
    /// byte at a time.
    ///
    /// The two shapes are the same bytes, and the sniffer must not care how
    /// they were cut up.
    #[test]
    fn the_cost_does_not_depend_on_how_the_bytes_arrived() {
        let bytes = vec![b'x'; 4096];

        let whole = FlowSniffer::new();
        whole.feed(Side::Client, &bytes);

        let dribbled = FlowSniffer::new();
        for byte in &bytes {
            dribbled.feed(Side::Client, std::slice::from_ref(byte));
        }

        assert_eq!(
            whole.examined(),
            dribbled.examined(),
            "the same bytes cost the same however they arrive"
        );
    }

    /// A `ClientHello` that asks for `name`.
    ///
    /// Built here rather than captured, because the bytes have to be exactly
    /// what the parse expects and a capture would drag a TLS stack into the
    /// test.
    fn client_hello(name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = name {
            let mut entry = Vec::new();
            entry.push(0x00); // name_type: host_name
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());

            let mut list = Vec::new();
            list.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            list.extend_from_slice(&entry);

            extensions.extend_from_slice(&0u16.to_be_bytes()); // server_name
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1); // compression methods length
        body.push(0x00);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn sniffer() -> (Arc<FlowSniffer>, Side) {
        (Arc::new(FlowSniffer::new()), Side::Client)
    }

    #[test]
    fn a_client_hello_names_the_host_it_asked_for() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, &client_hello(Some("example.com")));

        assert_eq!(
            sniffer.verdict(),
            Some(FlowDetail::Tls {
                sni: Some("example.com".to_string())
            })
        );
    }

    /// The name can be split across two reads, and the answer must not depend
    /// on how the bytes arrived.
    #[test]
    fn a_client_hello_split_across_reads_is_still_read() {
        let (sniffer, side) = sniffer();
        let hello = client_hello(Some("example.com"));
        let (head, tail) = hello.split_at(7);

        sniffer.feed(side, head);
        assert_eq!(sniffer.verdict(), None, "the record was not complete yet");

        sniffer.feed(side, tail);
        assert_eq!(
            sniffer.verdict(),
            Some(FlowDetail::Tls {
                sni: Some("example.com".to_string())
            })
        );
    }

    /// A client that connects by address asks for no name. That is a TLS
    /// handshake, and it is not the same answer as "this was not TLS".
    #[test]
    fn a_client_hello_without_a_name_is_still_a_tls_flow() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, &client_hello(None));

        assert_eq!(sniffer.verdict(), Some(FlowDetail::Tls { sni: None }));
    }

    #[test]
    fn a_plaintext_request_is_read() {
        let (sniffer, side) = sniffer();
        sniffer.feed(
            side,
            b"GET /api/v1/items?page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );

        assert_eq!(
            sniffer.verdict(),
            Some(FlowDetail::Http {
                method: "GET".to_string(),
                target: "/api/v1/items?page=2".to_string(),
                version: "HTTP/1.1".to_string(),
                status: None,
            })
        );
    }

    #[test]
    fn the_status_the_origin_answered_with_is_read() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        sniffer.feed(
            Side::Backend,
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        );

        assert_eq!(
            sniffer.verdict(),
            Some(FlowDetail::Http {
                method: "GET".to_string(),
                target: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                status: Some(404),
            })
        );
    }

    /// A protocol that opens with something else is not an HTTP request, and
    /// saying otherwise would put a made-up request line in the access log.
    #[test]
    fn another_protocol_is_not_mistaken_for_http() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, b"SSH-2.0-OpenSSH_9.6\r\n");

        assert_eq!(sniffer.verdict(), None);
    }

    /// Two words are not a request line either.
    #[test]
    fn a_two_word_greeting_is_not_a_request() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, b"EHLO client.example\r\n");

        assert_eq!(sniffer.verdict(), None);
    }

    #[test]
    fn a_flow_that_says_nothing_has_no_verdict() {
        let (sniffer, side) = sniffer();
        sniffer.feed(side, b"");

        assert_eq!(sniffer.verdict(), None);
    }

    /// The reader hands the bytes on unchanged: a flow that is being watched
    /// is a flow that behaves exactly like one that is not.
    #[tokio::test]
    async fn the_bytes_pass_through_unchanged() {
        let (sniffer, _) = sniffer();
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut sniffed = SniffReader::new(reader, Arc::clone(&sniffer), Side::Client);

        let payload = client_hello(Some("example.com"));
        writer.write_all(&payload).await.unwrap();

        let mut seen = vec![0u8; payload.len()];
        sniffed.read_exact(&mut seen).await.unwrap();

        assert_eq!(seen, payload);
        assert_eq!(
            sniffer.verdict(),
            Some(FlowDetail::Tls {
                sni: Some("example.com".to_string())
            })
        );
    }

    /// The buffer follows the answer, not the flow: once the sniffer knows
    /// what the bytes are, it lets go of them and takes no more.
    #[tokio::test]
    async fn the_buffer_is_released_once_the_answer_is_known() {
        let (sniffer, _) = sniffer();
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let mut sniffed = SniffReader::new(reader, Arc::clone(&sniffer), Side::Client);

        let payload = client_hello(Some("example.com"));
        writer.write_all(&payload).await.unwrap();
        let mut seen = vec![0u8; payload.len()];
        sniffed.read_exact(&mut seen).await.unwrap();
        assert_eq!(sniffer.buffered(), 0, "the handshake is still held");

        // The rest of the conversation changes nothing.
        writer.write_all(&vec![0u8; 32 * 1024]).await.unwrap();
        let mut more = [0u8; 1024];
        sniffed.read_exact(&mut more).await.unwrap();

        assert_eq!(sniffer.buffered(), 0);
    }

    /// The whole way round: a flow that speaks TLS is read while it runs, and
    /// the name in the handshake is what the access log will say.
    #[tokio::test]
    async fn a_tls_flow_is_read_end_to_end() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        let sniffer = Arc::new(FlowSniffer::new());
        let watcher = Arc::clone(&sniffer);
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            crate::l4::serve_tcp(
                server,
                &backend_addr.to_string(),
                Vec::new(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                &sniffer,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let hello = client_hello(Some("www.example.com"));
        client_write.write_all(&hello).await.unwrap();

        let mut status = [0u8; 1];
        client_read.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], nexapipe_proto::Status::Ok.as_byte());

        // The backend echoes the handshake, so the flow ends when the client
        // does.
        let mut echoed = vec![0u8; hello.len()];
        client_read.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, hello);

        drop(client_write);
        drop(client_read);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should end with the client")
            .unwrap();
        assert!(outcome.is_ok());
        echo.await.unwrap();

        assert_eq!(
            watcher.verdict(),
            Some(FlowDetail::Tls {
                sni: Some("www.example.com".to_string())
            })
        );
    }

    /// The same way round for a plaintext HTTP flow, which also answers the
    /// question of where the status code comes from: the other end.
    #[tokio::test]
    async fn a_plaintext_http_flow_is_read_end_to_end() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        const ANSWER: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let answer = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(ANSWER).await.unwrap();
        });

        let sniffer = Arc::new(FlowSniffer::new());
        let watcher = Arc::clone(&sniffer);
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            crate::l4::serve_tcp(
                server,
                &backend_addr.to_string(),
                Vec::new(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                &sniffer,
            )
            .await
        });

        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(b"GET /v1/items HTTP/1.1\r\nHost: api.test\r\n\r\n")
            .await
            .unwrap();

        let mut status = [0u8; 1];
        client_read.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], nexapipe_proto::Status::Ok.as_byte());

        let mut answer_bytes = vec![0u8; ANSWER.len()];
        client_read.read_exact(&mut answer_bytes).await.unwrap();
        assert_eq!(&answer_bytes, ANSWER);

        drop(client_write);
        drop(client_read);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the flow should end with the client")
            .unwrap();
        assert!(outcome.is_ok());
        answer.await.unwrap();

        assert_eq!(
            watcher.verdict(),
            Some(FlowDetail::Http {
                method: "GET".to_string(),
                target: "/v1/items".to_string(),
                version: "HTTP/1.1".to_string(),
                status: Some(404),
            })
        );
    }
}
