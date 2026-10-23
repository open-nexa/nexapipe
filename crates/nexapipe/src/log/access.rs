//! The access log: one line per proxied request.
//!
//! The line is a fixed set of columns, so that a script splitting it on
//! spaces still finds the host, the status and the duration where it always
//! did. The request id, the identity of the caller and whatever the flow said
//! about itself follow those, at the end of the line.
//!
//! A query string is redacted before it reaches the line, and the file and the
//! tracing event are given the same redacted text: redacting one and not the
//! other only moves the leak next door.

use chrono::Local;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, OnceLock};

use crate::conn::peers::PeerIdentity;

use super::sink::FileSink;

#[cfg(test)]
use std::sync::Arc;

/// Access log: one line per proxied request, in Apache-ish common log format.
struct AccessLogger {
    enabled: bool,
    file: Option<FileSink>,
}

/// Where a finished access line goes: stdout, or the log file.
enum AccessTarget {
    Stdout,
    File(FileSink),
}

/// The thread that writes access lines, and the queue in front of it.
///
/// `log_access` runs on a tokio worker, on the critical path of the very
/// request it is logging, and `FileSink::write_line` is a `write` plus a
/// `flush` behind a mutex every connection shares. Done inline, one request's
/// line made every other request wait behind the disk — and a slow or
/// contended mount turned into latency on connections that never asked for an
/// access log. One writer thread takes the syscalls off the workers and, being
/// the only writer, keeps the lines in the order they were queued.
///
/// Started with the first line rather than at `init`, so a proxy that never
/// logs an access line never starts the thread.
static ACCESS_WRITER: OnceLock<SyncSender<(FileSink, String)>> = OnceLock::new();

/// How many lines may be waiting for the writer thread.
///
/// Bounded because the queue is fed by request handlers and drained by one
/// thread doing a write and a flush per line: unbounded, a disk slower than
/// the traffic makes the queue the place memory goes, and the proxy dies of
/// that long before it dies of the disk. A line refused here is dropped and
/// counted — an access log that skips is worth more than an OOM.
const ACCESS_LOG_QUEUE: usize = 4096;

/// Lines dropped because the queue was full, and a warning every so often so
/// the gap is visible instead of being something someone notices in the file.
static DROPPED_ACCESS_LINES: AtomicU64 = AtomicU64::new(0);

/// How many dropped lines the writer thread lets pass before it warns. The
/// count is raised on the request path; the warning never is.
const DROPPED_LINES_PER_WARNING: u64 = 100;

/// `None` when the writer thread could not be started, which the caller treats
/// as "write it here instead": failing to spawn a thread must not lose the
/// line, any more than failing to open the file must.
fn access_writer() -> Option<&'static SyncSender<(FileSink, String)>> {
    if ACCESS_WRITER.get().is_none() {
        let (sender, receiver) = sync_channel::<(FileSink, String)>(ACCESS_LOG_QUEUE);
        match std::thread::Builder::new()
            .name("nexapipe-access-log".to_string())
            .spawn(move || {
                // Ends when the last sender is dropped, which for the one
                // stored in the `OnceLock` is never: this thread runs for the
                // life of the process.
                let mut warned_at = 0u64;
                while let Ok((sink, line)) = receiver.recv() {
                    sink.write_line(&line);

                    // Reported here rather than where the line is dropped: the
                    // file layer writes and flushes synchronously, so warning
                    // from a request handler would put the disk this thread
                    // exists to hide back in front of the request that happened
                    // to be logging.
                    let dropped = DROPPED_ACCESS_LINES.load(Ordering::Relaxed);
                    if dropped >= warned_at + DROPPED_LINES_PER_WARNING {
                        warned_at = dropped;
                        tracing::warn!(
                            "Access log: {dropped} lines dropped, the writer cannot keep up"
                        );
                    }
                }
            }) {
            Ok(_) => {
                // A racing caller loses here and drops its sender, which ends
                // the thread it just spawned.
                let _ = ACCESS_WRITER.set(sender);
            }
            Err(e) => eprintln!("nexapipe: no access log writer thread: {e}"),
        }
    }

    ACCESS_WRITER.get()
}

/// `None` until [`init`] ran, so embedders keep the stdout-only behaviour.
static ACCESS_LOGGER: Mutex<Option<AccessLogger>> = Mutex::new(None);

pub(super) fn init_access_logger(enabled: bool, file: Option<FileSink>) {
    let mut logger = ACCESS_LOGGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *logger = Some(AccessLogger { enabled, file });
}

/// Written in place of a query parameter value.
const REDACTED: &str = "<redacted>";

/// Whether access log lines have their query values replaced.
///
/// Redacting is the default — and stays in force when [`init`] never ran —
/// because keeping a stray token out of a file that gets rotated, archived and
/// handed to someone else is worth more than reading it back. Only
/// `[log] redact_query = false` turns it off.
pub(super) static REDACT_QUERY: AtomicBool = AtomicBool::new(true);

pub(super) fn set_redact_query(redact: bool) {
    REDACT_QUERY.store(redact, Ordering::Relaxed);
}

fn redacting() -> bool {
    REDACT_QUERY.load(Ordering::Relaxed)
}

/// The URI as a log line should carry it.
///
/// The same redaction the access log applies, and for the same reason: the
/// access log is not the only place a URI ends up. A tracing span's fields
/// are rendered into the general log file by every event inside the span, so
/// a query value recorded there has been rotated, archived and handed to
/// someone else exactly as a value in the access log has.
///
/// The access log redacts once and hands the same string to both of its sinks
/// — "or redacting the file only moves the leak next door". This is that
/// string, for the sinks the access log does not own.
fn uri_for_log(uri: &str) -> String {
    if redacting() {
        redact_query(uri)
    } else {
        uri.to_string()
    }
}

/// Records a request's method and URI on the current span.
///
/// The URI recorded is the redacted one. A span's fields are rendered into
/// the general log file by every event inside the span — not only by the
/// access line — so a query value written here is a query value in a file
/// that gets rotated, archived and handed to someone else.
///
/// Every call site goes through this, rather than recording a URI of its own,
/// because the rule is one rule and the call sites are four.
pub(crate) fn record_request_on_span(span: &tracing::Span, method: &str, uri: &str) {
    span.record("method", method);
    span.record("uri", uri_for_log(uri).as_str());
}

/// Replaces the values in a URI's query string, keeping the parameter names.
///
/// `?token=abc&page=2` becomes `?token=<redacted>&page=<redacted>`. Names stay
/// because they are the part that makes an access log worth reading; values go
/// because that is where tokens, signatures and one-time codes travel. A
/// parameter with no `=` is a flag (`?raw`) and has no value to hide.
///
/// The path is left as it is. It can carry a secret too (`/api/keys/abc123`),
/// but nothing in it says which segment is an identifier and which is an
/// endpoint, so redacting it would mean dropping the path — and an access log
/// with no path in it tells you nothing.
pub(super) fn redact_query(uri: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };

    let mut out = String::with_capacity(uri.len());
    out.push_str(path);
    out.push('?');

    for (index, param) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match param.split_once('=') {
            Some((name, _value)) => {
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED);
            }
            // A bare flag carries no value, so there is nothing to hide.
            None => out.push_str(param),
        }
    }

    out
}

/// What a tunnelled flow said about itself, when it could be read.
///
/// The L4 tunnel carries bytes, so the line for one of its flows used to say
/// only what the tunnel did with them. A flow that speaks TLS or plaintext HTTP
/// says more than that, and this is what it said — read off the wire, without
/// the proxy terminating anything.
///
/// It is a log-line concern and lives here rather than with the code that reads
/// the bytes, because the redaction of a query string is this module's rule and
/// a sniffed request target is a query string like any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDetail {
    /// A TLS handshake. `sni` is the name it asked for, if it asked for one:
    /// a client that connects by address asks for nothing.
    Tls { sni: Option<String> },
    /// A plaintext HTTP request, and the status the origin answered with.
    ///
    /// `status` is `None` when the origin never answered — the flow broke
    /// before the response head arrived, which is not the same as an answer.
    Http {
        method: String,
        target: String,
        version: String,
        status: Option<u16>,
    },
}

/// Builds one access line.
///
/// The id goes last of the fixed columns, not first: everything before it
/// keeps the column it had, so a script that splits this line on spaces still
/// finds the host, the status and the duration where it always did. The
/// identity and the flow's own facts follow it, each at the end of the line,
/// for the same reason.
///
/// Separate from the writing, so a test can say what the line looks like
/// without arming the global logger.
#[allow(clippy::too_many_arguments)]
pub(super) fn access_line(
    request_id: &str,
    remote_addr: &str,
    method: &str,
    uri: &str,
    status: u16,
    duration_ms: u64,
    bytes_sent: usize,
    identity: &str,
    detail: &str,
) -> String {
    format!(
        "{} - - [{}] \"{} {}\" {} {} {}ms id={}{}{}",
        remote_addr,
        Local::now().format("%d/%b/%Y:%H:%M:%S %z"),
        method,
        uri,
        status,
        bytes_sent,
        duration_ms,
        request_id,
        identity,
        detail
    )
}

/// The suffix a flow's facts add to its access line.
///
/// Appended after the request id and the identity, so the columns before it
/// keep the meaning they have had: the status on a flow's line is still what
/// the tunnel did, not what the origin behind it answered.
pub(super) fn flow_detail_suffix(detail: &FlowDetail) -> String {
    match detail {
        FlowDetail::Tls { sni } => {
            // A dash rather than an empty field, because "this was a TLS
            // handshake that named no host" and "this was not TLS at all" are
            // not the same answer.
            format!(" sni={}", sni.as_deref().unwrap_or("-"))
        }
        FlowDetail::Http {
            method,
            target,
            version,
            status,
        } => {
            // The target is the client's own bytes, so it is sanitized and
            // redacted like any other URI in this file: a query value is
            // where tokens travel, and a control character would let the
            // client write the next line of the log itself.
            let target = redact_query(&sanitize(target));
            let method = sanitize(method);
            let version = sanitize(version);
            format!(
                " http=\"{method} {target} {version}\" http_status={}",
                status
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "-".to_string())
            )
        }
    }
}

/// Strips the characters that would break a log line out of a sniffed value.
///
/// A client controls these bytes, and a log line is read by people and by
/// scripts: a newline in here would append a line of the client's choosing,
/// and a quote would end the quoted part early. Both are dropped rather than
/// replaced, because a value that cannot be printed is not a value.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect()
}

/// The ` client=… device=…` suffix of one access line: whose request it was.
///
/// Both fields are printable ASCII by the time they get here — `conn` rejects a
/// client id or a device id that is not before it is used for anything, which
/// is what keeps a peer from ending its own name with a CRLF and writing the
/// next line itself — so neither can break a line into more columns than it
/// has.
///
/// Empty when there is no client to name, which is every request of a
/// deployment with 2FA off and every one on the plaintext listener: a line
/// answering "whose request was this" with `-` on all of them is noise, not an
/// answer. `device=-` is not the same silence — it says the client
/// authenticated and named no device, which is the one the client's own secret
/// is for.
pub(super) fn access_identity(who: Option<&PeerIdentity>) -> String {
    let Some(client_id) = who.and_then(|identity| identity.client_id.as_deref()) else {
        return String::new();
    };
    let device = who
        .and_then(|identity| identity.device.as_deref())
        .unwrap_or("-");
    format!(" client={client_id} device={device}")
}

/// One id per request: 32 lowercase hex digits, 128 bits.
///
/// Random rather than a counter for two reasons — a counter publishes how many
/// requests this process has served to anyone who can read the log, and it
/// restarts at zero on every run, so two runs hand out the same ids. `rand`
/// and `hex` are already dependencies, so this adds none.
///
/// Generated where the request enters, not where it is logged: the id is
/// carried by the tracing span as well, and a span opened after the request
/// has been parsed would miss the part where it was routed.
///
/// **One request, one id.** A connection may carry several requests — hyper
/// serves keep-alive requests on one stream — so the id is minted per
/// request, where the request enters, and never per connection. An id that
/// belonged to the connection would belong to every request on it, and a
/// client quoting it could not be matched to one log line.
pub fn next_request_id() -> String {
    let hi: u64 = rand::random();
    let lo: u64 = rand::random();
    let mut out = String::with_capacity(32);
    out.push_str(&hex::encode(hi.to_be_bytes()));
    out.push_str(&hex::encode(lo.to_be_bytes()));
    out
}

/// `who` is who the request came from, when anybody asked: `None` for the
/// plaintext listener and for a deployment with 2FA off, which never learn it.
// One field of the line per argument, which is the shape a log call has had
// since it was written; bundling them into a struct would move the list into a
// builder without making any of the dozen call sites shorter. `who` is last
// because it is the newest thing the line carries.
#[allow(clippy::too_many_arguments)]
pub fn log_access(
    request_id: &str,
    remote_addr: &str,
    method: &str,
    uri: &str,
    status: u16,
    duration_ms: u64,
    bytes_sent: usize,
    who: Option<&PeerIdentity>,
) {
    write_access_line(
        request_id,
        remote_addr,
        method,
        uri,
        status,
        duration_ms,
        bytes_sent,
        who,
        None,
    );
}

/// The line for a tunnelled flow rather than a request.
///
/// The first four arguments are the same facts the request line carries: the
/// protocol where a method would be, the target where a URI would be, and the
/// outcome of the tunnel itself. `detail` is what the flow said about itself —
/// the name a TLS handshake asked for, the request line and status a
/// plaintext HTTP flow exchanged — and it is appended to the line rather than
/// folded into the columns before it, so a script that reads the status of a
/// flow keeps reading the outcome of the tunnel.
#[allow(clippy::too_many_arguments)]
pub fn log_access_flow(
    request_id: &str,
    remote_addr: &str,
    proto: &str,
    target: &str,
    status: u16,
    duration_ms: u64,
    bytes_sent: usize,
    who: Option<&PeerIdentity>,
    detail: Option<&FlowDetail>,
) {
    write_access_line(
        request_id,
        remote_addr,
        proto,
        target,
        status,
        duration_ms,
        bytes_sent,
        who,
        detail,
    );
}

/// Builds the line and hands it to the sink.
///
/// One function behind both entry points, so a flow's line and a request's
/// line are the same line with one more field at the end of one of them.
#[allow(clippy::too_many_arguments)]
fn write_access_line(
    request_id: &str,
    remote_addr: &str,
    method: &str,
    uri: &str,
    status: u16,
    duration_ms: u64,
    bytes_sent: usize,
    who: Option<&PeerIdentity>,
    detail: Option<&FlowDetail>,
) {
    // Decided before anything is formatted: a proxy with the access log turned
    // off used to build the line for every request and then drop it, paying for
    // a `Local::now()` and an allocation per request to log nothing.
    let target = {
        let logger = ACCESS_LOGGER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match logger.as_ref() {
            // Not configured (library embedder): keep printing to stdout.
            None => Some(AccessTarget::Stdout),
            Some(logger) if !logger.enabled => None,
            Some(logger) => Some(match &logger.file {
                Some(sink) => AccessTarget::File(sink.clone()),
                None => AccessTarget::Stdout,
            }),
        }
    };

    // One string for both sinks: the line on disk and the tracing event must
    // agree, or redacting the file only moves the leak next door.
    let uri = if redacting() {
        redact_query(uri)
    } else {
        uri.to_string()
    };

    // Printed last, so everything before it keeps the column it had.
    let identity = access_identity(who);

    // And after that: what the flow said about itself. It goes at the very
    // end for the same reason the id does — a new field must not move a
    // column that a script already knows where to find.
    let detail = detail.map(flow_detail_suffix).unwrap_or_default();

    if let Some(target) = target {
        let line = access_line(
            request_id,
            remote_addr,
            method,
            &uri,
            status,
            duration_ms,
            bytes_sent,
            &identity,
            &detail,
        );

        // A test that watches the lines sees them here, before they go
        // wherever they are headed.
        #[cfg(test)]
        capture_line(&line);

        match target {
            AccessTarget::Stdout => println!("{}", line),
            // Queued for the writer thread. Anything still queued when the
            // process goes away is lost — the price of not making the request
            // wait for the disk; a line is written within a millisecond of
            // being queued, so what can be lost is what the last one did.
            AccessTarget::File(sink) => match access_writer() {
                Some(writer) => match writer.try_send((sink, line)) {
                    Ok(()) => {}
                    // The disk is behind the traffic. Waiting would put the
                    // delay on the request that happened to be logging, which
                    // is the thing the writer thread exists to prevent, so the
                    // line goes and the count stands in for it.
                    Err(TrySendError::Full(_)) => {
                        // Counted and nothing more. The writer thread raises
                        // the warning when it next sees the count, so a slow
                        // disk cannot reach back into the request that happened
                        // to be the one logging.
                        DROPPED_ACCESS_LINES.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        eprintln!("nexapipe: access log writer is gone");
                    }
                },
                None => sink.write_line(&line),
            },
        }
    }

    // The same facts as the line above, and the same redacted detail: the
    // event and the file have to agree, or redacting the file only moves the
    // leak next door.
    //
    // **Its own target, so the server's log file does not carry it.** The
    // access log has the line already, and the file layer writes every event
    // it is given — synchronously, in the request's own task, under the sink's
    // lock. So the line was written to a file, and then written again to
    // another file, and the request paid for both.
    tracing::info!(
        target: ACCESS_TARGET,
        "Access: {} {} {} {} {}ms{}",
        remote_addr,
        method,
        uri,
        status,
        duration_ms,
        detail
    );
}

/// The target the access line is logged under.
///
/// Its own, so that the layer writing the server's log file can leave it out:
/// the access log has the line, and a file that has it twice is a file with
/// every request in it twice.
pub(super) const ACCESS_TARGET: &str = "access";

/// The access lines a test is watching, if a test is watching any.
///
/// The access log goes to a file or to stdout, and neither can be read back
/// from a test: the file is written on a thread of its own, and the console
/// belongs to the test harness. This is where the lines go instead, while a
/// test holds the handle.
#[cfg(test)]
static CAPTURED_ACCESS_LINES: Mutex<Option<Arc<Mutex<Vec<String>>>>> = Mutex::new(None);

/// The lines the watching test collects.
#[cfg(test)]
fn captured_access_lines() -> &'static Mutex<Option<Arc<Mutex<Vec<String>>>>> {
    &CAPTURED_ACCESS_LINES
}

/// Watches the access lines, and hands them to the test that watches them.
///
/// The watching stops when the handle is dropped: the lines belong to the
/// test, and a test that is over should not be collecting them.
#[cfg(test)]
pub(crate) fn capture_access_lines() -> AccessLineCapture {
    let lines = Arc::new(Mutex::new(Vec::new()));
    *captured_access_lines()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lines.clone());
    AccessLineCapture { lines }
}

/// Hands a line to the test that is watching, if there is one.
#[cfg(test)]
fn capture_line(line: &str) {
    let watching = captured_access_lines()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lines) = watching.as_ref() {
        lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(line.to_string());
    }
}

/// The handle a test holds while it watches the access lines.
#[cfg(test)]
pub(crate) struct AccessLineCapture {
    lines: Arc<Mutex<Vec<String>>>,
}

#[cfg(test)]
impl AccessLineCapture {
    /// The lines seen so far, in the order they were written.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[cfg(test)]
impl Drop for AccessLineCapture {
    fn drop(&mut self) {
        *captured_access_lines()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}
