//! Logging setup.
//!
//! Two streams are written here:
//!
//! * the regular `tracing` log (everything the program emits), which goes to
//!   stdout and, when `[log] file = true`, to `<dir>/nexapipe.log`;
//! * the access log (one line per proxied request) in `<dir>/access.log`.
//!
//! Both files are appended to, rotate on a schedule and/or by size, and keep a
//! bounded number of rotated copies, so a long running container cannot fill the
//! disk. Writes are synchronous and flushed per line: `tail -f` works and logs
//! that were emitted before an `std::process::exit` are never lost.

use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;
use crate::conn::peers::PeerIdentity;

/// Timestamp format of every log line, in local time.
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";

/// Overrides `[log] dir`; convenient inside containers.
const LOG_DIR_ENV: &str = "NEXAPIPE_LOG_DIR";

/// Install the global logger and the access logger.
///
/// Everything that can go wrong here (unwritable log directory, a logger that
/// was already installed) degrades to stdout logging instead of aborting: a
/// misconfigured `[log]` section must not keep the proxy from starting.
pub fn init(config: Option<&LogConfig>, debug: bool) {
    let settings = Settings::from_config(config);
    // Set before anything can return early: an access line must not be written
    // verbatim just because the global logger could not be installed.
    set_redact_query(settings.redact_query);
    let filter = EnvFilter::new(format!("nexapipe={}", if debug { "debug" } else { "info" }));

    let log_sink = open_sink(&settings, &settings.file_name);
    let access_sink = if settings.access_log {
        open_sink(&settings, &settings.access_file_name)
    } else {
        None
    };

    let console = settings.console || log_sink.is_none();
    if !settings.console && log_sink.is_none() {
        eprintln!(
            "nexapipe: [log] console = false but no log file is available, keeping console output"
        );
    }

    let registry = tracing_subscriber::registry().with(filter);
    let installed = match (console, log_sink.clone()) {
        (true, Some(sink)) => registry
            .with(console_layer())
            .with(file_layer(sink))
            .try_init(),
        (true, None) => registry.with(console_layer()).try_init(),
        (false, Some(sink)) => registry.with(file_layer(sink)).try_init(),
        // Unreachable: `console` is forced on when there is no file to write to.
        (false, None) => registry.with(console_layer()).try_init(),
    };

    if installed.is_err() {
        eprintln!("nexapipe: a global logger is already installed, keeping it");
        return;
    }

    init_access_logger(settings.access_log, access_sink.clone());

    if let Some(sink) = &log_sink {
        let keep = if settings.max_files == 0 {
            "unlimited".to_string()
        } else {
            settings.max_files.to_string()
        };
        tracing::info!(
            "Logging to {} ({} rotation, keeping {} rotated file(s))",
            sink.path().display(),
            settings.rotation.label(),
            keep
        );
        if let Some(access) = &access_sink {
            tracing::info!("Access log: {}", access.path().display());
        }
    }
}

fn console_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_target(false)
        .with_timer(ChronoLocal::new(TIME_FORMAT.to_string()))
}

fn file_layer<S>(sink: FileSink) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_target(false)
        // No colour escape codes in the file.
        .with_ansi(false)
        .with_timer(ChronoLocal::new(TIME_FORMAT.to_string()))
        .with_writer(sink)
}

/// Open one of the log files, reporting a failure on stderr instead of aborting.
fn open_sink(settings: &Settings, file_name: &str) -> Option<FileSink> {
    if !settings.write_file {
        return None;
    }

    match settings.file_sink(file_name) {
        Ok(sink) => Some(sink),
        Err(err) => {
            eprintln!(
                "nexapipe: cannot open log file {}/{}: {}",
                settings.dir.display(),
                file_name,
                err
            );
            None
        }
    }
}

/// Resolved `[log]` settings, with the defaults applied.
#[derive(Debug, Clone)]
struct Settings {
    write_file: bool,
    dir: PathBuf,
    file_name: String,
    access_log: bool,
    access_file_name: String,
    rotation: Rotation,
    max_size_mb: u64,
    max_files: usize,
    console: bool,
    redact_query: bool,
}

impl Settings {
    fn from_config(config: Option<&LogConfig>) -> Self {
        let config = config.cloned().unwrap_or_default();

        let dir = std::env::var(LOG_DIR_ENV)
            .ok()
            .filter(|dir| !dir.trim().is_empty())
            .or_else(|| config.dir.clone())
            .unwrap_or_else(|| "./logs".to_string());

        Self {
            write_file: config.file.unwrap_or(true),
            dir: PathBuf::from(dir),
            file_name: config
                .file_name
                .unwrap_or_else(|| "nexapipe.log".to_string()),
            access_log: config.access_log.unwrap_or(true),
            access_file_name: config
                .access_log_file_name
                .unwrap_or_else(|| "access.log".to_string()),
            rotation: config
                .rotation
                .as_deref()
                .map(Rotation::parse)
                .unwrap_or(Rotation::Daily),
            max_size_mb: config.max_size_mb.unwrap_or(0),
            max_files: config.max_files.unwrap_or(14),
            console: config.console.unwrap_or(true),
            redact_query: config.redact_query.unwrap_or(true),
        }
    }

    fn file_sink(&self, file_name: &str) -> io::Result<FileSink> {
        FileSink::new(
            &self.dir,
            file_name,
            self.rotation,
            self.max_size_mb,
            self.max_files,
        )
    }
}

/// When a log file is rolled over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rotation {
    Never,
    Hourly,
    Daily,
}

impl Rotation {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "never" | "none" | "off" => Self::Never,
            "hourly" | "hour" => Self::Hourly,
            _ => Self::Daily,
        }
    }

    /// Identifier of the current rotation bucket, `None` when time based
    /// rotation is disabled.
    fn stamp(&self) -> Option<String> {
        match self {
            Self::Never => None,
            Self::Hourly => Some(Local::now().format("%Y-%m-%d-%H").to_string()),
            Self::Daily => Some(Local::now().format("%Y-%m-%d").to_string()),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
        }
    }
}

/// A shared, self-rotating log file. Cloning is cheap: every clone writes to the
/// same file, which is what [`MakeWriter`] needs for each `tracing` event.
#[derive(Clone)]
pub struct FileSink {
    state: Arc<Mutex<SinkState>>,
}

struct SinkState {
    /// Path of the active file; rotated copies live next to it.
    path: PathBuf,
    file: Option<File>,
    rotation: Rotation,
    /// Bucket the active file belongs to.
    stamp: Option<String>,
    /// Bytes in the active file so far.
    written: u64,
    /// Rotate once the active file would exceed this (0 = time based only).
    max_bytes: u64,
    /// Rotated copies to keep (0 = keep all).
    max_files: usize,
    /// Whether the last failure was already reported on stderr.
    reported: bool,
}

impl FileSink {
    fn new(
        dir: &Path,
        name: &str,
        rotation: Rotation,
        max_size_mb: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        fs::create_dir_all(dir)?;

        let path = dir.join(name);
        let file = open_append(&path)?;
        // The file is opened in append mode, so carry on counting where the
        // previous run stopped.
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);

        Ok(Self {
            state: Arc::new(Mutex::new(SinkState {
                path,
                file: Some(file),
                rotation,
                stamp: rotation.stamp(),
                written,
                max_bytes: max_size_mb.saturating_mul(1024 * 1024),
                max_files,
                reported: false,
            })),
        })
    }

    /// Path of the active file.
    pub fn path(&self) -> PathBuf {
        self.lock().path.clone()
    }

    /// Append one line, adding a trailing newline when missing.
    pub fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        if !line.ends_with('\n') {
            buf.push(b'\n');
        }

        let _ = self.lock().append(&buf);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
        // A panic somewhere else must not take logging down with it.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SinkState {
    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.rotate_if_needed(buf.len());

        let result = match self.file.as_mut() {
            Some(file) => file.write_all(buf).and_then(|()| file.flush()),
            None => Err(io::Error::other("log file is not open")),
        };

        match result {
            Ok(()) => {
                self.written += buf.len() as u64;
                self.reported = false;
                Ok(())
            }
            Err(err) => {
                // Report once and stay quiet afterwards: a full disk must not
                // turn every log line into another stderr message.
                if !self.reported {
                    eprintln!("nexapipe: failed to write {}: {}", self.path.display(), err);
                    self.reported = true;
                }
                // The file may have been removed or replaced behind our back
                // (host side rotation, `docker compose down`, ...): reopen it.
                self.file = open_append(&self.path).ok();
                Err(err)
            }
        }
    }

    fn rotate_if_needed(&mut self, incoming: usize) {
        let by_size = self.max_bytes > 0
            && self.written > 0
            && self.written.saturating_add(incoming as u64) > self.max_bytes;
        let by_time = self
            .rotation
            .stamp()
            .is_some_and(|stamp| self.stamp.as_deref() != Some(stamp.as_str()));

        if by_size || by_time {
            self.rotate();
        }
    }

    /// Rename the active file to `<stem>.<stamp>.<ext>` and start a fresh one.
    ///
    /// Failures are reported on stderr and never propagate: dropping a log line
    /// because rotation failed would be worse than a mixed up file.
    fn rotate(&mut self) {
        let stamp = self
            .rotation
            .stamp()
            .unwrap_or_else(|| Local::now().format("%Y-%m-%d-%H%M%S").to_string());
        let rotated = rotated_path(&self.path, &stamp);

        // Windows refuses to rename a file that is still open.
        drop(self.file.take());
        let renamed = fs::rename(&self.path, &rotated);
        self.file = open_append(&self.path).ok();

        match renamed {
            Ok(()) => {
                self.written = 0;
                self.stamp = self.rotation.stamp();
                prune_rotated_files(&self.path, self.max_files);
            }
            Err(err) => {
                if !self.reported {
                    eprintln!(
                        "nexapipe: failed to rotate {}: {}",
                        self.path.display(),
                        err
                    );
                    self.reported = true;
                }
                // Do not retry the same rotation on every following line.
                self.max_bytes = 0;
                self.stamp = self.rotation.stamp();
            }
        }
    }
}

/// Writer handed to `tracing` for every event; writes into the shared [`FileSink`].
pub struct SinkWriter {
    sink: FileSink,
}

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sink.lock().append(buf) {
            Ok(()) => Ok(buf.len()),
            // `tracing` swallows writer errors, so reporting the failure instead
            // of pretending the write succeeded is what keeps it visible.
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.sink.lock().file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for FileSink {
    type Writer = SinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter { sink: self.clone() }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `<dir>/<stem>.<stamp>.<ext>`, with a counter appended when that name is taken.
fn rotated_path(active: &Path, stamp: &str) -> PathBuf {
    let dir = active.parent().unwrap_or_else(|| Path::new("."));
    let stem = active
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("nexapipe");
    let ext = active.extension().and_then(|ext| ext.to_str());

    let named = |suffix: &str| match ext {
        Some(ext) => dir.join(format!("{}.{}.{}", stem, suffix, ext)),
        None => dir.join(format!("{}.{}", stem, suffix)),
    };

    let mut candidate = named(stamp);
    let mut counter = 1;
    while candidate.exists() {
        candidate = named(&format!("{}-{}", stamp, counter));
        counter += 1;
    }
    candidate
}

/// Keep at most `keep` rotated files for `active`, deleting the oldest first.
fn prune_rotated_files(active: &Path, keep: usize) {
    if keep == 0 {
        return;
    }

    let Some(active_name) = active.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let Some(dir) = active.parent() else {
        return;
    };
    let prefix = format!(
        "{}.",
        active
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(active_name)
    );
    let suffix = active
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext));

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut rotated: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        // Only ever touch files this sink created: `<stem>.<stamp>.<ext>`.
        if name == active_name || !name.starts_with(&prefix) {
            continue;
        }
        if let Some(suffix) = &suffix
            && !name.ends_with(suffix.as_str())
        {
            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        rotated.push((modified, path));
    }

    if rotated.len() <= keep {
        return;
    }

    rotated.sort_by_key(|(modified, _)| *modified);
    for (_, path) in rotated.iter().take(rotated.len() - keep) {
        let _ = fs::remove_file(path);
    }
}

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

fn init_access_logger(enabled: bool, file: Option<FileSink>) {
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
static REDACT_QUERY: AtomicBool = AtomicBool::new(true);

fn set_redact_query(redact: bool) {
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
pub(crate) fn uri_for_log(uri: &str) -> String {
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
fn redact_query(uri: &str) -> String {
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
fn access_line(
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
fn flow_detail_suffix(detail: &FlowDetail) -> String {
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
fn access_identity(who: Option<&PeerIdentity>) -> String {
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
    tracing::info!(
        "Access: {} {} {} {} {}ms{}",
        remote_addr,
        method,
        uri,
        status,
        duration_ms,
        detail
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn redacts_every_query_value() {
        assert_eq!(
            redact_query("/api/v1/items?token=hunter2&page=2"),
            "/api/v1/items?token=<redacted>&page=<redacted>"
        );
    }

    #[test]
    fn leaves_a_uri_without_a_query_alone() {
        assert_eq!(redact_query("/api/v1/items"), "/api/v1/items");
    }

    #[test]
    fn keeps_the_question_mark_of_an_empty_query() {
        assert_eq!(redact_query("/search?"), "/search?");
    }

    #[test]
    fn keeps_a_bare_flag() {
        // No `=`, so there is no value to hide — and `?raw` is a useful thing
        // to still be able to read in a log.
        assert_eq!(
            redact_query("/file?raw&token=hunter2"),
            "/file?raw&token=<redacted>"
        );
    }

    #[test]
    fn redacts_a_value_that_is_itself_empty() {
        assert_eq!(
            redact_query("/x?token=&ok=1"),
            "/x?token=<redacted>&ok=<redacted>"
        );
    }

    /// A span layer that remembers what was recorded into its `uri` field.
    ///
    /// A span's fields are rendered into the general log file by every event
    /// inside the span, so what lands in a span is what lands in that file.
    /// This is how the test sees it.
    #[derive(Clone, Default)]
    struct CapturedUri(Arc<Mutex<Option<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedUri {
        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = UriVisitor(None);
            values.record(&mut visitor);
            if let Some(uri) = visitor.0 {
                *self.0.lock().unwrap() = Some(uri);
            }
        }
    }

    /// Picks the `uri` field out of a recorded span.
    struct UriVisitor(Option<String>);

    impl tracing::field::Visit for UriVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "uri" {
                self.0 = Some(value.to_string());
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "uri" {
                self.0 = Some(format!("{value:?}"));
            }
        }
    }

    /// A query value recorded into a span is redacted.
    ///
    /// The span is the other way a URI reaches a log file. The access log
    /// redacts its own copy, but a span's fields are rendered into the
    /// *general* log file by every event inside the span — so a query value
    /// written there was a query value in a file that gets rotated, archived
    /// and handed to someone else, with the access log's redaction nowhere
    /// near it.
    #[test]
    fn a_uri_recorded_into_a_span_is_redacted() {
        let captured = CapturedUri::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", uri = tracing::field::Empty);
            let _guard = span.enter();
            super::record_request_on_span(&span, "GET", "/api/v1/items?token=hunter2&page=2");
        });

        let recorded = captured
            .0
            .lock()
            .unwrap()
            .clone()
            .expect("the span recorded a uri");
        assert_eq!(
            recorded, "/api/v1/items?token=<redacted>&page=<redacted>",
            "a query value reached the span, and the span is rendered into the log file"
        );
    }

    #[test]
    fn redacting_is_the_default() {
        // The flag starts on, so a line is never written verbatim just because
        // `init` was not called (a library embedder, or an already installed
        // global logger).
        assert!(REDACT_QUERY.load(Ordering::Relaxed));
    }

    /// The suffix a flow's facts add to a line.
    #[test]
    fn a_flow_says_what_it_was() {
        assert_eq!(
            flow_detail_suffix(&FlowDetail::Tls {
                sni: Some("www.example.com".to_string())
            }),
            " sni=www.example.com"
        );

        // A TLS handshake that named no host is not the same answer as a flow
        // that was not TLS at all.
        assert_eq!(flow_detail_suffix(&FlowDetail::Tls { sni: None }), " sni=-");

        assert_eq!(
            flow_detail_suffix(&FlowDetail::Http {
                method: "GET".to_string(),
                target: "/v1/items".to_string(),
                version: "HTTP/1.1".to_string(),
                status: Some(404),
            }),
            " http=\"GET /v1/items HTTP/1.1\" http_status=404"
        );

        // An origin that never answered is not an answer.
        assert_eq!(
            flow_detail_suffix(&FlowDetail::Http {
                method: "GET".to_string(),
                target: "/v1/items".to_string(),
                version: "HTTP/1.1".to_string(),
                status: None,
            }),
            " http=\"GET /v1/items HTTP/1.1\" http_status=-"
        );
    }

    /// A sniffed target is a URI like any other, so its query values are
    /// redacted too.
    #[test]
    fn a_sniffed_target_is_redacted() {
        assert_eq!(
            flow_detail_suffix(&FlowDetail::Http {
                method: "GET".to_string(),
                target: "/api/v1/items?token=hunter2".to_string(),
                version: "HTTP/1.1".to_string(),
                status: Some(200),
            }),
            " http=\"GET /api/v1/items?token=<redacted> HTTP/1.1\" http_status=200"
        );
    }

    /// The client owns these bytes, and a log line is read by people and by
    /// scripts: a newline in here would write the next line of the log
    /// itself, and a quote would end the quoted part early.
    #[test]
    fn a_sniffed_value_cannot_break_the_line() {
        let suffix = flow_detail_suffix(&FlowDetail::Http {
            method: "GET".to_string(),
            target: "/x\r\nGET /secret HTTP/1.1".to_string(),
            version: "HTTP/1.1".to_string(),
            status: None,
        });

        assert!(!suffix.contains('\n'), "the line can be broken: {suffix}");
        assert!(!suffix.contains('\r'), "the line can be broken: {suffix}");
        assert_eq!(
            suffix.matches('"').count(),
            2,
            "the quoting is broken: {suffix}"
        );
    }

    /// The columns before the id keep the shape they have had, and the flow's
    /// own facts go at the very end.
    #[test]
    fn a_flow_facts_do_not_move_the_columns() {
        let line = access_line(
            "abc123",
            "203.0.113.9",
            "TCP",
            "db.test:5432",
            200,
            12,
            0,
            "",
            " sni=www.example.com",
        );

        assert!(
            line.contains("\"TCP db.test:5432\" 200 0 12ms id=abc123 sni=www.example.com"),
            "unexpected line: {line}"
        );
    }

    #[test]
    fn settings_honour_redact_query() {
        let off = LogConfig {
            redact_query: Some(false),
            ..Default::default()
        };
        assert!(!Settings::from_config(Some(&off)).redact_query);
        // Absent means redact, and so does a `[log]` section that is missing
        // altogether.
        assert!(Settings::from_config(Some(&LogConfig::default())).redact_query);
        assert!(Settings::from_config(None).redact_query);
    }

    /// Byte level size budget, which the public API only exposes in MiB.
    fn sink_with(dir: &Path, name: &str, max_bytes: u64, max_files: usize) -> FileSink {
        let path = dir.join(name);
        let file = open_append(&path).unwrap();

        FileSink {
            state: Arc::new(Mutex::new(SinkState {
                path,
                file: Some(file),
                rotation: Rotation::Never,
                stamp: None,
                written: 0,
                max_bytes,
                max_files,
                reported: false,
            })),
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    fn rotated(dir: &Path, active: &str) -> Vec<String> {
        names(dir)
            .into_iter()
            .filter(|name| name != active)
            .collect()
    }

    /// The line is written by a thread of its own, so this waits for it — but
    /// what it is really checking is that the path from `log_access` through
    /// the queue to `FileSink` still ends up on disk, redacted and complete.
    #[test]
    fn an_access_line_reaches_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let sink = FileSink::new(dir.path(), "access.log", Rotation::Daily, 0, 14).unwrap();
        init_access_logger(true, Some(sink));

        let id = next_request_id();
        log_access(
            &id,
            "203.0.113.9",
            "GET",
            "/api/v1/items?token=hunter2",
            200,
            12,
            512,
            Some(&PeerIdentity {
                client_id: Some("acme".to_string()),
                device: Some("laptop".to_string()),
            }),
        );

        let path = dir.path().join("access.log");
        for _ in 0..200 {
            if let Ok(contents) = fs::read_to_string(&path)
                && !contents.is_empty()
            {
                assert!(
                    contents.contains("token=<redacted>"),
                    "the query value was not redacted: {contents}"
                );
                assert!(
                    contents.contains("\"GET /api/v1/items?token=<redacted>\" 200 512 12ms"),
                    "unexpected line: {contents}"
                );
                assert!(
                    contents.contains(&format!("id={id}")),
                    "the request id is missing from the line: {contents}"
                );
                // Whose request it was, which is the one thing the line could
                // not answer before: the client and device the connection
                // authenticated as.
                assert!(
                    contents.contains("client=acme device=laptop"),
                    "the client and device are missing from the line: {contents}"
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!("the access line never reached {}", path.display());
    }

    /// The three shapes the suffix takes. Tested apart from the line itself
    /// because two of them never reach a sink in a test: whether the logger is
    /// armed is global state, and two tests arming it at once would race.
    #[test]
    fn the_access_line_names_the_client_and_the_device_it_came_from() {
        assert_eq!(
            access_identity(Some(&PeerIdentity {
                client_id: Some("acme".to_string()),
                device: Some("laptop".to_string()),
            })),
            " client=acme device=laptop"
        );

        // Authenticated but unnamed: the device that carries the client's own
        // secret. A dash rather than an empty field, because "no name" and "no
        // client" are not the same answer.
        assert_eq!(
            access_identity(Some(&PeerIdentity {
                client_id: Some("acme".to_string()),
                device: None,
            })),
            " client=acme device=-"
        );

        // No handshake: the plaintext listener, and 2FA off.
        assert_eq!(access_identity(None), "");
        assert_eq!(access_identity(Some(&PeerIdentity::default())), "");
        assert_eq!(
            access_identity(Some(&PeerIdentity {
                client_id: None,
                device: Some("laptop".to_string()),
            })),
            "",
            "a device with no client is not something a line should assert"
        );
    }

    #[test]
    fn appends_lines_to_the_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let sink = FileSink::new(dir.path(), "test.log", Rotation::Daily, 0, 14).unwrap();

        sink.write_line("first");
        sink.write_line("second\n");

        assert_eq!(
            fs::read_to_string(dir.path().join("test.log")).unwrap(),
            "first\nsecond\n"
        );
        assert!(names(dir.path()).contains(&"test.log".to_string()));
    }

    #[test]
    fn rotates_once_the_size_budget_is_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink_with(dir.path(), "test.log", 8, 1);

        sink.write_line("aaaa"); // 5 bytes, still under the budget
        sink.write_line("bbbb"); // would exceed it: rotate first

        assert_eq!(
            fs::read_to_string(dir.path().join("test.log")).unwrap(),
            "bbbb\n"
        );

        let rotated = rotated(dir.path(), "test.log");
        assert_eq!(rotated.len(), 1);
        assert!(rotated[0].starts_with("test."), "{:?}", rotated);
        assert!(rotated[0].ends_with(".log"), "{:?}", rotated);
        assert_eq!(
            fs::read_to_string(dir.path().join(&rotated[0])).unwrap(),
            "aaaa\n"
        );
    }

    #[test]
    fn keeps_only_the_configured_number_of_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let sink = sink_with(dir.path(), "test.log", 1, 2);

        for i in 0..6 {
            sink.write_line(&i.to_string());
        }

        assert_eq!(rotated(dir.path(), "test.log").len(), 2);
    }

    #[test]
    fn parses_rotation_names() {
        assert_eq!(Rotation::parse("hourly"), Rotation::Hourly);
        assert_eq!(Rotation::parse("NEVER"), Rotation::Never);
        assert_eq!(Rotation::parse("daily"), Rotation::Daily);
        assert_eq!(Rotation::parse("something else"), Rotation::Daily);
    }
}
