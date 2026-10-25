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
//!
//! It is three things, and they are three files:
//!
//! - `sink` — the file a line is written to, and how it rolls over.
//! - `access` — the access line, what it says, and what is redacted from it.
//! - this one — the layers the program installs, and the settings they read.

mod access;
mod record;
mod sink;

#[cfg(test)]
mod tests;

use chrono::Local;
use std::io;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;

use access::{ACCESS_TARGET, init_access_logger, set_redact_query};

pub(crate) use access::record_request_on_span;
pub use access::{FlowDetail, log_access, log_access_flow, next_request_id};
pub use record::{AccessRecord, AccessSink, add_access_sink};
pub use sink::{FileSink, SinkWriter};

#[cfg(test)]
pub(crate) use access::{AccessLineCapture, capture_access_lines};

/// The filter every layer is under.
///
/// **It names the access target as well as the crate's own.** The access line
/// is logged under a target of its own, so that the layer writing the server's
/// log file can leave it out — and a filter that named only `nexapipe` would
/// drop the line altogether, rather than let it through to the console alone.
fn env_filter(debug: bool) -> EnvFilter {
    EnvFilter::new(format!(
        "nexapipe={},access=info",
        if debug { "debug" } else { "info" }
    ))
}

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
    // The access line has a target of its own, so the filter has to name it:
    // a filter that names only the crate's own target would drop the line
    // altogether rather than let it through to the console alone.
    let filter = env_filter(debug);

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
    // Whether the access line has a file of its own. It is the operator's
    // setting rather than the sink, so a failure to open the file does not
    // silently move the line back into the server's log — the access logger
    // already falls back to stdout for that case.
    let access_has_a_file = settings.access_log;
    let installed = match (console, log_sink.clone()) {
        (true, Some(sink)) => registry
            .with(console_layer())
            .with(file_layer(sink, access_has_a_file))
            .try_init(),
        (true, None) => registry.with(console_layer()).try_init(),
        (false, Some(sink)) => registry
            .with(file_layer(sink, access_has_a_file))
            .try_init(),
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

/// The server's own log file.
///
/// `access_has_a_file` says whether the access line has a file of its own to go
/// to. When it does, the line is left out of this one: the access log has it,
/// and it is written on a thread of its own — a request that also wrote the
/// line here would pay for a second synchronous write, under this sink's lock,
/// to put the same line in another file.
///
/// When it does **not** — `[log] access_log = false` — this file is the only
/// place the line can reach besides the console, which is where it was before
/// the filter existed. Dropping it here as well would take access lines away
/// from a server that was configured to keep them in its one log file.
fn file_layer<S>(sink: FileSink, access_has_a_file: bool) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_target(false)
        // No colour escape codes in the file.
        .with_ansi(false)
        .with_timer(ChronoLocal::new(TIME_FORMAT.to_string()))
        .with_writer(sink)
        .with_filter(filter_fn(move |metadata| {
            !access_has_a_file || metadata.target() != ACCESS_TARGET
        }))
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
