//! The tests of the log: the layers it installs, the file a line is written to,
//! and the access line that is built and redacted.

use super::access::{REDACT_QUERY, access_identity, access_line, flow_detail_suffix, redact_query};
use super::sink::sink_with;

use super::*;
use crate::conn::peers::PeerIdentity;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// The access line goes to the console and to the access log, and not to
/// the server's log file.
///
/// The file layer writes every event it is given — synchronously, in the
/// request's own task, under the sink's lock — so an access line that
/// reached it as well was a second write of the same line, into a second
/// file, on the path of every request.
#[test]
fn the_access_line_is_not_written_to_the_server_log_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let sink = FileSink::new(dir.path(), "server.log", Rotation::Never, 0, 0).expect("a log file");
    let path = sink.path();
    let subscriber = tracing_subscriber::registry()
        .with(env_filter(false))
        .with(file_layer(sink, true));

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: ACCESS_TARGET, "Access: 1.2.3.4 GET / 200");
        tracing::info!("a server event");
    });

    let written = std::fs::read_to_string(path).expect("the log file");
    assert!(
        written.contains("a server event"),
        "the server's own events are in the file: {written}"
    );
    assert!(
        !written.contains("Access:"),
        "the access line is in the file as well: {written}"
    );
}

/// With no access log of its own, the line stays in the server's log file.
///
/// `[log] access_log = false` is a server that keeps one file, and the
/// access line was in that file before the filter existed. A filter that
/// dropped it here as well would answer a configuration that asked for no
/// *separate* access log with no access lines at all.
#[test]
fn the_access_line_stays_in_the_server_log_when_it_has_nowhere_else_to_go() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let sink = FileSink::new(dir.path(), "server.log", Rotation::Never, 0, 0).expect("a log file");
    let path = sink.path();
    let subscriber = tracing_subscriber::registry()
        .with(env_filter(false))
        .with(file_layer(sink, false));

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: ACCESS_TARGET, "Access: 1.2.3.4 GET / 200");
    });

    let written = std::fs::read_to_string(path).expect("the log file");
    assert!(
        written.contains("Access:"),
        "the line has no other file to go to: {written}"
    );
}

/// The access line's own target has to be named by the filter the server
/// installs, or the line is dropped altogether — and the console is where
/// it is supposed to be.
#[test]
fn the_filter_names_the_access_target() {
    for debug in [false, true] {
        let filter = format!("{:?}", env_filter(debug));
        assert!(
            filter.contains("access"),
            "the filter drops the access line: {filter}"
        );
    }
}

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
