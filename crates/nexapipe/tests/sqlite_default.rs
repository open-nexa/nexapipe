//! The database store as the default, and the `config.toml` that predates it.
//!
//! A deployment that names no store keeps its configuration in a database
//! beside `--config`. A deployment that has been running on the file store
//! already has that file, so the first start that finds an empty database
//! imports it — once, and without taking the file away.
//!
//! These tests drive the real binary, because what they pin is a startup
//! decision: which store is opened, what is written into it before the log
//! exists, and what the operator is told afterwards.

#![cfg(feature = "storage-sqlite")]

use nexapipe::storage::Storage;
use nexapipe::storage::sqlite::SqliteStorage;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a start gets to print its Node ID.
const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// A configuration that starts without a network: one route, relay off, no
/// address lookup.
const LEGACY_CONFIG: &str = "\
# Written when the configuration lived in a file.

[[routes]]
host_pattern = \"legacy.example\"
backends = [\"http://127.0.0.1:18080\"]

[iroh]
relay_mode = \"disabled\"
discovery = \"none\"
";

/// Starts the server and returns everything it printed before its Node ID line.
///
/// Reading while the process runs is what makes this work: the server does not
/// exit, so waiting for it would block forever on a process behaving exactly
/// as it should. The child is left running for the caller to kill.
fn start(config: &Path) -> (String, Child) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe");

    let stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let done = line.trim().starts_with("Node ID");
                    let _ = tx.send(line.clone());
                    if done {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut collected = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                collected.push_str(&line);
                if line.trim().starts_with("Node ID") {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "nexapipe printed no Node ID within {}s.\nCaptured so far:\n{collected}",
                    STARTUP_DEADLINE.as_secs()
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("nexapipe closed stdout before printing a Node ID:\n{collected}");
            }
        }
    }

    (collected, child)
}

/// The database the default store keeps beside `config`.
fn database(config: &Path) -> PathBuf {
    config.with_file_name("nexapipe.db")
}

/// The configuration the database holds, as the store hands it out.
async fn stored_config(database: &Path) -> String {
    let store = SqliteStorage::open(database.to_str().expect("utf-8 path"))
        .await
        .expect("the database opens");
    store
        .config()
        .await
        .expect("the store is readable")
        .expect("the store holds a configuration")
        .expose_secret()
        .to_string()
}

/// A first start with nothing anywhere ends up on the database, with the
/// first-run configuration written into it and no file on disk.
#[tokio::test]
async fn a_fresh_start_keeps_the_configuration_in_the_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let (output, mut child) = start(&config);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        database(&config).exists(),
        "the default store is the database beside the configuration: {}",
        database(&config).display()
    );
    assert!(
        !config.exists(),
        "and it writes no file: the configuration is in the database"
    );
    assert!(
        output.contains("wrote a minimal one"),
        "the operator is told the store was empty:\n{output}"
    );

    let stored = stored_config(&database(&config)).await;
    assert!(
        stored.contains("enabled = true"),
        "the first-run configuration is in the database: {stored}"
    );
}

/// A `config.toml` beside an empty database is imported, the operator is told
/// which file and which database, and the file is left where it was.
#[tokio::test]
async fn the_file_beside_an_empty_database_is_imported_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    fs::write(&config, LEGACY_CONFIG).expect("the legacy file is written");

    let (output, mut child) = start(&config);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        output.contains("Imported the configuration from"),
        "the import is reported:\n{output}"
    );
    assert!(
        output.contains(&config.display().to_string()),
        "the report names the file it read:\n{output}"
    );
    assert!(
        output.contains("nexapipe.db"),
        "and the database it is read from now:\n{output}"
    );
    assert!(
        config.exists(),
        "the file is left where it was: `--storage toml` still reads it"
    );

    let stored = stored_config(&database(&config)).await;
    assert!(
        stored.contains("legacy.example"),
        "the route came across: {stored}"
    );

    // The second start finds the configuration already there, so it reads no
    // file and imports nothing.
    let (output, mut child) = start(&config);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !output.contains("Imported the configuration from"),
        "the import fires once:\n{output}"
    );
    assert!(
        stored_config(&database(&config))
            .await
            .contains("legacy.example"),
        "the configuration the first start imported is still what is read"
    );
}

/// A file that cannot be read as a configuration stops the start, names the
/// reason, and leaves the database holding nothing.
#[tokio::test]
async fn a_file_that_does_not_parse_stops_the_start() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    fs::write(&config, "no_such_key = true\n").expect("the broken file is written");

    let output = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    assert!(!output.status.success(), "the start fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("config.toml") && stderr.contains("cannot be read as a configuration"),
        "the refusal names the file and the reason:\n{stderr}"
    );

    let store = SqliteStorage::open(database(&config).to_str().expect("utf-8 path"))
        .await
        .expect("the database was opened before the import ran");
    assert!(
        store
            .config()
            .await
            .expect("the store is readable")
            .is_none(),
        "the database is left holding no configuration"
    );
}
