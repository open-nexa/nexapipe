//! The `[limits]` section, end to end through the real binary.
//!
//! The ceilings the process runs under used to be reachable only through four
//! environment variables, which meant a deployment that described itself in a
//! `config.toml` had to describe its own limits somewhere else as well — and a
//! limit nobody wrote down is a limit nobody knows is in force.
//!
//! These tests pin the three things that could go wrong, from the outside:
//! that the section reaches the running server, that the environment still
//! outranks it (the four variables are older than the section and keep
//! working), and that a limit which cannot work refuses the start rather than
//! quietly not applying.
//!
//! Each server is started with the relay disabled, so a test needs no network.
//! The process is killed rather than waited on: it is a server, and there is no
//! clean shutdown to wait for.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nexapipe::config::ProxyConfig;

/// How long a start gets to report the ceilings it is running with.
const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// How long a server started against a broken config gets to refuse to start.
const EXIT_DEADLINE: Duration = Duration::from_secs(10);

/// A config that starts a server without a network, plus the `[limits]` block
/// the caller wants.
fn write_config(dir: &Path, limits: &str) -> PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            "# My proxy.\n\
             \n\
             [[routes]]\n\
             host_pattern = \"*\"\n\
             backends = [\"http://127.0.0.1:18080\"]\n\
             \n\
             [iroh]\n\
             relay_mode = \"disabled\"\n\
             {limits}"
        ),
    )
    .expect("write config");
    path
}

/// Starts the server and returns once it has reported the ceilings it is
/// running with, or once the deadline passes.
///
/// Reading stdout while the process runs is what makes this work at all: the
/// server does not exit, so `wait_with_output` would block forever on a process
/// behaving exactly as it should. The child is killed before this returns, so
/// a failing test does not leave a server running.
fn start_until_ceilings(config: &Path, env: &[(&str, &str)]) -> (String, Child) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    command
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = command.spawn().expect("spawn nexapipe");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = std::io::BufReader::new(stdout);

    let mut text = String::new();
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        let mut line = String::new();
        match std::io::BufRead::read_line(&mut stdout, &mut line) {
            Ok(0) => break,
            Ok(_) => {
                text.push_str(&line);
                if line.contains("Accepting at most") {
                    break;
                }
            }
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    (text, child)
}

/// Waits for a server that is expected to refuse to start, and returns what it
/// said on the way out.
fn start_until_refused(config: &Path) -> (bool, String) {
    let child = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe");

    let (status, stdout, stderr) = wait_with_output_and_deadline(child, EXIT_DEADLINE);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    (!status.success(), text)
}

/// The same bounded wait, for a process that is expected to exit.
fn wait_with_output_and_deadline(
    mut child: Child,
    timeout: Duration,
) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout), &mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr), &mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    break child.wait().expect("wait after kill");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };

    (
        status,
        stdout_thread.join().unwrap_or_default(),
        stderr_thread.join().unwrap_or_default(),
    )
}

/// The shipped example config parses, and its `[limits]` block is the
/// commented-out one the rest of the file uses for a section it does not
/// enable.
///
/// The example is the first thing an operator copies, so a change to it that
/// breaks its TOML is a change that breaks their first hour with the server.
#[test]
fn the_shipped_example_config_still_parses() {
    let path = "../../config.toml.example";

    let config = ProxyConfig::from_file(path).expect("the shipped example parses");
    assert_eq!(
        config.limits.max_connections_per_peer, None,
        "the example leaves the limits at their defaults"
    );
}

/// A config with no `[limits]` section parses, and names no ceiling.
#[test]
fn a_config_without_limits_leaves_every_ceiling_unnamed() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");

    let config = ProxyConfig::from_file(path.to_str().unwrap()).expect("the config parses");
    assert_eq!(config.limits.max_connections_per_peer, None);
    assert_eq!(config.limits.max_connections_global, None);
    assert_eq!(config.limits.max_streams_global, None);
    assert_eq!(config.limits.max_body_bytes, None);
}

/// Every key in `[limits]` reaches the parsed config.
#[test]
fn the_limits_section_parses() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "\n[limits]\n\
         max_connections_per_peer = 11\n\
         max_connections_global = 22\n\
         max_streams_global = 33\n\
         max_body_bytes = 44\n",
    );

    let config = ProxyConfig::from_file(path.to_str().unwrap()).expect("the config parses");
    assert_eq!(config.limits.max_connections_per_peer, Some(11));
    assert_eq!(config.limits.max_connections_global, Some(22));
    assert_eq!(config.limits.max_streams_global, Some(33));
    assert_eq!(config.limits.max_body_bytes, Some(44));
}

/// A misspelled key is refused at load, rather than a ceiling that silently
/// does not apply.
///
/// The failure this guards against is the quiet one: a limit that is not the
/// limit the operator wrote is a limit nobody knows is in force.
#[test]
fn an_unknown_key_in_limits_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "\n[limits]\nmax_connections = 10\n");

    let error = ProxyConfig::from_file(path.to_str().unwrap())
        .expect_err("a misspelled key is not a limit");
    let message = format!("{error:#}");
    assert!(
        message.contains("max_connections"),
        "the error names the key that was not understood: {message}"
    );
}

/// The ceilings the section names are the ceilings the server runs with.
#[test]
fn the_limits_reach_the_running_server() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "\n[limits]\n\
         max_connections_per_peer = 11\n\
         max_connections_global = 22\n\
         max_streams_global = 33\n\
         max_body_bytes = 44\n",
    );

    let (text, _child) = start_until_ceilings(&path, &[]);
    assert!(
        text.contains("11 concurrent connections per peer"),
        "the per-peer ceiling is the one that was written: {text}"
    );
    assert!(
        text.contains("22 across the process"),
        "the process-wide ceiling is the one that was written: {text}"
    );
    assert!(
        text.contains("33 streams across the process"),
        "the stream ceiling is the one that was written: {text}"
    );
    assert!(
        text.contains("44 bytes of request bodies across the process"),
        "the body budget is the one that was written: {text}"
    );
}

/// A config with no `[limits]` section runs with the defaults it always ran
/// with — the section is a way to write a ceiling down, not a new one.
#[test]
fn a_config_without_limits_runs_with_the_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");

    let (text, _child) = start_until_ceilings(&path, &[]);
    assert!(
        text.contains("64 concurrent connections per peer"),
        "the default per-peer ceiling is unchanged: {text}"
    );
    assert!(
        text.contains("4096 across the process"),
        "the default process-wide ceiling is unchanged: {text}"
    );
}

/// The environment still outranks the config.
///
/// The four variables are older than the section, so a deployment that sets
/// them keeps the behaviour it had; the section is what a deployment that
/// does not use the environment writes its ceilings into.
#[test]
fn the_environment_outranks_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "\n[limits]\nmax_connections_per_peer = 11\n");

    let (text, _child) = start_until_ceilings(&path, &[("NEXAPIPE_MAX_CONNS_PER_PEER", "7")]);
    assert!(
        text.contains("7 concurrent connections per peer"),
        "the environment wins, as it does for every other credential: {text}"
    );
    assert!(
        !text.contains("11 concurrent connections per peer"),
        "the config's value is not the one in force: {text}"
    );
}

/// A ceiling of zero refuses the start.
///
/// It would refuse every connection, which is a typo rather than a setting,
/// and the file is somewhere the operator can read the error.
#[test]
fn a_zero_limit_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "\n[limits]\nmax_connections_per_peer = 0\n");

    let (refused, text) = start_until_refused(&path);
    assert!(refused, "a limit of zero must not start the server: {text}");
    assert!(
        text.contains("max_connections_per_peer"),
        "the error names the key that cannot work: {text}"
    );
}

/// A zero in the environment is ignored rather than refused.
///
/// A bad variable in a Dockerfile should not keep the server from starting:
/// the default is used instead, and the log says so.
#[test]
fn a_zero_limit_in_the_environment_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");

    let (text, _child) = start_until_ceilings(&path, &[("NEXAPIPE_MAX_CONNS_PER_PEER", "0")]);
    assert!(
        text.contains("64 concurrent connections per peer"),
        "the default is used instead of the unusable value: {text}"
    );
}
