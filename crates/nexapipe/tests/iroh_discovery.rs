//! The address-lookup switch, end to end through the real binary.
//!
//! Endpoint ID discovery is the one piece of n0's infrastructure a relay
//! setting does not reach: turning a Node ID into "where do I send QUIC
//! packets" asks n0's `dns.iroh.link`, over HTTPS and over DNS, whatever
//! `relay_mode` says. `discovery = "none"` switches it off — and a spelling it
//! does not know has to stop the server rather than quietly mean "n0", because
//! a config that says one thing and does another is the failure nobody sees.
//!
//! Each server is started with the relay disabled, so a test needs no network:
//! the same reason `data_plane.rs` binds loopback endpoints.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How long a start gets before the test gives up on it.
///
/// Generous, because the first start of a test binary also pays for loading
/// the endpoint machinery.
const STARTUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// A config with one catch-all route, the relay off, and the discovery mode
/// the test asks for.
fn scratch_config(discovery: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
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
             discovery = \"{discovery}\"\n"
        ),
    )
    .expect("write config");
    (dir, path)
}

/// Starts the server and waits for it to exit, returning what it said.
///
/// The server is expected to fail here, so this waits for the exit rather than
/// for a line of output: a server that came up anyway would have to be killed,
/// and a test that leaves a server bound to a port is a test that breaks the
/// next one.
fn run_until_exit(config: &Path) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    command
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command.spawn().expect("spawn nexapipe");
    let output = child.wait_with_output().expect("wait for nexapipe");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// A discovery mode nobody knows is refused, and the message says which key it
/// was — an operator who wrote `discovery = "off"` has to learn that the
/// spelling is the problem, not that the server is unhappy about something
/// else.
#[test]
fn an_unknown_discovery_mode_refuses_the_start() {
    let (_dir, config) = scratch_config("off");

    let (ok, output) = run_until_exit(&config);
    assert!(
        !ok,
        "the server started with an unknown discovery mode:\n{output}"
    );
    assert!(
        output.contains("discovery") && output.contains("off"),
        "the message must name the key and the value:\n{output}"
    );
}

/// The mode the switch exists for starts, and says so.
#[test]
fn discovery_can_be_switched_off() {
    let (_dir, config) = scratch_config("none");

    let mut command = Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    command
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn nexapipe");

    // The server does not exit, so this waits for a line of output and then
    // kills it. The line that matters is the one the startup log prints.
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = std::io::BufReader::new(stdout);
    let deadline = std::time::Instant::now() + STARTUP_DEADLINE;
    let mut collected = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        match std::io::BufRead::read_line(&mut stdout, &mut line) {
            Ok(0) => break,
            Ok(_) => {
                collected.push_str(&line);
                if collected.contains("Discovery: none") {
                    break;
                }
            }
            Err(_) => break,
        }
        if std::time::Instant::now() > deadline {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        collected.contains("Discovery: none"),
        "the startup log must say that the lookup is off:\n{collected}"
    );
}
