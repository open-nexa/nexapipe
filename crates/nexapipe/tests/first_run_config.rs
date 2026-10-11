//! The config generated on a first start, end to end through the real binary.
//!
//! Starting with no `config.toml` used to be a dead end: the server printed
//! `Config file not found` and exited, leaving a new operator with nothing to
//! edit. These pin what replaces that — a minimal file that starts, that has
//! 2FA on, and that does not overwrite anything the operator has since written.
//!
//! Each server is started with the relay disabled, so a test needs no network.
//! The process is killed rather than waited on: it is a server, and there is no
//! clean shutdown to wait for.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nexapipe::config::ProxyConfig;

/// How long a start gets to write the config and print its Node ID.
const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// An empty directory: the state of a host where nobody has run the server yet.
fn empty_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    assert!(!path.exists(), "the fixture has to start with no config");
    (dir, path)
}

/// Starts the server and returns once it has printed its Node ID, or once the
/// deadline passes.
///
/// Reading stdout while the process runs is what makes this work at all: the
/// server does not exit, so `wait_with_output` would block forever on a process
/// behaving exactly as it should. The child is killed before this returns —
/// including on the timeout path, where an assertion fires — so a failing test
/// does not leave a server bound to a port.
fn start_until_node_id(config: &Path) -> (String, Child) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = std::io::BufReader::new(stdout);

    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut collected = String::new();
    let mut line = String::new();
    let node_id = loop {
        line.clear();
        match std::io::BufRead::read_line(&mut stdout, &mut line) {
            Ok(0) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("nexapipe exited before printing a Node ID:\n{collected}");
            }
            Ok(_) => {
                collected.push_str(&line);
                if let Some(rest) = line
                    .trim()
                    .strip_prefix("Node ID (stable, for server_node_id):")
                {
                    break rest.trim().to_string();
                }
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("reading nexapipe's stdout failed: {e}");
            }
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "nexapipe printed no Node ID within {}s.\nCaptured so far:\n{collected}",
                STARTUP_DEADLINE.as_secs()
            );
        }
    };

    (node_id, child)
}

/// A missing config is written, and the server it describes actually starts.
///
/// The two halves are asserted together on purpose. A file that is written but
/// unreadable — a bad template, a syntax error — would satisfy "the file exists"
/// and leave an operator with a config that refuses to load, which is the
/// situation this feature exists to close.
#[test]
fn a_missing_config_is_written_and_the_server_starts() {
    let (_dir, path) = empty_dir();

    let (node_id, mut child) = start_until_node_id(&path);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !node_id.is_empty(),
        "the server has to reach a usable state"
    );
    let content = fs::read_to_string(&path).expect("the first start wrote a config");
    assert!(
        !content.trim().is_empty(),
        "an empty file is not a config: {content:?}"
    );
    ProxyConfig::from_file(path.to_str().expect("utf-8 path"))
        .expect("the generated config has to load through the normal path");
}

/// 2FA is on, and there is no client.
///
/// The pair is the point. `enabled = true` with an empty `[auth.clients]` means
/// nothing can connect, which is the correct state for a config nobody has
/// written — but only because both halves are asserted: a generated file with
/// `enabled = false` would serve every host that can reach it, which is the
/// opposite of what this is for.
#[test]
fn the_generated_config_enables_2fa_with_no_clients() {
    let (_dir, path) = empty_dir();

    let (_node_id, mut child) = start_until_node_id(&path);
    let _ = child.kill();
    let _ = child.wait();

    let (_, auth) = ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
        .expect("the generated config loads");
    let auth = auth.expect("the generated config declares an [auth] section");
    assert!(
        auth.enabled,
        "a config nobody has written must not leave the listener ungated"
    );
    assert!(
        auth.clients.is_empty(),
        "no client is invented: a generated secret would be a credential in a \
         log, and enrolling one is the operator's call. Got {:?}",
        auth.clients.keys().collect::<Vec<_>>()
    );
}

/// The file is created private on Unix.
///
/// The generated config turns 2FA on, which `holds_credentials` counts, so the
/// startup permission check *refuses to start* a world-readable one. Creating
/// it 0644 by umask and tightening it after the write would mean the server
/// refuses to start on the file it wrote itself.
#[cfg(unix)]
#[test]
fn the_generated_config_is_private_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, path) = empty_dir();

    let (_node_id, mut child) = start_until_node_id(&path);
    let _ = child.kill();
    let _ = child.wait();

    let mode = fs::metadata(&path)
        .expect("stat the config")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "a config holding 2FA settings must not be reachable by another \
         account (mode {mode:o})"
    );
}

/// A second start leaves the operator's edits alone.
///
/// The regression this guards is quiet and destructive: a generate-on-start
// that does not check for an existing file would overwrite a real config with
// the template on every restart, taking the routes, the enrolled clients and the
/// lockout counters with it. The marker stands in for all three.
#[test]
fn a_second_start_does_not_overwrite_the_config() {
    let (_dir, path) = empty_dir();

    let (_first, mut child) = start_until_node_id(&path);
    let _ = child.kill();
    let _ = child.wait();

    let edited = format!(
        "{}\n# operator marker\n[[routes]]\nhost_pattern = \"*\"\nbackends = [\"http://127.0.0.1:18080\"]\n",
        fs::read_to_string(&path).expect("read the generated config")
    );
    fs::write(&path, &edited).expect("edit the config");

    let (_second, mut child) = start_until_node_id(&path);
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        fs::read_to_string(&path).expect("the config is still there"),
        edited,
        "a start must never regenerate a config that already exists"
    );
}

/// An existing config is left untouched even when it is one nobody wrote.
///
/// Same invariant as above, reached the other way round: the file was already
/// there before this start, so nothing about it is this start's business. A
/// config that fails to *parse* is the sharper case — it must still fail the
/// start rather than be replaced by a default that looks deliberate.
#[test]
fn a_broken_config_is_not_replaced_by_a_generated_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    let broken = "[auth\nenabled = true\n";
    fs::write(&path, broken).expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", path.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe")
        .wait_with_output()
        .expect("nexapipe refuses to start, so it exits");

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "a config that cannot be parsed must not start:\n{text}"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("the config is still there"),
        broken,
        "the operator's file has to survive so they can see the typo:\n{text}"
    );
}

/// A read-only command does not create the config.
///
/// `status` reports on a server that is already running and `--generate-2fa`
/// works with no config at all; neither is a reason to leave a file behind on a
/// host where an operator deliberately has none. This is the boundary that
/// keeps the feature from turning every invocation into a config-generating one.
#[test]
fn status_does_not_create_a_config() {
    let (_dir, path) = empty_dir();

    let _ = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", path.to_str().expect("utf-8 path"), "status"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe")
        .wait_with_output()
        .expect("status exits");

    assert!(
        !path.exists(),
        "a read-only command must not leave a config behind: {}",
        path.display()
    );
}
