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

/// How long a server started against a broken config gets to refuse to start
/// before the test gives up and kills it.
const EXIT_DEADLINE: Duration = Duration::from_secs(10);

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
/// behaving exactly as it should. The deadline bounds the whole wait, not just
/// the iterations — `read_line` blocks until data, EOF, or error, so a child
/// that is alive but stops producing output would otherwise hang the test
/// past `STARTUP_DEADLINE`, because the deadline check below the read never
/// runs. Reading on a separate thread and `recv_timeout`-ing from here closes
/// that gap; the child is killed on timeout, the test process exiting will
/// reap anything else.
fn start_until_node_id(config: &Path) -> (String, Child) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    command
        .args(["--config", config.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    start_until_node_id_with(command)
}

/// Same as [`start_until_node_id`], but lets the caller configure the
/// `Command` before it is spawned. Used by tests that need to set env vars
/// (e.g. `NEXAPIPE_CONFIG_DIR`) rather than pass `--config` explicitly.
fn start_until_node_id_with(mut command: Command) -> (String, Child) {
    let mut child = command.spawn().expect("spawn nexapipe");
    let stdout = child.stdout.take().expect("stdout is piped");

    // The reader thread owns the pipe and exits when stdout EOFs (the child
    // closing it on exit, or a kill closing it for us). The main thread does
    // not touch the pipe at all, so its `recv_timeout` is the only thing that
    // can fire while the child is alive-but-quiet.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let is_node_id = line
                        .trim()
                        .starts_with("Node ID (stable, for server_node_id):");
                    // Send even if the receiver has gone — the test moved on.
                    let _ = tx.send(line.clone());
                    if is_node_id {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut collected = String::new();
    let node_id = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                collected.push_str(&line);
                if let Some(rest) = line
                    .trim()
                    .strip_prefix("Node ID (stable, for server_node_id):")
                {
                    break rest.trim().to_string();
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
    };

    (node_id, child)
}

/// Run `child` to completion, or kill it after `timeout`. Stdout and stderr are
/// drained on background threads so the child cannot block on a full pipe
/// before the deadline, and the captured bytes are returned alongside the
/// exit status.
///
/// `wait_with_output` is what the broken-config test used, and it blocks until
/// the child exits. A regression that turned a refused-to-start server into a
/// persistent one would hang the test forever — the deadline is what turns
/// that hang into a clear failure with the captured output.
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

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    (status, stdout, stderr)
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
/// `write_config_file` opens the temp file at mode 0600 up front, so a config
/// carrying 2FA settings is never on disk at the umask default — tightening the
/// mode after the write would leave it 0644 for the length of the write.
/// Startup no longer refuses a permissive config, but the generated file stays
/// private by default; the credential sidecar files are still enforced 0600.
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

    let child = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args(["--config", path.to_str().expect("utf-8 path")])
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

    assert!(
        !status.success(),
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

/// `--generate-2fa` early-returns before `ensure_config_file` even runs, so a
/// missing config on the path makes it error out — and crucially, without
/// leaving one behind. The existing client-cli suite already exercises
/// `--generate-2fa` against a config that *exists*; this pins the *missing*
/// half of the same invariant.
#[test]
fn generate_2fa_does_not_create_a_config() {
    let (_dir, path) = empty_dir();

    let _ = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args([
            "--config",
            path.to_str().expect("utf-8 path"),
            "--generate-2fa",
            "client-001",
            "--qr-format",
            "none",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe")
        .wait_with_output()
        .expect("--generate-2fa exits");

    assert!(
        !path.exists(),
        "--generate-2fa must not leave a config behind: {}",
        path.display()
    );
}

/// `client list` reads the file via `ProxyConfig::load_with_auth`, which fails
/// on a missing one. The subcommand is the write half of the management
/// surface and shares the file lock with the server, but it should never be
/// the *reason* a file appears on disk — the operator chose to run a query
/// against nothing, and the answer is "no such file", not "I made you one".
#[test]
fn client_list_does_not_create_a_config() {
    let (_dir, path) = empty_dir();

    let _ = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args([
            "--config",
            path.to_str().expect("utf-8 path"),
            "client",
            "list",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe")
        .wait_with_output()
        .expect("client list exits");

    assert!(
        !path.exists(),
        "`client list` must not leave a config behind: {}",
        path.display()
    );
}

/// `--local-proxy` does not early-return the way the read-only commands do,
/// but it is still gated out of `ensure_config_file` by `!cli.local_proxy`:
/// the template describes a *server*, and handing a server-shaped config to
/// the client half would be worse than the "config not found" it replaces.
/// Pinning the gate separately from the early-return paths catches a future
/// flag landing below `ensure_config_file` without the `!cli.local_proxy`
/// guard.
#[test]
fn local_proxy_does_not_create_a_config() {
    let (_dir, path) = empty_dir();

    let _ = Command::new(env!("CARGO_BIN_EXE_nexapipe"))
        .args([
            "--config",
            path.to_str().expect("utf-8 path"),
            "--local-proxy",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexapipe")
        .wait_with_output()
        .expect("--local-proxy exits");

    assert!(
        !path.exists(),
        "--local-proxy must not leave a server-style config behind: {}",
        path.display()
    );
}

/// `NEXAPIPE_CONFIG_DIR` shifts the default config path the binary uses when
/// `--config` is not given. The docker setup relies on this: with the env var
/// unset the default is `./config.toml`, and with it set the default is
/// `<dir>/config.toml` — the same path the docker-compose bind-mount resolves
/// to inside the container.
///
/// The whole point of the env var is that a fresh start works without an
/// operator having to mkdir anything. Regression: a previous version opened
/// the lock file `<path>.lock` before the parent directory existed, and the
/// start aborted with `cannot open ...lock: 系统找不到指定的路径` — leaving
/// the operator with no config and a misleading "the file is still in cwd"
/// impression. This test pins the happy path: with the env var set and no
/// `--config`, the file lands at `<dir>/config.toml`, and the dir is created
/// if it was missing.
#[test]
fn the_env_var_shifts_the_default_config_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A subdirectory inside the tempdir, the way docker-compose mounts a
    // bind target — the parent dir does not exist when the binary starts.
    let config_dir = dir.path().join("config");
    assert!(!config_dir.exists(), "the parent must start missing");

    // Run with the env var set and *no* `--config`, so the default path is
    // what `compute_default_config()` returns. The server does not exit on
    // its own — `start_until_node_id` waits for the Node ID line on stdout,
    // which means the server has reached the "running" state and the auto
    // write has already landed. We kill it before reading the file so the
    // config lock is released.
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    command
        .env(
            "NEXAPIPE_CONFIG_DIR",
            config_dir.to_str().expect("utf-8 path"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (_node_id, mut child) = start_until_node_id_with(command);
    let _ = child.kill();
    let _ = child.wait();

    let config_path = config_dir.join("config.toml");
    assert!(
        config_path.exists(),
        "the env var must shift the default to <dir>/config.toml: {}",
        config_path.display(),
    );
    assert!(
        !dir.path().join("config.toml").exists(),
        "no file at the old default path (cwd) — the env var fully overrides it"
    );
}
