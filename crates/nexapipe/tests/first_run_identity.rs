//! The endpoint identity on a first start, end to end through the real binary.
//!
//! Getting a stable Node ID used to take two manual steps before the first
//! `cargo run`: run `--generate-secret`, then paste its output into
//! `[iroh] secret_key`. Skip them and the server came up fine — with a
//! *different* Node ID after every restart, which is the part that hurts,
//! because a client that stored the Node ID stops being able to find the server
//! and nothing in the log says why.
//!
//! So these drive the binary the way an operator does and pin three things: the
//! key lands in the config file without anyone asking, the Node ID that comes
//! out is the same one the next start produces, and the escape hatch
//! (`NEXAPIPE_NO_PERSIST_IDENTITY`) really does keep the file untouched.
//!
//! Each server is started with the relay disabled, so a test needs no network
//! and no discovery — the same reason `data_plane.rs` binds loopback
//! endpoints. The process is killed rather than waited on: it is a server, and
//! there is no clean shutdown to wait for.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a start gets to write the key and print its Node ID.
///
/// Generous, because the first start of a test binary also pays for loading
/// the endpoint machinery; the point of the bound is that a regression fails
/// instead of hanging the suite until CI's own timeout does.
const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// A three-line config: one catch-all route, no `[iroh]` section at all. This is
/// what the README's quick start tells people to write, so it is the case that
/// has to gain a key on its own.
fn scratch_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        "# My proxy.\n\
         \n\
         [[routes]]\n\
         host_pattern = \"*\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [iroh]\n\
         relay_mode = \"disabled\"\n",
    )
    .expect("write config");
    (dir, path)
}

/// Starts the server and returns once it has printed its Node ID, or once the
/// deadline passes.
///
/// Reading its stdout is the only way to learn the Node ID, and reading it
/// *while* the process runs is what makes this work at all: the server does not
/// exit, so a `wait_with_output` would block forever on a process that is
/// behaving exactly as it should. The child is killed before this returns —
/// including on the timeout path, where an assertion fires — so a failing test
/// does not leave a server bound to a port.
fn start_until_node_id(config: &Path, env: &[(&str, &str)]) -> (String, Child) {
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

/// The `[iroh] secret_key` currently in the config file.
///
/// `toml::from_str`, not `str::parse`: a `Value`'s `FromStr` reads a single
/// TOML *value*, so it rejects a whole document with "unexpected content,
/// expected nothing" — the same trap `load_with_auth` documents.
fn configured_secret_key(config: &Path) -> Option<String> {
    let content = fs::read_to_string(config).expect("the config is still there");
    let parsed: toml::Value = toml::from_str(&content).expect("the config is still valid TOML");
    parsed
        .get("iroh")?
        .get("secret_key")?
        .as_str()
        .map(str::to_string)
}

/// The first start writes a key, and the Node ID it prints is derived from it.
///
/// The two halves are asserted together on purpose. A key on disk that the
/// endpoint ignored would leave the Node ID changing on every restart *and* look
/// correct to anyone reading the config — which is exactly the bug being closed
/// here, so checking only the file would pass on a regression.
#[test]
fn a_first_start_writes_the_key_and_binds_the_node_id_to_it() {
    let (_dir, path) = scratch_config();

    assert!(
        configured_secret_key(&path).is_none(),
        "the config has to start without a key, or this proves nothing"
    );

    let (node_id, mut child) = start_until_node_id(&path, &[]);
    let _ = child.kill();
    let _ = child.wait();

    let key = configured_secret_key(&path).expect("the first start wrote a key");
    // The length, never the value: CI keeps a failed test's output, and this is
    // the endpoint's real private key. `{key:?}` here would put it in the build
    // log of every run that ever trips this assertion.
    assert_eq!(
        key.len(),
        64,
        "an ed25519 key is 32 bytes of hex, got {} characters",
        key.len()
    );

    // The key the file now holds is the one the Node ID came from.
    let derived = iroh::SecretKey::from_bytes(
        &hex::decode(&key)
            .expect("the generated key is hex")
            .try_into()
            .expect("32 bytes"),
    )
    .public();
    assert_eq!(
        node_id,
        derived.to_string(),
        "the printed Node ID has to be the public key of the key on disk"
    );
}

/// Two starts, one Node ID. This is the whole point of writing the key, and it
/// cannot be observed from the file alone: the endpoint could still pick a fresh
/// identity per run while the config held a perfectly good key.
#[test]
fn the_node_id_is_the_same_after_a_restart() {
    let (_dir, path) = scratch_config();

    let (first, mut child) = start_until_node_id(&path, &[]);
    let _ = child.kill();
    let _ = child.wait();

    let (second, mut child) = start_until_node_id(&path, &[]);
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        first, second,
        "the key written on the first start has to be reused on the next"
    );
}

/// `NEXAPIPE_NO_PERSIST_IDENTITY` keeps the key off disk. The file has to come
/// back byte for byte: an operator who turned this on is saying "do not touch my
/// config", and a server that still rewrote it would be the surprising half.
#[test]
fn the_env_var_keeps_the_config_untouched() {
    let (_dir, path) = scratch_config();
    let before = fs::read_to_string(&path).expect("read the config");

    let (node_id, mut child) = start_until_node_id(&path, &[("NEXAPIPE_NO_PERSIST_IDENTITY", "1")]);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !node_id.is_empty(),
        "an ephemeral identity still has to be a working Node ID"
    );
    assert_eq!(
        configured_secret_key(&path),
        None,
        "nothing may be written when the env var is set"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("the config is still there"),
        before,
        "the file has to come back byte for byte"
    );
}

/// Two ephemeral starts are two different Node IDs. Without this the env var
/// could be "honoured" by quietly persisting the key anyway — which the previous
/// test alone would not catch, since it only ever starts one server.
#[test]
fn an_ephemeral_identity_differs_between_starts() {
    let (_dir, path) = scratch_config();
    let env = [("NEXAPIPE_NO_PERSIST_IDENTITY", "1")];

    let (first, mut child) = start_until_node_id(&path, &env);
    let _ = child.kill();
    let _ = child.wait();

    let (second, mut child) = start_until_node_id(&path, &env);
    let _ = child.kill();
    let _ = child.wait();

    assert_ne!(
        first, second,
        "the point of the env var is an identity that does not survive a restart"
    );
}

/// An ephemeral identity must not make the config count as holding a credential.
///
/// Regression. The startup permission check asks
/// `ProxyConfig::holds_credentials()`, which looks at the config *as loaded*; an
/// implementation that folded a never-written key into that struct would claim
/// the file holds a secret key, and the check refuses to start a world-readable
/// file that says so. The deployment that needs an ephemeral identity is exactly
/// the read-only one, so that turns the graceful degradation into a refusal to
/// boot.
///
/// Asserted through the file rather than through the mode, so it runs on every
/// platform: a key that was never written cannot be the one the check reads.
#[test]
fn an_ephemeral_identity_is_not_a_credential_in_the_config() {
    let (_dir, path) = scratch_config();
    let env = [("NEXAPIPE_NO_PERSIST_IDENTITY", "1")];

    let (node_id, mut child) = start_until_node_id(&path, &env);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !node_id.is_empty(),
        "an ephemeral identity still has to be a working Node ID"
    );
    // The invariant, read back the way the permission check reads it: a config
    // whose key was never written holds no credential, so the check cannot
    // start refusing a deployment on the strength of a key that is not there.
    let reloaded = nexapipe::config::ProxyConfig::from_file(path.to_str().expect("utf-8 path"))
        .expect("the config still parses after an ephemeral start");
    assert_eq!(
        configured_secret_key(&path),
        None,
        "an ephemeral identity must not reach the file"
    );
    assert!(
        !reloaded.holds_credentials(),
        "a config that gained no key holds no credential, so the startup permission \
         check keeps warning where it used to instead of refusing"
    );
}

/// A key that does not parse refuses the start, and the refusal says what to do.
///
/// This used to be a warning and a random key: the server came up, served
/// traffic, and came back on a different Node ID next time. A client that had
/// stored the old one was simply never able to connect again, and the log said
/// the problem had been handled.
#[test]
fn a_broken_key_refuses_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        "[[routes]]\n\
         host_pattern = \"*\"\n\
         backends = [\"http://127.0.0.1:18080\"]\n\
         \n\
         [iroh]\n\
         relay_mode = \"disabled\"\n\
         secret_key = \"not-a-key\"\n",
    )
    .expect("write config");

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
        "a config whose key cannot be parsed must not start:\n{text}"
    );
    assert!(
        text.contains("not a valid key"),
        "the refusal names the key it could not use:\n{text}"
    );
    assert!(
        configured_secret_key(&path).as_deref() == Some("not-a-key"),
        "the operator's typo has to survive so they can see it:\n{text}"
    );
}
