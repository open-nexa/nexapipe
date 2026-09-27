//! `--generate-invite <CLIENT_ID> --create-client`, end to end through the
//! real binary.
//!
//! The point of the flag is that enrolling a brand new client used to take two
//! commands in a fixed order: `--generate-2fa` to put a secret in the config,
//! then `--generate-invite` to hand the same secret out. Skip the first and the
//! second refused with "run --generate-2fa ... first"; run them in the other
//! order and you got nothing useful at all. These tests pin the one-command
//! behaviour and, just as importantly, the parts that must *not* change: an
//! existing client keeps the secret it has, and `--create-client` on its own
//! stays a usage error.

use std::fs;
use std::path::{Path, PathBuf};

/// A config with a stable endpoint identity and 2FA on, so nothing but the
/// client has to be set up for an invite to be printable.
fn scratch_config(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    // The secret key fixes the endpoint ID the invite advertises; without it
    // `--generate-invite` insists on `--endpoint-id` instead.
    fs::write(
        &path,
        "# my proxy\n\
         \n\
         [iroh]\n\
         secret_key = \"f3d4cade20c162ac5bb9d582b84a10755b1bf61a44c05f4fec4e4282f2f1f9c0\"\n\
         \n\
         [auth]\n\
         enabled = true\n",
    )
    .expect("write config");
    (dir, path)
}

/// Runs the binary the way the operator would and returns whether it succeeded
/// together with stdout and stderr — the CLI splits advisory lines across both,
/// so a test that only read stdout would miss the `warning:` it is asserting on.
///
/// Both streams have to be captured explicitly, because `run()` fills only the
/// field whose `*_capture` was requested and lets every other stream through to
/// the test harness, where it is printed but not returned. The tempting
/// `.stderr_to_stdout().run()` does not help: it redirects stderr into a stdout
/// that is *also* uncaptured, so both disappear and the failure message is
/// empty. Verified combinations on Windows: `stdout_capture` alone gives
/// stdout, `stderr_capture` alone gives stderr, both gives both, and
/// `stderr_to_stdout` is only useful with `read()` — which cannot be used here,
/// because it errors on the non-zero exit a refusal case is asserting on.
fn run(config: &Path, args: &[&str]) -> (bool, String) {
    let output = duct::cmd(env!("CARGO_BIN_EXE_nexapipe"), full_args(config, args))
        .stdin_null()
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .expect("run nexapipe");

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

fn full_args(config: &Path, args: &[&str]) -> Vec<String> {
    let mut full = vec![
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
    ];
    full.extend(args.iter().map(|arg| arg.to_string()));
    full
}

fn invite(config: &Path, extra: &[&str]) -> (bool, String) {
    run(config, extra)
}

/// Whatever `secret=` ended up in the printed invite.
fn invite_secret(output: &str) -> Option<String> {
    output
        .lines()
        .find(|line| line.contains("nexapipe://"))
        .and_then(|line| line.split("secret=").nth(1))
        .and_then(|rest| rest.split('&').next())
        .map(str::to_string)
}

/// The secret the server would load for `client_id`, read back through the same
/// loader the server uses.
fn configured_secret(config: &Path, client_id: &str) -> Option<String> {
    let (_, auth) = nexapipe::config::ProxyConfig::load_with_auth(config.to_str().unwrap())
        .expect("config still parses");
    auth.and_then(|auth| auth.clients.get(client_id).map(|c| c.secret.clone()))
}

/// The whole point: one command creates the client *and* hands out its
/// credential, and the two have to be the same secret or the invite is a
/// credential the server rejects.
#[test]
fn creates_a_missing_client_and_puts_its_secret_in_the_invite() {
    let (_dir, path) = scratch_config("config.toml");

    let (ok, output) = invite(
        &path,
        &[
            "--generate-invite",
            "client-001",
            "--create-client",
            "--qr-format",
            "none",
        ],
    );
    assert!(
        ok,
        "creating and inviting in one step has to succeed:\n{output}"
    );

    let invite_secret = invite_secret(&output).expect("the invite carries a secret");
    assert_eq!(
        configured_secret(&path, "client-001").as_deref(),
        Some(invite_secret.as_str()),
        "the invite must carry the very secret that was written to disk"
    );

    // The operator has to be told a client appeared, or the next `git diff`
    // is a surprise.
    assert!(output.contains("Created"), "{output}");
    // And that the secret is not live until a restart, which is the thing that
    // makes a correct invite still fail on first connect.
    assert!(
        output.to_lowercase().contains("restart the server"),
        "{output}"
    );
}

/// `--registration` writes a `pending_enrollment` token, and the config writer
/// refuses to do that for a client with no secret. `--create-client` has to
/// supply one first, which is exactly the ordering that used to need two
/// commands.
#[test]
fn creates_a_missing_client_for_an_enrollment_invite() {
    let (_dir, path) = scratch_config("config.toml");

    let (ok, output) = invite(
        &path,
        &[
            "--generate-invite",
            "client-007",
            "--create-client",
            "--registration",
            "--qr-format",
            "none",
        ],
    );
    assert!(
        ok,
        "an enrollment invite for a new client has to work:\n{output}"
    );
    assert!(
        output.contains("enroll="),
        "the link carries a token:\n{output}"
    );

    let (_, auth) = nexapipe::config::ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect("config still parses");
    let client = &auth.expect("[auth] exists").clients["client-007"];
    assert!(!client.secret.is_empty(), "a secret was written first");
    assert!(
        client.pending_enrollment.is_some(),
        "the token joined the secret in one pass"
    );
}

/// An existing client must keep the secret it has: `--create-client` says "make
/// one if there is none", not "rotate this one". Silently issuing a second
/// secret would lock every already-enrolled device out.
#[test]
fn an_existing_client_is_not_recreated() {
    let (_dir, path) = scratch_config("config.toml");

    let (ok, first) = invite(
        &path,
        &[
            "--generate-invite",
            "client-001",
            "--create-client",
            "--qr-format",
            "none",
        ],
    );
    assert!(ok, "{first}");
    let original = invite_secret(&first).expect("secret in invite");

    let (ok, second) = invite(
        &path,
        &[
            "--generate-invite",
            "client-001",
            "--create-client",
            "--qr-format",
            "none",
        ],
    );
    assert!(ok, "{second}");

    assert!(
        !second.contains("Created"),
        "nothing was created the second time:\n{second}"
    );
    assert_eq!(
        invite_secret(&second).as_deref(),
        Some(original.as_str()),
        "the second invite must reuse the stored secret, not mint a new one"
    );
    assert_eq!(
        configured_secret(&path, "client-001").as_deref(),
        Some(original.as_str())
    );
}

/// Without the flag the old behaviour stands — and the error now names the fix
/// instead of sending the operator off to run a second command by hand.
#[test]
fn a_missing_client_still_needs_the_flag() {
    let (_dir, path) = scratch_config("config.toml");

    let (ok, output) = invite(
        &path,
        &["--generate-invite", "client-001", "--qr-format", "none"],
    );
    assert!(!ok, "an unknown client is still refused:\n{output}");
    assert!(
        output.contains("--create-client"),
        "the fix is named:\n{output}"
    );
    assert_eq!(
        configured_secret(&path, "client-001"),
        None,
        "a refused invite must not have written anything"
    );
}

/// `--create-client` is only meaningful next to `--generate-invite`; clap is
/// the one that says so, so the flag can never be mistaken for a standalone
/// "add a client" command.
#[test]
fn the_flag_requires_generate_invite() {
    let (_dir, path) = scratch_config("config.toml");

    let (ok, output) = invite(&path, &["--create-client"]);
    assert!(!ok, "the flag needs --generate-invite:\n{output}");
    assert!(
        output.contains("--generate-invite"),
        "clap names the missing flag:\n{output}"
    );
}
