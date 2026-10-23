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
//!
//! The form of the invite is part of it. A client this run creates is handed
//! out as a one-time enrollment token rather than as the secret: the secret was
//! minted a moment ago and no device is enrolled with it, so the first device
//! to scan the link trades the token for a secret of its own and the link stops
//! being a credential there and then. A client that exists already keeps the
//! secret its devices are enrolled with, and the link that carries it says so.

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
    auth.and_then(|auth| {
        auth.clients
            .get(client_id)
            .map(|c| c.secret.expose_secret().to_string())
    })
}

/// The whole point: one command creates the client *and* hands out a
/// credential for it.
///
/// The credential is the one-time token, not the secret. The secret was minted
/// a moment ago and no device is enrolled with it, so there is nothing to lose
/// by the first device trading the token for a secret of its own — and a link
/// that carries the secret stays a password for as long as that secret lives,
/// while a link that carries the token stops being one the moment it is used.
#[test]
fn creates_a_missing_client_and_puts_a_one_time_token_in_the_invite() {
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

    assert!(
        output.contains("enroll="),
        "the invite carries a one-time token:\n{output}"
    );
    assert!(
        invite_secret(&output).is_none(),
        "the invite must not carry the secret:\n{output}"
    );

    let (_, auth) = nexapipe::config::ProxyConfig::load_with_auth(path.to_str().unwrap())
        .expect("config still parses");
    let client = &auth.expect("[auth] exists").clients["client-001"];
    assert!(
        !client.secret.expose_secret().is_empty(),
        "the client exists in the config"
    );
    assert!(
        client.pending_enrollment.is_some(),
        "the token is recorded in the config, so the server accepts it"
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
    assert!(
        !client.secret.expose_secret().is_empty(),
        "a secret was written first"
    );
    assert!(
        client.pending_enrollment.is_some(),
        "the token joined the secret in one pass"
    );
}

/// An existing client must keep the secret it has: `--create-client` says "make
/// one if there is none", not "rotate this one". Silently issuing a second
/// secret would lock every already-enrolled device out.
///
/// The first run creates the client and the second finds it, so the second
/// invite carries the secret that is in the config — and that secret is the one
/// the first run wrote, not a new one.
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
    let original = configured_secret(&path, "client-001").expect("the client was created");

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

/// A client that exists already is handed out as the secret it has, and the
/// link says what that is: a password that stays one until the secret is
/// rotated. The one-time form is named beside it, because the operator is the
/// one who has to choose between them.
#[test]
fn an_existing_client_gets_a_link_that_says_it_is_a_credential() {
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

    let (ok, second) = invite(
        &path,
        &["--generate-invite", "client-001", "--qr-format", "none"],
    );
    assert!(ok, "{second}");

    assert!(
        invite_secret(&second).is_some(),
        "the link carries the secret:\n{second}"
    );
    assert!(
        !second.contains("enroll="),
        "the secret form is not the one-time form:\n{second}"
    );
    assert!(
        second.contains("THIS LINK IS A CREDENTIAL"),
        "the link says what it is:\n{second}"
    );
    assert!(
        second.contains("--registration"),
        "the one-time form is named:\n{second}"
    );
}

/// The one-time form is only worth anything while the server runs the 2FA
/// handshake, so with 2FA off a client this run creates falls back to the
/// secret — and the output says why. "The link is a password" is a worse
/// answer than "the link is a password because the server never asks for one".
#[test]
fn without_the_handshake_the_one_time_form_is_not_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        "# my proxy\n\
         \n\
         [iroh]\n\
         secret_key = \"f3d4cade20c162ac5bb9d582b84a10755b1bf61a44c05f4fec4e4282f2f1f9c0\"\n\
         \n\
         [auth]\n\
         enabled = false\n",
    )
    .expect("write config");

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
    assert!(ok, "{output}");
    assert!(
        invite_secret(&output).is_some(),
        "the link carries the secret:\n{output}"
    );
    assert!(
        !output.contains("enroll="),
        "a token that could never be exchanged is not in the link:\n{output}"
    );
    assert!(
        output.contains("one-time enrollment form was not used"),
        "the output says why:\n{output}"
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
