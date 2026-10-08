//! `nexapipe client list|add|revoke`, end to end through the real binary.
//!
//! The write half of the management surface is a subcommand rather than a
//! `POST /v1/clients` because the admin token is one opaque value with no scope
//! and no rotation — so these tests drive it the way an operator would: with a
//! config file on disk, reading the file back afterwards to see what it did.
//!
//! The device cases are the ones worth pinning. `client add <id>` and
//! `client add <id> --device <name>` look like the same command and are not: the
//! first rotates the credential every unnamed device of that client is using,
//! the second leaves it alone and writes a credential of its own. Which one ran
//! is the difference between re-enrolling a client and adding a laptop.

use std::fs;
use std::path::{Path, PathBuf};

fn scratch_config(name: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(&path, source).expect("write config");
    (dir, path)
}

/// A config with 2FA on and no clients, which is where `client add` starts.
fn empty_auth() -> (tempfile::TempDir, PathBuf) {
    scratch_config(
        "config.toml",
        "[auth]\n\
         enabled = true\n",
    )
}

/// Runs the binary the way an operator would and returns whether it succeeded
/// together with everything it printed — the CLI splits advisory lines across
/// stdout and stderr, so a test that read only one would miss the `warning:` it
/// may be asserting on.
fn run(config: &Path, args: &[&str]) -> (bool, String) {
    let mut full = vec![
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
    ];
    full.extend(args.iter().map(|arg| arg.to_string()));
    // No QR code: a QR in the output makes the assertions below unreadable and
    // `add` prints the URI on its own line either way.
    if !args.contains(&"--qr-format") {
        full.push("--qr-format".to_string());
        full.push("none".to_string());
    }

    let output = duct::cmd(env!("CARGO_BIN_EXE_nexapipe"), full)
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

/// The `secret=` of the `otpauth://` URI a run printed, which is the credential
/// the QR code carries and the one the config has to end up holding.
fn printed_secret(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| line.contains("otpauth://totp/"))
        .unwrap_or_else(|| panic!("no otpauth URI in:\n{text}"));
    let rest = line
        .split_once("secret=")
        .expect("the URI carries a secret")
        .1;
    rest.split('&')
        .next()
        .expect("the URI has a first parameter")
        .to_string()
}

#[test]
fn a_config_with_no_auth_section_has_no_clients() {
    let (_dir, path) = scratch_config("config.toml", "# no [auth] here\n");

    let (ok, text) = run(&path, &["client", "list"]);
    assert!(
        ok,
        "listing a config with no [auth] is not an error:\n{text}"
    );
    assert!(text.contains("no [auth] section"), "{text}");
}

#[test]
fn adding_a_client_writes_the_secret_the_qr_code_carries() {
    let (_dir, path) = empty_auth();

    let (ok, text) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "add failed:\n{text}");

    let secret = printed_secret(&text);
    let written = fs::read_to_string(&path).expect("read the config back");
    assert!(written.contains("[auth.clients.acme]"), "{written}");
    assert!(
        written.contains(&format!("secret = \"{secret}\"")),
        "the server has to hold the credential the code carries:\n{written}"
    );
    // The comment an operator wrote is still there: the file is edited as TOML,
    // not re-serialized.
    assert!(written.contains("[auth]"), "{written}");
}

#[test]
fn adding_a_client_twice_is_refused_without_force() {
    let (_dir, path) = empty_auth();

    let (ok, first) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "the first add failed:\n{first}");
    let secret = printed_secret(&first);

    let (ok, second) = run(&path, &["client", "add", "acme"]);
    assert!(
        !ok,
        "a second add must not rotate a credential by accident:\n{second}"
    );
    assert!(second.contains("already has a secret"), "{second}");
    let still_there = fs::read_to_string(&path)
        .expect("read back")
        .contains(&format!("secret = \"{secret}\""));
    assert!(still_there, "the secret is untouched");

    let (ok, forced) = run(&path, &["client", "add", "acme", "--force"]);
    assert!(ok, "--force should rotate it:\n{forced}");
    let rotated = printed_secret(&forced);
    assert_ne!(secret, rotated, "rotating has to issue a different secret");
    assert!(
        fs::read_to_string(&path)
            .expect("read back")
            .contains(&format!("secret = \"{rotated}\"")),
        "the config holds the new one"
    );
}

/// The one difference that matters: a device's credential is written beside the
/// client's, not over it, so the devices that were already using the client's
/// secret keep working.
#[test]
fn a_device_gets_a_credential_of_its_own() {
    let (_dir, path) = empty_auth();

    let (ok, _) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "the client should be added first");
    let client_secret = printed_secret(&run(&path, &["--show-2fa", "acme"]).1);

    let (ok, text) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "adding the device failed:\n{text}");
    let device_secret = printed_secret(&text);

    let written = fs::read_to_string(&path).expect("read back");
    assert!(
        written.contains("[auth.clients.acme.devices]"),
        "the device needs a table of the client's own:\n{written}"
    );
    assert!(written.contains(&device_secret), "{written}");
    assert!(
        written.contains(&format!("secret = \"{client_secret}\"")),
        "the client's own secret must survive — it is the credential of the device that names \
         none:\n{written}"
    );
    assert_ne!(client_secret, device_secret);

    // And it is not merely text in the file: the server has to read it back as a
    // credential of that device.
    let (_, auth) =
        nexapipe::config::ProxyConfig::load_with_auth(path.to_str().expect("utf-8 path"))
            .expect("config still parses");
    let auth = auth.expect("[auth] exists");
    assert_eq!(auth.clients["acme"].devices["laptop"].secret, device_secret);
    assert_eq!(auth.clients["acme"].secret, client_secret);
}

#[test]
fn a_device_cannot_be_the_first_thing_a_client_gets() {
    let (_dir, path) = empty_auth();

    let (ok, text) = run(&path, &["client", "add", "ghost", "--device", "laptop"]);
    assert!(!ok, "a device under no client must not be created:\n{text}");
    assert!(text.contains("add the client first"), "{text}");
    let written = fs::read_to_string(&path).expect("read back");
    assert!(!written.contains("ghost"), "{written}");
}

#[test]
fn the_list_names_the_devices_and_prints_no_secret() {
    let (_dir, path) = empty_auth();
    let (ok, text) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "{text}");
    let secret = printed_secret(&text);
    let (ok, text) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "{text}");
    let device_secret = printed_secret(&text);

    let (ok, listed) = run(&path, &["client", "list"]);
    assert!(ok, "{listed}");
    assert!(listed.contains("acme"), "{listed}");
    assert!(listed.contains("laptop"), "{listed}");
    // The command run to see what is configured is the worst place for a
    // credential: scrollback, pastes and screenshots outlive it.
    assert!(
        !listed.contains(&secret),
        "the client's secret is printed:\n{listed}"
    );
    assert!(
        !listed.contains(&device_secret),
        "the device's secret is printed:\n{listed}"
    );
}

#[test]
fn the_list_is_parseable_as_json_and_carries_no_secret() {
    let (_dir, path) = empty_auth();
    let (ok, text) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "{text}");
    let secret = printed_secret(&text);
    let (ok, _) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "the device should be added");

    let (ok, text) = run(&path, &["client", "list", "--json"]);
    assert!(ok, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).expect("valid JSON");
    let clients = parsed.as_array().expect("a list of clients");
    assert_eq!(clients.len(), 1, "{clients:?}");
    assert_eq!(clients[0]["id"], "acme");
    assert_eq!(clients[0]["has_secret"], true);
    let devices = clients[0]["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert_eq!(devices[0]["name"], "laptop");
    assert!(
        !text.contains(&secret),
        "the JSON carries the secret:\n{text}"
    );
}

#[test]
fn revoking_a_device_leaves_the_client_alone() {
    let (_dir, path) = empty_auth();
    let (ok, text) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "{text}");
    let client_secret = printed_secret(&text);
    let (ok, _) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "the device should be added");

    let (ok, text) = run(&path, &["client", "revoke", "acme", "--device", "laptop"]);
    assert!(ok, "revoking failed:\n{text}");

    let written = fs::read_to_string(&path).expect("read back");
    assert!(!written.contains("laptop"), "{written}");
    assert!(
        written.contains(&format!("secret = \"{client_secret}\"")),
        "the client's own credential is not a device's to revoke:\n{written}"
    );
    let (ok, listed) = run(&path, &["client", "list"]);
    assert!(ok, "{listed}");
    assert!(listed.contains("devices     none"), "{listed}");
}

#[test]
fn revoking_a_client_takes_its_devices_with_it() {
    let (_dir, path) = empty_auth();
    let (ok, _) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "the client should be added");
    let (ok, _) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "the device should be added");

    let (ok, text) = run(&path, &["client", "revoke", "acme"]);
    assert!(ok, "revoking failed:\n{text}");
    assert!(text.contains("1 device credential"), "{text}");

    let written = fs::read_to_string(&path).expect("read back");
    assert!(!written.contains("acme"), "{written}");
    // `[auth]` itself stays: revoking a client is not disabling 2FA.
    assert!(written.contains("[auth]"), "{written}");
}

/// A revoke that names something absent is an error rather than a success, so a
/// typo cannot read as "the credential is gone" when it never was.
#[test]
fn revoking_what_is_not_there_is_an_error() {
    let (_dir, path) = empty_auth();
    let (ok, _) = run(&path, &["client", "add", "acme"]);
    assert!(ok, "the client should be added");
    let (ok, _) = run(&path, &["client", "add", "acme", "--device", "laptop"]);
    assert!(ok, "the device should be added");

    let (ok, text) = run(&path, &["client", "revoke", "ghost"]);
    assert!(!ok, "{text}");
    assert!(text.contains("ghost"), "{text}");

    // A device that is not there names the ones that are, so a typo reads as a
    // typo rather than as "revoked".
    let (ok, text) = run(&path, &["client", "revoke", "acme", "--device", "tablet"]);
    assert!(!ok, "{text}");
    assert!(text.contains("tablet"), "{text}");
    assert!(text.contains("laptop"), "{text}");

    let written = fs::read_to_string(&path).expect("read back");
    assert!(written.contains("acme"), "nothing was revoked:\n{written}");
    assert!(
        written.contains("laptop"),
        "nothing was revoked:\n{written}"
    );
}
