//! `device invite`, end to end through the real binary.
//!
//! The command replaces the operator-named device join: it writes a one-time
//! token with a deadline, prints a link that carries the same deadline, and
//! refuses the old spellings with a pointer to the new one.

use std::fs;
use std::path::{Path, PathBuf};

fn scratch_config(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(
        &path,
        "# my proxy\n\
         \n\
         [iroh]\n\
         secret_key = \"f3d4cade20c162ac5bb9d582b84a10755b1bf61a44c05f4fec4e4282f2f1f9c0\"\n\
         \n\
         [auth]\n\
         enabled = true\n\
         \n\
         [auth.clients.alice]\n\
         secret = \"JBSWY3DPEHPK3PXP\"\n",
    )
    .expect("write config");
    (dir, path)
}

fn run(config: &Path, args: &[&str]) -> (bool, String) {
    let mut full = vec![
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
    ];
    full.extend(args.iter().map(|arg| arg.to_string()));
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

fn auth_clients(config: &Path) -> nexapipe::auth::AuthConfig {
    let (_, auth) = nexapipe::config::Config::load_with_auth(config.to_str().unwrap())
        .expect("config still parses");
    auth.expect("[auth] in the scratch config")
}

#[test]
fn a_device_invite_has_a_deadline_on_disk_and_in_the_link() {
    let (_dir, config) = scratch_config("device-invite.toml");
    let (ok, output) = run(
        &config,
        &["device", "invite", "--client", "alice", "--ttl", "5m"],
    );
    assert!(ok, "{output}");

    let link = output
        .lines()
        .find(|line| line.contains("nexapipe://"))
        .expect("the printed invite link");
    assert!(link.contains("enroll="), "{link}");
    let exp = link
        .split("exp=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("the link carries a numeric deadline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        (now + 240..=now + 301).contains(&exp),
        "exp={exp}, now={now}"
    );

    let client = &auth_clients(&config).clients["alice"];
    let token = client.pending_enrollment.as_ref().expect("a pending token");
    assert!(!token.expose_secret().is_empty());
    assert_eq!(client.pending_enrollment_expires_at, Some(exp));
}

#[test]
fn the_default_lifetime_is_fifteen_minutes() {
    let (_dir, config) = scratch_config("default-ttl.toml");
    let (ok, output) = run(&config, &["device", "invite", "--client", "alice"]);
    assert!(ok, "{output}");
    let client = &auth_clients(&config).clients["alice"];
    let exp = client.pending_enrollment_expires_at.expect("a deadline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        (now + 890..=now + 901).contains(&exp),
        "exp={exp}, now={now}"
    );
}

#[test]
fn a_new_invite_replaces_the_outstanding_one() {
    let (_dir, config) = scratch_config("replace.toml");
    assert!(run(&config, &["device", "invite", "--client", "alice"]).0);
    let first = auth_clients(&config).clients["alice"]
        .pending_enrollment
        .as_ref()
        .unwrap()
        .expose_secret()
        .to_string();
    assert!(
        run(
            &config,
            &["device", "invite", "--client", "alice", "--ttl", "1h"]
        )
        .0
    );
    let client = &auth_clients(&config).clients["alice"];
    let second = client
        .pending_enrollment
        .as_ref()
        .unwrap()
        .expose_secret()
        .to_string();
    assert_ne!(first, second, "a replacement token is a different token");
    assert!(client.pending_enrollment_expires_at.unwrap() > 0);
}

#[test]
fn the_old_named_device_spellings_point_at_the_new_command() {
    let (_dir, config) = scratch_config("legacy.toml");

    let (ok, output) = run(&config, &["--generate-invite", "alice", "--registration"]);
    assert!(!ok);
    assert!(output.contains("device invite"), "{output}");

    let (ok, output) = run(&config, &["client", "add", "bob", "--device", "laptop"]);
    assert!(!ok);
    assert!(output.contains("device invite"), "{output}");
}

#[test]
fn a_public_key_is_filed_under_its_fingerprint() {
    let (_dir, config) = scratch_config("key-name.toml");
    assert!(run(&config, &["client", "add", "bob"]).0);
    let key = iroh::SecretKey::generate();
    let hex = hex::encode(key.public().as_bytes());
    let (ok, output) = run(&config, &["client", "add", "bob", "--public-key", &hex]);
    assert!(ok, "{output}");
    let expected = nexapipe::auth::device_id_from_public_key(key.public().as_bytes());
    let clients = auth_clients(&config).clients;
    assert!(clients["bob"].devices.contains_key(&expected), "{output}");
}

#[test]
fn client_list_shows_the_deadline() {
    let (_dir, config) = scratch_config("list.toml");
    assert!(
        run(
            &config,
            &["device", "invite", "--client", "alice", "--ttl", "2h"]
        )
        .0
    );
    let (ok, output) = run(&config, &["client", "list", "--json"]);
    assert!(ok, "{output}");
    assert!(output.contains("invite_expires_at"), "{output}");
}
