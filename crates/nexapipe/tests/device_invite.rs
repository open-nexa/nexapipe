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

/// The identity the scratch configurations run as.
const SERVER_SECRET: &str = "f3d4cade20c162ac5bb9d582b84a10755b1bf61a44c05f4fec4e4282f2f1f9c0";

/// A scratch config with discovery disabled: a Node ID cannot be resolved
/// there, so the invite has to carry a ticket with the addresses in it.
fn scratch_config_without_discovery(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(
        &path,
        format!(
            "# my proxy\n\
             \n\
             [iroh]\n\
             secret_key = \"{SERVER_SECRET}\"\n\
             discovery = \"none\"\n\
             \n\
             [auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.alice]\n\
             secret = \"JBSWY3DPEHPK3PXP\"\n"
        ),
    )
    .expect("write config");
    (dir, path)
}

/// A ticket for the endpoint this scratch config runs as. An invite carrying
/// a credential is checked against the server's own identity, so the ticket
/// has to name this endpoint.
fn own_ticket() -> String {
    use iroh::{EndpointAddr, SecretKey};
    use iroh_tickets::endpoint::EndpointTicket;
    let key: SecretKey = SERVER_SECRET.parse().expect("secret key");
    EndpointTicket::new(EndpointAddr::new(key.public())).to_string()
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

/// `discovery = "none"` is the case the ticket exists for, and `device invite`
/// has to accept it: `--invite-ticket` used to be tied to `--generate-invite`,
/// whose early return meant the ticket could never reach this command.
#[test]
fn a_device_invite_can_carry_an_endpoint_ticket() {
    let (_dir, config) = scratch_config_without_discovery("ticket.toml");
    let ticket = own_ticket();

    let (ok, output) = run(
        &config,
        &[
            "device",
            "invite",
            "--client",
            "alice",
            "--invite-ticket",
            &ticket,
        ],
    );

    assert!(ok, "the ticket invitation was refused:\n{output}");
    assert!(output.contains("nexapipe://ticket/"), "{output}");
    assert!(
        output.contains("enroll=") && output.contains("exp="),
        "the ticket still carries the one-time invitation:\n{output}"
    );
    assert!(
        !output.contains("cannot be resolved"),
        "a ticket invite needs no discovery warning:\n{output}"
    );
    assert!(
        auth_clients(&config).clients["alice"]
            .pending_enrollment_expires_at
            .is_some()
    );
}

/// The warning has to name a command that actually accepts the ticket, not a
/// flag that only the endpoint invite defines.
#[test]
fn the_discovery_warning_points_at_a_command_that_accepts_the_ticket() {
    let (_dir, config) = scratch_config_without_discovery("warn.toml");

    let (ok, output) = run(&config, &["device", "invite", "--client", "alice"]);

    assert!(ok, "{output}");
    assert!(
        output.contains("device invite --client alice --invite-ticket"),
        "the warning has to name a command that accepts the ticket:\n{output}"
    );
}

/// Making the flag global must not let a stray ticket be silently dropped on
/// a plain proxy start.
#[test]
fn an_invite_ticket_without_an_invite_is_rejected() {
    let (_dir, config) = scratch_config("ticket-alone.toml");
    let ticket = own_ticket();

    let (ok, output) = run(&config, &["--invite-ticket", &ticket]);

    assert!(!ok, "a stray ticket was silently ignored:\n{output}");
    assert!(
        output.contains("is used with --generate-invite or"),
        "{output}"
    );
}
