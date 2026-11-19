//! `device invite`, end to end through the real binary.
//!
//! The command replaces the operator-named device join: it writes a one-time
//! token with a deadline, prints a link that carries the same deadline, and
//! refuses the old spellings with a pointer to the new one.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Generated at runtime: the tree holds no credential, not even a test one.
/// Every fixture in this file shares these, so a ticket built from
/// `SERVER_SECRET` still names the endpoint its scratch config runs as.
static SERVER_SECRET: LazyLock<String> = LazyLock::new(nexapipe::config::generate_secret_key_hex);
static CLIENT_SECRET: LazyLock<String> =
    LazyLock::new(nexapipe::auth::TotpValidator::generate_secret);

fn scratch_config(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(
        &path,
        format!(
            "# my proxy\n\
             \n\
             [iroh]\n\
             secret_key = \"{}\"\n\
             \n\
             [auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.alice]\n\
             secret = \"{}\"\n",
            SERVER_SECRET.as_str(),
            CLIENT_SECRET.as_str()
        ),
    )
    .expect("write config");
    (dir, path)
}

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
             secret_key = \"{}\"\n\
             discovery = \"none\"\n\
             \n\
             [auth]\n\
             enabled = true\n\
             \n\
             [auth.clients.alice]\n\
             secret = \"{}\"\n",
            SERVER_SECRET.as_str(),
            CLIENT_SECRET.as_str()
        ),
    )
    .expect("write config");
    (dir, path)
}

/// A ticket for the endpoint this scratch config runs as, carrying a direct
/// address the way the ticket the server prints at start-up does. With
/// `discovery = "none"` a ticket with no addresses cannot be resolved, and
/// the invite path warns about that.
fn own_ticket() -> String {
    use iroh::{EndpointAddr, SecretKey};
    use iroh_tickets::endpoint::EndpointTicket;
    let key: SecretKey = SERVER_SECRET.as_str().parse().expect("secret key");
    let addr = EndpointAddr::new(key.public())
        .with_ip_addr("192.0.2.1:4242".parse().expect("socket addr"));
    EndpointTicket::new(addr).to_string()
}

/// The same endpoint, but an address-free ticket — the degenerate form that
/// cannot be resolved when discovery is off.
fn own_ticket_without_addresses() -> String {
    use iroh::{EndpointAddr, SecretKey};
    use iroh_tickets::endpoint::EndpointTicket;
    let key: SecretKey = SERVER_SECRET.as_str().parse().expect("secret key");
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
        !output.contains("cannot be resolved") && !output.contains("carries no addresses"),
        "a ticket with addresses needs no discovery warning:\n{output}"
    );

    // Decode the printed target rather than trusting the prefix: the link has
    // to carry the addresses the ticket was built with, otherwise the invite
    // is not resolvable with discovery off.
    let link = output
        .lines()
        .find(|line| line.contains("nexapipe://"))
        .map(str::trim)
        .expect("the printed invite link");
    let invite = nexapipe_client::provisioning::EndpointInvite::from_uri(link)
        .expect("the link parses back into an invite");
    let encoded = match &invite.target {
        nexapipe_client::provisioning::EndpointTarget::Ticket(ticket) => ticket,
        _ => panic!("the link names a ticket target: {link}"),
    };
    let parsed: iroh_tickets::endpoint::EndpointTicket =
        encoded.parse().expect("the ticket in the link parses");
    let addr: iroh::EndpointAddr = parsed.into();
    assert!(
        addr.addrs
            .iter()
            .any(|a| a.to_string().contains("192.0.2.1:4242")),
        "the link carries the direct address from the ticket: {:?}",
        addr.addrs
    );

    assert!(
        auth_clients(&config).clients["alice"]
            .pending_enrollment_expires_at
            .is_some()
    );
}

/// A ticket with no addresses is no better than a bare Node ID when discovery
/// is off, so the invite has to say the link may not resolve.
#[test]
fn an_address_free_ticket_warns_when_discovery_is_off() {
    let (_dir, config) = scratch_config_without_discovery("empty-ticket.toml");
    let ticket = own_ticket_without_addresses();

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

    assert!(ok, "{output}");
    assert!(output.contains("nexapipe://ticket/"), "{output}");
    assert!(
        output.contains("carries no addresses"),
        "the operator has to be told the ticket cannot be resolved:\n{output}"
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

/// The stray-ticket check has to run before the other early returns, or a
/// flag such as --generate-secret would succeed and silently swallow it.
#[test]
fn an_invite_ticket_is_rejected_before_other_early_returns() {
    let (_dir, config) = scratch_config("ticket-with-secret.toml");
    let ticket = own_ticket();

    let (ok, output) = run(&config, &["--generate-secret", "--invite-ticket", &ticket]);

    assert!(!ok, "the ticket was silently ignored:\n{output}");
    assert!(
        output.contains("is used with --generate-invite or"),
        "{output}"
    );
    assert!(
        !output.contains("Generated secret key"),
        "the early return must not run first:\n{output}"
    );
}
