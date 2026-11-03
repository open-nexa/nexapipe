//! `--invite-ticket`, end to end through the real binary.
//!
//! With `[iroh] discovery = "none"` a Node ID is not an address any more, so
//! the invite has to carry the addresses itself. These tests pin the two
//! halves of that: a ticket invite really is a `nexapipe://ticket/` link, and
//! a Node ID invite says out loud that it cannot be resolved under that
//! configuration.

use std::fs;
use std::path::{Path, PathBuf};

use iroh::{EndpointAddr, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;

fn scratch_config(name: &str, discovery: Option<&str>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    let lookup = discovery
        .map(|value| format!("discovery = \"{value}\"\n"))
        .unwrap_or_default();
    fs::write(
        &path,
        format!(
            "# my proxy\n\
             \n\
             [iroh]\n\
             secret_key = \"f3d4cade20c162ac5bb9d582b84a10755b1bf61a44c05f4fec4e4282f2f1f9c0\"\n\
             {lookup}"
        ),
    )
    .expect("write config");
    (dir, path)
}

/// A ticket as the server prints one: a stable identity and nothing else is
/// enough here, because the test only checks what the CLI puts in the link.
fn ticket() -> String {
    let id = SecretKey::generate().public();
    EndpointTicket::new(EndpointAddr::new(id)).to_string()
}

fn run(config: &Path, args: &[&str]) -> (bool, String) {
    let mut full = vec!["--config".to_string(), config.to_string_lossy().into_owned()];
    full.extend(args.iter().map(|arg| arg.to_string()));
    let output = duct::cmd(env!("CARGO_BIN_EXE_nexapipe"), full)
        .stdin_null()
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .expect("run nexapipe");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn a_ticket_invite_carries_the_addresses_in_the_link() {
    let (_dir, config) = scratch_config("config.toml", None);
    let ticket = ticket();

    let (ok, output) = run(&config, &["--generate-invite", "--invite-ticket", &ticket]);

    assert!(ok, "the ticket invite was refused:\n{output}");
    assert!(output.contains("nexapipe://ticket/"), "{output}");
    assert!(
        output.contains("ticket, the addresses travel with the code"),
        "{output}"
    );
}

#[test]
fn a_node_id_invite_warns_when_the_lookup_is_off() {
    let (_dir, config) = scratch_config("config.toml", Some("none"));

    let (ok, output) = run(&config, &["--generate-invite"]);

    assert!(ok, "the invite was refused:\n{output}");
    assert!(output.contains("nexapipe://endpoint/"), "{output}");
    assert!(
        output.contains("--invite-ticket") && output.contains("discovery = \"none\""),
        "the operator has to be told why a Node ID invite will not resolve:\n{output}"
    );
}

#[test]
fn a_ticket_invite_and_an_endpoint_id_are_mutually_exclusive() {
    let (_dir, config) = scratch_config("config.toml", None);
    let ticket = ticket();

    let (ok, output) = run(
        &config,
        &[
            "--generate-invite",
            "--invite-ticket",
            &ticket,
            "--endpoint-id",
            &SecretKey::generate().public().to_string(),
        ],
    );

    assert!(!ok, "two competing targets were accepted:\n{output}");
}
