//! Choosing the store, from the command line and from the environment.
//!
//! The file backend is the default and has to stay it: a deployment that says
//! nothing about where its configuration lives is a deployment with a
//! `config.toml` next to it, and that is what every existing deployment has.
//!
//! The database backends are behind cargo features, so a build without them
//! has to say so rather than pretend to open a database it has no driver for.

use nexapipe::storage::StorageKind;

use std::process::{Command, Stdio};

/// The name of the binary the integration tests drive.
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nexapipe"))
}

/// The spellings an operator may write for each store.
#[test]
fn the_spellings_are_the_ones_an_operator_would_guess() {
    assert_eq!(StorageKind::parse("toml").unwrap(), StorageKind::Toml);
    assert_eq!(StorageKind::parse("file").unwrap(), StorageKind::Toml);
    assert_eq!(StorageKind::parse("TOML").unwrap(), StorageKind::Toml);
    assert_eq!(StorageKind::parse("sqlite").unwrap(), StorageKind::Sqlite);
    assert_eq!(
        StorageKind::parse("postgres").unwrap(),
        StorageKind::Postgres
    );
    assert_eq!(
        StorageKind::parse("postgresql").unwrap(),
        StorageKind::Postgres
    );
    assert_eq!(StorageKind::parse("pg").unwrap(), StorageKind::Postgres);
}

/// A store that is not one of the three is refused rather than guessed: a
/// store that is not the one the operator asked for is a store that keeps the
/// configuration somewhere they are not looking.
#[test]
fn an_unknown_store_is_refused() {
    let error = StorageKind::parse("mysql").unwrap_err();
    assert!(
        error.to_string().contains("sqlite"),
        "the refusal names the ones there are: {error}"
    );
}

/// The file backend is what a run without `--storage` gets.
#[test]
fn the_default_is_the_file_backend() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = binary()
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "client",
            "list",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    // The command fails — there is no configuration to list — but it fails
    // reading the file, not refusing a store it does not have.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("storage backend"),
        "the file backend is the default: {stderr}"
    );
}

/// A build without the sqlite backend says so, and says which feature
/// carries it.
#[test]
fn a_backend_this_build_does_not_have_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = binary()
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "--storage",
            "sqlite",
            "client",
            "list",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    assert!(!output.status.success(), "the run fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("storage-sqlite"),
        "the refusal names the feature that would have it: {stderr}"
    );
}

/// The environment says the same thing the command line does, for a deployment
/// that cannot change how the binary is started.
#[test]
fn the_environment_chooses_the_store_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = binary()
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "client",
            "list",
        ])
        .env("NEXAPIPE_STORAGE", "postgres")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    assert!(!output.status.success(), "the run fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("storage-postgres"),
        "the refusal names the feature that would have it: {stderr}"
    );
}
