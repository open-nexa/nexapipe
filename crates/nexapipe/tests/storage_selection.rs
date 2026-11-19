//! Choosing the store, from the command line and from the environment.
//!
//! A deployment that says nothing gets the database, and the database lives
//! beside the configuration file `--config` names. The file store is one flag
//! away, and every spelling that names it keeps working.
//!
//! The database backends are behind cargo features, so a build without them
//! has to say so rather than pretend to open a database it has no driver for.

use nexapipe::storage::StorageKind;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The name of the binary the integration tests drive.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nexapipe"));
    // A store inherited from the caller's environment would open a database
    // other than the one the test named, and a start that is expected to fail
    // would then wait forever. Each test names its own store explicitly.
    command
        .env_remove("NEXAPIPE_STORAGE")
        .env_remove("NEXAPIPE_STORAGE_URL");
    command
}

/// Runs the binary with `args`, stdin closed, and gives back what it said.
fn run(args: &[&str]) -> Output {
    binary()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs")
}

/// The database the default store would keep beside `config`.
fn database(config: &Path) -> PathBuf {
    config.with_file_name("nexapipe.db")
}

/// The configuration a deployment that names the file store has.
const FILE_CONFIG: &str = "\
[auth]
enabled = true

[auth.clients.client-001]
secret = \"JBSWY3DPEHPK3PXP\"
";

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

/// A run that names no store keeps its configuration in the database beside
/// the configuration file.
#[cfg(feature = "storage-sqlite")]
#[test]
fn the_default_is_the_database_beside_the_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "client",
        "list",
    ]);

    // The run fails — the store holds no configuration yet — but it fails
    // reading the database, not refusing a store this build does not have.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        database(&config).exists(),
        "the default store is the database beside the configuration: {}",
        database(&config).display()
    );
    assert!(
        !config.exists(),
        "and it is not the file: `client list` must not write one"
    );
    assert!(
        stderr.contains("nexapipe.db"),
        "the failure names the store that was read: {stderr}"
    );
    assert!(
        !stderr.contains("storage-sqlite"),
        "this build has the store, so it does not refuse it: {stderr}"
    );
}

/// Naming the file store keeps the configuration in the file, and opens no
/// database.
#[test]
fn naming_the_file_store_keeps_the_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, FILE_CONFIG).expect("the configuration is written");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "--storage",
        "toml",
        "client",
        "list",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "the file store is there: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("client-001"),
        "the configuration was read from the file: {stdout}"
    );
    assert!(
        !database(&config).exists(),
        "an explicitly named file store opens no database"
    );
}

/// The environment says the same thing the command line does, for a deployment
/// that cannot change how the binary is started.
#[test]
fn the_environment_chooses_the_file_store() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, FILE_CONFIG).expect("the configuration is written");

    let output = binary()
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "client",
            "list",
            "--json",
        ])
        .env("NEXAPIPE_STORAGE", "toml")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    assert!(output.status.success(), "the file store is there");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("client-001"),
        "the configuration was read from the file"
    );
    assert!(
        !database(&config).exists(),
        "NEXAPIPE_STORAGE=toml opens no database"
    );
}

/// Naming the database store opens it — and an explicit URL decides where it
/// is, rather than the path derived from the configuration file.
#[cfg(feature = "storage-sqlite")]
#[test]
fn naming_the_database_store_opens_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    let named = dir.path().join("elsewhere.db");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "--storage",
        "sqlite",
        "--storage-url",
        named.to_str().expect("utf-8 path"),
        "client",
        "list",
    ]);

    // The store opens and holds no configuration yet, which is what the
    // failure says — and it names the path it was given, not the derived one.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(named.exists(), "the named database is the one opened");
    assert!(
        stderr.contains(named.to_str().expect("utf-8 path")),
        "the store that was opened is the named one: {stderr}"
    );
    assert!(
        !database(&config).exists(),
        "the derived path is not used when a URL is given"
    );
}

/// The environment names the database too, and it wins over the derived path.
#[cfg(feature = "storage-sqlite")]
#[test]
fn the_environment_names_the_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    let named = dir.path().join("from-env.db");

    let output = binary()
        .args([
            "--config",
            config.to_str().expect("utf-8 path"),
            "client",
            "list",
        ])
        .env("NEXAPIPE_STORAGE_URL", named.to_str().expect("utf-8 path"))
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(named.exists(), "NEXAPIPE_STORAGE_URL decides the path");
    assert!(
        stderr.contains(named.to_str().expect("utf-8 path")),
        "the store that was opened is the one the environment named: {stderr}"
    );
    assert!(
        !database(&config).exists(),
        "and the derived path is not used"
    );
}

/// The store a build does not carry is refused by name: a build without the
/// driver says so rather than pretending to open it.
#[test]
fn a_store_this_build_does_not_carry_is_refused_by_name() {
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

/// A build without the SQLite driver refuses the sqlite store by name, however
/// it was asked for.
#[cfg(not(feature = "storage-sqlite"))]
#[test]
fn a_backend_this_build_does_not_have_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "--storage",
        "sqlite",
        "client",
        "list",
    ]);

    assert!(!output.status.success(), "the run fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("storage-sqlite"),
        "the refusal names the feature that would have it: {stderr}"
    );
}

/// In a build without the driver, the default store is the one it does not
/// have — and it says so by name rather than falling back to a file the
/// deployment may not have.
#[cfg(not(feature = "storage-sqlite"))]
#[test]
fn the_default_in_a_file_only_build_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "client",
        "list",
    ]);

    assert!(!output.status.success(), "the run fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("storage-sqlite"),
        "the refusal names the feature that would have it: {stderr}"
    );
}

/// A build with the sqlite backend opens the store instead of refusing it.
#[cfg(feature = "storage-sqlite")]
#[test]
fn a_backend_this_build_has_is_opened() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("config.toml");
    let named = dir.path().join("nexapipe.db");

    let output = run(&[
        "--config",
        config.to_str().expect("utf-8 path"),
        "--storage",
        "sqlite",
        "--storage-url",
        named.to_str().expect("utf-8 path"),
        "client",
        "list",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("storage-sqlite"),
        "this build has the backend, so it does not refuse it: {stderr}"
    );
}
