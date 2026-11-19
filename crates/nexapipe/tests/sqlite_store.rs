//! The SQLite store, end to end.
//!
//! The store is behind the `storage-sqlite` feature, so this file is behind it
//! too: a build without the driver has no store to test.

#![cfg(feature = "storage-sqlite")]

use nexapipe::config::{ClientSecretWrite, Config};
use nexapipe::storage::sqlite::SqliteStorage;
use nexapipe::storage::{DeviceCredential, Stamp, Storage, StorageKind};

use nexapipe_proto::secret::SecretString;

use std::path::PathBuf;

/// A store in a throwaway directory, and the path it is at.
async fn store(dir: &tempfile::TempDir) -> (SqliteStorage, PathBuf) {
    let path = dir.path().join("nexapipe.db");
    let store = SqliteStorage::open(path.to_str().expect("utf-8 path"))
        .await
        .expect("the store opens");
    (store, path)
}

/// A configuration that says everything a deployment can say.
const CONFIG: &str = r#"
debug = true

[server]
listen_addr = "127.0.0.1:8080"

[[routes]]
host_pattern = "example.com"
backends = ["http://127.0.0.1:8081"]

[[routes]]
host_pattern = "*.example.org"
mode = "tcp"
backends = ["127.0.0.1:5432"]

[auth]
enabled = true

[auth.clients.client-001]
secret = "JBSWY3DPEHPK3PXP"
allow_hosts = ["example.com"]
"#;

/// The store says what it is.
#[tokio::test]
async fn the_store_says_what_it_is() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, path) = store(&dir).await;

    assert_eq!(store.kind(), StorageKind::Sqlite);
    assert_eq!(store.describe(), path.display().to_string());
}

/// A store that holds nothing holds no configuration.
#[tokio::test]
async fn an_empty_store_holds_no_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    assert!(
        store.config().await.expect("the store answers").is_none(),
        "a store that was never written holds no configuration"
    );
}

/// The configuration survives the round trip through the rows.
///
/// The store hands its configuration back as the same TOML a file would have
/// held, so a reader cannot tell which store it came from — and a route that
/// was written is a route that is still there.
#[tokio::test]
async fn the_configuration_survives_the_round_trip() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    assert!(
        store
            .ensure_config(CONFIG)
            .await
            .expect("the configuration is written"),
        "the store was empty, so the configuration is new"
    );

    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    let config = Config::from_toml_text(text.expose_secret()).expect("the configuration parses");

    let routes = config.routes.as_ref().expect("the routes are there");
    assert_eq!(routes.len(), 2, "both routes are there");
    assert_eq!(routes[0].host_pattern, "example.com");
    assert_eq!(routes[0].backends, vec!["http://127.0.0.1:8081"]);
    assert_eq!(routes[1].host_pattern, "*.example.org");
    assert_eq!(routes[1].mode.as_deref(), Some("tcp"));

    assert_eq!(
        config
            .server
            .as_ref()
            .and_then(|s| s.listen_addr.as_deref()),
        Some("127.0.0.1:8080")
    );
    assert!(config.debug.unwrap_or(false));

    let auth = config.auth.as_ref().expect("the [auth] section is there");
    assert!(auth.enabled.unwrap_or(false));
    assert_eq!(auth.clients.len(), 1, "the client is there");
    assert_eq!(
        auth.clients["client-001"].secret.expose_secret(),
        "JBSWY3DPEHPK3PXP",
        "the seed survived"
    );
}

/// A store that already holds a configuration keeps it.
///
/// `ensure_config` writes the template only into a store that holds nothing:
/// a second start must not lay the template over what the operator has since
/// changed.
#[tokio::test]
async fn a_store_that_holds_a_configuration_keeps_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");
    assert!(
        !store
            .ensure_config(CONFIG)
            .await
            .expect("the store answers"),
        "a store that holds a configuration is not written again"
    );
}

/// A client's secret is written, and read back.
///
/// The write is by entity: it touches that client's row and nothing else.
#[tokio::test]
async fn a_clients_secret_is_written_and_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");

    let secret = SecretString::new("NEWSECRETNEWSECRET".to_string());
    let written = store
        .write_client_secret("client-002", &secret, false)
        .await
        .expect("the secret is written");
    assert_eq!(written, ClientSecretWrite::Added);

    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    let config = Config::from_toml_text(text.expose_secret()).expect("the configuration parses");
    let auth = config.auth.as_ref().expect("the [auth] section is there");

    assert_eq!(
        auth.clients["client-002"].secret.expose_secret(),
        "NEWSECRETNEWSECRET",
        "the secret was written"
    );
    assert_eq!(
        auth.clients["client-001"].secret.expose_secret(),
        "JBSWY3DPEHPK3PXP",
        "the other client is untouched"
    );
}

/// An existing secret is not replaced without `force`.
///
/// A device that already imported the old secret stops authenticating the
/// instant it changes, so replacing one is something an operator has to ask
/// for.
#[tokio::test]
async fn an_existing_secret_is_not_replaced_without_force() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");

    let secret = SecretString::new("NEWSECRETNEWSECRET".to_string());
    let error = store
        .write_client_secret("client-001", &secret, false)
        .await
        .expect_err("the write is refused");
    assert!(
        error.to_string().contains("already has a secret"),
        "the refusal says why: {error}"
    );

    let replaced = store
        .write_client_secret("client-001", &secret, true)
        .await
        .expect("the write is allowed");
    assert_eq!(replaced, ClientSecretWrite::Replaced);
}

/// A device's credential is written, and read back.
#[tokio::test]
async fn a_devices_credential_is_written_and_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");

    let written = store
        .write_device_credential(
            "client-001",
            "laptop",
            DeviceCredential::Secret(SecretString::new("DEVICESECRETDEVICESECRET".to_string())),
            false,
        )
        .await
        .expect("the credential is written");
    assert_eq!(written, ClientSecretWrite::Added);

    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    let config = Config::from_toml_text(text.expose_secret()).expect("the configuration parses");
    let auth = config.auth.as_ref().expect("the [auth] section is there");
    let device = &auth.clients["client-001"].devices["laptop"];

    assert_eq!(
        device
            .secret
            .as_ref()
            .expect("the secret is there")
            .expose_secret(),
        "DEVICESECRETDEVICESECRET"
    );
}

/// A device's credential is dropped, and a client is dropped with it.
///
/// A revoke is a delete and not a rotation: a deleted entry is the one thing
/// the handshake reads as "this device has no credential".
#[tokio::test]
async fn a_device_and_a_client_are_dropped() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");
    store
        .write_device_credential(
            "client-001",
            "laptop",
            DeviceCredential::Secret(SecretString::new("DEVICESECRETDEVICESECRET".to_string())),
            false,
        )
        .await
        .expect("the credential is written");

    store
        .remove_device("client-001", "laptop")
        .await
        .expect("the device is dropped");
    let error = store
        .remove_device("client-001", "laptop")
        .await
        .expect_err("the second revoke is refused");
    assert!(
        error.to_string().contains("no device"),
        "the refusal says why: {error}"
    );

    store
        .remove_client("client-001")
        .await
        .expect("the client is dropped");
    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    let config = Config::from_toml_text(text.expose_secret()).expect("the configuration parses");
    let auth = config.auth.as_ref().expect("the [auth] section is there");
    assert!(auth.clients.is_empty(), "the client is gone");
}

/// The revision moves when the configuration does, and not otherwise.
///
/// This is what the watcher compares: a store whose revision does not move is
/// a store whose changes are not seen.
#[tokio::test]
async fn the_revision_moves_on_a_write() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    let before = store.stamp().await.expect("the store answers");
    let Stamp::Database { revision } = before else {
        panic!("a database is stamped by its revision, not by a file");
    };

    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");
    let after = store.stamp().await.expect("the store answers");
    let Stamp::Database { revision: moved } = after else {
        panic!("a database is stamped by its revision, not by a file");
    };
    assert_ne!(moved, revision, "the write moved the revision");

    // A read is not a write, and does not move it.
    let read = store.stamp().await.expect("the store answers");
    assert_eq!(read, after, "a read does not move the revision");
}

/// The endpoint's key is written into the configuration.
///
/// The key is the endpoint's identity: it is written once, on the first start
/// that finds none, and the Node ID it decides has to survive every restart
/// after that.
#[tokio::test]
async fn the_endpoint_key_is_written() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .ensure_config(CONFIG)
        .await
        .expect("the configuration is written");

    let key = SecretString::new("0123456789abcdef".to_string());
    store
        .write_endpoint_key(&key)
        .await
        .expect("the key is written");

    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    let config = Config::from_toml_text(text.expose_secret()).expect("the configuration parses");
    let iroh = config.iroh.as_ref().expect("the [iroh] section is there");
    assert_eq!(
        iroh.secret_key
            .as_ref()
            .expect("the key is there")
            .expose_secret(),
        "0123456789abcdef"
    );
}

/// The key needs a configuration to go into.
///
/// The key is written into the configuration, and a store that wrote one into
/// nothing would answer "the configuration is written" to the next reader
/// while holding a document with nothing but a key in it.
#[tokio::test]
async fn the_endpoint_key_needs_a_configuration_to_go_into() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    let error = store
        .write_endpoint_key(&SecretString::new("0123456789abcdef".to_string()))
        .await
        .expect_err("the write is refused");
    assert!(
        error.to_string().contains("no configuration"),
        "the refusal says why: {error}"
    );
}

/// The counters survive a restart, and so does the admin token.
#[tokio::test]
async fn the_counters_and_the_token_survive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, path) = store(&dir).await;

    let mut state = nexapipe::auth::state::RuntimeState::default();
    state.clients.insert(
        "client-001".to_string(),
        nexapipe::auth::state::ClientState {
            failed_attempts: 3,
            locked_until: Some(1_700_000_000),
            ..Default::default()
        },
    );
    store
        .put_state(&state)
        .await
        .expect("the counters are written");

    let token = SecretString::new("an-admin-token".to_string());
    store
        .put_admin_token(&token)
        .await
        .expect("the token is written");

    // A second store on the same database: what a restart reads.
    let reopened = SqliteStorage::open(path.to_str().expect("utf-8 path"))
        .await
        .expect("the store opens");
    let read = reopened.state().await.expect("the counters are read");
    assert_eq!(read.clients["client-001"].failed_attempts, 3);
    assert_eq!(read.clients["client-001"].locked_until, Some(1_700_000_000));

    let read = reopened
        .admin_token()
        .await
        .expect("the token is read")
        .expect("the store holds a token");
    assert_eq!(read.expose_secret(), "an-admin-token");
}

/// A token that is already there is not replaced.
///
/// Whoever is using it would be locked out without being told.
#[tokio::test]
async fn an_admin_token_is_not_replaced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    store
        .put_admin_token(&SecretString::new("first".to_string()))
        .await
        .expect("the token is written");
    let error = store
        .put_admin_token(&SecretString::new("second".to_string()))
        .await
        .expect_err("the second write is refused");
    assert!(
        error.to_string().contains("already"),
        "the refusal says why: {error}"
    );
}

/// A store on a path whose directory does not exist is created.
///
/// A deployment that names a database under a directory it has not made yet
/// should not have to make the directory itself.
#[tokio::test]
async fn the_directory_of_the_store_is_created() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nested").join("deeper").join("nexapipe.db");

    let store = SqliteStorage::open(path.to_str().expect("utf-8 path"))
        .await
        .expect("the store opens");
    assert!(path.exists(), "the database is there");
    assert!(store.config().await.expect("the store answers").is_none());
}
