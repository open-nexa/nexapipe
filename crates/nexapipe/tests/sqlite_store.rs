//! The SQLite store, end to end.
//!
//! The store is behind the `storage-sqlite` feature, so this file is behind it
//! too: a build without the driver has no store to test.

#![cfg(feature = "storage-sqlite")]

use nexapipe::config::{ClientSecretWrite, Config, RouteSpec};
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

/// A store accepts a whole configuration, and the revision moves with the
/// write — a watcher comparing stamps sees it.
#[tokio::test]
async fn a_whole_configuration_can_be_put() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    let config = Config::from_toml_text(CONFIG).expect("the configuration parses");
    let before = store.stamp().await.expect("the store answers");
    store
        .put_config(&config)
        .await
        .expect("the configuration is written");
    let after = store.stamp().await.expect("the store answers");
    assert_ne!(after, before, "the write moved the revision");

    let text = store
        .config()
        .await
        .expect("the store is readable")
        .expect("the store holds a configuration");
    let written = text.expose_secret();
    assert!(written.contains("example.com"), "the route came across");
    assert!(
        written.contains("JBSWY3DPEHPK3PXP"),
        "the credential came across"
    );

    // Writing it a second time replaces the configuration rather than adding
    // to it, and moves the revision again.
    let again = Config::from_toml_text("[server]\nlisten_addr = \"127.0.0.1:9090\"\n")
        .expect("the second configuration parses");
    store
        .put_config(&again)
        .await
        .expect("the configuration is replaced");
    let last = store.stamp().await.expect("the store answers");
    assert_ne!(last, after, "the replacement moved the revision as well");

    let text = store
        .config()
        .await
        .expect("the store is readable")
        .expect("the store holds a configuration");
    assert!(
        !text.expose_secret().contains("example.com"),
        "the rows that were there before are gone: {}",
        text.expose_secret()
    );
}

/// The route the tests write, parsed by the schema so that the store is
/// handed the same shape a configuration file would have given it.
fn route() -> RouteSpec {
    toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/api\"\nbackends = [\"http://127.0.0.1:9090\"]\n",
    )
    .expect("the route parses")
}

/// The configuration the store hands back.
async fn configuration(store: &SqliteStorage) -> Config {
    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    Config::from_toml_text(text.expose_secret()).expect("the configuration parses")
}

/// The stable id the route list gives the route with this host and path.
async fn route_id(store: &SqliteStorage, host: &str, path: &str) -> String {
    let spec = configuration(store)
        .await
        .routes
        .unwrap_or_default()
        .into_iter()
        .find(|route| route.host_pattern == host && route.path_pattern == path)
        .expect("the route is in the store");
    nexapipe::storage::route_id(&spec)
}

/// A route written into the store is in the configuration it hands back, and
/// the revision moves with the write — a watcher comparing stamps sees it.
#[tokio::test]
async fn a_route_written_into_the_store_is_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");

    let before = store.stamp().await.expect("the store answers");
    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");
    let after = store.stamp().await.expect("the store answers");
    assert_ne!(after, before, "the write moved the revision");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    assert!(
        routes
            .iter()
            .any(|route| route.host_pattern == "console.example" && route.path_pattern == "/api"),
        "the route is in the configuration: {routes:?}"
    );
    // The routes that were there before are still there: a write of one route
    // is a write of one route.
    assert!(
        routes
            .iter()
            .any(|route| route.host_pattern == "example.com"),
        "the route that was there before is still there: {routes:?}"
    );
}

/// A route written twice is one route, not two.
#[tokio::test]
async fn a_route_written_twice_is_one_route() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");

    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");
    store
        .write_route(&route(), None)
        .await
        .expect("the route is written again");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    let matching = routes
        .iter()
        .filter(|route| route.host_pattern == "console.example")
        .count();
    assert_eq!(matching, 1, "the route is one route: {routes:?}");
}

/// A route dropped from the store is gone from the configuration it hands
/// back, and the revision moves with the drop.
#[tokio::test]
async fn a_route_dropped_from_the_store_is_gone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");
    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");

    let before = store.stamp().await.expect("the store answers");
    let id = route_id(&store, "console.example", "/api").await;
    let dropped = store
        .remove_route(id.clone())
        .await
        .expect("the route is dropped");
    assert!(dropped, "there was a route to drop");
    let after = store.stamp().await.expect("the store answers");
    assert_ne!(after, before, "the drop moved the revision");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    assert!(
        !routes
            .iter()
            .any(|route| route.host_pattern == "console.example"),
        "the route is gone: {routes:?}"
    );

    // A route that is not there is an answer, not a failure. The same id is
    // past the end of the list now that the row is gone.
    let again = store.remove_route(id).await.expect("the store answers");
    assert!(!again, "there was no route to drop the second time");
}

/// A write into a store that holds no configuration is refused, and neither
/// the revision nor the contents move.
#[tokio::test]
async fn a_route_write_into_an_uninitialised_store_changes_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;

    let before = store.stamp().await.expect("the store answers");
    assert!(
        store.write_route(&route(), None).await.is_err(),
        "there is no configuration to add a route to"
    );
    assert_eq!(
        store.stamp().await.expect("the store answers"),
        before,
        "the revision did not move"
    );
    assert!(
        store.config().await.expect("the store answers").is_none(),
        "no configuration was invented"
    );
}

/// A failure after the row has been mutated rolls the whole write back: the
/// route and the revision stay as they were, so a watcher never sees a half
/// write.
#[tokio::test]
async fn a_failed_route_write_rolls_back_the_row_and_the_revision() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, path) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");
    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");
    let id = route_id(&store, "console.example", "/api").await;

    // An AFTER UPDATE trigger fails the mutation itself, after the store has
    // opened its transaction: the only way out is the rollback `?` takes.
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5)),
    )
    .await
    .expect("the second connection opens");
    sqlx::query(
        "CREATE TRIGGER fail_route_write AFTER UPDATE ON routes \
         BEGIN SELECT RAISE(FAIL, 'injected failure'); END;",
    )
    .execute(&pool)
    .await
    .expect("the trigger is installed");

    let before = store.stamp().await.expect("the store answers");
    let edited: RouteSpec = toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/api\"\nbackends = [\"http://127.0.0.1:9099\"]\n",
    )
    .expect("the route parses");
    assert!(
        store.write_route(&edited, Some(id)).await.is_err(),
        "the mutation failed"
    );

    assert_eq!(
        store.stamp().await.expect("the store answers"),
        before,
        "the revision did not move with a failed write"
    );
    let routes = configuration(&store).await.routes.unwrap_or_default();
    let written = routes
        .iter()
        .find(|route| route.host_pattern == "console.example")
        .expect("the route is still there");
    assert_eq!(
        written.backends[0], "http://127.0.0.1:9090",
        "the row was not left half-written: {routes:?}"
    );

    sqlx::query("DROP TRIGGER fail_route_write")
        .execute(&pool)
        .await
        .expect("the trigger is removed");
    pool.close().await;
}

/// Two routes that share a host and a path but not their modes are two rows,
/// and removing one by id leaves the other one alone.
#[tokio::test]
async fn routes_sharing_host_and_path_are_addressed_by_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");

    let http: RouteSpec =
        toml::from_str("host_pattern = \"app.example\"\nbackends = [\"http://127.0.0.1:8080\"]\n")
            .expect("the route parses");
    let passthrough: RouteSpec = toml::from_str(
        "host_pattern = \"app.example\"\nmode = \"passthrough\"\nbackends = [\"10.0.0.5:443\"]\n",
    )
    .expect("the route parses");
    store
        .write_route(&http, None)
        .await
        .expect("the HTTP route is written");
    store
        .write_route(&passthrough, None)
        .await
        .expect("the passthrough route is written");

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        4,
        "CONFIG holds two, and the two new ones are distinct rows: {routes:?}"
    );

    let dropped = store
        .remove_route(nexapipe::storage::route_id(&passthrough))
        .await
        .expect("the route is dropped");
    assert!(dropped, "there was a route at that id");

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(routes.len(), 3, "only the named row went: {routes:?}");
    assert!(
        routes
            .iter()
            .any(|route| route.host_pattern == "app.example" && route.mode.is_none()),
        "the HTTP row is still there: {routes:?}"
    );
}

/// A stale id cannot name a different row in the database either: the id is
/// resolved against the rows the transaction just read, not a position.
#[tokio::test]
async fn a_stale_id_cannot_remove_or_replace_a_different_route() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (store, _) = store(&dir).await;
    store
        .put_config(&Config::from_toml_text(CONFIG).expect("the configuration parses"))
        .await
        .expect("the configuration is written");

    let a: RouteSpec =
        toml::from_str("host_pattern = \"a.example\"\nbackends = [\"http://127.0.0.1:8001\"]\n")
            .expect("the route parses");
    let b: RouteSpec =
        toml::from_str("host_pattern = \"b.example\"\nbackends = [\"http://127.0.0.1:8002\"]\n")
            .expect("the route parses");
    let c: RouteSpec =
        toml::from_str("host_pattern = \"c.example\"\nbackends = [\"http://127.0.0.1:8003\"]\n")
            .expect("the route parses");
    for route in [&a, &b, &c] {
        store
            .write_route(route, None)
            .await
            .expect("the route is written");
    }

    let id_a = nexapipe::storage::route_id(&a);
    let id_b = nexapipe::storage::route_id(&b);
    let id_c = nexapipe::storage::route_id(&c);

    // CONFIG holds two routes. A and B go away, and the stale id for B must
    // not take one of the others with it.
    assert!(
        store
            .remove_route(id_a)
            .await
            .expect("the first route is dropped"),
        "A was there"
    );
    assert!(
        store
            .remove_route(id_b.clone())
            .await
            .expect("the second removal is answered"),
        "B is the row the stale id still names"
    );

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(routes.len(), 3, "only A and B went: {routes:?}");
    assert!(
        routes.iter().any(|route| route.host_pattern == "c.example"),
        "C is untouched: {routes:?}"
    );
    assert!(
        !routes
            .iter()
            .any(|route| route.host_pattern == "a.example" || route.host_pattern == "b.example"),
        "A and B are gone: {routes:?}"
    );
    assert!(
        routes
            .iter()
            .any(|route| route.host_pattern == "example.com"),
        "the CONFIG rows are untouched: {routes:?}"
    );

    // The same id in a write is refused rather than editing another row.
    let edited: RouteSpec =
        toml::from_str("host_pattern = \"b.example\"\nbackends = [\"http://127.0.0.1:9999\"]\n")
            .expect("the route parses");
    assert!(
        store.write_route(&edited, Some(id_b)).await.is_err(),
        "a stale id is refused, not applied to another row"
    );
    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        3,
        "the refused write changed nothing: {routes:?}"
    );
    assert!(
        !routes
            .iter()
            .any(|route| route.backends[0].contains("9999")),
        "no row was silently edited: {routes:?}"
    );

    assert!(
        store
            .remove_route(id_c)
            .await
            .expect("the last removal is answered"),
        "C is still addressable by the id it was given"
    );
}
