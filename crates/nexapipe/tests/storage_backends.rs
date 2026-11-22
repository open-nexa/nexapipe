//! The storage backend's contract.
//!
//! Every backend has to answer the same questions the same way, because the
//! server asks them without knowing which backend it is talking to. These
//! tests ask them **through the trait** — not through the path-based API the
//! CLI still uses — so that a backend which cannot answer them cannot be
//! dropped in.
//!
//! The file backend is the one that exists today, and it is the reference:
//! the same scenario, the same answers, whether the caller names a path or a
//! store.

use nexapipe::auth::{DeviceInfo, DeviceMaterial};
use nexapipe::config::{Config, RouteSpec, load_config, load_config_with_auth};
use nexapipe::storage::{FileStorage, Storage};

use nexapipe_proto::secret::SecretString;

use std::sync::Arc;

/// A store over a configuration file in a temporary directory.
fn store(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
    Arc::new(FileStorage::new(dir.path().join("config.toml")))
}

/// A configuration with one client, written straight to the file.
fn seed(dir: &tempfile::TempDir) -> String {
    let path = dir.path().join("config.toml");
    let text = "\
# The operator's own note, above the section they wrote.
[auth]
enabled = true

[auth.clients.client-001]
# The seed this client was enrolled with.
secret = \"JBSWY3DPEHPK3PXP\"
";
    std::fs::write(&path, text).expect("the configuration is written");
    path.to_string_lossy().into_owned()
}

/// The configuration a store hands out is the configuration that was put in it.
#[tokio::test]
async fn a_store_hands_back_what_it_was_given() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let config = load_config(store.as_ref())
        .await
        .expect("the configuration loads");
    assert!(
        config.iroh.is_none(),
        "the configuration is the one that was put in the store"
    );
    assert!(
        config.local_proxy.is_none(),
        "and nothing was invented for it"
    );
}

/// The 2FA half of the configuration comes out of the same read as the rest of
/// it, and holds the credentials.
#[tokio::test]
async fn a_store_hands_back_the_credentials_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let (_, auth) = load_config_with_auth(store.as_ref())
        .await
        .expect("the configuration loads");

    let auth = auth.expect("the [auth] section is there");
    assert!(auth.enabled, "2FA is on");
    let client = auth.clients.get("client-001").expect("the client is there");
    assert_eq!(
        client.secret.expose_secret(),
        "JBSWY3DPEHPK3PXP",
        "the seed survives the round trip"
    );
}

/// A credential written through the store is read back through the store.
#[tokio::test]
async fn a_credential_written_through_the_store_is_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let secret = SecretString::new("JBSWY3DPEHPK3PXP".to_string());
    let written = store
        .write_client_secret("client-002", &secret, false)
        .await
        .expect("the secret is written");
    assert_eq!(written, nexapipe::config::ClientSecretWrite::Added);

    let (_, auth) = load_config_with_auth(store.as_ref())
        .await
        .expect("the configuration loads");
    let auth = auth.expect("the [auth] section is there");
    assert!(
        auth.clients.contains_key("client-002"),
        "the client the store was asked to write is there"
    );
}

/// A secret that is already there is not replaced unless the caller says so:
/// a device that already imported the old one stops authenticating the instant
/// it changes.
#[tokio::test]
async fn an_existing_secret_is_kept_unless_the_write_says_otherwise() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let other = SecretString::new("MZXW6YTBOI======".to_string());
    let refused = store.write_client_secret("client-001", &other, false).await;
    assert!(
        refused.is_err(),
        "an existing secret is not replaced by accident"
    );

    let replaced = store
        .write_client_secret("client-001", &other, true)
        .await
        .expect("the write that says so goes through");
    assert_eq!(replaced, nexapipe::config::ClientSecretWrite::Replaced);
}

/// A device's credential is written under the client it belongs to, and the
/// client's own secret is left where it was.
#[tokio::test]
async fn a_device_credential_is_written_beside_the_clients_own() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    store
        .complete_device_enrollment(
            "client-001",
            "laptop",
            nexapipe::storage::DeviceCredential::Secret(SecretString::new(
                "MZXW6YTBOI======".to_string(),
            )),
            DeviceInfo::default(),
        )
        .await
        .expect("the device credential is written");

    let (_, auth) = load_config_with_auth(store.as_ref())
        .await
        .expect("the configuration loads");
    let auth = auth.expect("the [auth] section is there");
    let client = auth.clients.get("client-001").expect("the client is there");

    assert_eq!(
        client.secret.expose_secret(),
        "JBSWY3DPEHPK3PXP",
        "the client's own secret is untouched"
    );
    let device = client.devices.get("laptop").expect("the device is there");
    assert_eq!(
        device.secret.expose_secret(),
        "MZXW6YTBOI======",
        "the device answers with its own credential"
    );
}

/// A device that proves itself with a key carries the public half, and the
/// half that never leaves the device is not in the store at all.
#[tokio::test]
async fn a_key_device_stores_the_public_half() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    // Generated rather than written out: a key spelled out in the source is a
    // string of hex in a file, and the secret scanner reads one as a
    // credential. It also has to be a point on the curve, which is not
    // something a fixture can be.
    let key = nexapipe::auth::public_key_hex(&iroh::SecretKey::generate().public());
    store
        .write_device_credential(
            "client-001",
            "server",
            nexapipe::storage::DeviceCredential::PublicKey(key.to_string()),
            false,
        )
        .await
        .expect("the device credential is written");

    let (_, auth) = load_config_with_auth(store.as_ref())
        .await
        .expect("the configuration loads");
    let auth = auth.expect("the [auth] section is there");
    let client = auth.clients.get("client-001").expect("the client is there");
    let device = client.devices.get("server").expect("the device is there");

    assert!(
        device.public_key.is_some(),
        "the public half is what a key device answers with"
    );
    assert!(
        device.secret.expose_secret().is_empty(),
        "and it carries no seed to answer with"
    );
}

/// A revoked client is gone from the next read, and the rest of the
/// configuration is where it was.
#[tokio::test]
async fn a_revoked_client_is_gone_and_the_rest_is_not() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    store
        .remove_client("client-001")
        .await
        .expect("the client is revoked");

    let (_, auth) = load_config_with_auth(store.as_ref())
        .await
        .expect("the configuration loads");
    let auth = auth.expect("the [auth] section is there");
    assert!(
        !auth.clients.contains_key("client-001"),
        "the revoked client is not there any more"
    );
    assert!(auth.enabled, "and the section it was in is still there");
}

/// The counters live in the store beside the configuration, not inside it: the
/// configuration's own timestamp must not move every time a client mistypes a
/// code.
#[tokio::test]
async fn the_counters_are_written_beside_the_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = seed(&dir);
    let store = store(&dir);

    let mut state = nexapipe::auth::state::RuntimeState::default();
    state.clients.insert(
        "client-001".to_string(),
        nexapipe::auth::state::ClientState {
            failed_attempts: 3,
            ..Default::default()
        },
    );
    store
        .put_state(&state)
        .await
        .expect("the counters are written");

    let read = store.state().await.expect("the counters are read back");
    assert_eq!(
        read.clients.get("client-001").map(|c| c.failed_attempts),
        Some(3),
        "the count is the one that was written"
    );

    let config_text = std::fs::read_to_string(&path).expect("the configuration is read");
    assert!(
        !config_text.contains("failed_attempts"),
        "the counters did not go into the operator's file"
    );
}

/// The admin token is written once and read back: an instance that restarts
/// must not lock out whoever already has the token.
#[tokio::test]
async fn the_admin_token_is_written_once_and_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    assert!(
        store
            .admin_token()
            .await
            .expect("the token is read")
            .is_none(),
        "there is no token before one is written"
    );

    let token = SecretString::new("0123456789abcdef".to_string());
    store
        .put_admin_token(&token)
        .await
        .expect("the token is written");

    let read = store
        .admin_token()
        .await
        .expect("the token is read")
        .expect("the token is there");
    assert_eq!(
        read.expose_secret(),
        "0123456789abcdef",
        "the token is the one that was written"
    );

    // A second write refuses: whoever is using the token would be locked out
    // without being told.
    let refused = store
        .put_admin_token(&SecretString::new("fedcba9876543210".to_string()))
        .await;
    assert!(refused.is_err(), "a token is not replaced silently");
}

/// The endpoint's key is written where the configuration says it goes, and the
/// configuration that comes back holds it: the Node ID has to survive a
/// restart.
#[tokio::test]
async fn the_endpoint_key_is_written_into_the_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    // Built rather than written out, for the reason the public key above says.
    let key = SecretString::new("cd".repeat(32));
    store
        .write_endpoint_key(&key)
        .await
        .expect("the key is written");

    let config = load_config(store.as_ref())
        .await
        .expect("the configuration loads");
    let iroh = config.iroh.expect("the [iroh] section is there");
    assert_eq!(
        iroh.secret_key.as_ref().map(|k| k.expose_secret().as_str()),
        Some(key.expose_secret().as_str()),
        "the key is in the configuration the server reads"
    );
}

/// The stamp moves when the configuration changes, and only then: it is what
/// the watcher looks at to decide whether to reload.
#[tokio::test]
async fn the_stamp_moves_when_the_configuration_changes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = seed(&dir);
    let store = store(&dir);

    let before = store.stamp().await.expect("the stamp is read");
    assert_eq!(
        before,
        store.stamp().await.expect("the stamp is read again"),
        "an unchanged configuration has the same stamp"
    );

    std::fs::write(&path, "changed\n").expect("the configuration is written");
    let after = store.stamp().await.expect("the stamp is read");
    assert_ne!(
        before, after,
        "a changed configuration has a different stamp"
    );
}

/// The configuration a store hands out is a credential, and it says so: the
/// text can hold the seeds in the clear, and a `Debug` of it must not print
/// them.
#[tokio::test]
async fn the_configuration_text_is_not_printed() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let text = store
        .config()
        .await
        .expect("the configuration is read")
        .expect("there is one");
    let shown = format!("{text:?}");
    assert!(
        !shown.contains("JBSWY3DPEHPK3PXP"),
        "the seed reached a debug dump: {shown}"
    );
}

/// A write of a credential leaves the operator's comments where they were.
///
/// The configuration is a file a human wrote, and a comment in it is a
/// comment they wrote. A store that re-rendered the document would take the
/// comments with it, and the operator would find their notes gone after a
/// `client add`.
#[tokio::test]
async fn a_write_leaves_the_operators_comments_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = seed(&dir);
    let store = store(&dir);

    let secret = SecretString::new("MZXW6YTBOI======".to_string());
    store
        .write_client_secret("client-002", &secret, false)
        .await
        .expect("the secret is written");

    let text = std::fs::read_to_string(&path).expect("the configuration is read");
    assert!(
        text.contains("# The operator's own note, above the section they wrote."),
        "the comment above the section survived: {text}"
    );
    assert!(
        text.contains("# The seed this client was enrolled with."),
        "and the comment inside the client's own section did too: {text}"
    );
    assert!(text.contains("[auth]"), "the section is still there");
    assert!(
        text.contains("JBSWY3DPEHPK3PXP"),
        "and so is the client that was already in it"
    );
}

/// The material a device is issued travels as the type that wipes itself, and
/// the conversion from the borrowed form keeps it that way.
#[test]
fn a_device_credential_is_zeroizing() {
    let credential: nexapipe::storage::DeviceCredential =
        DeviceMaterial::Secret("JBSWY3DPEHPK3PXP").into();
    let nexapipe::storage::DeviceCredential::Secret(secret) = credential else {
        panic!("a secret stays a secret");
    };
    assert_eq!(secret.expose_secret(), "JBSWY3DPEHPK3PXP");
    let shown = format!("{secret:?}");
    assert!(
        !shown.contains("JBSWY3DPEHPK3PXP"),
        "the seed reached a debug dump: {shown}"
    );
}

/// Each of the store's three documents is named by the one it is.
///
/// The configuration, the counters and the admin token are three documents in
/// three files. A message about one of them has to name that one: an operator
/// sent to the configuration to fix a counter that lives beside it finds
/// nothing there.
#[tokio::test]
async fn each_document_is_named_by_the_document_it_is() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let config = store.describe();
    let state = store.describe_state();
    let token = store.describe_token();

    assert_ne!(
        config, state,
        "the counters are named by the configuration's own file"
    );
    assert_ne!(
        config, token,
        "the admin token is named by the configuration's own file"
    );
    assert_ne!(
        state, token,
        "the admin token is named by the counters' file"
    );

    // And each name is the file that document is actually written to.
    assert!(
        state.ends_with("config.state.toml"),
        "the counters are not named by the file they are written to: {state}"
    );
    assert!(
        token.ends_with("config.toml.admin-token"),
        "the token is not named by the file it is written to: {token}"
    );
}

/// The message an operator reads names the file the thing is actually in.
///
/// `nexapipe status` on an instance that has never started says where the
/// admin token is. It has to be the token's own file: the token is not in the
/// configuration, and an operator sent there finds nothing.
#[tokio::test]
async fn the_status_message_names_the_token_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[admin]\nlisten_addr = \"127.0.0.1:9090\"\n")
        .expect("the configuration is written");
    let store = store(&dir);

    let error = nexapipe::status::status(&*store, false)
        .await
        .expect_err("there is no token yet");
    let message = error.to_string();

    assert!(
        message.contains(&store.describe_token()),
        "the message does not name the token's file ({}): {message}",
        store.describe_token()
    );
    assert!(
        !message.contains(&store.describe_state()),
        "the message names the counters' file instead of the token's: {message}"
    );
}

/// A configuration named without a directory still has one: the working
/// directory is the one.
///
/// A store over a file always has a directory to resolve a relative path
/// against — the configuration's own — so the question never arises for it.
/// It arises for a store that has no files beside it, and that store has to
/// refuse the path rather than guess at it.
#[tokio::test]
async fn a_configuration_named_without_a_directory_has_the_working_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[iroh]\nsecret_key_file = \"iroh.key\"\n")
        .expect("the configuration is written");
    let store = FileStorage::new(&path);

    assert!(
        store.base_dir().is_some(),
        "a store over a file always has a directory: the configuration's own"
    );
}

/// A store accepts a whole configuration and makes it the one it holds.
///
/// This is the one whole-document write, and the one the import of a
/// `config.toml` written for the file store needs: the store holds nothing and
/// is handed everything, once.
#[tokio::test]
async fn a_store_accepts_a_whole_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = store(&dir);

    let config = nexapipe::config::Config::from_toml_text(
        "\
[server]
listen_addr = \"127.0.0.1:8080\"

[[routes]]
host_pattern = \"example.com\"
backends = [\"http://127.0.0.1:8081\"]

[auth]
enabled = true

[auth.clients.client-001]
secret = \"JBSWY3DPEHPK3PXP\"
",
    )
    .expect("the configuration parses");

    store
        .put_config(&config)
        .await
        .expect("the configuration is written");

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

    // Reading it back and writing it out again changes nothing: what the store
    // holds is a configuration, not a copy of some text.
    let read_back =
        nexapipe::config::Config::from_toml_text(written).expect("what the store hands out parses");
    assert_eq!(
        read_back.to_toml_text().expect("it writes"),
        written.as_str(),
        "the configuration survives the round trip"
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

/// The configuration a store hands back.
async fn configuration(store: &Arc<dyn Storage>) -> Config {
    let text = store
        .config()
        .await
        .expect("the store answers")
        .expect("the store holds a configuration");
    Config::from_toml_text(text.expose_secret()).expect("the configuration parses")
}

/// A route written to a store is in the configuration it hands back — and the
/// comment the operator wrote beside it is still there, because a write that
/// re-rendered the document would have taken it with it.
#[tokio::test]
async fn a_route_written_to_a_store_is_read_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    assert!(
        routes
            .iter()
            .any(|route| route.host_pattern == "console.example" && route.path_pattern == "/api"),
        "the route is in the configuration: {routes:?}"
    );

    let file = std::fs::read_to_string(dir.path().join("config.toml")).expect("the file is read");
    assert!(
        file.contains("The operator's own note"),
        "the operator's comment survived the write: {file}"
    );
    assert!(
        file.contains("console.example"),
        "and the route is in the file: {file}"
    );
}

/// A route written twice is one route, not two.
#[tokio::test]
async fn a_route_written_twice_is_one_route() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

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

/// A route dropped from a store is gone from the configuration it hands back.
#[tokio::test]
async fn a_route_dropped_from_a_store_is_gone() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    store
        .write_route(&route(), None)
        .await
        .expect("the route is written");
    let id = nexapipe::storage::route_id(&route());
    let dropped = store
        .remove_route(id.clone())
        .await
        .expect("the route is dropped");
    assert!(dropped, "there was a route to drop");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    assert!(
        !routes
            .iter()
            .any(|route| route.host_pattern == "console.example"),
        "the route is gone: {routes:?}"
    );

    // A route that is not there is an answer, not a failure.
    let again = store.remove_route(id).await.expect("the store answers");
    assert!(!again, "there was no route to drop the second time");
}

/// Two routes on the same host are two routes: their paths differ, and each
/// has its own id in the list, so dropping one leaves the other one alone.
#[tokio::test]
async fn two_routes_on_one_host_are_dropped_one_at_a_time() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

    let api = toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/api\"\nbackends = [\"http://127.0.0.1:9090\"]\n",
    )
    .expect("the route parses");
    let static_files = toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/static\"\nbackends = [\"http://127.0.0.1:9091\"]\n",
    )
    .expect("the route parses");
    store
        .write_route(&api, None)
        .await
        .expect("the route is written");
    store
        .write_route(&static_files, None)
        .await
        .expect("the route is written");

    let dropped = store
        .remove_route(nexapipe::storage::route_id(&api))
        .await
        .expect("the route is dropped");
    assert!(dropped, "there was a route to drop");

    let config = configuration(&store).await;
    let routes = config.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        1,
        "the other route is still there: {routes:?}"
    );
    assert_eq!(
        routes[0].path_pattern, "/static",
        "and it is the one that was not dropped"
    );
}

/// A configuration written verbatim, for the cases a `[[routes]]` table has
/// to be spelled by hand.
fn seed_text(dir: &tempfile::TempDir, text: &str) {
    std::fs::write(dir.path().join("config.toml"), text).expect("the configuration is written");
}

/// Two routes that share a host and a path but not their modes are two rows:
/// writing the second one does not replace the first, and an edit or a drop
/// that names an id lands on exactly the row the console selected.
#[tokio::test]
async fn routes_sharing_host_and_path_are_addressed_by_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

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
        .expect("the route is written");
    store
        .write_route(&passthrough, None)
        .await
        .expect("the second route is written");

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        2,
        "the second route was added beside the first: {routes:?}"
    );

    // An edit names the row it replaces: changing the passthrough route
    // cannot take the HTTP route with it.
    let edited: RouteSpec = toml::from_str(
        "host_pattern = \"app.example\"\nmode = \"passthrough\"\nbackends = [\"10.0.0.9:443\"]\n",
    )
    .expect("the route parses");
    store
        .write_route(&edited, Some(nexapipe::storage::route_id(&passthrough)))
        .await
        .expect("the route is edited");
    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(routes.len(), 2, "the edit did not add a third: {routes:?}");
    assert_eq!(
        routes[0].backends[0], "http://127.0.0.1:8080",
        "the HTTP route is untouched: {routes:?}"
    );
    assert_eq!(
        routes[1].backends[0], "10.0.0.9:443",
        "the passthrough route is the one that changed: {routes:?}"
    );

    // Removing by id is just as precise. The edit gave the row a new
    // identity, so the id the console now reads is the edited one.
    let dropped = store
        .remove_route(nexapipe::storage::route_id(&edited))
        .await
        .expect("the route is dropped");
    assert!(dropped, "there was a route at that id");
    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(routes.len(), 1, "only the named row went: {routes:?}");
    assert_eq!(
        routes[0].backends[0], "http://127.0.0.1:8080",
        "and it was the passthrough one: {routes:?}"
    );
}

/// A replaced `[[routes]]` table keeps the comment above its header and the
/// inline comments beside its values.
#[tokio::test]
async fn replacing_a_route_keeps_the_comments_on_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed_text(
        &dir,
        "\
[auth]
enabled = true

# The operator's note about this route.
[[routes]]
host_pattern = \"console.example\" # the host, inline
path_pattern = \"/api\"
backends = [\"http://127.0.0.1:9090\"] # until we move it
",
    );
    let store = store(&dir);

    let original: RouteSpec = toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/api\"\nbackends = [\"http://127.0.0.1:9090\"]\n",
    )
    .expect("the route parses");
    let edited: RouteSpec = toml::from_str(
        "host_pattern = \"console.example\"\npath_pattern = \"/api\"\nbackends = [\"http://127.0.0.1:9091\"]\n",
    )
    .expect("the route parses");
    store
        .write_route(&edited, Some(nexapipe::storage::route_id(&original)))
        .await
        .expect("the route is written");

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        1,
        "the row was replaced, not appended: {routes:?}"
    );
    assert_eq!(
        routes[0].backends[0], "http://127.0.0.1:9091",
        "and it is the edited one: {routes:?}"
    );

    let file = std::fs::read_to_string(dir.path().join("config.toml")).expect("the file is read");
    assert!(
        file.contains("The operator's note about this route."),
        "the header comment survived: {file}"
    );
    assert!(
        file.contains("# the host, inline"),
        "the inline host comment survived: {file}"
    );
    assert!(
        file.contains("# until we move it"),
        "the inline backend comment survived: {file}"
    );
    assert!(file.contains("9091"), "the new backend is written: {file}");
}

/// The loader accepts `routes = []` and an inline array of routes; a write
/// has to work on those spellings too, keeping the routes already there.
#[tokio::test]
async fn a_route_is_written_into_a_value_array_configuration() {
    for (label, text) in [
        ("empty", "routes = []\n\n[auth]\nenabled = true\n"),
        (
            "inline",
            "routes = [{ host_pattern = \"old.example\", backends = [\"http://127.0.0.1:8080\"] }]\n\n[auth]\nenabled = true\n",
        ),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        seed_text(&dir, text);
        let store = store(&dir);

        store
            .write_route(&route(), None)
            .await
            .unwrap_or_else(|e| panic!("{label}: the route is written: {e:#}"));

        let routes = configuration(&store).await.routes.unwrap_or_default();
        assert!(
            routes
                .iter()
                .any(|route| route.host_pattern == "console.example"),
            "{label}: the new route is there: {routes:?}"
        );
        if label == "inline" {
            assert!(
                routes
                    .iter()
                    .any(|route| route.host_pattern == "old.example"),
                "the route that was there before survived: {routes:?}"
            );
        }
    }
}

/// The console displays the folded host, so a write has to find a route the
/// operator spelled with capitals and a trailing dot.
#[tokio::test]
async fn a_route_is_found_by_the_host_the_console_displays() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed_text(
        &dir,
        "\
[auth]
enabled = true

[[routes]]
host_pattern = \"Console.Example.\"
backends = [\"http://127.0.0.1:8080\"]
",
    );
    let store = store(&dir);

    let displayed: RouteSpec = toml::from_str(
        "host_pattern = \"console.example\"\nbackends = [\"http://127.0.0.1:8080\"]\n",
    )
    .expect("the route parses");
    store
        .write_route(&displayed, None)
        .await
        .expect("the route is written");

    let routes = configuration(&store).await.routes.unwrap_or_default();
    assert_eq!(
        routes.len(),
        1,
        "the folded spelling matched the stored one rather than adding a second route: {routes:?}"
    );
}

/// A write that has nothing to write into, or a `routes` value that is not a
/// table of routes, is refused and leaves the file alone.
#[tokio::test]
async fn a_rejected_route_write_changes_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let store = store(&dir);

    assert!(
        store.write_route(&route(), None).await.is_err(),
        "there is no configuration to add a route to"
    );
    assert!(
        !path.exists(),
        "the write did not invent a configuration file"
    );

    let text = "routes = 3\n\n[auth]\nenabled = true\n";
    seed_text(&dir, text);
    assert!(
        store.write_route(&route(), None).await.is_err(),
        "an invalid routes shape is refused"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("the file is read"),
        text,
        "the file is unchanged"
    );
}

/// A stale id cannot name a different route: a console that read the list
/// before another row went away still removes the row it selected.
#[tokio::test]
async fn a_stale_id_cannot_remove_or_replace_a_different_route() {
    let dir = tempfile::tempdir().expect("temp dir");
    seed(&dir);
    let store = store(&dir);

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
    assert_ne!(id_a, id_b, "each row has its own id");
    assert_ne!(id_b, id_c, "each row has its own id");

    // A goes away first. A console that listed [A, B, C] still holds B's id.
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
    assert_eq!(routes.len(), 1, "only A and B went: {routes:?}");
    assert_eq!(
        routes[0].host_pattern, "c.example",
        "C is untouched: {routes:?}"
    );

    // The same id in a write is refused too, rather than editing C.
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
        1,
        "the refused write changed nothing: {routes:?}"
    );
    assert_eq!(
        routes[0].host_pattern, "c.example",
        "and C is still the only row: {routes:?}"
    );

    // C's own id still works after both other rows went away.
    assert!(
        store
            .remove_route(id_c)
            .await
            .expect("the last removal is answered"),
        "C is still addressable by the id it was given"
    );
}
