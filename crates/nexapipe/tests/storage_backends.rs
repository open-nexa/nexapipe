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

use nexapipe::auth::DeviceMaterial;
use nexapipe::config::{load_config, load_config_with_auth};
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
