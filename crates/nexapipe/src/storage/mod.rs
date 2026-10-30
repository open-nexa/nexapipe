//! Where the proxy keeps what it keeps.
//!
//! The configuration, the runtime counters and the admin token are three
//! things that outlive a request and outlive the process, and until now they
//! were three files at three paths, read and written by name from wherever
//! needed. That is fine for one store and awkward for two: a deployment that
//! keeps its configuration in a database has no file to read, and every reader
//! that names a path is a reader that cannot be moved.
//!
//! So the paths move behind a trait. [`Storage`] says what a store has to be
//! able to do — read the configuration, write a client's credential, count a
//! lockout, hand out the admin token — and a backend says how it does it.
//! [`file::FileStorage`] is the one that exists today, and it behaves exactly
//! as the code behaved before: the same files, the same locks, the same
//! messages.
//!
//! # What the interface hands out
//!
//! The configuration is handed out as **text**, not as a parsed tree and not
//! as a struct. The text is what the file holds, the parse is what the schema
//! does with it, and the schema is the one place a key is named — so a store
//! that keeps its configuration in rows still answers with the same TOML the
//! file would have held, and every reader, every error message and every
//! validation runs exactly once, in one place.
//!
//! The credentials are not handed out as text: a client's secret, a device's
//! key and the admin token are values, and they travel as the zeroizing
//! types they have always travelled as.
//!
//! # What a write means
//!
//! A write is **by entity**, never by document. The reason is the comment in
//! the file an operator wrote: a write that re-rendered the whole
//! configuration would take their comments with it, and a write that replaced
//! the whole document would take a route somebody added while the server was
//! running with it. So the interface says "this client's secret" and "this
//! device's credential", and the backend decides what that means in its own
//! terms: an edit of the file for the file backend, an update of a row for a
//! database one.
//!
//! # Why the interface is asynchronous
//!
//! Because a database is. The file backend does its work in a blocking task
//! and answers immediately; a backend that talks to a server answers when the
//! server answers, and the interface that cannot express "later" would have
//! to be rewritten before a second backend could exist at all. The price is
//! that the interface hands out boxed futures rather than `async fn`s — a
//! trait whose methods are `async fn` cannot be held behind a `dyn`, and the
//! backend is chosen at run time.

pub mod file;
pub mod open;

pub use file::FileStorage;
pub use open::{choose, open};

use crate::auth::state::RuntimeState;
use crate::config::ClientSecretWrite;

use futures_util::future::BoxFuture;

use nexapipe_proto::secret::SecretString;

use std::path::Path;
use std::time::SystemTime;

/// What a store is, for the log line that says which one is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// The configuration, the counters and the token as files beside each other.
    Toml,
    /// The same three, in a SQLite database.
    Sqlite,
    /// The same three, in a PostgreSQL database.
    Postgres,
}

impl StorageKind {
    /// The spelling used in the log.
    pub fn name(self) -> &'static str {
        match self {
            StorageKind::Toml => "toml",
            StorageKind::Sqlite => "sqlite",
            StorageKind::Postgres => "postgres",
        }
    }

    /// The spelling an operator writes on the command line or in the
    /// environment.
    ///
    /// Refused rather than guessed: a store that is not the one the operator
    /// asked for is a store that keeps the configuration somewhere they are not
    /// looking.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "toml" | "file" => Ok(StorageKind::Toml),
            "sqlite" => Ok(StorageKind::Sqlite),
            "postgres" | "postgresql" | "pg" => Ok(StorageKind::Postgres),
            other => anyhow::bail!(
                "{other:?} is not a storage backend; expected \"toml\", \"sqlite\" or \"postgres\""
            ),
        }
    }
}

impl std::str::FromStr for StorageKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// A value that changes whenever the configuration changes.
///
/// What it is depends on the store: a file is stamped by its modification
/// time and its length, a row by a counter the store bumps on every write.
/// The watcher compares two of them and reloads when they differ, so all it
/// asks of a stamp is that it moves when the configuration does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamp {
    /// A file: when it was last modified, and how long it is.
    ///
    /// The length is here as well as the time, for the two reasons the
    /// watcher's own stamp gives: a file written twice inside one second has
    /// the same time and a different length, and a file that replaced another
    /// one can be older.
    File { modified: SystemTime, len: u64 },
}

impl Stamp {
    /// The stamp of a store that has not been loaded yet.
    ///
    /// A file that is not there is not a file that is empty: it is a file
    /// that has not been read, and the first tick reads it whatever its time
    /// would have been.
    pub fn unknown() -> Self {
        Stamp::File {
            modified: SystemTime::UNIX_EPOCH,
            len: 0,
        }
    }
}

/// The credential a device is issued.
///
/// **Owned**, and the secret half zeroizing: the write path copies it into a
/// document, and a copy that does not wipe itself is a second seed in the heap
/// for as long as the allocator keeps the buffer.
///
/// The public half of a key pair is not a secret — it is public by definition —
/// so it travels as the plain string it is.
#[derive(Clone)]
pub enum DeviceCredential {
    /// A Base32 TOTP seed the device shares with the server.
    Secret(SecretString),
    /// A device's Ed25519 public key, hex.
    PublicKey(String),
}

impl From<crate::auth::DeviceMaterial<'_>> for DeviceCredential {
    fn from(material: crate::auth::DeviceMaterial<'_>) -> Self {
        match material {
            crate::auth::DeviceMaterial::Secret(secret) => {
                DeviceCredential::Secret(SecretString::new(secret.to_string()))
            }
            crate::auth::DeviceMaterial::PublicKey(key) => {
                DeviceCredential::PublicKey(key.to_string())
            }
        }
    }
}

/// The endpoint's identity, generated and written back when the configuration
/// holds none.
///
/// The key is the endpoint's identity: it is written once, on the first start
/// that finds none, and the Node ID it decides has to survive every restart
/// after that.
pub async fn ensure_endpoint_identity(
    storage: &dyn Storage,
    config: &crate::config::ProxyConfig,
) -> anyhow::Result<crate::config::EndpointIdentity> {
    use crate::config::{IdentityAction, identity_action, identity_into_file};

    match identity_action(config, storage.base_dir(), &storage.describe())? {
        IdentityAction::Configured(key) => Ok(crate::config::EndpointIdentity::Configured(key)),
        IdentityAction::Ephemeral => Ok(crate::config::EndpointIdentity::Ephemeral(
            SecretString::new(crate::config::generate_secret_key_hex()),
        )),
        IdentityAction::IntoFile(full) => Ok(identity_into_file(&full)),
        IdentityAction::IntoConfig => {
            // The key is zeroizing from the moment it exists. A plain `String`
            // would leave the hex in the heap on the path where the write
            // failed, and the clone the write needed would leave a second copy
            // there on the path where it succeeded.
            let hex = SecretString::new(crate::config::generate_secret_key_hex());
            match storage.write_endpoint_key(&hex).await {
                Ok(()) => {
                    tracing::info!(
                        "Generated an endpoint identity and saved it in {} as [iroh] secret_key; \
                         the Node ID is now stable across restarts",
                        storage.describe()
                    );
                    Ok(crate::config::EndpointIdentity::Generated(hex))
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not write an endpoint identity to {} ({e:#}); starting on a \
                         throwaway one, so the Node ID will be different after the next restart",
                        storage.describe()
                    );
                    Ok(crate::config::EndpointIdentity::Ephemeral(
                        SecretString::new(crate::config::generate_secret_key_hex()),
                    ))
                }
            }
        }
    }
}

/// A store the proxy keeps its configuration and its runtime state in.
///
/// The three documents it holds are the ones the server has always kept: the
/// configuration, the runtime counters, and the admin token. They are named
/// here rather than being paths, because a store that has no files has no
/// paths either.
pub trait Storage: Send + Sync + 'static {
    /// What this store is.
    fn kind(&self) -> StorageKind;

    /// What this store is called, for the messages that name it.
    ///
    /// A file store names the file it reads; a database store names the
    /// database. The message an operator reads when the configuration is not
    /// there says which one, because "not found" without a name is a question
    /// the operator has to answer by guessing.
    ///
    /// This is the **configuration**. The two documents the process writes
    /// beside it are named by [`Storage::describe_state`] and
    /// [`Storage::describe_token`], because a message about one of them has
    /// to name that one: an operator sent to the configuration file to fix a
    /// counter that lives in another file finds nothing there.
    fn describe(&self) -> String;

    /// What this store calls the document the runtime counters are kept in.
    ///
    /// The counters — how many times a client got it wrong, until when it is
    /// locked out, when it was last seen — are kept beside the configuration
    /// rather than in it, so the file that holds them is not the file the
    /// operator edits.
    fn describe_state(&self) -> String;

    /// What this store calls the document the admin token is kept in.
    ///
    /// The token is one opaque value in a document of its own, and the message
    /// that says where to find it has to name the document it is in rather
    /// than the configuration next to it.
    fn describe_token(&self) -> String;

    /// The directory a relative path in the configuration is resolved against.
    ///
    /// `None` for a store that has no directory: a database has no file next
    /// to it, so a `secret_key_file = "keys/iroh"` in it has nothing to be
    /// relative to and is refused rather than resolved against the working
    /// directory, which would be a guess.
    fn base_dir(&self) -> Option<&Path>;

    /// The file whose permissions guard the credentials, when there is one.
    ///
    /// A database has no file and therefore no mode to check: the perimeter
    /// there is the database's own access control, and there is nothing for
    /// the warning about a readable file to say.
    fn credential_file(&self) -> Option<&Path>;

    /// A value that changes whenever the configuration changes.
    fn stamp(&self) -> BoxFuture<'_, anyhow::Result<Stamp>>;

    /// The configuration, as the text it is written in.
    ///
    /// `None` when the store holds none — a first start, before the default
    /// configuration has been written.
    ///
    /// A [`SecretString`]: the text can hold the 2FA seeds in the clear, and
    /// the copy the reader parses is not the copy that should be left in the
    /// heap.
    fn config(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>>;

    /// Writes the default configuration when the store holds none.
    ///
    /// `template` is the TOML a first start is given, comments and all. A
    /// store that keeps its configuration as text writes it as it is; a store
    /// that keeps it as rows reads it and lays it out.
    ///
    /// Whether one was written.
    fn ensure_config(&self, template: &str) -> BoxFuture<'_, anyhow::Result<bool>>;

    /// Writes a client's secret, replacing an existing one only with `force`.
    ///
    /// A device that already imported the old secret stops authenticating the
    /// instant it changes, so a caller keeps the existing secret unless it is
    /// told otherwise.
    fn write_client_secret<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>>;

    /// Records a one-time enrollment token for a client.
    ///
    /// Any token already outstanding is replaced, which is how an invitation
    /// that never arrived gets revoked.
    fn write_pending_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Spends the token: writes the issued secret and drops the token, so the
    /// same link cannot enroll twice.
    fn complete_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Spends the token for one named device: writes that device's own
    /// credential and drops the token, leaving the client's secret as it was.
    fn complete_device_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Writes one device's credential — a TOTP secret or a public key.
    ///
    /// The client's own secret is left alone: it is the credential of the
    /// device that names none.
    fn write_device_credential<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>>;

    /// Drops one device's credential, leaving the client itself.
    ///
    /// A revoke is a delete and not a rotation: a deleted entry is what the
    /// handshake reads as "this device has no credential".
    fn remove_device<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Drops a client and every device under it.
    fn remove_client<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Writes the endpoint's private key.
    ///
    /// The key is the endpoint's identity: it is written once, on the first
    /// start that finds none, and the Node ID it decides has to survive every
    /// restart after that.
    fn write_endpoint_key<'a>(&'a self, key: &'a SecretString)
    -> BoxFuture<'a, anyhow::Result<()>>;

    /// The runtime counters: how many times a client got it wrong, until when
    /// it is locked out, when it was last seen.
    ///
    /// A store that holds none has counted nothing yet, which is a state, not
    /// an error.
    fn state(&self) -> BoxFuture<'_, anyhow::Result<RuntimeState>>;

    /// Writes the runtime counters.
    fn put_state<'a>(&'a self, state: &'a RuntimeState) -> BoxFuture<'a, anyhow::Result<()>>;

    /// The admin token, when the store holds one.
    fn admin_token(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>>;

    /// Writes the admin token.
    ///
    /// Refuses to replace one that is already there: whoever is using it would
    /// be locked out without being told.
    fn put_admin_token<'a>(&'a self, token: &'a SecretString) -> BoxFuture<'a, anyhow::Result<()>>;
}
