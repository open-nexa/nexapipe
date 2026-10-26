//! The file backend: the configuration, the counters and the token as files.
//!
//! This is the store the proxy has always used, and it behaves the way it
//! always has: the configuration is a TOML file, the counters are a file
//! beside it, the token is a file beside that, and every write of the
//! configuration goes through a lock and lands through a temporary file and a
//! rename.
//!
//! # What the backend does with a write
//!
//! The document is **edited**, not re-rendered. The configuration is a file an
//! operator wrote, and a comment in it is a comment they wrote: a write that
//! replaced the document would take the comments with it, and a write that
//! re-serialized a struct would take the layout with it. So every writer here
//! opens the document, changes the one thing it is about, and puts the rest
//! back exactly as it was.
//!
//! # What the backend does with a read
//!
//! It hands out the text, wrapped in the zeroizing type the credentials in it
//! deserve. The parse is not this backend's business: the schema is the one
//! place a key is named, and it is the same schema whichever store the text
//! came from.

use crate::auth::state::RuntimeState;
use crate::config::ClientSecretWrite;

use futures_util::future::BoxFuture;

use nexapipe_proto::secret::SecretString;

use std::fs;
use std::io::Write;

use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use super::{DeviceCredential, Stamp, Storage, StorageKind};

use crate::toml_zeroize::zeroize_document;

/// The store that keeps everything in files beside each other.
#[derive(Debug, Clone)]
pub struct FileStorage {
    /// The configuration file.
    config_path: PathBuf,
    /// The counters, named after the configuration file.
    state_path: PathBuf,
    /// The admin token, beside the configuration file.
    token_path: PathBuf,
}

impl FileStorage {
    /// The store for the configuration at `config_path`.
    ///
    /// The other two paths are derived from it, the way they have always been:
    /// the counters are named after the configuration (`config.toml` puts its
    /// counters in `config.state.toml`), and the token is a sibling of it
    /// (`config.toml.admin-token`).
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        let config_path = config_path.into();
        let as_text = config_path.to_string_lossy().into_owned();
        let state_path = crate::auth::state::path_for(&as_text);
        let token_path = PathBuf::from(crate::admin::token::token_file_path(&as_text));
        Self {
            config_path,
            state_path,
            token_path,
        }
    }

    /// The configuration file this store reads and writes.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// The file the counters are kept in.
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// The file the admin token is kept in.
    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    // ---- The work, synchronously ----
    //
    // The trait's methods are asynchronous because a database is; the work
    // behind them is not, and it is written here once, synchronously, so that
    // the path-based API this crate still offers — the one the CLI and the
    // tests use — is the same code and not a second implementation of it.

    /// The configuration's text, or `None` when there is no file.
    pub fn config_text(&self) -> anyhow::Result<Option<SecretString>> {
        let path = &self.config_path;
        match fs::read_to_string(path) {
            Ok(content) => Ok(Some(SecretString::new(content))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to read config file: {e}")),
        }
    }

    /// Writes the default configuration when there is none.
    pub fn ensure_config(&self, template: &str) -> anyhow::Result<bool> {
        let path = &self.config_path;
        if path.exists() {
            return Ok(false);
        }

        // `with_lock` opens `<path>.lock` and that fails when the parent
        // directory does not yet exist, so the directory is created before the
        // lock is taken. The lock file is otherwise useless: every write of
        // this path goes through this function and through the other writers
        // in this crate, all of which take the same lock. Idempotent — running
        // it on a directory that already exists is a no-op.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", parent.display()))?;
        }

        with_lock(path, || {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(template.as_bytes())
                        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
                    file.sync_all()
                        .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", path.display()))?;
                    Ok(true)
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A non-locking writer (operator with an editor, a sibling
                    // tool) created the file between our existence check and
                    // our create. Preserve whatever they wrote.
                    Ok(false)
                }
                Err(e) => Err(anyhow::anyhow!("cannot create {}: {e}", path.display())),
            }
        })
    }

    /// Writes a client's secret.
    pub fn write_client_secret(
        &self,
        client_id: &str,
        secret: &SecretString,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "secret not written")?;

            let auth = sub_table(doc.as_table_mut(), "auth", &path)?;
            let clients = sub_table(auth, "clients", &path)?;
            let client = sub_table(clients, client_id, &path)?;

            let replaced = client.contains_key("secret");
            if replaced && !force {
                anyhow::bail!(
                    "client \"{client_id}\" already has a secret in {}",
                    path.display()
                );
            }
            client.insert("secret", toml_edit::value(secret.expose_secret().as_str()));

            write_document(&path, doc)?;

            Ok(if replaced {
                ClientSecretWrite::Replaced
            } else {
                ClientSecretWrite::Added
            })
        })
    }

    /// Records a one-time enrollment token for a client.
    pub fn write_pending_enrollment(
        &self,
        client_id: &str,
        token: &SecretString,
    ) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "token not written")?;

            let auth = sub_table(doc.as_table_mut(), "auth", &path)?;
            let clients = sub_table(auth, "clients", &path)?;
            let client = sub_table(clients, client_id, &path)?;
            if !client.contains_key("secret") {
                anyhow::bail!(
                    "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {}; \
                     run --generate-2fa {client_id} first",
                    path.display()
                );
            }

            client.insert(
                "pending_enrollment",
                toml_edit::value(token.expose_secret().as_str()),
            );

            write_document(&path, doc)
        })
    }

    /// Spends the token: writes the issued secret and drops the token.
    pub fn complete_enrollment(
        &self,
        client_id: &str,
        secret: &SecretString,
    ) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "enrollment not saved")?;

            let auth = sub_table(doc.as_table_mut(), "auth", &path)?;
            let clients = sub_table(auth, "clients", &path)?;
            let client = sub_table(clients, client_id, &path)?;

            client.insert("secret", toml_edit::value(secret.expose_secret().as_str()));
            client.remove("pending_enrollment");

            write_document(&path, doc)
        })
    }

    /// Spends the token for one named device.
    pub fn complete_device_enrollment(
        &self,
        client_id: &str,
        device: &str,
        credential: DeviceCredential,
    ) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "enrollment not saved")?;

            let auth = sub_table(doc.as_table_mut(), "auth", &path)?;
            let clients = sub_table(auth, "clients", &path)?;
            let client = sub_table(clients, client_id, &path)?;

            let devices = device_table(client, client_id, &path)?;
            devices.insert(device, device_entry(credential, &path)?);

            client.remove("pending_enrollment");

            write_document(&path, doc)
        })
    }

    /// Writes one device's credential — a TOTP secret or a public key.
    pub fn write_device_credential(
        &self,
        client_id: &str,
        device: &str,
        credential: DeviceCredential,
        force: bool,
    ) -> anyhow::Result<ClientSecretWrite> {
        // The name becomes a key in this file and the subject of every log line
        // about the device, so it is checked here rather than on its way into
        // either. An empty one is not a name: the unnamed device is what the
        // client's own `secret` is for.
        if !crate::auth::is_presentable_device_id(device) {
            anyhow::bail!(
                "device name {device:?} is printable ASCII of at most {} characters — it is a key \
                 in {} and the subject of every log line about it",
                crate::auth::MAX_DEVICE_ID_LEN,
                self.config_path.display()
            );
        }

        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "secret not written")?;

            let auth = sub_table(doc.as_table_mut(), "auth", &path)?;
            let clients = sub_table(auth, "clients", &path)?;
            let client = sub_table(clients, client_id, &path)?;
            if !client.contains_key("secret") {
                anyhow::bail!(
                    "client \"{client_id}\" has no [auth.clients.{client_id}] secret in {}; \
                     run --generate-2fa {client_id} first",
                    path.display()
                );
            }

            let devices = device_table(client, client_id, &path)?;
            let replaced = devices.contains_key(device);
            if replaced && !force {
                anyhow::bail!(
                    "device \"{device}\" of client \"{client_id}\" already has a credential in {}",
                    path.display()
                );
            }

            devices.insert(device, device_entry(credential, &path)?);

            write_document(&path, doc)?;

            Ok(if replaced {
                ClientSecretWrite::Replaced
            } else {
                ClientSecretWrite::Added
            })
        })
    }

    /// Drops one device's credential.
    pub fn remove_device(&self, client_id: &str, device: &str) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "nothing revoked")?;

            // Not `sub_table`: revoking must never create the thing it is about
            // to delete, and an absent section is the operator naming
            // something that is not there, which is worth saying.
            let clients = auth_clients(doc.as_table_mut());
            let Some(clients) = clients else {
                anyhow::bail!(
                    "{} has no [auth.clients] table, nothing revoked",
                    path.display()
                );
            };
            let Some(client) = clients
                .get_mut(client_id)
                .and_then(|item| item.as_table_like_mut())
            else {
                anyhow::bail!(
                    "client \"{client_id}\" has no [auth.clients.{client_id}] section in {}, \
                     nothing revoked",
                    path.display()
                );
            };
            let Some(devices) = client
                .get_mut("devices")
                .and_then(|item| item.as_table_like_mut())
            else {
                anyhow::bail!(
                    "client \"{client_id}\" has no devices in {}, nothing revoked",
                    path.display()
                );
            };
            if devices.remove(device).is_none() {
                anyhow::bail!(
                    "client \"{client_id}\" has no device \"{device}\" in {}; its devices are {}",
                    path.display(),
                    device_names(devices)
                );
            }

            write_document(&path, doc)
        })
    }

    /// Drops a client and every device under it.
    pub fn remove_client(&self, client_id: &str) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "nothing revoked")?;

            let clients = auth_clients(doc.as_table_mut());
            let Some(clients) = clients else {
                anyhow::bail!(
                    "{} has no [auth.clients] table, nothing revoked",
                    path.display()
                );
            };
            if clients.remove(client_id).is_none() {
                anyhow::bail!(
                    "client \"{client_id}\" has no [auth.clients.{client_id}] section in {}, \
                     nothing revoked",
                    path.display()
                );
            }

            write_document(&path, doc)
        })
    }

    /// Writes the endpoint's private key into `[iroh]`.
    pub fn write_endpoint_key(&self, key: &SecretString) -> anyhow::Result<()> {
        let path = self.config_path.clone();
        with_lock(&path, || {
            let mut doc = read_document(&path, "secret_key not written")?;

            // `sub_table` rather than `entry("iroh")`: a config with no
            // `[iroh]` section gains an implicit one, and the section stays
            // out of the output until it holds something.
            let iroh_table = sub_table(doc.as_table_mut(), "iroh", &path).map_err(|_| {
                anyhow::anyhow!(
                    "{}: [iroh] is not a table, secret_key not written",
                    path.display()
                )
            })?;
            iroh_table.insert("secret_key", toml_edit::value(key.expose_secret().as_str()));

            write_document(&path, doc)
        })
    }

    /// The counters, as they are on disk.
    pub fn state(&self) -> anyhow::Result<RuntimeState> {
        crate::auth::state::load(&self.state_path)
    }

    /// Writes the counters.
    ///
    /// Under the lock of the state file, not of the configuration: the two are
    /// separate documents with separate writers, and a counter write must not
    /// wait for a configuration edit.
    pub fn put_state(&self, state: &RuntimeState) -> anyhow::Result<()> {
        let path = self.state_path.clone();
        with_lock(&path, || crate::auth::state::save(&self.state_path, state))
    }

    /// The admin token, when there is one.
    pub fn admin_token(&self) -> anyhow::Result<Option<SecretString>> {
        Ok(crate::admin::token::load_existing(
            &self.config_path.to_string_lossy(),
        ))
    }

    /// Writes the admin token, refusing to replace one that is already there.
    pub fn put_admin_token(&self, token: &SecretString) -> anyhow::Result<()> {
        crate::admin::token::write_token(&self.token_path.to_string_lossy(), token)
            .map_err(|reason| anyhow::anyhow!("{reason}"))
    }

    /// What the configuration file looks like right now.
    pub fn stamp(&self) -> anyhow::Result<Stamp> {
        match fs::metadata(&self.config_path) {
            Ok(metadata) => Ok(Stamp::File {
                modified: metadata
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                len: metadata.len(),
            }),
            // A file that is not there yet is a file that has not been loaded:
            // the first tick loads it, whatever its time says.
            Err(_) => Ok(Stamp::File {
                modified: std::time::SystemTime::UNIX_EPOCH,
                len: 0,
            }),
        }
    }
}

impl Storage for FileStorage {
    fn kind(&self) -> StorageKind {
        StorageKind::Toml
    }

    fn describe(&self) -> String {
        self.config_path.display().to_string()
    }

    fn base_dir(&self) -> Option<&Path> {
        self.config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    }

    fn credential_file(&self) -> Option<&Path> {
        Some(&self.config_path)
    }

    fn stamp(&self) -> BoxFuture<'_, anyhow::Result<Stamp>> {
        let this = self.clone();
        Box::pin(async move { blocking(move || this.stamp()).await })
    }

    fn config(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>> {
        let this = self.clone();
        Box::pin(async move { blocking(move || this.config_text()).await })
    }

    fn ensure_config(&self, template: &str) -> BoxFuture<'_, anyhow::Result<bool>> {
        let this = self.clone();
        let template = template.to_string();
        Box::pin(async move { blocking(move || this.ensure_config(&template)).await })
    }

    fn write_client_secret<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let secret = secret.clone();
        Box::pin(async move {
            blocking(move || this.write_client_secret(&client_id, &secret, force)).await
        })
    }

    fn write_pending_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let token = token.clone();
        Box::pin(async move {
            blocking(move || this.write_pending_enrollment(&client_id, &token)).await
        })
    }

    fn complete_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        secret: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let secret = secret.clone();
        Box::pin(
            async move { blocking(move || this.complete_enrollment(&client_id, &secret)).await },
        )
    }

    fn complete_device_enrollment<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let device = device.to_string();
        Box::pin(async move {
            blocking(move || this.complete_device_enrollment(&client_id, &device, credential)).await
        })
    }

    fn write_device_credential<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
        credential: DeviceCredential,
        force: bool,
    ) -> BoxFuture<'a, anyhow::Result<ClientSecretWrite>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let device = device.to_string();
        Box::pin(async move {
            blocking(move || this.write_device_credential(&client_id, &device, credential, force))
                .await
        })
    }

    fn remove_device<'a>(
        &'a self,
        client_id: &'a str,
        device: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        let device = device.to_string();
        Box::pin(async move { blocking(move || this.remove_device(&client_id, &device)).await })
    }

    fn remove_client<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let client_id = client_id.to_string();
        Box::pin(async move { blocking(move || this.remove_client(&client_id)).await })
    }

    fn write_endpoint_key<'a>(
        &'a self,
        key: &'a SecretString,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let key = key.clone();
        Box::pin(async move { blocking(move || this.write_endpoint_key(&key)).await })
    }

    fn state(&self) -> BoxFuture<'_, anyhow::Result<RuntimeState>> {
        let this = self.clone();
        Box::pin(async move { blocking(move || this.state()).await })
    }

    fn put_state<'a>(&'a self, state: &'a RuntimeState) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let state = state.clone();
        Box::pin(async move { blocking(move || this.put_state(&state)).await })
    }

    fn admin_token(&self) -> BoxFuture<'_, anyhow::Result<Option<SecretString>>> {
        let this = self.clone();
        Box::pin(async move { blocking(move || this.admin_token()).await })
    }

    fn put_admin_token<'a>(&'a self, token: &'a SecretString) -> BoxFuture<'a, anyhow::Result<()>> {
        let this = self.clone();
        let token = token.clone();
        Box::pin(async move { blocking(move || this.put_admin_token(&token)).await })
    }
}

/// Runs the file backend's work on a blocking thread.
///
/// A file read or a file write blocks: run on a runtime thread, it parks every
/// other task behind a disk that is busy, and the proxy is a proxy first and a
/// config reader second. The thread is the one built for work like this, and
/// the answer comes back the same way.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| anyhow::anyhow!("the storage task did not run: {e}"))?
}

/// Reads the config file into a document, with the text it was read from/// wiped when it goes out of scope.
///
/// The file can hold the 2FA seeds in the clear, so its text is a copy of a
/// credential: it is read into a buffer that is zeroed as soon as the
/// document it was parsed into exists. `what` says what was not written, for
/// the error a malformed file produces.
pub(crate) fn read_document(path: &Path, what: &str) -> anyhow::Result<toml_edit::DocumentMut> {
    let content = SecretString::new(
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?,
    );
    content
        .expose_secret()
        .parse()
        .map_err(|e| anyhow::anyhow!("{} is not valid TOML, {what} ({e})", path.display()))
}

/// Writes a document to the config, and zeroes the copies of it that the
/// write needed.
///
/// The document holds the 2FA seeds in the clear, and so does the text it is
/// rendered into: a copy that would otherwise outlive the write by however
/// long the allocator keeps the buffer. The document is zeroed too, so the
/// tree it was parsed into does not keep them either.
///
/// What is left is one copy of every string on the write path: the raw text
/// `toml_edit` keeps for each value it parsed, next to the decoded value
/// above. It lives in a private `RawString` this crate cannot reach, and
/// closing that would take `unsafe` or a fork of the library. See
/// [`crate::toml_zeroize`].
pub(crate) fn write_document(
    path: &Path,
    mut document: toml_edit::DocumentMut,
) -> anyhow::Result<()> {
    let mut text = document.to_string();
    let result = write_file(path, &text);
    text.zeroize();
    zeroize_document(&mut document);
    result
}

/// Replaces the file at `path` with `contents` in one step.
///
/// Written next to the target and renamed over it, rather than truncated in
/// place: a process killed in the middle of `fs::write` leaves a short file,
/// and a short config is one the proxy cannot start from again. A rename is a
/// single directory entry swap, so anything reading the file sees either the
/// old contents or the new ones.
///
/// The replacement is created `0600`, because what it holds is TOTP secrets and
/// enrollment tokens: a new file takes the umask, and the file it replaces may
/// have been wider.
///
/// The mode is part of the call that creates the file, not a `chmod` after the
/// write. Tightening it afterwards leaves the secrets on disk at `0644` for as
/// long as the write takes, and `write_all` plus `sync_all` make sure they
/// really are on disk in that window — a file only its owner can read is what
/// the write is for, and the seconds it spends at the umask's width would
/// undo it.
///
/// Crate-private on purpose: the text of a config is a copy of its
/// credentials, so every write of one goes through [`write_document`], which
/// zeroes the text it renders and the document it came from. A caller that
/// reached this function directly would skip that, and the seeds would sit in
/// the heap for as long as the allocator kept the buffer.
pub(crate) fn write_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let target = path;
    let directory = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    // The pid alone was not enough to keep two writers apart: pids are reused,
    // and a pid that comes back while an older temp file of the same name is
    // still there would have the new write truncate a file it did not create.
    // The random half makes the name this process's own regardless.
    let temp = directory.join(format!(
        ".{name}.{}.{:x}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));

    let write = || -> anyhow::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", temp.display()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", temp.display()))?;
        Ok(())
    };

    if let Err(e) = write() {
        let _ = fs::remove_file(&temp);
        return Err(e);
    }

    // Renaming over a symlink puts a regular file where the link was: the
    // indirection an operator set up is gone, the file the link pointed at
    // keeps its old contents, and every command involved still reports
    // success. A config reached through a link is a normal way to keep one
    // file in version control or out of a container image, so the rename is
    // aimed at what the link resolves to instead — the real file is replaced
    // and the link stays.
    //
    // `Path::join` with an absolute path yields that path, so a link pointing
    // outside this directory needs no special case; a relative one resolves
    // against the directory holding the link, which is what the shell does.
    let destination = match fs::read_link(target) {
        Ok(resolved) => directory.join(resolved),
        Err(_) => target.to_path_buf(),
    };

    // A rename cannot replace a file that is itself a mount point, which is
    // what a bind-mounted single config file is. Falling back to writing in
    // place is the lesser evil: it loses the atomicity, not the write.
    if let Err(rename) = fs::rename(&temp, &destination) {
        let _ = fs::remove_file(&temp);

        // Writing in place keeps whatever mode the target already has, so the
        // mode is tightened *before* anything is written: a target that was
        // world-readable would otherwise hold the secrets that way for as long
        // as the write leaves it. A mode that cannot be set is an error rather
        // than something to log past — a config of secrets at 0644 is worse
        // than one that was not written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if target.exists() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|e| {
                    anyhow::anyhow!("cannot set the mode of {}: {e}", target.display())
                })?;
            }
        }

        let written = fs::write(target, contents).map_err(|e| {
            anyhow::anyhow!(
                "cannot write {}: {e} (rename failed: {rename})",
                target.display()
            )
        });

        // Covers a target that did not exist: the write above creates it under
        // the process umask, which is not what a file of secrets should inherit.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if written.is_ok() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|e| {
                    anyhow::anyhow!("cannot set the mode of {}: {e}", target.display())
                })?;
            }
        }

        return written;
    }

    Ok(())
}

/// Runs `work` while holding an exclusive lock on the file at `path`.
///
/// Every read-modify-write of the configuration goes through this.
/// The write itself makes a single write atomic, but it says nothing about two
/// writers that both read first: the second one's write is built from the
/// contents it read before the first one landed, so one of the two edits is
/// lost.
///
/// The lock is advisory: a writer that does not take it still races. That is
/// acceptable, because every writer of this file is this program.
pub fn with_lock<T>(path: &Path, work: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
    let _guard = ConfigLock::acquire(path)?;
    work()
}

/// The lock file sits *beside* the config rather than being the config itself.
///
/// Writes go through [`write_file`], which is a temp file and a rename,
/// and a rename swaps the directory entry for a different inode — so a lock
/// taken on the config path would stay behind on a file that was replaced
/// underneath it, and every writer would hold a different lock. A separate file
/// is never renamed, so it stays the one thing everybody contends for.
struct ConfigLock {
    file: fs::File,
}

impl ConfigLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        // The lock file is the configuration's name with `.lock` after it, so
        // `config.toml` is locked by `config.toml.lock` — the name the file
        // had before this moved.
        let lock_path = PathBuf::from(format!("{}.lock", path.to_string_lossy()));
        let file = fs::OpenOptions::new()
            .create(true)
            // The lock file is a lock, not a document: whatever it already
            // holds is nobody's data, and truncating a file another process may
            // be about to open buys nothing.
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", lock_path.display()))?;

        // Beside a file that holds TOTP secrets, so it is created the way the
        // config itself is checked for: private to its owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                anyhow::anyhow!("cannot set the mode of {}: {e}", lock_path.display())
            })?;
        }

        // `File::lock`, standard since 1.89: `flock(2)` on Unix and
        // `LockFileEx` on Windows, which is the pair writing by hand would have
        // meant two `unsafe` blocks to reach.
        file.lock()
            .map_err(|e| anyhow::anyhow!("cannot lock {}: {e}", lock_path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Released on close regardless; unlocking explicitly keeps the pairing
        // visible, and the error has nowhere to go from a `Drop`.
        let _ = self.file.unlock();
    }
}

/// The `[auth.clients]` table of `doc`, when the document has one.
///
/// Shared by the two revoking writers, which must find the table without ever
/// creating it: a revoke that invented an empty `[auth.clients]` to delete from
/// would leave the file changed while reporting that nothing was revoked.
fn auth_clients(doc: &mut toml_edit::Table) -> Option<&mut dyn toml_edit::TableLike> {
    doc.get_mut("auth")
        .and_then(|item| item.as_table_like_mut())
        .and_then(|auth| auth.get_mut("clients"))
        .and_then(|item| item.as_table_like_mut())
}

/// The names of the devices in `devices`, for the message a revoke leaves
/// behind when it is asked for one that is not there.
fn device_names(devices: &dyn toml_edit::TableLike) -> String {
    let mut names: Vec<&str> = devices.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    if names.is_empty() {
        return "none".to_string();
    }
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `[auth.clients.<client_id>.devices]` as a table, created when it is missing.
///
/// Where a device's credential goes, for both of the writers that put one
/// there: the enrollment that spends a token, and the operator CLI behind
/// [`FileStorage::write_device_credential`]. One table either way, so a device
/// that enrolled and one that was handed a credential by hand are the same
/// shape on disk, and the handshake does not have to know which of the two it
/// is.
///
/// Not [`sub_table`], which makes an implicit table: a device added under one
/// would be written as `devices.laptop = { … }` on a line of the client's own
/// section, and a table that says what it holds reads better than a dotted key
/// that does not.
fn device_table<'a>(
    client: &'a mut dyn toml_edit::TableLike,
    client_id: &str,
    path: &Path,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match client.entry("devices") {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            entry.insert(toml_edit::Item::Table(toml_edit::Table::new()))
        }
    };
    item.as_table_like_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "{}: [auth.clients.{client_id}.devices] is not a table, the device secret was not \
             written",
            path.display()
        )
    })
}

/// The entry a device's credential is stored as: whichever of the two it is —
/// `secret` or `public_key` — and when it was issued, which is the one thing
/// the file says about a device besides its name.
///
/// Inline rather than a sub-table of its own, because the table it goes into
/// may itself be an inline one an operator wrote, and a sub-table cannot be
/// put inside one.
///
/// The material is checked here rather than written as handed over: the loader
/// refuses an empty secret (it would key this device's HMAC with nothing) and a
/// public key that is not a key, so an unchecked write would hand back success
/// while leaving a config that cannot be read again. A key is written in the
/// canonical spelling — lowercase hex — whatever case it arrived in.
fn device_entry(credential: DeviceCredential, path: &Path) -> anyhow::Result<toml_edit::Item> {
    let mut entry = toml_edit::InlineTable::new();
    match credential {
        DeviceCredential::Secret(secret) => {
            let secret = secret.expose_secret();
            if secret.is_empty() {
                anyhow::bail!(
                    "{}: a device secret cannot be empty; an empty one keys this device's HMAC with \
                     nothing and leaves a config that cannot be loaded",
                    path.display()
                );
            }
            entry.insert("secret", toml_edit::Value::from(secret));
        }
        DeviceCredential::PublicKey(public_key) => {
            let key = crate::auth::parse_public_key(&public_key)
                .map_err(|why| anyhow::anyhow!("{}: {why}", path.display()))?;
            entry.insert(
                "public_key",
                toml_edit::Value::from(crate::auth::public_key_hex(&key)),
            );
        }
    }
    entry.insert(
        "created_at",
        toml_edit::Value::from(crate::auth::config::default_created_at()),
    );
    Ok(toml_edit::value(entry))
}

/// `parent[key]` as a table, creating it when it is missing.
///
/// A table created here is implicit: it is left out of the output while it holds
/// nothing of its own, so a config with no `[auth]` at all gains the one leaf
/// section instead of two empty headers above it.
fn sub_table<'a>(
    parent: &'a mut dyn toml_edit::TableLike,
    key: &str,
    path: &Path,
) -> anyhow::Result<&'a mut dyn toml_edit::TableLike> {
    let item = match parent.entry(key) {
        toml_edit::Entry::Occupied(entry) => entry.into_mut(),
        toml_edit::Entry::Vacant(entry) => {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            entry.insert(toml_edit::Item::Table(table))
        }
    };
    item.as_table_like_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "{}: [{key}] is not a table, secret not written",
            path.display()
        )
    })
}
