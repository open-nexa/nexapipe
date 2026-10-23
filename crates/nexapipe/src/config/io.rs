//! Reading and writing the configuration file.
//!
//! The file is written through a temporary file and renamed over the old one, so a
//! crash halfway through leaves the old file rather than a half-written one, and a
//! credential in it is never readable by anybody else.

use crate::toml_zeroize::zeroize_document;

use nexapipe_proto::secret::SecretString;

use std::fs;
use std::io::Write;

use std::path::Path;

use zeroize::Zeroize;

use super::*;

/// Parses the configuration file's text, with an error that says what to do
/// about a key this build does not know.
///
/// serde already names the key, and it already says which keys the section
/// does have. What it cannot say is the one thing the operator can do about
/// it, and it is the same either way: the key is a typo, or it belongs to a
/// version of the file this build does not read. Both are fixed by removing it
/// or by fixing its spelling.
pub(crate) fn parse_config<T: serde::de::DeserializeOwned>(text: &str) -> anyhow::Result<T> {
    match toml::from_str::<T>(text) {
        Ok(value) => Ok(value),
        Err(error) => {
            let message = error.to_string();
            if error.message().contains("unknown field") {
                anyhow::bail!(
                    "{message}\n\nThis build does not know that key: remove it, or fix its spelling."
                );
            }
            Err(anyhow::anyhow!("{message}"))
        }
    }
}

impl ProxyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let path = Path::new(path);
        tracing::debug!("Loading config from: {}", path.display());

        if !path.exists() {
            return Err(anyhow::anyhow!("Config file not found: {}", path.display()));
        }

        tracing::debug!("Config file exists, reading content");
        // The file can hold the 2FA secrets in the clear, so the text it lands
        // in is wiped once the parse has copied them into the zeroizing fields
        // it fills.
        let content = SecretString::new(
            fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?,
        );

        tracing::debug!("Config content read successfully, parsing TOML");
        let mut config: Self = parse_config(content.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {e:#}"))?;
        config.resolve_external_credentials(path.parent())?;

        tracing::debug!("Config parsed successfully: {:?}", config);
        Ok(config)
    }
}

/// Warns when the config file holds a credential and lets somebody other than
/// its owner read it.
///
/// **A warning, not a refusal.** The check that used to stop the server from
/// starting over a readable config was removed on purpose (ROADMAP §3.5), so
/// that a `0644` bind mount starts. Putting it back would undo that decision.
///
/// Silence is the part that is wrong: a TOTP seed in a file the whole machine
/// can read is a credential anybody can use to generate a valid code, and
/// nothing about it is visible. One line at startup and one after a reload is
/// enough to say it.
///
/// Unix only, and it says so by doing nothing elsewhere: the permission bits
/// are a Unix idea, and on Windows the file's ACL decides, which this does not
/// read.
///
/// `auth` is the `[auth]` half of the same file, and it is `None` when the file
/// has no such section — which is not the same as "no credential". A config
/// that names an inline `[iroh]` key and no `[auth]` at all is a credential in
/// the open. The files this server ships — the generated first-run template
/// and `config.toml.example` — both carry `[auth] enabled = true` now, but a
/// deployment whose file predates the section still has one, and a warning
/// that needed an `AuthConfig` to exist would be silent for exactly that file.
pub fn warn_about_readable_credentials(
    path: &std::path::Path,
    proxy: &ProxyConfig,
    auth: Option<&crate::auth::AuthConfig>,
) {
    if !should_warn_about_permissions(path, proxy, auth) {
        return;
    }
    tracing::warn!(
        "{} holds a credential and is readable by others (mode {:04o}); anyone who can read it \
         can use it — `chmod 600`, or move the secret into a 0600 file of its own",
        path.display(),
        file_mode(path),
    );
}

/// Whether the loaded config should be warned about: it holds a credential,
/// and the file it came from is readable by somebody other than its owner.
///
/// The decision on its own, so that it can be tested without a log
/// subscriber: the warning is a line of text, and what matters is the
/// question it answers.
pub fn should_warn_about_permissions(
    path: &std::path::Path,
    proxy: &ProxyConfig,
    auth: Option<&crate::auth::AuthConfig>,
) -> bool {
    // A credential the file holds in the clear: an inline `[iroh]` key or
    // token, or a 2FA seed. One that lives in a sidecar file of its own is
    // not in this file, and that file is held to the `0600` rule in the
    // config's place — see `read_credential_file`.
    let holds_a_seed = auth.is_some_and(|auth| auth.holds_inline_secrets());
    if !proxy.holds_credentials() && !holds_a_seed {
        return false;
    }
    readable_by_others(path)
}

/// The permission bits of the file, or 0 when they cannot be read.
#[cfg(unix)]
pub(crate) fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0)
}

#[cfg(not(unix))]
pub(crate) fn file_mode(_path: &std::path::Path) -> u32 {
    0
}

/// Whether somebody other than the owner can read the file.
#[cfg(unix)]
pub(crate) fn readable_by_others(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode() & 0o077 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub(crate) fn readable_by_others(_path: &std::path::Path) -> bool {
    false
}

/// The config written when there is none: 2FA on, nothing else.
///
/// Deliberately small, and deliberately **not** a working proxy: it carries no
/// `[[routes]]`, so every host is answered 404 until one is added. A generated
/// backend address would be a guess — `127.0.0.1:3000` is only right by
/// coincidence — and a wrong one fails every request while looking configured.
/// The commented route below is the shape to uncomment.
///
/// `[auth] enabled = true` is the one setting that is not the operator's to
/// infer: a config with no `[auth.clients]` refuses every connection, which is
/// the correct state for a file nobody has written yet.
///
/// **The file's own permission is not checked, and that is deliberate.** A
/// startup check that refused to run over a world-readable config was removed
/// on purpose (ROADMAP §3.5) so that a `0644` bind mount starts — a config
/// that is a bind mount of a secret store is readable by design, and a server
/// that refused to start over it would be a server nobody could run that way.
///
/// What is left is a **warning**: when the config itself holds a credential —
/// an inline `[iroh]` key, or a 2FA seed — and the file is readable by
/// others, the server says so once, naming the path and the mode. See
/// [`warn_about_readable_credentials`].
///
/// The file still goes out through [`write_config_file`] rather than
/// `fs::write`, so that the one it writes is `0600` from the start.
///
/// No `[iroh] secret_key`: the endpoint identity is generated and written back
/// on first start (see `ensure_iroh_secret_key`), so writing one here would be
/// a second answer to the same question.
pub(crate) const FIRST_RUN_CONFIG: &str = include_str!("../../templates/first-run-config.toml");

/// Writes a minimal config at `path` when there is none, and reports whether it
/// did.
///
/// Only `NotFound` leads to a write. A file that exists but cannot be read or
/// parsed is somebody's typo to fix, and generating over it would replace a
/// config they wrote — or, worse, a half-written one — with a default that
/// looks deliberate. So the read still happens in [`ProxyConfig::from_file`],
/// and its error still reaches the operator.
///
/// The create is atomic via `OpenOptions::create_new(true)` (the "create and
/// must-not-exist" check is a single syscall). That matters because the check
/// above and the write below are two steps: an external writer that does not
/// take the config lock — an operator saving in their editor, a sibling tool
/// — could otherwise slip a file in between, and `write_config_file` would
/// rename its temp file over that destination, discarding the operator's
/// routes and credentials. `create_new` makes the second step safe by failing
/// rather than overwriting.
///
/// `create_new` only succeeds when the parent directory already exists, so
/// the parent is created with `fs::create_dir_all` first. That is what
/// makes the docker default path (`<NEXAPIPE_CONFIG_DIR>/config.toml`)
/// work for a fresh start: `docker-compose.yaml` binds the directory the
/// env var names into the container, but a first start that runs before
/// any config has been written would otherwise fail with "no such file or
/// directory" on the lock file `with_config_lock` opens.
///
/// Under the config lock, on principle: the lock no longer *needs* to be
/// taken, because `create_new` is already atomic. Kept for symmetry with the
/// rest of the config writers — it serialises a `ensure_config_file` call
/// with an in-progress 2FA writeback so the new template never lands between
/// the 2FA reader and the 2FA writer.
///
/// Not for every command. `status` reads the config of a process that is
/// already running and `--generate-2fa` works without one, so neither should
/// leave a file behind; this is called from the server start path only.
pub fn ensure_config_file(path: &str) -> anyhow::Result<bool> {
    if Path::new(path).exists() {
        return Ok(false);
    }

    // `with_config_lock` opens `<path>.lock` and that fails when the parent
    // directory does not yet exist, so the directory is created before the
    // lock is taken. The lock file is otherwise useless: every write of this
    // path goes through this function and through the other writers in this
    // crate, all of which take the same lock. Idempotent — running it on a
    // directory that already exists is a no-op.
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", parent.display()))?;
    }

    with_config_lock(path, || {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(path) {
            Ok(mut file) => {
                file.write_all(FIRST_RUN_CONFIG.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path))?;
                file.sync_all()
                    .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", path))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A non-locking writer (operator with an editor, a sibling
                // tool) created the file between our existence check and
                // our create. Preserve whatever they wrote.
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!("cannot create {}: {e}", path)),
        }
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
pub(crate) fn device_entry(
    material: crate::auth::DeviceMaterial<'_>,
    path: &str,
) -> anyhow::Result<toml_edit::Item> {
    let mut entry = toml_edit::InlineTable::new();
    match material {
        crate::auth::DeviceMaterial::Secret(secret) => {
            if secret.is_empty() {
                anyhow::bail!(
                    "{path}: a device secret cannot be empty; an empty one keys this device's \
                     HMAC with nothing and leaves a config that cannot be loaded"
                );
            }
            entry.insert("secret", toml_edit::Value::from(secret));
        }
        crate::auth::DeviceMaterial::PublicKey(public_key) => {
            let key = crate::auth::parse_public_key(public_key)
                .map_err(|why| anyhow::anyhow!("{path}: {why}"))?;
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

/// Runs `work` while holding an exclusive lock on the config file at `path`.
///
/// Every read-modify-write of the config goes through this. `write_config_file`
/// makes a single write atomic, but it says nothing about two writers that both
/// read first: the second one's write is built from the contents it read before
/// the first one landed, so one of the two edits is lost. The three callers are
/// in this binary — a CLI command, the enrollment flow and the 2FA counter
/// writeback — and any two of them can coincide.
///
/// The lock is advisory: a writer that does not take it still races. That is
/// acceptable, because every writer of this file is this program.
pub fn with_config_lock<T>(
    path: &str,
    work: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = ConfigLock::acquire(path)?;
    work()
}

/// The lock file sits *beside* the config rather than being the config itself.
///
/// Writes go through [`write_config_file`], which is a temp file and a rename,
/// and a rename swaps the directory entry for a different inode — so a lock
/// taken on the config path would stay behind on a file that was replaced
/// underneath it, and every writer would hold a different lock. A separate file
/// is never renamed, so it stays the one thing everybody contends for.
pub(crate) struct ConfigLock {
    file: fs::File,
}

impl ConfigLock {
    fn acquire(path: &str) -> anyhow::Result<Self> {
        let lock_path = format!("{path}.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            // The lock file is a lock, not a document: whatever it already
            // holds is nobody's data, and truncating a file another process may
            // be about to open buys nothing.
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("cannot open {lock_path}: {e}"))?;

        // Beside a file that holds TOTP secrets, so it is created the way the
        // config itself is checked for: private to its owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("cannot set the mode of {lock_path}: {e}"))?;
        }

        // `File::lock`, standard since 1.89: `flock(2)` on Unix and
        // `LockFileEx` on Windows, which is the pair writing by hand would have
        // meant two `unsafe` blocks to reach.
        file.lock()
            .map_err(|e| anyhow::anyhow!("cannot lock {lock_path}: {e}"))?;
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
/// credentials, so every write of one goes through [`write_config_document`],
/// which zeroes the text it renders and the document it came from. A caller
/// that reached this function directly would skip that, and the seeds would
/// sit in the heap for as long as the allocator kept the buffer.
pub(crate) fn write_config_file(path: &str, contents: &str) -> anyhow::Result<()> {
    let target = Path::new(path);
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
    // indirection an operator set up is gone, the file the link pointed at keeps
    // its old contents, and every command involved still reports success. A
    // config reached through a link is a normal way to keep one file in version
    // control or out of a container image, so the rename is aimed at what the
    // link resolves to instead — the real file is replaced and the link stays.
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
        // mode is tightened *before* anything is written: a target that is
        // world-readable would otherwise hold the secrets that way for as long
        // as the write leaves it. A mode that cannot be set is an error rather
        // than something to log past — a config of secrets at 0644 is worse
        // than one that was not written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if target.exists() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("cannot set the mode of {path}: {e}"))?;
            }
        }

        let written = fs::write(target, contents)
            .map_err(|e| anyhow::anyhow!("cannot write {path}: {e} (rename failed: {rename})"));

        // Covers a target that did not exist: the write above creates it under
        // the process umask, which is not what a file of secrets should inherit.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if written.is_ok() {
                fs::set_permissions(target, fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("cannot set the mode of {path}: {e}"))?;
            }
        }

        return written;
    }

    Ok(())
}

/// Reads the config file into a document, with the text it was read from
/// wiped when it goes out of scope.
///
/// The file can hold the 2FA seeds in the clear, so its text is a copy of a
/// credential: it is read into a buffer that is zeroed as soon as the
/// document it was parsed into exists. `what` says what was not written, for
/// the error a malformed file produces.
pub(crate) fn read_config_document(
    path: &str,
    what: &str,
) -> anyhow::Result<toml_edit::DocumentMut> {
    let content = SecretString::new(
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?,
    );
    content
        .expose_secret()
        .parse()
        .map_err(|e| anyhow::anyhow!("{path} is not valid TOML, {what} ({e})"))
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
pub(crate) fn write_config_document(
    path: &str,
    mut document: toml_edit::DocumentMut,
) -> anyhow::Result<()> {
    let mut text = document.to_string();
    let result = write_config_file(path, &text);
    text.zeroize();
    zeroize_document(&mut document);
    result
}
