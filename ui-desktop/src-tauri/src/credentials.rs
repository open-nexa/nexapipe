//! Encrypted at-rest storage for the credentials the UI used to keep in `localStorage`.
//!
//! A node's TOTP secret, its enrollment token, the relay bearer used to reach
//! the server's relay, and the connection string it reaches that server by are
//! the most sensitive things this app holds, and they used to sit in a WebView
//! `localStorage` blob: an unencrypted SQLite file inside the user's WebKit data
//! directory, readable by anything the user runs and protected by nothing the OS
//! knows about. The Android client keeps the same values in the Keystore; this is
//! the desktop equivalent.
//!
//! # Shape
//!
//! Two pieces, because only one of them belongs in the OS keychain:
//!
//! * A **master key** — 32 random bytes — held by the keychain (Credential
//!   Manager on Windows, the Secret Service on Linux). Only *it* is worth
//!   putting there: it is one small entry, and losing it is a single,
//!   comprehensible failure. macOS has a keychain too but keeps this key in the
//!   same `0600` file as the fallback instead, because reading a keychain entry
//!   is an *access* macOS asks about with a sheet of its own — at startup, and
//!   again whenever the app's signature changes — and there is no way to read
//!   one without being asked.
//! * The **credentials themselves**, in an AES-256-GCM encrypted JSON file the
//!   app owns. A file rather than one keychain entry per credential because the
//!   elevated service has to be able to read them on two platforms — root and
//!   LocalSystem both read a user's private file, while neither can unlock
//!   another account's keychain — and because a file can be backed up.
//!
//! # Failure
//!
//! A keychain that cannot be reached (headless Linux with no Secret Service, a
//! locked keychain) — or that this platform does not use — falls back to a
//! `0600` file **and says so**, through [`status`]. It never falls back to plaintext: a credential store that quietly
//! degrades is how a secret ends up in a file nobody thinks is sensitive, which
//! is the bug this module exists to remove.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::error::{codes, AppError};

/// Service name the master key is filed under in the OS keychain.
const KEYCHAIN_SERVICE: &str = "nexapipe";
/// Account name the master key is filed under.
const KEYCHAIN_ACCOUNT: &str = "credential-store-master-key";

/// File holding the encrypted credentials.
const STORE_FILE: &str = "credentials.v1.json";
/// File holding the master key when the keychain is unavailable.
const FALLBACK_KEY_FILE: &str = "master.key";

/// Bytes in an AES-256 key.
const KEY_LEN: usize = 32;
/// Bytes in a GCM nonce.
const NONCE_LEN: usize = 12;

/// Marks an entry as one this module wrote, so a future format can be told apart
/// from this one rather than guessed at.
const ENTRY_PREFIX: &str = "v1:";

/// What the OS gave us to hold the master key in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// The keychain took it: the master key never touches the filesystem.
    Keychain,
    /// No keychain would take it, so it is a `0600` file beside the credentials.
    /// Weaker — another process running as this user can read it — which is why
    /// [`status`] reports it instead of leaving it implied.
    File,
}

impl KeySource {
    /// What [`status`] hands to the frontend.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Keychain => "keychain",
            KeySource::File => "file",
        }
    }
}

/// Which credentials a caller may name, so a typo or an unexpected shape fails at
/// the command boundary instead of becoming an entry nothing ever reads back.
///
/// Keys are built by [`secret_key`] rather than by the caller, and every one of
/// them names the node it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// A node's TOTP secret.
    TotpSecret,
    /// A node's one-time enrollment token.
    EnrollmentToken,
    /// The bearer token a custom relay asks for. Not per-node: it is a global setting.
    RelayToken,
    /// The ticket a node reaches its server by. An address-bearing invite string,
    /// which is a credential and not configuration: it names an endpoint *and*
    /// carries whatever the server put in it, so anyone holding it can connect.
    Ticket,
    /// The bare Node ID a node reaches its server by. Weaker than a ticket on its
    /// own — it names a node without carrying a way to reach it — but it is still
    /// what a node is, and it is what an invite of that kind hands out.
    EndpointId,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::TotpSecret => "totp",
            CredentialKind::EnrollmentToken => "enrollment",
            CredentialKind::RelayToken => "relay",
            CredentialKind::Ticket => "ticket",
            CredentialKind::EndpointId => "endpoint",
        }
    }
}

/// Characters of a masked value kept at the front, and at the back.
///
/// Enough to recognise a value the user has seen before — which node this is,
/// which of two similar tickets it is not — and not enough to reconstruct it.
/// The same eight and four the UI used to keep, minus the rule that a short
/// value was shown whole.
const MASK_HEAD: usize = 8;
const MASK_TAIL: usize = 4;

/// What stands in for the rest.
const MASK_MIDDLE: &str = "••••";

/// The longest value that keeps nothing at all.
///
/// A TOTP secret is 16 base32 characters, so 16 is not an arbitrary line: it is
/// the length at which "just the first few characters" is most of the value.
/// Everything at or below it is replaced whole rather than trimmed, because the
/// mask is not there to make a secret harder to read over somebody's shoulder —
/// it is there so a secret is never on the screen at all.
const MASK_WHOLE: usize = 16;

/// The projection of a credential that is safe to render: enough to recognise,
/// not enough to use.
///
/// Computed here rather than in the renderer, because a mask the renderer
/// computes is not one: to shorten a value it already holds, and what it holds
/// is the whole thing, one devtools panel away from whoever is looking. A
/// surface that needs the value itself asks for it through the reveal path
/// instead, which is a deliberate act and, once the lock is in, an authenticated
/// one.
///
/// Empty in, empty out: "no credential" and "a credential so short it is all
/// bullets" must stay tellable apart, and that is the caller's call to make.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return String::new();
    }

    if chars.len() <= MASK_WHOLE {
        // Length is not the secret, so it is kept — up to a point, past which
        // counting bullets stops being informative and starts being decoration.
        return "•".repeat(chars.len().min(MASK_HEAD));
    }

    let head: String = chars.iter().take(MASK_HEAD).collect();
    let tail: String = chars.iter().skip(chars.len() - MASK_TAIL).collect();
    format!("{head}{MASK_MIDDLE}{tail}")
}

/// The key a credential is filed under.
///
/// Built here and not by the caller so the two sides cannot disagree about the
/// spelling: a secret written under one spelling and read under another is a
/// secret that is simply gone.
pub fn secret_key(kind: CredentialKind, node_id: &str) -> String {
    match kind {
        CredentialKind::RelayToken => format!("{}:global", kind.as_str()),
        _ => format!("{}:{}", kind.as_str(), node_id),
    }
}

/// The master key, zeroed when it goes out of scope.
struct MasterKey {
    key: [u8; KEY_LEN],
    source: KeySource,
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A cached master key: the bytes, and where they came from.
type CachedMasterKey = ([u8; KEY_LEN], KeySource);

/// The master key once it has been read or minted, kept for the rest of the
/// process.
///
/// `MasterKey::load` runs on every credential command, and Tauri runs commands
/// in parallel — the frontend fires several at once, `removeNode` with
/// `Promise.all` among them. On a first run two of them would each find the
/// keychain empty and each mint a key: the second `set_password` overwrites the
/// first, and every entry the first had already encrypted becomes unreadable.
/// One key behind one lock makes the second caller wait instead of racing.
static MASTER_KEY: std::sync::LazyLock<std::sync::Mutex<Option<CachedMasterKey>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Serialises the read-change-write sequences in [`Store`].
///
/// `put` and `remove` are three steps — read the whole file, change it, write it
/// back — and two at once both start from the same snapshot, so the second write
/// drops the first one's change: a deleted secret comes back, or a new one
/// disappears. Both also write to the same temporary path, which two writers can
/// interleave into a file that is not valid JSON. The lock is what makes each
/// sequence appear whole.
static STORE_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl MasterKey {
    /// The master key for this installation, creating one if there is none yet.
    ///
    /// Cached in [`MASTER_KEY`]: the key is the same for the life of the process,
    /// and minting it twice is the one thing here that loses data.
    fn load(dir: &Path) -> Result<Self, AppError> {
        let mut cached = MASTER_KEY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((key, source)) = *cached {
            return Ok(Self { key, source });
        }

        let loaded = Self::load_uncached(dir)?;
        *cached = Some((loaded.key, loaded.source));
        Ok(loaded)
    }

    /// The uncached half of [`Self::load`]: where the key actually comes from.
    fn load_uncached(dir: &Path) -> Result<Self, AppError> {
        // macOS used to keep the key in the keychain and does not any more, so
        // the one time it is still found there it moves out — see
        // [`Self::migrate_keychain_key`].
        #[cfg(target_os = "macos")]
        if let Some(key) = Self::migrate_keychain_key(dir) {
            return Ok(Self {
                key,
                source: KeySource::File,
            });
        }

        #[cfg(not(target_os = "macos"))]
        if let Some(key) = Self::from_keychain(dir) {
            return Ok(Self {
                key,
                source: KeySource::Keychain,
            });
        }

        // No keychain holds it — headless Linux with no Secret Service, a locked
        // keychain, a build without the platform backend, or macOS, which keeps
        // the key in this file on purpose. The credentials are still encrypted;
        // only the key is now a private file.
        let key = Self::from_file(dir)?;
        Ok(Self {
            key,
            source: KeySource::File,
        })
    }

    /// Moves the master key out of the keychain and into the file, once.
    ///
    /// The key is what every credential in the store is sealed with, so it is
    /// moved rather than replaced: minting a fresh one here would leave every
    /// stored node unreadable, which is indistinguishable from losing them.
    ///
    /// `None` when there is nothing to move, which is every launch but the first
    /// after this change — a file already holding the key, an install that never
    /// used the keychain, a keychain that will not answer. Asking is the reason
    /// this is guarded by the file's absence rather than done every time: it is
    /// the one read that puts a sheet on the screen, and it is spent once.
    #[cfg(target_os = "macos")]
    fn migrate_keychain_key(dir: &Path) -> Option<[u8; KEY_LEN]> {
        if dir.join(FALLBACK_KEY_FILE).exists() {
            return None;
        }

        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).ok()?;
        let key = parse_key(&entry.get_password().ok()?)?;

        // Written before the keychain copy is deleted, so there is no moment in
        // which neither of them holds it.
        write_private(&dir.join(FALLBACK_KEY_FILE), &hex(&key)).ok()?;

        // A copy left behind is a copy macOS still asks about. Deleted on a best
        // effort: a key now in two places is not a failure, but it is the thing
        // this change exists to stop.
        if let Err(e) = entry.delete_credential() {
            tracing::warn!("the master key moved out of the keychain, but the copy stayed: {e}");
        }
        Some(key)
    }

    /// The keychain's copy, generating one when the keychain has none.
    ///
    /// macOS is deliberately not one of these platforms: see
    /// [`Self::migrate_keychain_key`].
    ///
    /// `None` when there is no usable keychain at all — not when the entry is
    /// merely missing, which is the ordinary first run and creates one.
    ///
    /// `dir` is where a key that predates a working keychain would be: see
    /// [`Self::adopt_file_key`].
    #[cfg(not(target_os = "macos"))]
    fn from_keychain(dir: &Path) -> Option<[u8; KEY_LEN]> {
        use keyring::Entry;

        let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) else {
            return None;
        };

        match entry.get_password() {
            Ok(hex) => {
                if let Some(key) = parse_key(&hex) {
                    return Some(key);
                }
                // Present but unreadable: carrying on would overwrite a key that
                // existing credentials are encrypted under, so this is left alone
                // and the caller falls back — with a key that cannot decrypt them
                // either.
                tracing::warn!("the keychain master key is not 32 bytes; not replacing it");
                return None;
            }
            // The ordinary first run, and the one case in which minting a key is
            // right: there is nothing there for it to overwrite. A key left in
            // the fallback file by a build with no keychain backend is not a
            // first run, so it is moved across first.
            Err(keyring::Error::NoEntry) => {
                if let Some(key) = Self::adopt_file_key(&entry, dir) {
                    return Some(key);
                }
            }
            // Anything else — a locked keychain, access denied, a backend that
            // would not start — is not proof that no key exists. Minting one
            // here would replace a key that credentials are encrypted under,
            // which is unrecoverable; a call that cannot read loses nothing.
            Err(e) => {
                tracing::warn!("the keychain could not be read, master key left alone: {e}");
                return None;
            }
        }

        let Ok(fresh) = random_bytes::<KEY_LEN>() else {
            return None;
        };
        if entry.set_password(&hex(&fresh)).is_err() {
            return None;
        }
        Some(fresh)
    }

    /// Moves a master key out of the fallback file and into the keychain.
    ///
    /// This is the upgrade path for an installation that ran without a keychain
    /// backend — Linux, before this build — and so kept its master key in
    /// [`FALLBACK_KEY_FILE`]. Every credential in the store is encrypted under
    /// that one key, so minting a fresh keychain key here would not improve
    /// anything: it would replace the key the whole store is sealed with, and
    /// every entry would come back undecryptable, which is indistinguishable
    /// from losing them. The key moves as it is; only its holder changes.
    ///
    /// `None` when there is no file key to move, or when the keychain would not
    /// take it — either way the caller falls back to the file, which is exactly
    /// where the key already is.
    #[cfg(not(target_os = "macos"))]
    fn adopt_file_key(entry: &keyring::Entry, dir: &Path) -> Option<[u8; KEY_LEN]> {
        let key = Self::file_key(dir)?;

        if entry.set_password(&hex(&key)).is_err() {
            tracing::warn!(
                "the keychain would not take the existing master key; it stays in {}",
                dir.join(FALLBACK_KEY_FILE).display()
            );
            return None;
        }

        // Removed only once the keychain holds it, so there is no moment in which
        // neither does. A build that predates this one cannot read the keychain
        // and would mint a key of its own on the way down, so re-importing a node
        // is the price of the weaker file no longer being there — the settings
        // page says which of the two the key is in.
        let path = dir.join(FALLBACK_KEY_FILE);
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(
                "the master key is in the keychain but {} could not be removed: {e}",
                path.display()
            );
        }
        Some(key)
    }

    /// The fallback file's key, when the file holds one.
    ///
    /// `None` on a first run, which is every platform but a Linux install
    /// upgraded from a build with no keychain backend. A file that is there and
    /// does not parse is reported rather than ignored: something wrote it, and
    /// moving on silently mints a key that cannot read what that one sealed.
    fn file_key(dir: &Path) -> Option<[u8; KEY_LEN]> {
        let path = dir.join(FALLBACK_KEY_FILE);
        let Ok(contents) = std::fs::read_to_string(&path) else {
            return None;
        };

        match parse_key(contents.trim()) {
            Some(key) => Some(key),
            None => {
                tracing::warn!(
                    "{} is not a 32-byte key; not replacing it",
                    path.display()
                );
                None
            }
        }
    }

    /// The fallback file's copy, generating one when there is none.
    fn from_file(dir: &Path) -> Result<[u8; KEY_LEN], AppError> {
        let path = dir.join(FALLBACK_KEY_FILE);

        if let Some(key) = Self::file_key(dir) {
            return Ok(key);
        }
        if path.exists() {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("{} is not a 32-byte key", path.display()),
            ));
        }

        let fresh = random_bytes::<KEY_LEN>()?;
        write_private(&path, &hex(&fresh))?;
        Ok(fresh)
    }
}

/// The encrypted credential file.
struct Store {
    path: PathBuf,
    master: MasterKey,
}

/// One persisted file: a version and the encrypted entries.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Entries {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    entries: HashMap<String, String>,
}

impl Store {
    /// The store for this installation.
    fn open() -> Result<Self, AppError> {
        let dir = store_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;

        Ok(Self {
            master: MasterKey::load(&dir)?,
            path: dir.join(STORE_FILE),
        })
    }

    /// A store over an explicit directory and key, for tests.
    #[cfg(test)]
    fn with_key(dir: &Path, key: [u8; KEY_LEN]) -> Self {
        Self {
            path: dir.join(STORE_FILE),
            master: MasterKey {
                key,
                source: KeySource::File,
            },
        }
    }

    /// One credential, decrypted. `None` when this key has never been written.
    fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        let entries = self.load()?;
        let Some(blob) = entries.entries.get(key) else {
            return Ok(None);
        };
        self.decrypt(key, blob).map(Some)
    }

    /// Every key currently stored, so a caller can drop entries whose node is gone.
    fn keys(&self) -> Result<Vec<String>, AppError> {
        let mut keys: Vec<String> = self.load()?.entries.into_keys().collect();
        keys.sort();
        Ok(keys)
    }

    /// Writes one credential, leaving the rest alone.
    fn put(&self, key: &str, value: &str) -> Result<(), AppError> {
        let mut entries = self.load()?;
        entries.entries.insert(key.to_string(), self.encrypt(key, value)?);
        self.save(&entries)
    }

    /// Drops one credential. Absent is not an error: there is nothing to forget.
    fn remove(&self, key: &str) -> Result<(), AppError> {
        let mut entries = self.load()?;
        if entries.entries.remove(key).is_none() {
            return Ok(());
        }
        self.save(&entries)
    }

    fn load(&self) -> Result<Entries, AppError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents).map_err(|e| {
                AppError::cause(
                    codes::CREDENTIALS_STORE_FAILED,
                    format!("{} is not a credential store: {e}", self.path.display()),
                )
            }),
            // First run, or a machine where no credential was ever saved.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Entries {
                version: 1,
                entries: HashMap::new(),
            }),
            Err(e) => Err(AppError::cause(codes::CREDENTIALS_STORE_FAILED, e)),
        }
    }

    fn save(&self, entries: &Entries) -> Result<(), AppError> {
        let contents = serde_json::to_string_pretty(entries)
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;

        // Written beside the real file and renamed over it: a crash mid-write
        // leaves the previous store intact rather than a truncated one that
        // decrypts to nothing.
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, &contents)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            AppError::cause(
                codes::CREDENTIALS_STORE_FAILED,
                format!("cannot replace {}: {e}", self.path.display()),
            )
        })
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.master.key))
    }

    fn encrypt(&self, key: &str, value: &str) -> Result<String, AppError> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let blob = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                // The key is authenticated as well as encrypted: moving one entry's
                // value under another key has to fail, not silently re-label a secret.
                Payload {
                    msg: value.as_bytes(),
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| {
                AppError::with_detail(codes::CREDENTIALS_STORE_FAILED, "encryption failed")
            })?;

        let mut out = String::from(ENTRY_PREFIX);
        out.push_str(&hex(&nonce));
        out.push_str(&hex(&blob));
        Ok(out)
    }

    fn decrypt(&self, key: &str, blob: &str) -> Result<String, AppError> {
        let Some(body) = blob.strip_prefix(ENTRY_PREFIX) else {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is not in this store's format"),
            ));
        };

        // Nonce first, then the ciphertext, both hex: one blob, no separator to
        // disagree about, and a wrong length is caught before anything is fed to
        // the cipher.
        if body.len() < NONCE_LEN * 2 {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is truncated"),
            ));
        }
        let nonce = unhex(&body[..NONCE_LEN * 2]).ok_or_else(|| {
            AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} has an unreadable nonce"),
            )
        })?;
        let sealed = unhex(&body[NONCE_LEN * 2..]).ok_or_else(|| {
            AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is not hex"),
            )
        })?;

        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed,
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| {
                // Deliberately not "corrupted": the same failure is what a wrong
                // master key and a hand-edited file look like, and the honest
                // reading is that this value cannot be trusted.
                AppError::with_detail(
                    codes::CREDENTIALS_STORE_FAILED,
                    format!("the entry for {key:?} could not be decrypted"),
                )
            })?;

        String::from_utf8(plaintext).map_err(|e| {
            AppError::cause(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is not text: {e}"),
            )
        })
    }
}

/// Reads one credential. `None` when it was never stored.
pub fn get(key: &str) -> Result<Option<String>, AppError> {
    let _guard = lock_store();
    Store::open()?.get(key)
}

/// Writes one credential.
pub fn put(key: &str, value: &str) -> Result<(), AppError> {
    // Held across all three steps, not just the write: see [`STORE_LOCK`].
    let _guard = lock_store();
    Store::open()?.put(key, value)
}

/// Forgets one credential.
pub fn remove(key: &str) -> Result<(), AppError> {
    let _guard = lock_store();
    Store::open()?.remove(key)
}

/// Every stored key, for dropping credentials whose node no longer exists.
pub fn keys() -> Result<Vec<String>, AppError> {
    let _guard = lock_store();
    Store::open()?.keys()
}

/// Where the master key ended up, so the UI can say when the weaker fallback is
/// in use instead of letting it look identical to the keychain case.
pub fn status() -> Result<KeySource, AppError> {
    let _guard = lock_store();
    let dir = store_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;
    Ok(MasterKey::load(&dir)?.source)
}

/// Where the encrypted store lives.
///
/// The app's own state directory — beside the logs — rather than a Tauri-provided
/// path, so the service binary and the UI resolve the same location without
/// either of them having to be running inside a Tauri context.
fn store_dir() -> PathBuf {
    crate::log_dir()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::log_dir)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AppError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| {
        AppError::cause(
            codes::CREDENTIALS_STORE_FAILED,
            format!("cannot read {N} random bytes from the OS: {e}"),
        )
    })?;
    Ok(bytes)
}

fn write_private(path: &Path, contents: &str) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents.as_bytes())
            .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))
    }
}

fn parse_key(hex: &str) -> Option<[u8; KEY_LEN]> {
    if hex.len() != KEY_LEN * 2 {
        return None;
    }

    // Converted whole rather than copied into a zeroed buffer: a key made of
    // zeroes is what a short conversion would silently leave behind, and the
    // two are indistinguishable once the bytes are out of this function.
    let bytes = unhex(hex)?;
    <[u8; KEY_LEN]>::try_from(bytes).ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{hex, parse_key, random_bytes, CredentialKind, Store, ENTRY_PREFIX, KEY_LEN};
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nexapipe-creds-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn store(name: &str) -> (PathBuf, Store) {
        let dir = scratch(name);
        let key = random_bytes::<KEY_LEN>().expect("a key");
        let store = Store::with_key(&dir, key);
        (dir, store)
    }

    #[test]
    fn a_written_credential_reads_back() {
        let (_dir, store) = store("roundtrip");

        store
            .put("totp:node-1", "JBSWY3DPEHPK3PXP")
            .expect("the write succeeds");

        assert_eq!(
            store.get("totp:node-1").expect("the read succeeds").as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn an_unwritten_credential_is_absent_rather_than_an_error() {
        let (_dir, store) = store("absent");

        assert_eq!(store.get("totp:nothing").expect("the read succeeds"), None);
        // So is removing one that was never there.
        store.remove("totp:nothing").expect("the removal succeeds");
    }

    #[test]
    fn two_credentials_are_stored_side_by_side() {
        let (_dir, store) = store("two");

        store.put("totp:node-1", "first").expect("written");
        store.put("totp:node-2", "second").expect("written");

        assert_eq!(store.get("totp:node-1").unwrap().as_deref(), Some("first"));
        assert_eq!(store.get("totp:node-2").unwrap().as_deref(), Some("second"));
    }

    /// The point of encrypting: the file on disk must not contain the secret.
    #[test]
    fn the_secret_is_not_in_the_file() {
        let (dir, store) = store("on-disk");

        store.put("totp:node-1", "JBSWY3DPEHPK3PXP").expect("written");

        let raw = std::fs::read_to_string(dir.join(super::STORE_FILE)).expect("the file is there");
        assert!(!raw.contains("JBSWY3DPEHPK3PXP"), "{raw}");
        assert!(raw.contains(ENTRY_PREFIX), "{raw}");
    }

    /// A different master key must not produce the plaintext: this is what a
    /// copied credential file comes to when the key does not come with it.
    #[test]
    fn another_master_key_cannot_read_the_store() {
        let dir = scratch("wrong-key");
        let original = Store::with_key(&dir, random_bytes::<KEY_LEN>().expect("a key"));
        original.put("totp:node-1", "secret").expect("written");

        let other = Store::with_key(&dir, random_bytes::<KEY_LEN>().expect("another key"));
        assert!(other.get("totp:node-1").is_err());
    }

    /// An entry moved under another key must not decrypt. The key is authenticated
    /// as well as used to look the value up, so re-labelling a secret is not a
    /// way to make it readable somewhere else.
    #[test]
    fn an_entry_does_not_decrypt_under_another_key() {
        let (_dir, store) = store("rebound");

        store.put("totp:node-1", "secret").expect("written");
        let blob = store
            .load()
            .expect("parsed")
            .entries
            .get("totp:node-1")
            .expect("the entry is there")
            .clone();

        assert!(store.decrypt("totp:node-2", &blob).is_err());
    }

    #[test]
    fn a_tampered_entry_is_refused() {
        let (_dir, store) = store("tampered");

        store.put("totp:node-1", "secret").expect("written");
        let mut blob = store
            .load()
            .expect("parsed")
            .entries
            .get("totp:node-1")
            .expect("the entry is there")
            .clone();
        // Flip the last hex character: the ciphertext no longer matches its tag.
        // The character has to be read before it is replaced. Pushing back a
        // fixed `a` or `b` sometimes restores the one that was just popped —
        // whenever the last character was `a` and the one before it was not —
        // and an untampered entry decrypts, failing this test about one run in
        // four.
        let last = blob.pop().expect("the blob is not empty");
        blob.push(if last == 'a' { 'b' } else { 'a' });

        assert!(store.decrypt("totp:node-1", &blob).is_err());
    }

    #[test]
    fn an_entry_in_an_unknown_format_is_refused() {
        let (_dir, store) = store("foreign");

        assert!(store.decrypt("totp:node-1", "not-ours").is_err());
        assert!(store.decrypt("totp:node-1", &format!("{ENTRY_PREFIX}zz")).is_err());
    }

    #[test]
    fn keys_are_listed_in_order() {
        let (_dir, store) = store("listed");

        store.put("totp:node-2", "b").expect("written");
        store.put("totp:node-1", "a").expect("written");

        assert_eq!(
            store.keys().expect("the keys are read"),
            vec!["totp:node-1".to_string(), "totp:node-2".to_string()]
        );
    }

    /// A store is only ever written `0600`: another account must not be able to
    /// read what the keychain key protects.
    #[cfg(unix)]
    #[test]
    fn the_store_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = store("permissions");
        store.put("totp:node-1", "secret").expect("written");

        let mode = std::fs::metadata(dir.join(super::STORE_FILE))
            .expect("the file is there")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    }

    /// An install that ran without a keychain backend — Linux, before this build
    /// — has its master key in a file, and every stored credential is sealed
    /// under it. `file_key` is what finds it, so the same key can move into the
    /// keychain rather than being replaced by a fresh one.
    #[test]
    fn a_master_key_left_in_a_file_is_read_back() {
        let dir = scratch("file-key");
        let key = random_bytes::<KEY_LEN>().expect("a key");
        std::fs::write(dir.join(super::FALLBACK_KEY_FILE), hex(&key)).expect("written");

        assert_eq!(super::MasterKey::file_key(&dir), Some(key));
    }

    /// The ordinary case on every platform with a keychain: nothing was ever
    /// written to the file, so there is nothing to move.
    #[test]
    fn a_first_run_has_no_file_key() {
        let dir = scratch("no-file-key");

        assert_eq!(super::MasterKey::file_key(&dir), None);
    }

    /// A file that is there but is not a key must not be read as one: a key made
    /// of zeroes, or a truncated one, would silently orphan the whole store.
    #[test]
    fn a_file_that_is_not_a_key_is_absent_rather_than_a_short_key() {
        let dir = scratch("bad-file-key");
        std::fs::write(dir.join(super::FALLBACK_KEY_FILE), "not-a-key").expect("written");

        assert_eq!(super::MasterKey::file_key(&dir), None);
    }

    /// A mask is not a shortening: none of the original characters of a short
    /// value may survive it, because a 16-character TOTP secret shortened by
    /// four characters is still a working TOTP secret on screen.
    #[test]
    fn a_short_value_is_replaced_whole() {
        let secret = "JBSWY3DPEHPK3PXP";

        let masked = super::mask(secret);
        assert!(!masked.is_empty(), "an empty mask reads as no credential");
        for part in ["JBSW", "3DPE", "PXP"] {
            assert!(!masked.contains(part), "{masked} still shows {part}");
        }
    }

    /// A long value keeps its ends, because "which of my nodes is this" is the
    /// question the mask exists to answer, and drops everything between them.
    #[test]
    fn a_long_value_keeps_its_ends_and_nothing_between() {
        let ticket = "e4f1c9a0b2d3e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3";

        let masked = super::mask(ticket);
        assert!(masked.starts_with("e4f1c9a0"), "{masked} lost its head");
        assert!(masked.ends_with("2d3"), "{masked} lost its tail");
        assert!(
            !masked.contains("b2d3e5f7a8b9c0d1"),
            "{masked} kept the middle of the ticket"
        );
    }

    /// Empty stays empty: "no credential" is a different thing from "a
    /// credential I am not showing you", and the UI says so differently.
    #[test]
    fn nothing_to_mask_is_an_empty_mask() {
        assert_eq!(super::mask(""), "");
    }

    /// A connection string is a credential, so it is keyed per node like the
    /// other two — a ticket written under one node's id and read under another's
    /// is a ticket nobody can spend.
    #[test]
    fn a_connection_string_is_keyed_by_the_node_it_connects() {
        assert_eq!(
            super::secret_key(CredentialKind::Ticket, "node-1"),
            "ticket:node-1"
        );
        assert_eq!(
            super::secret_key(CredentialKind::EndpointId, "node-1"),
            "endpoint:node-1"
        );
    }

    #[test]
    fn a_key_is_per_node_and_a_relay_token_is_global() {
        assert_eq!(
            super::secret_key(CredentialKind::TotpSecret, "node-1"),
            "totp:node-1"
        );
        assert_eq!(
            super::secret_key(CredentialKind::EnrollmentToken, "node-1"),
            "enrollment:node-1"
        );
        assert_eq!(super::secret_key(CredentialKind::RelayToken, "ignored"), "relay:global");
    }

    #[test]
    fn hex_round_trips_and_a_wrong_length_is_not_a_key() {
        let bytes = random_bytes::<KEY_LEN>().expect("random bytes");
        let encoded = hex(&bytes);

        assert_eq!(encoded.len(), KEY_LEN * 2);
        assert_eq!(parse_key(&encoded), Some(bytes));
        assert_eq!(parse_key(&encoded[..KEY_LEN * 2 - 1]), None);
    }
}
