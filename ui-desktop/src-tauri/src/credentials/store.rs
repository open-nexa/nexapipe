use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::bytes::{hex, random_bytes, unhex};
use super::files::{reject_readable_by_others, write_private};
use super::master_key::MasterKey;
use super::types::KeySource;
use crate::error::{codes, AppError};

#[cfg(test)]
use super::master_key::KEY_LEN;

/// File holding the encrypted credentials.
pub(super) const STORE_FILE: &str = "credentials.v1.json";

/// Bytes in a GCM nonce.
const NONCE_LEN: usize = 12;

/// Marks an entry as one this module wrote, so a future format can be told apart
/// from this one rather than guessed at.
pub(super) const ENTRY_PREFIX: &str = "v1:";

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

/// The encrypted credential file.
pub(super) struct Store {
    path: PathBuf,
    master: MasterKey,
}

/// One persisted file: a version and the encrypted entries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Entries {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    pub(super) entries: HashMap<String, String>,
}

impl Store {
    /// The store for this installation.
    pub(super) fn open() -> Result<Self, AppError> {
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
    pub(super) fn with_key(dir: &Path, key: [u8; KEY_LEN]) -> Self {
        Self {
            path: dir.join(STORE_FILE),
            master: MasterKey {
                key,
                source: KeySource::File,
            },
        }
    }

    /// One credential, decrypted. `None` when this key has never been written.
    pub(super) fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        let entries = self.load()?;
        let Some(blob) = entries.entries.get(key) else {
            return Ok(None);
        };
        self.decrypt(key, blob).map(Some)
    }

    /// Every key currently stored, so a caller can drop entries whose node is gone.
    pub(super) fn keys(&self) -> Result<Vec<String>, AppError> {
        let mut keys: Vec<String> = self.load()?.entries.into_keys().collect();
        keys.sort();
        Ok(keys)
    }

    /// Writes one credential, leaving the rest alone.
    pub(super) fn put(&self, key: &str, value: &str) -> Result<(), AppError> {
        let mut entries = self.load()?;
        entries
            .entries
            .insert(key.to_string(), self.encrypt(key, value)?);
        self.save(&entries)
    }

    /// Drops one credential. Absent is not an error: there is nothing to forget.
    pub(super) fn remove(&self, key: &str) -> Result<(), AppError> {
        let mut entries = self.load()?;
        if entries.entries.remove(key).is_none() {
            return Ok(());
        }
        self.save(&entries)
    }

    pub(super) fn load(&self) -> Result<Entries, AppError> {
        // Checked before the bytes are read, not after: the point is not to
        // decrypt a store another account could have read while it was there.
        reject_readable_by_others(&self.path)?;

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
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.master.key))
    }

    fn encrypt(&self, key: &str, value: &str) -> Result<String, AppError> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let blob = self
            .cipher()
            .encrypt(
                &Nonce::from(nonce),
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

    pub(super) fn decrypt(&self, key: &str, blob: &str) -> Result<String, AppError> {
        let Some(body) = blob.strip_prefix(ENTRY_PREFIX) else {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is not in this store's format"),
            ));
        };

        // Nonce first, then the ciphertext, both hex: one blob, no separator to
        // disagree about, and a wrong length is caught before anything is fed to
        // the cipher. Decoding straight into `[u8; NONCE_LEN]` rather than a `Vec`
        // is what lets the nonce move into `Nonce` without a length check the
        // slice above has already made.
        if body.len() < NONCE_LEN * 2 {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("the entry for {key:?} is truncated"),
            ));
        }
        let nonce = unhex(&body[..NONCE_LEN * 2])
            .and_then(|bytes| <[u8; NONCE_LEN]>::try_from(bytes).ok())
            .ok_or_else(|| {
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
                &Nonce::from(nonce),
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
