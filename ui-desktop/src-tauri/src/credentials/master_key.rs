use std::path::Path;
use zeroize::Zeroize;

use super::bytes::{hex, parse_key, random_bytes};
use super::files::{reject_readable_by_others, write_private};
use super::types::KeySource;
use crate::error::{codes, AppError};

/// Service name the master key is filed under in the OS keychain.
const KEYCHAIN_SERVICE: &str = "nexapipe";
/// Account name the master key is filed under.
const KEYCHAIN_ACCOUNT: &str = "credential-store-master-key";

/// File holding the master key when the keychain is unavailable.
pub(super) const FALLBACK_KEY_FILE: &str = "master.key";

/// Bytes in an AES-256 key.
pub(super) const KEY_LEN: usize = 32;

/// The master key, zeroed when it goes out of scope.
pub(super) struct MasterKey {
    pub(super) key: [u8; KEY_LEN],
    pub(super) source: KeySource,
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

impl MasterKey {
    /// The master key for this installation, creating one if there is none yet.
    ///
    /// Cached in [`MASTER_KEY`]: the key is the same for the life of the process,
    /// and minting it twice is the one thing here that loses data.
    pub(super) fn load(dir: &Path) -> Result<Self, AppError> {
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
        if let Some(key) = Self::migrate_keychain_key(dir)? {
            return Ok(Self {
                key,
                source: KeySource::File,
            });
        }

        #[cfg(not(target_os = "macos"))]
        if let Some(key) = Self::from_keychain(dir)? {
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
    /// `Ok(None)` when there is nothing to move, which is every launch but the
    /// first after this change — a file already holding the key, an install that
    /// never used the keychain. Asking is the reason this is guarded by the
    /// file's absence rather than done every time: it is the one read that puts
    /// a sheet on the screen, and it is spent once.
    ///
    /// A keychain that does not answer is not the same thing as one with no key
    /// in it, and telling the two apart is what this function is for. A read
    /// that failed because the keychain is locked, or because the sheet was
    /// dismissed, is not proof that no key is there, so it fails the load
    /// instead of falling through to [`Self::from_file`]: that would mint a
    /// fresh key, write it to the file, and — because the file's mere existence
    /// is what stops this from ever being tried again — leave the key that is
    /// still in the keychain unreachable for good, with every credential sealed
    /// under it unreadable. Failing costs a retry; minting costs the data.
    #[cfg(target_os = "macos")]
    fn migrate_keychain_key(dir: &Path) -> Result<Option<[u8; KEY_LEN]>, AppError> {
        if dir.join(FALLBACK_KEY_FILE).exists() {
            return Ok(None);
        }

        let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) else {
            // No keychain to ask at all, so nothing was declined either: the
            // file is where this platform keeps its key regardless.
            return Ok(None);
        };

        let stored = match entry.get_password() {
            Ok(stored) => stored,
            // The ordinary install that never used the keychain, and the only
            // case in which a key may be minted: there is nothing there for it
            // to overwrite.
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => {
                return Err(AppError::with_detail(
                    codes::CREDENTIALS_STORE_FAILED,
                    format!(
                        "the keychain could not be read, so its master key was left alone: {error}"
                    ),
                ));
            }
        };

        // Present but unreadable, which is no different from the read having
        // failed: something wrote this, and a fresh key cannot read what it
        // sealed.
        let Some(key) = parse_key(&stored) else {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                "the keychain master key is not 32 bytes; not replacing it",
            ));
        };

        // Written before the keychain copy is deleted, so there is no moment in
        // which neither of them holds it.
        write_private_atomic(&dir.join(FALLBACK_KEY_FILE), &hex(&key))?;

        // A copy left behind is a copy macOS still asks about. Deleted on a best
        // effort: a key now in two places is not a failure, but it is the thing
        // this change exists to stop.
        if let Err(e) = entry.delete_credential() {
            tracing::warn!("the master key moved out of the keychain, but the copy stayed: {e}");
        }
        Ok(Some(key))
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
    ///
    /// The `Result` carries the one failure that must not be read as "no
    /// keychain": a fallback file another account can read. Everything else
    /// still answers `None`, because falling back is the right answer to a
    /// keychain that cannot be reached — see [`Self::adopt_file_key`].
    #[cfg(not(target_os = "macos"))]
    fn from_keychain(dir: &Path) -> Result<Option<[u8; KEY_LEN]>, AppError> {
        use keyring::Entry;

        let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) else {
            return Ok(None);
        };

        match entry.get_password() {
            Ok(hex) => {
                if let Some(key) = parse_key(&hex) {
                    return Ok(Some(key));
                }
                // Present but unreadable: carrying on would overwrite a key that
                // existing credentials are encrypted under, so this is left alone
                // and the caller falls back — with a key that cannot decrypt them
                // either.
                tracing::warn!("the keychain master key is not 32 bytes; not replacing it");
                return Ok(None);
            }
            // The ordinary first run, and the one case in which minting a key is
            // right: there is nothing there for it to overwrite. A key left in
            // the fallback file by a build with no keychain backend is not a
            // first run, so it is moved across first.
            Err(keyring::Error::NoEntry) => {
                if let Some(key) = Self::adopt_file_key(&entry, dir)? {
                    return Ok(Some(key));
                }
            }
            // Anything else — a locked keychain, access denied, a backend that
            // would not start — is not proof that no key exists. Minting one
            // here would replace a key that credentials are encrypted under,
            // which is unrecoverable; a call that cannot read loses nothing.
            Err(e) => {
                tracing::warn!("the keychain could not be read, master key left alone: {e}");
                return Ok(None);
            }
        }

        let Ok(fresh) = random_bytes::<KEY_LEN>() else {
            return Ok(None);
        };
        if entry.set_password(&hex(&fresh)).is_err() {
            return Ok(None);
        }
        Ok(Some(fresh))
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
    ///
    /// A file key that is there but readable by other accounts is an `Err`
    /// rather than a `None`: falling back would reach
    /// [`Self::from_file`], which reads the same file and refuses it there, so
    /// the load fails either way — only this way says which file and why.
    #[cfg(not(target_os = "macos"))]
    fn adopt_file_key(
        entry: &keyring::Entry,
        dir: &Path,
    ) -> Result<Option<[u8; KEY_LEN]>, AppError> {
        let Some(key) = Self::file_key(dir)? else {
            return Ok(None);
        };

        if entry.set_password(&hex(&key)).is_err() {
            tracing::warn!(
                "the keychain would not take the existing master key; it stays in {}",
                dir.join(FALLBACK_KEY_FILE).display()
            );
            return Ok(None);
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
        Ok(Some(key))
    }

    /// The fallback file's key, when the file holds one.
    ///
    /// `Ok(None)` on a first run, which is every platform but a Linux install
    /// upgraded from a build with no keychain backend. A file that is there and
    /// does not parse is reported rather than ignored: something wrote it, and
    /// moving on silently mints a key that cannot read what that one sealed.
    ///
    /// A file another account can read is an `Err` rather than a `None`, because
    /// `None` here means "there is no key file" and the caller acts on that by
    /// minting a fresh key — which would leave every credential sealed under the
    /// readable one permanently undecryptable. See [`reject_readable_by_others`].
    pub(super) fn file_key(dir: &Path) -> Result<Option<[u8; KEY_LEN]>, AppError> {
        let path = dir.join(FALLBACK_KEY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        reject_readable_by_others(&path)?;

        let Ok(contents) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };

        Ok(match parse_key(contents.trim()) {
            Some(key) => Some(key),
            None => {
                tracing::warn!("{} is not a 32-byte key; not replacing it", path.display());
                None
            }
        })
    }

    /// The fallback file's copy, generating one when there is none.
    pub(super) fn from_file(dir: &Path) -> Result<[u8; KEY_LEN], AppError> {
        let path = dir.join(FALLBACK_KEY_FILE);

        if let Some(key) = Self::file_key(dir)? {
            return Ok(key);
        }
        if path.exists() {
            return Err(AppError::with_detail(
                codes::CREDENTIALS_STORE_FAILED,
                format!("{} is not a 32-byte key", path.display()),
            ));
        }

        let fresh = random_bytes::<KEY_LEN>()?;
        write_private_atomic(&path, &hex(&fresh))?;
        Ok(fresh)
    }
}

/// Writes `contents` to `path` so that `path` is never seen half-written.
///
/// Two things read the master key file and neither recovers from a short one:
/// [`MasterKey::file_key`] rejects a file that is not a 32-byte key, and
/// [`MasterKey::migrate_keychain_key`] takes the file's mere existence as
/// "already moved out". A write that dies halfway — a full disk, an I/O error
/// after the file was truncated — therefore leaves an installation that can
/// neither read its key nor read the keychain copy it still has. So the bytes
/// go to a sibling temporary file, are flushed out of the page cache, and only
/// then take the name they belong under: a rename is atomic to a reader, who
/// sees the old file or the new one and never a mixture of the two.
fn write_private_atomic(path: &Path, contents: &str) -> Result<(), AppError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(AppError::with_detail(
            codes::CREDENTIALS_STORE_FAILED,
            format!("{} has no file name to write beside", path.display()),
        ));
    };
    // A sibling rather than a system temporary directory: a rename across
    // filesystems is a copy, which is two writes with a gap between them.
    let tmp = path.with_file_name(format!("{name}.tmp"));

    match write_private(&tmp, contents).and_then(|()| sync_file(&tmp)) {
        Ok(()) => {}
        Err(error) => {
            // Nothing reads the temporary file, but it is a copy of the key
            // with the wrong name, so it does not stay behind.
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        AppError::cause(codes::CREDENTIALS_STORE_FAILED, e)
    })?;

    // A rename is atomic to a reader, not durable to a crash: the directory
    // entry it creates lives in the page cache until the directory itself is
    // flushed too. `migrate_keychain_key` deletes the keychain copy as soon as
    // this returns, so losing that entry costs the key rather than one write —
    // nothing holds it any more, and the next launch mints a fresh one that
    // cannot open what the lost one sealed.
    if let Some(parent) = path.parent() {
        sync_file(parent)?;
    }

    Ok(())
}

/// Pushes what was just written out of the page cache and onto the disk.
///
/// Dropping a [`std::fs::File`] does not do this: `write_all` can return `Ok`
/// with every byte still in the cache, which a crash would take with it.
///
/// `path` is a file or a directory — opening one and flushing it is how the
/// renaming done above is made to survive the same crash.
#[cfg(unix)]
fn sync_file(path: &Path) -> Result<(), AppError> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| AppError::cause(codes::CREDENTIALS_STORE_FAILED, e))
}

/// `sync_all` has no equivalent on Windows' standard file handle.
#[cfg(not(unix))]
fn sync_file(_path: &Path) -> Result<(), AppError> {
    Ok(())
}
