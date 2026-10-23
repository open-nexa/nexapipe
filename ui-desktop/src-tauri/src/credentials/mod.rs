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

// The pieces of it: the types the callers name, the store that holds the
// encrypted file, the master key that file is sealed with, the files they
// live in, and the bytes they are made of.
mod bytes;
mod files;
mod master_key;
mod store;
mod types;

#[cfg(test)]
mod tests;

pub use store::{get, keys, put, remove, status};
pub use types::{mask, secret_key, CredentialKind, KeySource};

// The private halves of the pieces, named here so that the test module can
// reach them under the names it has always used.
#[cfg(test)]
use bytes::{hex, parse_key, random_bytes};
#[cfg(test)]
use files::write_private;
#[cfg(test)]
use master_key::{MasterKey, FALLBACK_KEY_FILE, KEY_LEN};
#[cfg(test)]
use store::{Store, ENTRY_PREFIX, STORE_FILE};
