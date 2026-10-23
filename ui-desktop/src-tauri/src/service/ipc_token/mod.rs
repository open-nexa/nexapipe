//! The shared secret an IPC client must present before the service obeys it.
//!
//! `ServiceRunner` listens on a socket and runs elevated — SYSTEM on Windows,
//! root under systemd/launchd — while every IPC message is either harmless
//! (`GetStatus`) or drastic (`StartProxy` with `use_tun`, which takes over
//! routing and DNS). Nothing about the connection identifies its peer, so a
//! message arriving here used to be obeyed on trust: **any** process the user
//! ran could ask the elevated service to rewrite that user's routing table.
//! The token is what replaces that trust, and the account behind the
//! connection is what says whose traffic it may carry.
//!
//! # Who owns the token
//!
//! The **UI process** holds it, not the service. That direction matters:
//!
//! * The token has to live somewhere both sides can read. Writing it into the
//!   user's own directory means the ordinary filesystem permissions already say
//!   the right thing — readable by that user plus the elevated accounts that
//!   can read anything anyway — whereas a file the service created would either
//!   be unreadable to the UI or readable to every other user.
//! * It also means the file appears when somebody actually runs the desktop
//!   app, and its absence is a meaningful answer: nobody has asked for the
//!   service yet, so nothing gets obeyed.
//!
//! The service therefore only ever *reads* it, and does so per connection so a
//! regenerated token takes effect without a restart.
//!
//! # Who may present it
//!
//! A token on its own says who *knows* it, not who may *use* it: the service
//! finds token files in every account's profile, so a token that is found says
//! nothing about the account that presented it. Every candidate therefore
//! carries the account that owns the file it came from, and the service serves
//! the account it was installed for and nobody else — see
//! [`crate::service::platform::account::allows`].
//!
//! A candidate is only read at all when the directory holding it is one a
//! secret may be read from: a directory another account can write into is a
//! directory it can put a token of its own into, and `/tmp` — where a service
//! with neither `HOME` nor `XDG_RUNTIME_DIR` ends up — is world-writable.

mod candidate;
mod file;
mod handshake;
mod path;
mod secret;

#[cfg(test)]
mod tests;

/// Directory holding the token, relative to the base directory below.
const TOKEN_DIR: &str = "nexapipe";
/// File name of the token.
const TOKEN_FILE: &str = "ipc.token";

pub use candidate::{read_candidate_at, read_candidates, service_token_paths, TokenCandidate};
pub use file::{ensure_token, ensure_token_at, read_token_at};
pub use handshake::{auth_mac, proof_mac, proof_matches, token_for_auth};
pub use path::{runtime_file, token_path, TOKEN_PATH_ENV};
pub use secret::{generate_token, random_nonce, NONCE_BYTES};
