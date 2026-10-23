//! The two-factor handshake, and the state it authenticates against.
//!
//! A connection that has credentials opens a stream of its own and says who it
//! is; the server answers with a challenge, the client signs it, and the
//! connection is either authenticated or closed with a reason the client can
//! read. None of that is HTTP, and none of it belongs with the data plane:
//! it is three things, and they are three files.
//!
//! - [`state`] — the credentials the server holds and the counters it counted.
//! - [`enrollment`] — a client that asks for a credential, and what it gets.
//! - [`handshake`] — what a client says, and what it proves.

pub(super) mod enrollment;
pub(super) mod handshake;
pub(super) mod state;

pub use enrollment::count_enrollment_failure;
pub use state::AuthState;

pub(super) use enrollment::{AuthFailure, PeerRegistration};
pub(super) use handshake::perform_authentication;

/// Compares two byte strings in time that does not depend on where they differ.
///
/// A token is guessed the same way a password is, and an early exit on the
/// first differing byte turns "how long did that take" into "how many
/// characters did I get right".
pub(super) fn constant_time_eq(expected: &[u8], given: &[u8]) -> bool {
    if expected.len() != given.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(given.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
