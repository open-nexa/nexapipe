//! No door: a platform this app does not run on.
//!
//! The desktop app is built for macOS, Windows and Linux, and `gate::Os` has to
//! name something on every target the crate is *checked* on regardless. This is
//! that something, and it refuses: a platform with no way to ask has no answer
//! to give, and "cannot ask" is not permission.

use super::{Capability, OsGate, Outcome};

pub struct Absent;

impl OsGate for Absent {
    fn capability(&self) -> Capability {
        Capability::Unavailable
    }

    fn confirm(&self, _reason: &str, _password: Option<&str>) -> Outcome {
        Outcome::Unavailable
    }
}
