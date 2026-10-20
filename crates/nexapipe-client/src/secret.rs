//! Secret material that wipes itself when it goes out of scope.
//!
//! # Why this exists
//!
//! The credentials this workspace holds — a TOTP seed, an enrollment token, a
//! relay bearer, the endpoint's own private key — were plain `String`s and
//! `Vec<u8>`s. Masking them in `Debug` keeps them out of log lines, and that
//! half of the work is done; but the bytes themselves stay in the heap until
//! the allocator happens to reuse that memory. A core dump, a swap file, or a
//! read of `/proc/<pid>/mem` hands over every credential the process ever
//! held, long after the handshake that needed it is over — which is the same
//! defect as a secret in a log line, only quieter: nothing in the process
//! says it happened.
//!
//! [`Secret`] is the type that closes it. It holds the value, wipes it when it
//! is dropped, and never prints it.
//!
//! # What it promises, and what it does not
//!
//! It promises that *this* copy is wiped when it goes out of scope, and that
//! no `Debug` of it can leak it — so a struct that derives `Debug` and holds
//! a `Secret` is safe to log without anybody having to remember to write a
//! `Debug` for it. That is the difference between the two halves of the
//! defect: masking by hand is one field at a time, and the next field added
//! later is the one that leaks.
//!
//! It does not promise that a *copy* of the value is wiped. A value that
//! leaves this process — written to a config file, handed to the Android app
//! over JNI, put on the wire — is a copy this process can no longer reach, and
//! wiping it is the receiver's business. [`Secret::expose_secret`] and
//! [`Secret::expose_secret_cloned`] are therefore named the way they are: they
//! are the doors out of the type, and everything that goes through them is
//! outside its protection from that moment on.
//!
//! It also does not reach back and wipe a copy made before the value was
//! wrapped. A `String` that was cloned at the boundary where it entered the
//! process is a plain `String` for as long as it lives, so the value is
//! wrapped *at* that boundary rather than after it.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

/// A value that is wiped from memory when it is dropped, and that never
/// prints itself.
///
/// Wiping is `zeroize`'s: a volatile write the compiler is not allowed to
/// optimize away, so the bytes really are gone rather than merely
/// unreachable. The type itself is a thin wrapper — what it adds is the
/// guarantee, and the fact that the guarantee cannot be forgotten.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value, from here on.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The value, for the code that has to use it.
    ///
    /// Reading a secret is a decision rather than an accident, so it is spelled
    /// out: there is no `Deref`, and every read in this tree says
    /// `expose_secret` where it happens. A grep for that word is the list of
    /// the places a credential is handled.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// The value, copied out.
    ///
    /// The copy is a plain value again — nothing wipes it when this one is
    /// dropped, and the caller owns it from here on. This is the door out of
    /// the type, for the places where a credential genuinely has to leave:
    /// onto the wire, into a config file, or over JNI to the Android app.
    pub fn expose_secret_cloned(&self) -> T
    where
        T: Clone,
    {
        T::clone(&self.0)
    }
}

impl Secret<String> {
    /// The value as text, without copying it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Secret<Vec<u8>> {
    /// The value as bytes, without copying it.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<T> From<T> for Secret<T>
where
    T: Zeroize,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Redacted, always.
///
/// Not the value, not its length, not anything that varies with it: the point
/// of this type is that a `Debug` cannot leak what it holds, so a struct that
/// derives one and holds a `Secret` cannot leak it either.
impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Serialized exactly as the value it wraps.
///
/// The config file and the wire format are unchanged by this type: it changes
/// where the bytes live, not what they say. A `[auth]` section written by
/// this build is byte for byte the one the previous build wrote.
impl<T> Serialize for Secret<T>
where
    T: Zeroize + Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        T::serialize(&self.0, serializer)
    }
}

/// Deserialized into a value that is wiped when it goes out of scope.
///
/// The value is read straight into the wrapper — serde allocates it, and the
/// allocation is handed to [`Secret`] rather than copied — so there is no
/// unwiped intermediate to clean up afterwards.
impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: Zeroize + Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Secret::new)
    }
}

/// A secret as text — a TOTP seed, an enrollment token, a bearer.
pub type SecretString = Secret<String>;

/// A secret as bytes — a decoded TOTP seed.
pub type SecretBytes = Secret<Vec<u8>>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A value that records being wiped.
    ///
    /// The point of a wipe is that it happens, and the only way to show that
    /// without poking at freed memory is to let the value say so. A `String`
    /// cannot report its own zeroing, so this stands in for one.
    #[derive(Clone)]
    struct Spy(Arc<AtomicBool>);

    impl Zeroize for Spy {
        fn zeroize(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// The whole point of the type: a secret that goes out of scope leaves
    /// nothing behind.
    #[test]
    fn a_dropped_secret_is_wiped() {
        let wiped = Arc::new(AtomicBool::new(false));
        {
            let _secret = Secret::new(Spy(wiped.clone()));
            assert!(
                !wiped.load(Ordering::SeqCst),
                "the value is still readable while it is alive"
            );
        }
        assert!(
            wiped.load(Ordering::SeqCst),
            "the value survived its own scope"
        );
    }

    /// A `Debug` is what a log line, a panic message and a bug report are made
    /// of, so a secret that prints itself is a secret in every one of them.
    #[test]
    fn a_secret_never_prints_its_value() {
        let rendered = format!("{:?}", Secret::new("JBSWY3DPEHPK3PXP".to_string()));
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// A struct that derives `Debug` and holds a secret is the case that made
    /// this type necessary: nobody wrote a `Debug` for it, and nobody has to.
    #[test]
    fn a_derived_debug_cannot_leak_a_secret_it_holds() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: String,
            secret: SecretString,
        }

        let holder = Holder {
            name: "alice".to_string(),
            secret: Secret::new("JBSWY3DPEHPK3PXP".to_string()),
        };
        let rendered = format!("{holder:?}");

        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
        assert!(rendered.contains("alice"), "{rendered}");
    }

    /// The config file and the wire format are unchanged by this type: it
    /// changes where the bytes live, not what they say.
    #[test]
    fn a_secret_serializes_as_the_value_it_wraps() {
        let secret = Secret::new("JBSWY3DPEHPK3PXP".to_string());
        assert_eq!(
            serde_json::to_string(&secret).expect("serializable"),
            "\"JBSWY3DPEHPK3PXP\""
        );

        let back: SecretString =
            serde_json::from_str("\"JBSWY3DPEHPK3PXP\"").expect("deserializable");
        assert_eq!(back.as_str(), "JBSWY3DPEHPK3PXP");
    }

    /// Reading a secret is a decision, and the type says so out loud: there is
    /// no `Deref`, so every read in the tree is a place a reviewer can look.
    #[test]
    fn a_secret_is_read_through_its_explicit_door() {
        let secret = Secret::new("JBSWY3DPEHPK3PXP".to_string());
        assert_eq!(secret.expose_secret(), "JBSWY3DPEHPK3PXP");
        assert_eq!(secret.as_str(), "JBSWY3DPEHPK3PXP");
    }

    /// A clone is a second copy with a second wipe: it is not a hole in the
    /// type, it is the same promise made twice.
    #[test]
    fn a_cloned_secret_is_wiped_too() {
        let wiped = Arc::new(AtomicBool::new(false));
        {
            let secret = Secret::new(Spy(wiped.clone()));
            let _clone = secret.clone();
        }
        assert!(wiped.load(Ordering::SeqCst));
    }
}
