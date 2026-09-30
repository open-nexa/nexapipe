//! The macOS door: a keychain item only the user can read.
//!
//! Rather than a second, parallel notion of "who is at the keyboard", the gate
//! is a keychain item whose access control requires user presence. Asking is
//! reading: `SecItemCopyMatching` against an item protected that way makes the
//! system put up its own prompt — Touch ID where there is a sensor, the account
//! password otherwise — and fails when the user does not answer it. The prompt,
//! its wording, its lockout behaviour and its language are the system's, which
//! is the whole point of asking the system.
//!
//! The one thing that is not the system's is *what* is being unlocked: the
//! `reason` the caller passes cannot be put on a keychain prompt, so the item
//! carries a fixed label and the UI says what is about to be shown before it
//! asks.

use security_framework::access_control::SecAccessControl;
use security_framework::passwords;
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

use super::{Capability, OsGate, Outcome};

/// Where the sentinel is filed.
///
/// Not the credential store: this item is not a secret, and keeping it apart
/// means a reset of one does not affect the other.
const SERVICE: &str = "nexa";
const ACCOUNT: &str = "credential-gate";

/// What is stored. Nothing reads it — the value that matters is whether the
/// read was allowed at all.
const SENTINEL: &[u8] = b"present";

/// `errSecDuplicateItem`: already filed, which is the outcome wanted.
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
/// `errSecUserCanceled`: the prompt was dismissed.
const ERR_SEC_USER_CANCELED: i32 = -128;
/// `errSecAuthFailed`: what was presented was not accepted.
const ERR_SEC_AUTH_FAILED: i32 = -25293;
/// `errSecInteractionNotAllowed`: there is no session to put a prompt in — a
/// headless login, or a lockout still running.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

pub struct Keychain;

impl Keychain {
    /// Files the sentinel, unless it is already there.
    ///
    /// Adding an item whose access control requires user presence does not
    /// itself ask anything, so this is how "can this Mac confirm its user" is
    /// answered without putting a prompt on the screen: a machine with no
    /// passcode and no biometrics cannot hold the item at all.
    fn file() -> Result<(), security_framework::base::Error> {
        let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        options.set_label("Nexa credentials");
        options.set_access_control(SecAccessControl::create_with_flags(
            AccessControlOptions::USER_PRESENCE.bits(),
        )?);
        passwords::set_generic_password_options(SENTINEL, options)
    }
}

impl OsGate for Keychain {
    fn capability(&self) -> Capability {
        match Self::file() {
            Ok(()) => Capability::Available,
            // Filed on an earlier launch; asking is still possible.
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => Capability::Available,
            Err(error) => {
                tracing::warn!(
                    "macOS cannot hold a keychain item that requires the user: {}",
                    error
                );
                Capability::Unavailable
            }
        }
    }

    fn confirm(&self, _reason: &str, _password: Option<&str>) -> Outcome {
        // Blocks for as long as the prompt is up, which is why the caller runs
        // this on a blocking task rather than on the async runtime.
        match passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(_) => Outcome::Unlocked,
            Err(error) => match error.code() {
                // Dismissed, or not recognised. Neither is worth a message: the
                // user was asked and the answer was no.
                ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => Outcome::Refused,
                // Nothing on screen to ask on, so nothing can be shown.
                ERR_SEC_INTERACTION_NOT_ALLOWED => Outcome::Unavailable,
                _ => Outcome::Failed(
                    error
                        .message()
                        .unwrap_or_else(|| format!("keychain error {}", error.code())),
                ),
            },
        }
    }
}
