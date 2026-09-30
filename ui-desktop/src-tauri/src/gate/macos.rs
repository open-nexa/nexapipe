//! The macOS door: Authorization Services, and the sheet it brings with it.
//!
//! The keychain is the wrong instrument for this. An item there is *data*, and
//! reading one is a question macOS answers with a sheet of its own about that
//! item — at startup, again whenever the app's signature changes, and once more
//! for every prompt — which is how one unlock turned into two. What opens this
//! door is Authorization Services instead: the framework a System Settings pane
//! uses to put a lock on a page. It asks the Security Server for a right, and
//! the Security Server is what puts the familiar sheet on the screen.
//!
//! That leaves macOS like Windows and unlike Linux: the operating system brings
//! the dialog, so no password crosses the renderer and
//! [`OsGate::needs_password`] stays false. What is asked for is a *right*
//! rather than a credential, and the right is `system.privilege.admin` —
//! `kAuthorizationRightExecute`, the one `AuthorizationExecuteWithPrivileges`
//! asks for — because it is the right every macOS install defines with
//! `authenticate-user` turned on, so asking for it is what makes the system ask
//! the user. Nothing is executed and nothing is granted: the answer is taken as
//! a yes or a no, and the right is dropped on the way out.
//!
//! Why this right and not another authenticate-user one: the policy database
//! defines it with `shared = false`, so a credential is never reused across
//! authorization references — and `confirm` builds a fresh reference every
//! time, which is what brings the sheet back on every call. A shared right
//! such as `system.preferences` is the trap: its credential lives in the
//! session for its timeout (five minutes), and any authentication that landed
//! there — an unlock of System Settings counts — lets a later request through
//! without a sheet at all.
//!
//! Two consequences worth writing down:
//!
//! - The right is revoked as soon as it has been granted, so the sheet comes
//!   back every time. A right left standing stays valid for its timeout —
//!   minutes — and a granted admin right is a thing another process could ask
//!   to share.
//! - `system.privilege.admin` is defined for the `admin` group, so an account
//!   that is not an administrator is refused. A right of our own would have to
//!   be written into the policy database, which only root may do; a Mac whose
//!   user is not an administrator is not one this app got installed on by
//!   accident.

use security_framework::authorization::{
    Authorization as OsAuthorization, AuthorizationItemSetBuilder, Flags,
};
use security_framework::base::Error;
// The status codes are not part of the safe wrapper, only of the bindings under
// it, and "the user dismissed the sheet" is worth telling apart from "the
// machine has nothing to ask with". Renamed on the way in, because they arrive
// with the framework's own spelling of a constant.
use security_framework_sys::authorization::{
    errAuthorizationCanceled as CANCELED, errAuthorizationDenied as DENIED,
    errAuthorizationInteractionNotAllowed as INTERACTION_NOT_ALLOWED,
};

use super::{Capability, OsGate, Outcome};

/// The right asked for, which is only a way of being asked: see the module docs.
const RIGHT: &str = "system.privilege.admin";

/// The environment item that puts the caller's own words in the sheet, so it
/// says which credential is about to be shown rather than "wants to make
/// changes".
const PROMPT: &str = "prompt";

pub struct Authorization;

impl OsGate for Authorization {
    fn capability(&self) -> Capability {
        // Whether the right is defined at all — a question about the machine,
        // not to the user: reading the policy database puts nothing on the
        // screen, so this can be asked at startup without being a prompt.
        match OsAuthorization::right_exists(RIGHT) {
            Ok(true) => Capability::Available,
            Ok(false) => {
                tracing::warn!("Authorization Services does not define the {RIGHT} right");
                Capability::Unavailable
            }
            Err(error) => {
                tracing::warn!("the {RIGHT} right could not be read: {error}");
                Capability::Unavailable
            }
        }
    }

    fn confirm(&self, reason: &str, _password: Option<&str>) -> Outcome {
        let rights = match AuthorizationItemSetBuilder::new().add_right(RIGHT) {
            Ok(rights) => rights.build(),
            Err(error) => return failed(error),
        };
        let environment = match AuthorizationItemSetBuilder::new().add_string(PROMPT, reason) {
            Ok(environment) => environment.build(),
            Err(error) => return failed(error),
        };

        // Interaction is what puts the sheet on the screen, and extending is
        // what makes the Security Server try to grant the right rather than only
        // describe what granting it would take. Destroying it is the flag that
        // matters here: a granted right outlives this call by minutes otherwise,
        // and the answer was the point, not the right.
        let flags = Flags::INTERACTION_ALLOWED | Flags::EXTEND_RIGHTS | Flags::DESTROY_RIGHTS;

        match OsAuthorization::new(Some(rights), Some(environment), flags) {
            // Asked, and the Security Server granted it. The right is dropped
            // with the reference rather than held: the window this opens is
            // [`super::UNLOCK_WINDOW`] of memory, not five minutes of a granted
            // admin right.
            Ok(_) => Outcome::Unlocked,
            Err(error) => outcome_for(error),
        }
    }
}

/// What a no from the Security Server means, in the door's own words.
///
/// The message is the framework's, taken from `SecCopyErrorMessageString` when
/// it has one and from its `Display` when it does not: what went wrong is
/// Security Server's to say, not this module's to guess at.
fn failed(error: Error) -> Outcome {
    Outcome::Failed(error.message().unwrap_or_else(|| error.to_string()))
}

fn outcome_for(error: Error) -> Outcome {
    match error.code() {
        // The sheet was put up and dismissed. Asked, and the answer was no.
        CANCELED => Outcome::Refused,
        // Asked and not granted. Wrong passwords are the sheet's own business —
        // it shakes and asks again, and does not come back here — so what is
        // left is an account the right is not defined for.
        DENIED => Outcome::Refused,
        // There is nowhere to put a sheet: no GUI session to put one in, which
        // is what an app started over ssh or before login has.
        INTERACTION_NOT_ALLOWED => Outcome::Unavailable,
        // Anything else is the Security Server failing, and its own words are
        // worth more than anything this module would say.
        _ => failed(error),
    }
}
