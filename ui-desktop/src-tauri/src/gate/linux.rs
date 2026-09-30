//! The Linux door: PAM, with a password the UI collects.
//!
//! Linux has no system prompt of its own to borrow — nothing that answers for
//! the user the way macOS's Authorization Services sheet or Windows Hello does — so the
//! question goes to PAM, which is the one answer every distribution agrees on.
//! What it does not come with is a dialog, so unlike the other two platforms
//! this one asks the UI to collect the password and hands it over; see
//! [`OsGate::needs_password`].
//!
//! The password is the user's own and it goes to PAM and nowhere else: it is
//! not written to the store, not logged, and zeroed as soon as the answer comes
//! back. It does cross the renderer to get here, which is the cost of there
//! being nothing else to ask, and the reason this module exists rather than a
//! refusal.

use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use zeroize::Zeroizing;

use super::{Capability, OsGate, Outcome};

/// The PAM service the logged-in user is authenticated against.
///
/// Every desktop distribution ships `login`, and it is the one that answers for
/// the account already using the machine: `pam_unix` checks the password
/// through the setuid `unix_chkpwd` helper, which is what lets a process with
/// no privileges of its own verify the password of the user it runs as. A
/// service name of our own would be answered by `other`, which on Debian is
/// `pam_deny`.
const SERVICE: &str = "login";

pub struct Pam;

impl OsGate for Pam {
    fn capability(&self) -> Capability {
        // Whether the stack can be opened at all — not whether a given password
        // is right, which is `authenticate`'s answer and the user's to get
        // wrong. The conversation is the null one because nothing is being
        // asked yet: a module that wanted an answer here would be refused.
        match Context::new(SERVICE, None, pam_client2::conv_null::Conversation::new()) {
            Ok(_) => Capability::Available,
            Err(error) => {
                tracing::warn!("PAM cannot open the {SERVICE} stack: {error}");
                Capability::Unavailable
            }
        }
    }

    fn confirm(&self, _reason: &str, password: Option<&str>) -> Outcome {
        let Some(password) = password else {
            return Outcome::Failed("no password was supplied".to_string());
        };
        let Some(user) = current_user() else {
            // Nobody to authenticate, so nothing can be confirmed.
            return Outcome::Unavailable;
        };

        let result = Context::new(
            SERVICE,
            Some(&user),
            Conversation {
                password: Zeroizing::new(password.to_string()),
                user: user.clone(),
            },
        )
        .and_then(|mut context| context.authenticate(Flag::NONE));

        match result {
            Ok(()) => Outcome::Unlocked,
            Err(error) => match error.code() {
                // Asked, and the answer was no: wrong password, or the account
                // is not allowed to authenticate. Nothing to report.
                ErrorCode::AUTH_ERR
                | ErrorCode::PERM_DENIED
                | ErrorCode::MAXTRIES
                | ErrorCode::CRED_INSUFFICIENT
                | ErrorCode::AUTHTOK_ERR
                | ErrorCode::CRED_ERR => Outcome::Refused,
                // Nothing here to ask: no such user, no stack to ask through, a
                // module that could not be loaded, no way to talk to the user.
                ErrorCode::USER_UNKNOWN
                | ErrorCode::AUTHINFO_UNAVAIL
                | ErrorCode::SYSTEM_ERR
                | ErrorCode::SERVICE_ERR
                | ErrorCode::MODULE_UNKNOWN
                | ErrorCode::CONV_ERR
                | ErrorCode::CRED_UNAVAIL
                | ErrorCode::ABORT => Outcome::Unavailable,
                _ => Outcome::Failed(format!("{error}")),
            },
        }
    }

    fn needs_password(&self) -> bool {
        true
    }
}

/// Who the app is running as, which is who has to be authenticated.
///
/// Read from the process rather than from the environment. `USER` and `LOGNAME`
/// are whatever whoever started the app said they were, so a process launched
/// with `USER=somebody-else` would have this ask PAM to authenticate an account
/// it is not running as — and a password that is not the user's would open the
/// door. A uid cannot be handed in from outside.
fn current_user() -> Option<String> {
    // SAFETY: `geteuid` cannot fail, and `getpwuid_r` is given exactly what it
    // returned. The reentrant form rather than `getpwuid` because that one
    // answers out of storage libc owns and reuses: `confirm` runs on a blocking
    // task and nothing serialises two of them, so two readers could be handed
    // the same struct. Everything here is owned by this call — the entry, and
    // the buffer its strings point into.
    unsafe {
        let mut buffer_len = 1024_usize;
        loop {
            let mut buffer = vec![0_u8; buffer_len];
            let mut entry = MaybeUninit::<libc::passwd>::uninit();
            let mut result = std::ptr::null_mut();

            // Unlike `getpwuid`, this returns the error number rather than
            // setting `errno`, and it reports a uid with no entry as `0` with a
            // null result — which is "no such user", not "out of memory".
            let error = libc::getpwuid_r(
                libc::geteuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            );

            if error == libc::ERANGE {
                buffer_len = buffer_len.checked_mul(2)?;
                continue;
            }
            if error != 0 || result.is_null() {
                return None;
            }

            let entry = entry.assume_init();
            if entry.pw_name.is_null() {
                return None;
            }
            let name = CStr::from_ptr(entry.pw_name);
            let name = name.to_str().ok()?.to_string();
            return (!name.is_empty()).then_some(name);
        }
    }
}

/// Answers PAM's questions from what the UI collected.
struct Conversation {
    /// The password the user typed. Answers every prompt that must not be
    /// echoed, which is what a password prompt is.
    password: Zeroizing<String>,
    /// The account being authenticated. PAM asks for it when it wants the name
    /// confirmed; it is echoed, which is why it is not the password.
    user: String,
}

impl ConversationHandler for Conversation {
    fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        CString::new(self.user.as_str()).map_err(|_| ErrorCode::CONV_ERR)
    }

    fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        CString::new(self.password.as_str()).map_err(|_| ErrorCode::CONV_ERR)
    }

    fn text_info(&mut self, _msg: &CStr) {}

    fn error_msg(&mut self, _msg: &CStr) {}
}
