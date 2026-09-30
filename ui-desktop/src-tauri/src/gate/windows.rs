//! The Windows door: Windows Hello where there is one, the account password
//! otherwise.
//!
//! Hello is the right question to ask on a machine that has it — it is the
//! thing the user already uses to unlock the machine, and its prompt, its
//! lockout and its language are Windows'. Where it is not there, the fallback
//! is the account password checked by `LogonUserW`, which is the same
//! credential Windows Hello is built on.
//!
//! Windows Hello is a WinRT API and therefore asynchronous, but there is no
//! async down here: this module runs on a blocking task and waits the prompt
//! out. What makes that safe is the apartment — a multithreaded one, so the
//! completion handler runs on the threadpool rather than on the thread that is
//! waiting for it.

use std::sync::mpsc;

use windows::core::RuntimeType;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
// Not `Win32::Security::Authentication::Identity`, where the logon helpers used
// to sit before this version of the bindings moved them: `LogonUserW` is
// directly under `Win32::Security`, and it writes the token through an out
// parameter rather than returning it.
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, LogonUserW, TokenUser, LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_future::{AsyncOperationCompletedHandler, IAsyncOperation};

use super::{Capability, OsGate, Outcome};

pub struct Hello;

impl Hello {
    /// Whether Windows Hello can be asked on this machine.
    ///
    /// False is not the end of the door: it means the account password is what
    /// is left to ask, and [`OsGate::needs_password`] says so.
    fn available() -> bool {
        apartment();

        let operation = match UserConsentVerifier::CheckAvailabilityAsync() {
            Ok(operation) => operation,
            Err(error) => {
                tracing::debug!("Windows Hello availability could not be read: {error}");
                return false;
            }
        };

        match finish(operation) {
            Ok(availability) => availability == UserConsentVerifierAvailability::Available,
            Err(error) => {
                tracing::debug!("Windows Hello availability could not be read: {error}");
                false
            }
        }
    }

    /// Puts up the Hello prompt and waits for it.
    fn hello(reason: &str) -> Outcome {
        apartment();

        let operation = match UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
        {
            Ok(operation) => operation,
            Err(error) => return Outcome::Failed(format!("{error}")),
        };

        match finish(operation) {
            Ok(UserConsentVerificationResult::Verified) => Outcome::Unlocked,
            // Dismissed, or the wrong face or finger too many times.
            Ok(UserConsentVerificationResult::Canceled) => Outcome::Refused,
            Ok(UserConsentVerificationResult::RetriesExhausted) => Outcome::Refused,
            // Nothing enrolled and nothing configured: there is nothing to ask.
            Ok(UserConsentVerificationResult::DeviceNotPresent) => Outcome::Unavailable,
            Ok(UserConsentVerificationResult::NotConfiguredForUser) => Outcome::Unavailable,
            Ok(UserConsentVerificationResult::DisabledByPolicy) => Outcome::Unavailable,
            Ok(UserConsentVerificationResult::DeviceBusy) => {
                Outcome::Failed("Windows Hello is busy".to_string())
            }
            Ok(_) => Outcome::Refused,
            Err(error) => Outcome::Failed(format!("{error}")),
        }
    }

    /// Checks the password the UI collected against the account it belongs to.
    ///
    /// That account is the one this process is running as, read from its token
    /// rather than from the environment — see [`current_account`]. Authenticating
    /// some other account would open a door that was meant to open for one.
    ///
    /// An interactive logon rather than a network one because that is the check
    /// the lock screen makes; no token is kept, so nothing is held open by it.
    fn password(password: Option<&str>) -> Outcome {
        let Some(password) = password else {
            return Outcome::Failed("no password was supplied".to_string());
        };

        let (user, domain) = match current_account() {
            Some(account) => account,
            None => return Outcome::Failed("the account to authenticate is unknown".to_string()),
        };

        let user = HSTRING::from(user);
        let domain = HSTRING::from(domain);
        let password = HSTRING::from(password);

        // The handle is an out parameter: the call returns whether the logon
        // succeeded, and the token it opened comes back through `token`.
        let mut token = HANDLE::default();
        let result = unsafe {
            LogonUserW(
                PCWSTR(user.as_ptr()),
                PCWSTR(domain.as_ptr()),
                PCWSTR(password.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };

        match result {
            // An open handle to a token nobody asked for; it is closed at once
            // so a successful check leaves nothing behind.
            Ok(()) => {
                let closed = unsafe { CloseHandle(token) };
                if let Err(error) = closed {
                    tracing::debug!("the logon token could not be closed: {error}");
                }
                Outcome::Unlocked
            }
            Err(error) => {
                // A wrong password is a refusal, not a failure: the user was
                // asked and the answer was no.
                tracing::debug!("the account password was not accepted: {error}");
                Outcome::Refused
            }
        }
    }
}

/// A token handle that closes itself.
///
/// The token is opened to read one answer out of it, and an early return is a
/// normal outcome down here. A handle left open until the process exits is a
/// handle held for nothing, which is why closing is tied to the scope rather
/// than to the paths that happen to reach the end.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            tracing::debug!("a token handle could not be closed: {error}");
        }
    }
}

/// The account this process is running as, and the authority it belongs to.
///
/// Read out of the process token rather than from the environment. `USERNAME`
/// and `USERDOMAIN` are whatever whoever started the app said they were, so a
/// process launched with `USERNAME=somebody-else` asked Windows to authenticate
/// an account it is not running as — and a password that was not the user's
/// opened the door. The token is the process's own answer to who it is, and it
/// cannot be handed in from outside, which is the same reason the Linux gate
/// reads the effective uid.
///
/// `None` when any part of it cannot be read. The caller makes that a failure
/// rather than something weaker.
fn current_account() -> Option<(String, String)> {
    // SAFETY: `GetCurrentProcess` hands back a pseudo-handle that is not to be
    // closed, and the token opened from it is — which `TokenHandle` does.
    unsafe {
        let mut handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle).ok()?;
        let token = TokenHandle(handle);

        // Twice, because `TokenUser` is not the fixed-size answer the struct
        // suggests: Windows writes the variable-length SID *behind* the
        // `TOKEN_USER` it hands back, and `User.Sid` points into that same
        // buffer. One the size of the struct alone is therefore always too
        // small, the call reports that rather than answering, and the SID is
        // never reached. The first call is what says how much is needed.
        let mut needed = 0u32;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        // `u64` storage, so the buffer is aligned the way `TOKEN_USER` has to
        // be. It outlives the SID below: that pointer points into it, and is
        // read only while it is still alive.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .ok()?;
        let sid = (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid;

        // Twice, because the first call reports how long the two names are:
        // that is what the insufficient-buffer answer means here, not a failure
        // to look the SID up.
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_use = SID_NAME_USE(0);
        if LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_use,
        )
        .is_ok()
        {
            return None;
        }
        // Only the name is demanded. A SID Windows reports no authority for is
        // one `LogonUserW` is given `.` for below, and refusing it here would
        // leave that fallback unreachable.
        if name_len == 0 {
            return None;
        }

        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let domain_ptr = if domain.is_empty() {
            None
        } else {
            Some(PWSTR(domain.as_mut_ptr()))
        };
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            domain_ptr,
            &mut domain_len,
            &mut sid_use,
        )
        .ok()?;

        let name = wide_to_string(&name);
        if name.is_empty() {
            return None;
        }
        // A standalone machine names itself as the authority, and `LogonUserW`
        // accepts that; `.`, the guess made here before, is the local database
        // and is the wrong one for a local account on a machine that knows its
        // own name.
        let domain = wide_to_string(&domain);
        let domain = if domain.is_empty() {
            ".".to_string()
        } else {
            domain
        };

        Some((name, domain))
    }
}

/// Reads a NUL-terminated wide string out of a buffer Windows filled.
///
/// Cut at the terminator rather than at the reported length: the two disagree
/// about whether the terminator is counted, and stopping at the first NUL is
/// right either way.
fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

impl OsGate for Hello {
    fn capability(&self) -> Capability {
        // The account password is always something to ask, so a machine without
        // Hello is not a machine that cannot confirm its user.
        Capability::Available
    }

    /// The branch follows what the caller collected, not a second look at
    /// whether Hello is there.
    ///
    /// [`OsGate::needs_password`] already asked, and asking again can answer
    /// differently: the check is a WinRT call, and a machine can lose Hello
    /// between it and this. Taking the second answer at face value produced
    /// `Failed("no password was supplied")` — a machine that does have a way to
    /// confirm its user reported itself as broken, and the UI had no answer
    /// because nothing had changed as far as it could tell. A password that
    /// arrived means Hello was not there a moment ago, and it authenticates the
    /// user either way; a machine that has grown a Hello since is not one this
    /// password stopped working on.
    fn confirm(&self, reason: &str, password: Option<&str>) -> Outcome {
        match password {
            Some(_) => Self::password(password),
            None => Self::hello(reason),
        }
    }

    fn needs_password(&self) -> bool {
        !Self::available()
    }
}

/// Gives this thread a COM apartment, once, and keeps it.
///
/// WinRT activation needs one. It is not revoked afterwards: a thread in the
/// blocking pool is reused for the life of the process, and revoking an
/// apartment this thread did not exclusively ask for would break whatever else
/// on it has already asked.
fn apartment() {
    std::thread_local! {
        static APARTMENT: bool = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
    }
    APARTMENT.with(|_| ());
}

/// Waits a WinRT operation out and hands back its result.
///
/// The handler is what makes this safe to wait on: on a multithreaded apartment
/// it is invoked on a threadpool thread, so the thread blocked in `recv` is not
/// the thread the completion needs. On a single-threaded one it would be, and
/// this would wait forever.
fn finish<T: RuntimeType + 'static>(operation: IAsyncOperation<T>) -> windows::core::Result<T> {
    let (sender, receiver) = mpsc::channel::<()>();

    operation.SetCompleted(&AsyncOperationCompletedHandler::new(
        move |_operation, _status| {
            let _ = sender.send(());
            Ok(())
        },
    ))?;

    let _ = receiver.recv();
    operation.GetResults()
}
