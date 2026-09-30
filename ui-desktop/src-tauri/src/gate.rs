//! The door in front of the credentials this app holds.
//!
//! `credentials` seals them at rest under a key the operating system holds, and
//! `credentials::mask` keeps a whole value off the screen unless the user asks
//! for it. Neither asks *who* is asking. The store is open for as long as the
//! login session is, so anyone at the keyboard could read a TOTP secret; this
//! is that question, and it is the last piece of R14 on the desktop.
//!
//! Authentication is delegated to the operating system and to nothing else.
//! There is deliberately no app password — a credential of its own would be one
//! more thing to forget, reset and attack — so what gates the surfaces is the
//! same thing that gates the device: Authorization Services on macOS and Windows
//! Hello on Windows, each of which brings its own prompt, and PAM on Linux,
//! which has none and so is handed a password the UI collected.
//!
//! Two rules shape the rest of the code, both inherited from the Android app's
//! `CredentialGate`, which is the same door on another platform:
//!
//! - **A device with nothing to authenticate against is refused, not
//!   downgraded.** Showing a secret because the device cannot ask is the one
//!   outcome this module exists to prevent.
//! - **The unlock is a window, not a mode.** It lives in memory for
//!   [`UNLOCK_WINDOW`] and dies with the process. It is never persisted and
//!   never handed to the service, which has to keep being able to reopen its
//!   endpoints after a reboot with nobody at the keyboard.

use serde::Serialize;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

/// How long one successful authentication keeps the credential surfaces open.
///
/// Short enough that a laptop walked away from does not stay unlocked, long
/// enough that reading one secret does not mean authenticating twice. The same
/// two minutes the Android app uses, for the same reason.
pub const UNLOCK_WINDOW: Duration = Duration::from_secs(2 * 60);

/// Whether this device can confirm the user at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// The operating system has something to ask: a biometric, a password, a
    /// PAM stack.
    Available,
    /// It does not. Every surface stays shut — there is nothing to ask, and
    /// "cannot ask" is not permission.
    Unavailable,
}

/// What asking the operating system came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The user confirmed, and the window is open.
    Unlocked,
    /// The user was asked and did not confirm: dismissed the prompt, or gave a
    /// password that was not accepted. Not an error; nothing is said.
    Refused,
    /// The device has nothing to ask with. The UI has to say so, because the
    /// credential is unreachable until the device can confirm anybody.
    Unavailable,
    /// The OS side failed in a way worth reporting, in the OS's own words.
    Failed(String),
}

/// What the operating system has to answer for the door to work at all.
///
/// A trait rather than three functions with the same names so the contract is
/// written down once: this is everything the gate needs from a platform, and a
/// platform that cannot answer one of these is not one the gate can use.
pub trait OsGate {
    /// Whether this device can confirm the user at all.
    fn capability(&self) -> Capability;

    /// Asks the operating system to confirm the user. Blocking: every platform
    /// prompt is a modal the caller has to wait out, so this is called from a
    /// blocking task rather than on the async runtime.
    fn confirm(&self, reason: &str, password: Option<&str>) -> Outcome;

    /// Whether the UI has to collect a password before it can ask.
    ///
    /// False where the operating system brings its own prompt. True where it
    /// does not — PAM has no dialog of its own — and on Windows when Hello is
    /// not there to ask, which leaves the account password.
    fn needs_password(&self) -> bool {
        false
    }
}

/// The door this platform provides.
///
/// One function per platform rather than a type alias, because a type alias
/// names a type and this has to hand back a value.
#[cfg(target_os = "macos")]
pub fn os() -> macos::Authorization {
    macos::Authorization
}

/// The door this platform provides.
#[cfg(target_os = "windows")]
pub fn os() -> windows::Hello {
    windows::Hello
}

/// The door this platform provides.
#[cfg(target_os = "linux")]
pub fn os() -> linux::Pam {
    linux::Pam
}

/// The door this platform provides.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn os() -> unsupported::Absent {
    unsupported::Absent
}

/// Whether the window that ends at `until` is still open at `now`.
///
/// Split out of [`Window::is_open`] so the rule is testable without a clock and
/// without an operating system — the same reason the Android app's
/// `CredentialGate.isUnlockedAt` takes both times as arguments. An absent end
/// is a gate nobody has opened, which is shut.
pub fn is_unlocked_at(now: Instant, until: Option<Instant>) -> bool {
    match until {
        Some(until) => until > now,
        None => false,
    }
}

/// The window one authentication opens, and the only thing the gate remembers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Window {
    ends_at: Option<Instant>,
}

impl Window {
    /// Whether the window is still open at `now`.
    pub fn is_open(&self, now: Instant) -> bool {
        is_unlocked_at(now, self.ends_at)
    }

    /// Opens a whole window from `now`. Authenticating again near the end of
    /// one must not leave less time than authenticating at the start of one,
    /// so this is always `now + UNLOCK_WINDOW` and never `ends_at + something`.
    pub fn open(&mut self, now: Instant) {
        self.ends_at = Some(now + UNLOCK_WINDOW);
    }

    /// Closes it, without waiting for it to lapse.
    pub fn close(&mut self) {
        self.ends_at = None;
    }

    /// How much of the window is left at `now`. Zero when it is shut, and zero
    /// rather than a negative duration when it has already lapsed.
    pub fn remaining(&self, now: Instant) -> Duration {
        match self.ends_at {
            Some(ends_at) if ends_at > now => ends_at - now,
            _ => Duration::ZERO,
        }
    }
}

static GATE: LazyLock<Mutex<Window>> = LazyLock::new(|| Mutex::new(Window::default()));

/// Runs `f` against the window.
///
/// A poisoned mutex still holds the right answer: the window is one timestamp,
/// and a panic while it was held does not make it wrong.
fn with_window<R>(f: impl FnOnce(&mut Window) -> R) -> R {
    let mut guard = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// Whether credentials may be shown right now.
pub fn is_unlocked() -> bool {
    with_window(|window| window.is_open(Instant::now()))
}

/// Opens the window for [`UNLOCK_WINDOW`] from now.
pub fn unlock() {
    with_window(|window| window.open(Instant::now()));
}

/// Closes the window again.
pub fn lock() {
    with_window(|window| window.close());
}

/// What the UI needs to draw the door, read as one snapshot so the countdown
/// and the button cannot disagree.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Whether credentials may be shown right now.
    pub unlocked: bool,
    /// Milliseconds left in the window. Zero when it is shut, so the UI can
    /// tick a countdown of its own instead of asking again every second.
    pub ms_remaining: u64,
    /// Whether the device can confirm the user at all.
    pub can_authenticate: bool,
    /// Whether the UI has to collect a password before it can ask.
    pub needs_password: bool,
}

/// The door as a surface sees it.
///
/// It re-reads what the device can do, which is what makes this the one call
/// the UI has to make when it comes back into view: the window is two minutes
/// of memory and nothing checks it while it runs, so a machine that lost the
/// ability to ask — a password removed, a fingerprint deleted, a Hello enrolment
/// gone — must not keep a door open that nobody can confirm.
pub fn status() -> Status {
    let capability = os().capability();
    if capability == Capability::Unavailable {
        lock();
    }

    let needs_password = os().needs_password();
    let now = Instant::now();

    with_window(|window| Status {
        unlocked: window.is_open(now),
        ms_remaining: window.remaining(now).as_millis() as u64,
        can_authenticate: capability == Capability::Available,
        needs_password,
    })
}

/// Asks the operating system to confirm the user, and opens the window if it does.
///
/// `reason` is what the prompt says it is for, in the user's language: the
/// caller knows which credential is about to be shown and the gate does not.
/// `password` is what [`OsGate::needs_password`] asked the UI to collect; it is
/// `None` on the platforms that bring their own prompt.
pub fn confirm(reason: &str, password: Option<&str>) -> Outcome {
    let outcome = os().confirm(reason, password);
    if outcome == Outcome::Unlocked {
        unlock();
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::{is_unlocked_at, Window, UNLOCK_WINDOW};
    use std::time::{Duration, Instant};

    /// The gate, off-device.
    ///
    /// What can be pinned down here is the window and nothing else: whether a
    /// Mac has Touch ID or a Linux box has a PAM stack is an answer from the
    /// machine, and what a system prompt does with the result is an answer from
    /// the system. The window is the part worth being precise about — it is the
    /// difference between "authenticated two minutes ago" and "authenticated".
    fn start() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_gate_nobody_has_opened_is_shut() {
        assert!(
            !is_unlocked_at(start(), None),
            "a fresh gate must not be open"
        );
        assert!(!Window::default().is_open(start()));
    }

    /** The window is a duration, so the instant it ends has to be outside it. */
    #[test]
    fn the_window_is_closed_at_the_moment_it_ends() {
        let opened_at = start();
        let ends_at = opened_at + UNLOCK_WINDOW;

        assert!(
            !is_unlocked_at(ends_at, Some(ends_at)),
            "the last instant of the window is not in it"
        );
        assert!(
            is_unlocked_at(ends_at - Duration::from_millis(1), Some(ends_at)),
            "one instant earlier still is"
        );
    }

    #[test]
    fn unlocking_opens_the_window_and_locking_closes_it() {
        let opened_at = start();
        let mut window = Window::default();
        window.open(opened_at);

        assert!(window.is_open(opened_at + UNLOCK_WINDOW - Duration::from_millis(1)));
        assert!(!window.is_open(opened_at + UNLOCK_WINDOW));

        window.close();
        assert!(
            !window.is_open(opened_at + Duration::from_millis(1)),
            "locking must not wait for the window to lapse"
        );
    }

    /**
     * A second authentication extends the window rather than restarting a
     * shorter one: authenticating near the end of a window must not leave less
     * time than authenticating at the start of one.
     */
    #[test]
    fn unlocking_again_starts_a_full_window_from_there() {
        let mut window = Window::default();
        let opened_at = start();
        window.open(opened_at);
        let first_ends_at = opened_at + UNLOCK_WINDOW;

        window.open(first_ends_at - Duration::from_millis(1));

        assert!(
            window.is_open(
                first_ends_at - Duration::from_millis(1) + UNLOCK_WINDOW - Duration::from_millis(1)
            ),
            "the second window runs its full length from the moment it was opened"
        );
    }

    /** The policy itself, so a change to it has to be made on purpose. */
    #[test]
    fn the_window_last_two_minutes() {
        assert_eq!(Duration::from_secs(120), UNLOCK_WINDOW);
    }

    /** A shut window has nothing left, and never a negative amount. */
    #[test]
    fn what_is_left_of_a_closed_window_is_nothing() {
        let opened_at = start();
        let mut window = Window::default();
        assert_eq!(Duration::ZERO, window.remaining(opened_at));

        window.open(opened_at);
        assert_eq!(
            UNLOCK_WINDOW - Duration::from_millis(1),
            window.remaining(opened_at + Duration::from_millis(1))
        );
        assert_eq!(Duration::ZERO, window.remaining(opened_at + UNLOCK_WINDOW));
        assert_eq!(
            Duration::ZERO,
            window.remaining(opened_at + UNLOCK_WINDOW + Duration::from_secs(30)),
            "a lapsed window is not indebted to the clock"
        );
    }
}
