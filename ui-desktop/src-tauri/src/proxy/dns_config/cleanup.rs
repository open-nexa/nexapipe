//! The cleanup of a hijack that outlived the tunnel that installed it.
//!
//! The decision of what is stale is the shared one; the platforms differ
//! only in how they ask whether the address is still in use.

use super::*;

/// Resets adapters whose DNS still points at a TUN hijack that is no longer running.
///
/// The hijack normally restores the system DNS when the proxy stops, but a killed process
/// or a machine shutdown skips that — and static DNS entries survive a reboot, so the
/// machine comes back with its DNS pointing at a TUN address that does not exist (plus a
/// dead ::1) and "the internet is broken", including for this service itself (iroh cannot
/// publish to pkarr without name resolution). Called when the service starts and when the
/// desktop app starts, before anything needs DNS.
///
/// An adapter counts as stale when its IPv4 DNS is one of the TUN candidate addresses —
/// nobody configures those legitimately — or its IPv6 DNS is exactly ::1 while nothing
/// listens on [::1]:53 (the hijack's marker; a real localhost resolver holds that socket).
/// An NRPT rule naming one of those addresses is stale for the same reason and is
/// removed too — a rule is a registry entry, so it survives the reboot as well, and it
/// keeps its domains resolving against a TUN address nothing answers from.
///
/// The same question is asked on every platform — is the address still in use? — and
/// only the way it is answered differs: macOS and Linux ask the system resolver whether
/// an interface still holds the address ([`cleanup_stale_hijack_macos`],
/// [`cleanup_stale_hijack_linux`]), while Windows asks whether the tunnel's DNS server
/// is still listening on it ([`cleanup_stale_hijack_windows`]). The decision itself is
/// shared — see [`stale_adapter_indexes`] — so an adapter whose address a live tunnel
/// still holds is left alone everywhere.
pub fn cleanup_stale_hijack() {
    #[cfg(windows)]
    cleanup_stale_hijack_windows();

    #[cfg(target_os = "macos")]
    cleanup_stale_hijack_macos();

    #[cfg(target_os = "linux")]
    cleanup_stale_hijack_linux();
}
