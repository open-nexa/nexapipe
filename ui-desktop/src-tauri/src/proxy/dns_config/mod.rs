//! System DNS configuration — points system DNS at the TUN virtual IP so that queries reach
//! the local DNS server.
//!
//! Three ways of doing it, and **which one is done is the operator's decision**, spelled by
//! [`DnsStrategy`]:
//!
//! - **Scoped** (per-domain): only the proxied domains resolve through the TUN, and
//!   everything else keeps resolving wherever the machine was resolving it. This is
//!   what makes running alongside another tunnel possible — the other app's names,
//!   and the machine's own internal ones, are none of our business. The default.
//!   - macOS:   a file per domain under `/etc/resolver`
//!   - Linux:   `resolvectl` routing domains on the TUN link
//!   - Windows: NRPT rules (PowerShell `Add-DnsClientNrptRule`), read back afterwards
//! - **Global**: every query on the machine goes to the TUN resolver.
//!   - Windows: PowerShell Set-DnsClientServerAddress (netsh fallback), verified afterwards
//!   - Linux:   overwriting /etc/resolv.conf (with a backup, which the restore puts back)
//!   - macOS:   networksetup (iterating over every network service), with the pre-hijack
//!     servers kept on file so a restore can put them back
//! - **None**: the machine's DNS is left exactly as it is. The local DNS server still
//!   runs, so a PAC file or a hosts entry can point at it.
//!
//! The strategy is never quietly downgraded. A machine that cannot be scoped — one
//! whose domain policy overrides the local NRPT rules, or one whose configured domain
//! list cannot be named to the operating system at all — **fails** under the scoped
//! strategy and says so, rather than having its whole DNS replaced behind the user's
//! back. The global strategy is one click away for the machine that needs it.
//!
//! Which one a run ended up with is returned by [`set_system_dns`] and has to be handed
//! back to [`restore_system_dns`]: each is undone where it was done, and a scoped
//! hijack leaves nothing in the places a global one writes.
//!
//! A hijack that *fails* carries what it had already installed with it — see
//! [`DnsHijackFailure`] — because the global paths change the machine before they read
//! it back, and a read-back that does not show the TUN address leaves the machine
//! pointing at an address that will never come up.
//!
//! Note: the local DNS server (proxy/dns.rs) must be started before `set_system_dns`,
//! otherwise the switched-over system DNS queries would have nobody to answer them.

use anyhow::Result;

#[cfg(target_os = "macos")]
use std::collections::BTreeMap;

// `IpAddr` is imported one platform wider: the file's parsers are compiled under
// `test` everywhere so they can be exercised on any host, and this is the type they
// parse into. The two above are needed only by the platform code itself.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use std::net::IpAddr;

// One platform wider than the platform code, for the same reason as the parsers
// below: the per-domain resolver files are written and removed by functions that
// take the directory as an argument so that a test can exercise them on a
// temporary one. Overwriting another resolver's file, or leaving our own behind,
// is not something to ship unexercised.
#[cfg(any(target_os = "macos", test))]
use std::path::{Path, PathBuf};

// The three halves of the configuration. Each one is compiled only where it
// applies — except for the pure parts of each, which are compiled under `test`
// on every platform: the machine that has to read them back is not the one the
// tests run on.
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(any(windows, test))]
mod windows;

// The shared half, in the pieces it is made of: the strategy and the hijack
// it installs, the two paths that put it on the machine and take it back,
// the decision that tells a stale hijack from a live one, and the
// resolvers the machine is asked against.
mod cleanup;
mod hijack;
mod install;
mod liveness;
mod restore;
mod servers;
mod strategy;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "linux", test))]
use linux::*;
#[cfg(any(target_os = "macos", test))]
use macos::*;
#[cfg(any(windows, test))]
use windows::*;

pub use cleanup::cleanup_stale_hijack;
pub use hijack::{DnsHijack, DnsHijackFailure};
pub use install::{set_system_dns, undo_failed_hijack};
pub use restore::{restore_system_dns, RestoreScope};
pub use servers::{current_dns_servers, recorded_dns_servers};
pub use strategy::DnsStrategy;

// The liveness decision, and the pieces it is built from. The first is what
// the platform code asks; the rest is what the shared decision is made of.
#[cfg(any(target_os = "macos", target_os = "linux"))]
use liveness::address_is_held;
pub(crate) use liveness::is_tun_dns_address;
#[cfg(any(windows, test))]
pub(crate) use liveness::{stale_adapter_indexes, AdapterDns, LOCALHOST_V6};

// Whether every configured domain was routed, which is what tells a scoped
// install that took from one that did not.
#[cfg(any(target_os = "linux", windows, test))]
use install::routes_every_domain;
