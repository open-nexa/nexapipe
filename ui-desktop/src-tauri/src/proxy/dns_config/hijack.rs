//! The hijack: what a run installed, and what it left behind when it
//! failed.

/// How a run pointed system DNS at the TUN resolver.
///
/// Handed back to [`restore_system_dns`], which undoes each where it was done:
/// a scoped hijack has nothing in the places a global one writes, and a global
/// one cannot be removed by deleting per-domain files that were never created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsHijack {
    /// Only the configured domains resolve through the TUN. Everything else —
    /// the machine's own internal names, and another tunnel's, if one is
    /// running — keeps resolving where it always did.
    Scoped,
    /// Every query on the machine goes to the TUN resolver.
    Global,
    /// The machine's DNS was not touched, so there is nothing to undo.
    None,
}

/// A hijack that failed, and what it left behind.
///
/// "It failed" and "nothing happened" are two different things, and the
/// difference is the whole point of this type: the global paths change the
/// machine *first* and read it back afterwards — the Windows one resets and
/// re-points every adapter and then asks whether the TUN address is among
/// them, the macOS one writes every service and then asks whether any of them
/// points at the TUN address. A read-back that does not show the address is a
/// failure that leaves the machine pointing at a TUN address which will never
/// come up: no name resolution on that adapter or service, until something
/// else fixes it.
///
/// So the failure carries the hijack that was installed — at least in part —
/// and the caller undoes it with that.
#[derive(Debug)]
pub struct DnsHijackFailure {
    /// The kind of hijack that was installed, at least in part.
    pub hijack: DnsHijack,
    /// What went wrong.
    pub error: anyhow::Error,
}
