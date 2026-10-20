//! Whether this endpoint may ask n0 where a Node ID is.
//!
//! A Node ID is a public key, not an address. Turning one into "where do I send
//! QUIC packets" is a lookup, and iroh's default lookup asks n0: once as an
//! HTTPS request to `dns.iroh.link` and once as a DNS query, concurrently, with
//! the two answers merged.
//!
//! That lookup is the one piece of n0's infrastructure that a relay setting
//! does not reach — running your own relay does not remove it. This module is
//! the switch that does.
//!
//! # What turning it off costs
//!
//! With no address lookup at all, a Node ID on its own is no longer enough to
//! reach a peer. The peer has to be named by something that carries its
//! address: a ticket (`--generate-invite` produces one) or an explicit
//! `EndpointAddr`. That is the trade — no third party learns which Node ID is
//! being asked about, and nothing this endpoint sends leaves it — in exchange
//! for having to hand the address over instead of looking it up.
//!
//! What it does *not* cost is the peer-to-peer path: hole punching and direct
//! addresses are untouched, and a relay this endpoint was told to use still
//! works. Only the "ask somebody where they are" step goes away.

use anyhow::bail;
use iroh::endpoint::Builder;

/// The spellings [`DiscoveryMode::parse`] accepts.
pub const VALID_DISCOVERY_MODES: &[&str] = &["n0", "none"];

/// Whether an endpoint may use n0's address lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoveryMode {
    /// The default: n0's DNS and pkarr answer "where is this Node ID".
    ///
    /// The endpoint both publishes its own address there and resolves other
    /// endpoints' addresses through it.
    #[default]
    N0,
    /// No address lookup at all.
    ///
    /// Nothing is published to n0 and nothing is resolved through it. A peer
    /// is reachable only by an address that was handed over — a ticket or an
    /// explicit `EndpointAddr`.
    None,
}

impl DiscoveryMode {
    /// Resolves a configured value into a mode.
    ///
    /// An unknown spelling is an error rather than a fallback, the same rule
    /// the relay modes follow: a config that says `"off"` and gets `n0` anyway
    /// is a config that says one thing and does another, and the user reading
    /// the log has no way to tell which happened.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim() {
            "n0" => Ok(Self::N0),
            "none" => Ok(Self::None),
            other => bail!(
                "unknown discovery mode {other:?}, expected one of {}",
                VALID_DISCOVERY_MODES.join(", ")
            ),
        }
    }

    /// One line for the startup log: what actually took effect.
    pub fn describe(&self) -> String {
        match self {
            Self::N0 => "n0 (a Node ID is looked up through dns.iroh.link)".to_string(),
            Self::None => {
                "none (no lookup; a peer is reachable only by ticket or explicit address)"
                    .to_string()
            }
        }
    }

    /// Applies the mode to an endpoint builder.
    ///
    /// `none` clears the address lookup services the `N0` preset installs, so
    /// the endpoint neither publishes to n0 nor resolves through it. `n0`
    /// leaves the builder as it is.
    pub fn apply(self, builder: Builder) -> Builder {
        match self {
            Self::N0 => builder,
            Self::None => builder.clear_address_lookup(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_n0() {
        assert_eq!(DiscoveryMode::default(), DiscoveryMode::N0);
        assert!(DiscoveryMode::parse("n0").is_ok());
    }

    #[test]
    fn the_two_spellings_are_accepted() {
        assert_eq!(DiscoveryMode::parse("none").unwrap(), DiscoveryMode::None);
        assert_eq!(DiscoveryMode::parse("  n0  ").unwrap(), DiscoveryMode::N0);
    }

    #[test]
    fn an_unknown_spelling_is_refused_rather_than_assumed() {
        // "off" reads like a switch somebody would write, and silently
        // treating it as "n0" would leave the endpoint asking n0 while the
        // config says it does not.
        let err = DiscoveryMode::parse("off").unwrap_err();
        assert!(err.to_string().contains("unknown discovery mode"), "{err}");
        assert!(DiscoveryMode::parse("disabled").is_err());
        assert!(DiscoveryMode::parse("").is_err());
    }

    #[test]
    fn the_description_says_what_takes_effect() {
        assert!(DiscoveryMode::N0.describe().contains("dns.iroh.link"));
        assert!(DiscoveryMode::None.describe().contains("ticket"));
    }
}
