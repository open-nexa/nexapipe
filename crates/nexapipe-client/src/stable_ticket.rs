//! The ticket that does not go stale.
//!
//! A normal [`EndpointTicket`] carries an [`EndpointAddr`], and an
//! `EndpointAddr` carries **two** things that have very different lifetimes:
//!
//! - the **Node ID**, which is the endpoint's public key. It changes only if
//!   the endpoint's secret key changes, so a configured one is fixed for the
//!   life of the deployment.
//! - the **addresses** — the relay URLs and the IP addresses — which change
//!   whenever the host moves, the socket gets a new port, or the home relay
//!   migrates.
//!
//! The addresses are what make an ordinary ticket go stale, and a stale
//! ticket is worse than no ticket: it sends the client to an address that no
//! longer answers. That is why deployments end up carrying a bare Node ID
//! instead, and why a Node ID alone has to wait for an address lookup before
//! the first packet can go anywhere.
//!
//! # What this module builds
//!
//! A **stable ticket**: the Node ID plus exactly one relay URL, and no IP
//! addresses at all.
//!
//! - The **Node ID** keeps the identity fixed, which is the part an
//!   operator can actually pin.
//! - The **relay URL** gives the client a path it can use *immediately*. iroh
//!   does not wait for an address lookup when it already knows any path
//!   (`resolve_remote` in iroh's `remote_state`), so a client holding this
//!   ticket starts its handshake at once instead of after a DNS and pkarr
//!   round trip — which in a network where those lookups are slow or blocked
//!   is the difference between a connection and a timeout.
//! - The **lookup still runs**, and its result is merged into the path set
//!   when it arrives. So the direct addresses the peer publishes are still
//!   used, and hole punching still happens: this ticket removes the *wait*,
//!   not the *possibility* of a direct path.
//!
//! # When it is not enough
//!
//! The relay URL here is the one the endpoint is **pinned** to. An endpoint
//! whose relay mode is `default` picks its home relay by latency and may
//! migrate between them, so there is no single URL to write down. For those,
//! the caller gets [`StableTicket::relay`] as `None` and the ticket falls back
//! to the Node ID alone — which is exactly what the endpoint id is, and is
//! therefore no worse than not using a ticket at all.

use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use iroh_tickets::Ticket;
use iroh_tickets::endpoint::EndpointTicket;

use crate::relay::RelayModeSpec;

/// A ticket whose identity is fixed and whose single path is a relay the
/// endpoint stays registered at.
///
/// Built by [`StableTicket::build`]; the fields are public because a caller
/// needs to report what it got, not because it should assemble one by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableTicket {
    /// The endpoint this ticket names.
    pub endpoint_id: EndpointId,
    /// The relay the endpoint is reachable through, if it has a fixed one.
    ///
    /// `None` when the endpoint's relay mode does not pin one. The ticket is
    /// then the Node ID alone, which is still a valid address — the lookup
    /// fills in the rest.
    pub relay: Option<RelayUrl>,
}

impl StableTicket {
    /// Builds the stable ticket for an endpoint under a relay mode.
    ///
    /// `relay` is the mode the endpoint actually runs with, not the mode it
    /// was configured with: the two can differ, and the one that decides
    /// whether a relay URL is fixed is the one in force.
    ///
    /// The Node ID is the endpoint's own, so this is the one thing the caller
    /// must get right: a ticket for the wrong endpoint reaches the wrong
    /// endpoint, and no amount of address fixing repairs that.
    pub fn build(endpoint_id: EndpointId, relay: &RelayModeSpec) -> Self {
        Self {
            endpoint_id,
            relay: fixed_relay_of(relay),
        }
    }

    /// The ticket itself, ready to be handed to a client.
    ///
    /// The Node ID is always there; the relay URL is there when the endpoint
    /// has a fixed one. An endpoint with no fixed relay gets the Node ID
    /// alone, which is a valid address and is not worse than a bare Node ID.
    pub fn to_ticket(&self) -> EndpointTicket {
        let mut addr = EndpointAddr::new(self.endpoint_id);
        if let Some(relay) = &self.relay {
            addr.addrs.insert(TransportAddr::Relay(relay.clone()));
        }
        EndpointTicket::new(addr)
    }

    /// The ticket, encoded the way it is written down and handed out.
    pub fn to_ticket_string(&self) -> String {
        self.to_ticket().encode_string()
    }
}

/// The one relay a mode pins the endpoint to, if it pins one.
///
/// `pinned` names a fixed N0 relay and `custom` names the operator's own, so
/// both have exactly one URL. `default` lets iroh choose the home relay by
/// latency and migrate between them, so it has none; `disabled` has no relay
/// at all.
fn fixed_relay_of(relay: &RelayModeSpec) -> Option<RelayUrl> {
    match relay {
        RelayModeSpec::Pinned => Some(crate::relay::pinned_relay_url()),
        RelayModeSpec::Custom { url, .. } => Some(url.clone()),
        RelayModeSpec::Default | RelayModeSpec::Disabled => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::PINNED_RELAY_URL;

    fn node_id() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    /// A ticket for a pinned endpoint carries the Node ID and the pinned relay,
    /// and nothing else.
    #[test]
    fn a_pinned_endpoint_gets_a_relay_and_no_ip_addresses() {
        let id = node_id();
        let ticket = StableTicket::build(id, &RelayModeSpec::Pinned);

        assert_eq!(ticket.endpoint_id, id);
        let relay = ticket.relay.as_ref().expect("pinned has a relay");
        // Compared as a parsed URL, not as text: the parser normalises the
        // spelling, and the relay it names is the same relay either way.
        let expected: RelayUrl = PINNED_RELAY_URL.parse().expect("the pinned relay is a URL");
        assert_eq!(relay, &expected);

        let addr = ticket.to_ticket().endpoint_addr().clone();
        assert_eq!(addr.id, id);
        assert_eq!(addr.ip_addrs().count(), 0, "a stable ticket carries no IP");
        assert_eq!(addr.relay_urls().count(), 1);
    }

    /// The whole point: the ticket does not change when the host's addresses
    /// do. The same Node ID under the same mode yields the same ticket, every
    /// time — which is what "stable" has to mean.
    #[test]
    fn the_same_endpoint_and_mode_yield_the_same_ticket() {
        let id = node_id();
        let first = StableTicket::build(id, &RelayModeSpec::Pinned).to_ticket_string();
        let second = StableTicket::build(id, &RelayModeSpec::Pinned).to_ticket_string();
        assert_eq!(first, second);
    }

    /// A different endpoint is a different ticket, even under the same mode.
    #[test]
    fn a_different_endpoint_yields_a_different_ticket() {
        let first = StableTicket::build(node_id(), &RelayModeSpec::Pinned).to_ticket_string();
        let second = StableTicket::build(node_id(), &RelayModeSpec::Pinned).to_ticket_string();
        assert_ne!(first, second);
    }

    /// A mode that does not pin one relay has no fixed URL to write down. The
    /// ticket is then the Node ID alone — a valid address, and no worse than
    /// the endpoint id it replaces.
    #[test]
    fn a_migrating_relay_mode_yields_the_node_id_alone() {
        let id = node_id();
        for mode in [RelayModeSpec::Default, RelayModeSpec::Disabled] {
            let ticket = StableTicket::build(id, &mode);
            assert!(ticket.relay.is_none(), "{mode:?} has no fixed relay");

            let addr = ticket.to_ticket().endpoint_addr().clone();
            assert_eq!(addr.id, id);
            assert!(addr.addrs.is_empty(), "{mode:?} carries no address");
        }
    }

    /// A custom relay is the operator's own, and it is fixed — so it goes
    /// into the ticket like any other fixed relay.
    #[test]
    fn a_custom_relay_goes_into_the_ticket() {
        let url: RelayUrl = "https://relay.example.com".parse().unwrap();
        let spec = RelayModeSpec::parse(Some("custom"), Some("https://relay.example.com"), None)
            .unwrap()
            .unwrap();
        let ticket = StableTicket::build(node_id(), &spec);
        assert_eq!(ticket.relay.as_ref(), Some(&url));
    }

    /// The ticket round-trips: what is written down reads back as the same
    /// address, because that is the whole contract with the client.
    #[test]
    fn the_ticket_round_trips() {
        let id = node_id();
        let ticket = StableTicket::build(id, &RelayModeSpec::Pinned);
        let encoded = ticket.to_ticket_string();
        let parsed: EndpointTicket = encoded.parse().expect("a stable ticket parses");
        let addr = parsed.endpoint_addr().clone();

        assert_eq!(addr.id, id);
        assert_eq!(addr.relay_urls().count(), 1);
        assert_eq!(addr.ip_addrs().count(), 0);
    }
}
