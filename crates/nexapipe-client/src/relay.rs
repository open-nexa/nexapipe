//! One definition of "which relay do we use", shared by the server and both clients.
//!
//! The same four-value switch used to be implemented three times — the server
//! (`crates/nexapipe/src/proxy/mod.rs`), Android (`jni.rs`) and the desktop
//! (`ui-desktop/src-tauri/src/proxy/manager.rs`) — and the three copies disagreed
//! on what happens when a value is missing or nonsense. This module is the single
//! answer, so the three callers can only differ in what they do when *nothing* is
//! configured.
//!
//! Two rules it enforces, both of which used to be violated:
//!
//! * **No silent fallback.** A mode that is present but unusable (`custom` with an
//!   empty URL, an unknown spelling) is an error, not an excuse to quietly pick
//!   something else. Only "not configured at all" defers to the caller, which is
//!   reported as [`Option::None`].
//! * **`custom` is exclusive.** [`RelayModeSpec::relay_mode`] hands iroh a
//!   [`RelayMap`] holding that one relay, and `Builder::relay_mode` *replaces* the
//!   preset's map rather than adding to it, so no N0 relay is left in play — not as
//!   a home relay and not as a net_report probe target. Asking for `custom` with an
//!   n0-operated URL is rejected outright, because that would make "am I off the
//!   official relays?" impossible to answer from the configuration alone.
//!
//! The second rule is about *this* endpoint's own traffic. A peer's traffic is
//! another matter, and it is what [`RelayRestriction`] is for: `custom` says no
//! n0 relay is used, and a peer that hands over an address naming one is not
//! dialled through it either. What iroh resolves on its own — a peer named only
//! by a Node ID — is covered by turning the lookup off, which is
//! [`crate::discovery::DiscoveryMode`]'s job.

use std::sync::OnceLock;

use anyhow::{anyhow, bail};
use iroh::endpoint::{BeforeConnectOutcome, EndpointHooks};
use iroh::{EndpointAddr, RelayConfig, RelayMap, RelayMode, RelayUrl};

use crate::secret::SecretString;

/// The relay we pin to by default: aps1-1, Singapore.
///
/// iroh otherwise picks a home relay from the four N0 relays by latency and can
/// migrate between them; every home-relay switch drops the connections that were
/// routed through it (WebSocket in particular). Pinning is the reason the default
/// is not `default`.
pub const PINNED_RELAY_URL: &str = "https://aps1-1.relay.n0.iroh.link.";

/// Host suffix every n0-operated relay shares.
const N0_RELAY_SUFFIX: &str = ".relay.n0.iroh.link";

/// The spellings [`RelayModeSpec::parse`] accepts.
pub const VALID_MODES: &[&str] = &["disabled", "default", "pinned", "custom"];

/// Which relay an endpoint uses, once the configuration has been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayModeSpec {
    /// No relay transport at all.
    ///
    /// Stronger than "don't use my relay": with no relay transport the endpoint
    /// cannot dial through a *peer's* relay either, so a peer that is only
    /// reachable via relay becomes unreachable.
    Disabled,
    /// iroh's default: every N0 relay, home relay chosen by latency.
    Default,
    /// One fixed N0 relay, [`PINNED_RELAY_URL`].
    Pinned,
    /// A relay the operator runs. Exclusive — no N0 relay is used.
    Custom {
        url: RelayUrl,
        /// The bearer token this relay asks for, if it asks for one.
        ///
        /// A [`SecretString`]: a relay bearer is a credential, and this one is
        /// wiped when the spec is dropped. It also means the derived `Debug`
        /// cannot leak it — the token prints as `<redacted>`, not as the value.
        auth_token: Option<SecretString>,
    },
}

impl RelayModeSpec {
    /// Resolves the configuration into a mode.
    ///
    /// `Ok(None)` means nothing was configured; the caller decides what that means
    /// (the clients default to [`Self::Pinned`], the server to [`Self::Default`]).
    /// Every other outcome is either a mode or a hard error — there is no path that
    /// substitutes a different mode for one the user asked for.
    ///
    /// A `relay_url` without a `relay_mode` is read as `custom`.
    ///
    /// A `relay_url` alongside a mode that does not take one is *ignored*, not fatal: it is
    /// almost always a stale field left behind after someone switched modes, and refusing to
    /// start over it would strand configurations that already exist. Callers warn about it
    /// instead — `RelayModeSpec::Custom` is the only variant that carries a URL, so
    /// "not `Custom` while a URL is set" is the check.
    pub fn parse(
        mode: Option<&str>,
        url: Option<&str>,
        auth_token: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(mode) = mode.map(str::trim).filter(|m| !m.is_empty()) else {
            // No mode. A URL on its own still names a relay, so honour it.
            return match url.map(str::trim).filter(|u| !u.is_empty()) {
                Some(url) => Ok(Some(Self::custom(url, auth_token)?)),
                None => Ok(None),
            };
        };

        let url = url.map(str::trim).filter(|u| !u.is_empty());
        match mode {
            "disabled" => Ok(Some(Self::Disabled)),
            "default" => Ok(Some(Self::Default)),
            "pinned" => Ok(Some(Self::Pinned)),
            "custom" => {
                let url = url.ok_or_else(|| {
                    anyhow!("relay_mode = \"custom\" requires a non-empty relay_url")
                })?;
                Ok(Some(Self::custom(url, auth_token)?))
            }
            other => bail!(
                "unknown relay_mode {other:?}, expected one of {}",
                VALID_MODES.join(", ")
            ),
        }
    }

    /// Builds one `custom` mode, validating the URL while doing so.
    fn custom(url: &str, auth_token: Option<&str>) -> anyhow::Result<Self> {
        let url: RelayUrl = url
            .parse()
            .map_err(|e| anyhow!("invalid relay_url {url:?} ({e})"))?;
        if is_n0_relay(&url) {
            bail!(
                "relay_url {url} is an n0-operated relay; use relay_mode = \"pinned\" or \
                 \"default\" instead of \"custom\", so the configuration still says which \
                 relays are in play"
            );
        }
        let auth_token = auth_token
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| SecretString::new(t.to_string()));
        Ok(Self::Custom { url, auth_token })
    }

    /// The [`RelayMode`] to hand to `Endpoint::builder(..).relay_mode(..)`.
    ///
    /// The map handed to [`RelayMode::Custom`] holds exactly one relay, and
    /// `Builder::relay_mode` overwrites the preset's relay transport instead of
    /// merging with it, so this is what makes `custom` exclusive.
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Disabled => RelayMode::Disabled,
            Self::Default => RelayMode::Default,
            Self::Pinned => {
                RelayMode::Custom(RelayMap::from_iter([RelayConfig::from(pinned_relay_url())]))
            }
            Self::Custom { url, auth_token } => {
                let config = RelayConfig::from(url.clone());
                let config = match auth_token {
                    // Onto iroh, which keeps it for as long as the relay
                    // configuration lives: the copy here is handed over, and
                    // the one that stays is iroh's to wipe.
                    Some(token) => config.with_auth_token(token.expose_secret_cloned()),
                    None => config,
                };
                RelayMode::Custom(RelayMap::from_iter([config]))
            }
        }
    }

    /// The restriction this mode places on dialling a peer, if it places one.
    ///
    /// `None` means the mode places no restriction of its own, and the
    /// difference between that and "anything goes" is worth spelling out:
    ///
    /// - `default` and `pinned` put n0's relays in play on purpose, so a peer
    ///   may name any of them.
    /// - `disabled` needs no restriction here: `RelayMode::Disabled` takes the
    ///   relay transport off the endpoint, so this endpoint cannot dial *any*
    ///   relay — not its own, and not one a peer names either.
    /// - `custom` is the one that needs one, and it is what
    ///   [`RelayRestriction`] is for.
    pub fn dial_restriction(&self) -> Option<RelayRestriction> {
        match self {
            Self::Custom { url, .. } => Some(RelayRestriction::through(url.clone())),
            Self::Default | Self::Pinned | Self::Disabled => None,
        }
    }

    /// Whether this mode carries a relay URL of its own.
    ///
    /// Lets a caller notice a `relay_url` that does nothing: the field is stale, and while it must
    /// not stop the show, it should not stay silent either.
    pub fn uses_url(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }

    /// One line for the startup log: what actually took effect.
    pub fn describe(&self) -> String {
        match self {
            Self::Disabled => "disabled (no relay at all; a peer's relay is unusable too)".into(),
            Self::Default => "default (all N0 relays)".into(),
            Self::Pinned => format!("pinned ({PINNED_RELAY_URL})"),
            Self::Custom { url, auth_token } => format!(
                "custom ({url}, auth_token={})",
                if auth_token.is_some() { "set" } else { "none" }
            ),
        }
    }
}

/// The restriction `custom` places on dialling a peer.
///
/// `custom` says: this endpoint uses one relay, the one the operator runs, and
/// nothing else. iroh's `relay_mode` only bounds the relay *this* endpoint
/// registers with and probes through — a peer that hands over an address
/// naming a different relay is still dialled through it. That is how a
/// "custom" deployment could still put a peer's traffic through an n0 relay,
/// and it is the gap this closes.
///
/// It applies to the addresses the application hands to iroh:
///
/// - A peer that names a relay other than ours is not dialled through it.
/// - A peer named only by a Node ID is not dialled at all, because finding its
///   address means asking n0, and n0's answer may be an n0 relay.
///
/// The second is why `custom` asks for a ticket rather than a Node ID: a
/// ticket carries the address, so the peer is dialled through the relay the
/// ticket names — which is the one the operator runs, on both ends.
///
/// What it cannot cover is a peer whose address iroh resolves *after* the
/// check, which is the bare-Node-ID case above, and a peer's own choice of
/// relay when the peer is dialled through a path this endpoint does not
/// control. Turning n0's lookup off as well — see
/// [`crate::discovery::DiscoveryMode`] — is what closes the second half.
#[derive(Debug, Clone)]
pub struct RelayRestriction {
    /// The one relay a peer may be dialled through.
    relay: RelayUrl,
}

impl RelayRestriction {
    /// The restriction for a relay: peers are dialled through it and nothing else.
    pub fn through(relay: RelayUrl) -> Self {
        Self { relay }
    }

    /// The relay peers are dialled through.
    pub fn relay(&self) -> &RelayUrl {
        &self.relay
    }

    /// Whether `addr` may be dialled under this restriction.
    ///
    /// `Err` says why not, in a sentence meant to be read in a log.
    pub fn permits(&self, addr: &EndpointAddr) -> Result<(), String> {
        let mut named = addr.relay_urls().peekable();
        if named.peek().is_some() {
            // A peer may name more than one relay. Ours is among them, so the
            // restriction is satisfied whichever one iroh picks; ours is not,
            // then there is nothing here this endpoint may dial through.
            if named.all(|other| other == &self.relay) {
                return Ok(());
            }
            return Err(format!(
                "the peer names a relay this endpoint does not use, and this endpoint only uses {}",
                self.relay
            ));
        }

        if addr.ip_addrs().next().is_some() {
            // A direct address: no relay is involved, so nothing to refuse.
            return Ok(());
        }

        Err(format!(
            "the peer is named only by a Node ID, and finding its address means asking n0, \
             which may answer with an n0 relay; this endpoint only uses {}",
            self.relay
        ))
    }
}

impl EndpointHooks for RelayRestriction {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        match self.permits(remote_addr) {
            Ok(()) => BeforeConnectOutcome::Accept,
            Err(why) => {
                warn(&format!("[iroh] refusing to dial the peer: {why}"));
                BeforeConnectOutcome::Reject
            }
        }
    }
}

/// Says something that has to be seen, wherever this build logs.
///
/// The Android build has no `tracing` subscriber — it logs through `log`, at
/// a level the app shows — and the desktop has no `log` backend. So the two
/// are told apart here rather than at every call site.
#[cfg(feature = "jni")]
fn warn(message: &str) {
    log::warn!("{message}");
}

#[cfg(all(not(feature = "jni"), feature = "tracing"))]
fn warn(message: &str) {
    tracing::warn!("{message}");
}

#[cfg(all(not(feature = "jni"), not(feature = "tracing")))]
fn warn(message: &str) {
    let _ = message;
}

fn pinned_relay_url() -> RelayUrl {
    static PINNED: OnceLock<RelayUrl> = OnceLock::new();
    PINNED
        .get_or_init(|| {
            PINNED_RELAY_URL
                .parse()
                .expect("PINNED_RELAY_URL must be a valid relay URL")
        })
        .clone()
}

/// Whether `url` points at a relay n0 operates.
fn is_n0_relay(url: &RelayUrl) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == N0_RELAY_SUFFIX.trim_start_matches('.') || host.ends_with(N0_RELAY_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN_RELAY: &str = "https://relay.example.com";

    /// A Node ID to hang an address off. Any one will do: nothing here dials.
    fn node_id() -> iroh::EndpointId {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn nothing_configured_defers_to_the_caller() {
        assert_eq!(RelayModeSpec::parse(None, None, None).unwrap(), None);
        assert_eq!(RelayModeSpec::parse(Some(""), None, None).unwrap(), None);
        assert_eq!(RelayModeSpec::parse(Some("  "), None, None).unwrap(), None);
    }

    #[test]
    fn a_url_without_a_mode_is_custom() {
        let spec = RelayModeSpec::parse(None, Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        assert!(matches!(spec, RelayModeSpec::Custom { .. }));
    }

    #[test]
    fn modes_without_a_url() {
        assert_eq!(
            RelayModeSpec::parse(Some("disabled"), None, None).unwrap(),
            Some(RelayModeSpec::Disabled)
        );
        assert_eq!(
            RelayModeSpec::parse(Some("default"), None, None).unwrap(),
            Some(RelayModeSpec::Default)
        );
        assert_eq!(
            RelayModeSpec::parse(Some("pinned"), None, None).unwrap(),
            Some(RelayModeSpec::Pinned)
        );
    }

    #[test]
    fn custom_requires_a_url() {
        let err = RelayModeSpec::parse(Some("custom"), None, None).unwrap_err();
        assert!(
            err.to_string().contains("requires a non-empty relay_url"),
            "{err}"
        );
    }

    #[test]
    fn custom_rejects_an_n0_relay() {
        for url in [
            "https://aps1-1.relay.n0.iroh.link.",
            "https://use1-1.relay.n0.iroh.link",
            "https://relay.n0.iroh.link.",
        ] {
            let err = RelayModeSpec::parse(Some("custom"), Some(url), None).unwrap_err();
            assert!(
                err.to_string().contains("n0-operated relay"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn a_url_next_to_a_mode_that_ignores_it_is_not_fatal() {
        // A stale relay_url left behind after switching modes must not stop the show; the
        // callers warn about it instead.
        for mode in ["disabled", "default", "pinned"] {
            let spec = RelayModeSpec::parse(Some(mode), Some(OWN_RELAY), None)
                .unwrap()
                .unwrap();
            assert!(!spec.uses_url(), "{mode}");
        }
    }

    #[test]
    fn custom_uses_its_url() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        assert!(spec.uses_url());
    }

    #[test]
    fn unknown_mode_is_an_error() {
        let err = RelayModeSpec::parse(Some("custome"), Some(OWN_RELAY), None).unwrap_err();
        assert!(err.to_string().contains("unknown relay_mode"), "{err}");
    }

    #[test]
    fn custom_keeps_the_auth_token() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), Some("secret"))
            .unwrap()
            .unwrap();
        assert_eq!(
            spec,
            RelayModeSpec::Custom {
                url: OWN_RELAY.parse().unwrap(),
                auth_token: Some(SecretString::new("secret".to_string())),
            }
        );
    }

    /// A relay bearer is a credential, and this type's `Debug` is derived —
    /// so what makes it safe is the token's own type, not a hand-written
    /// `Debug` here. A `{:?}` of a spec must not carry the bearer.
    #[test]
    fn a_relay_spec_never_prints_its_bearer() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), Some("s3cret-bearer"))
            .unwrap()
            .unwrap();
        let rendered = format!("{spec:?}");

        assert!(!rendered.contains("s3cret-bearer"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn disabled_has_no_relay_transport() {
        assert!(matches!(
            RelayModeSpec::Disabled.relay_mode(),
            RelayMode::Disabled
        ));
    }

    #[test]
    fn custom_is_exclusive() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        let restriction = spec
            .dial_restriction()
            .expect("custom restricts which relay a peer is dialled through");
        assert_eq!(
            restriction.relay().to_string(),
            "https://relay.example.com/"
        );
    }

    #[test]
    fn the_modes_that_put_n0_relays_in_play_restrict_nothing() {
        // `default` and `pinned` use n0's relays on purpose, so a peer may
        // name any of them. `disabled` takes the relay transport off the
        // endpoint entirely, so no relay can be dialled at all — below us,
        // not by a restriction of ours.
        for spec in [
            RelayModeSpec::Default,
            RelayModeSpec::Pinned,
            RelayModeSpec::Disabled,
        ] {
            assert!(spec.dial_restriction().is_none(), "{spec:?}");
        }
    }

    /// A peer named only by a Node ID has to be looked up, and looking one up
    /// means asking n0 — so under `custom` it is not dialled at all.
    #[test]
    fn a_peer_named_only_by_a_node_id_is_refused() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        let restriction = spec.dial_restriction().unwrap();
        let addr = EndpointAddr::new(node_id());

        let why = restriction
            .permits(&addr)
            .expect_err("a bare Node ID is refused");
        assert!(why.contains("Node ID"), "{why}");
        assert!(why.contains("asking n0"), "{why}");
    }

    /// The peer that matters: one on the same relay, named by a ticket.
    #[test]
    fn a_peer_naming_our_relay_is_dialled() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        let restriction = spec.dial_restriction().unwrap();
        let addr = EndpointAddr::new(node_id()).with_relay_url(OWN_RELAY.parse().unwrap());

        assert!(restriction.permits(&addr).is_ok());
    }

    /// A peer on somebody else's relay — an n0 one, in the case that matters.
    #[test]
    fn a_peer_naming_another_relay_is_refused() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        let restriction = spec.dial_restriction().unwrap();
        let addr = EndpointAddr::new(node_id())
            .with_relay_url("https://aps1-1.relay.n0.iroh.link.".parse().unwrap());

        let why = restriction
            .permits(&addr)
            .expect_err("another relay is refused");
        assert!(why.contains("relay this endpoint does not use"), "{why}");
    }

    /// A peer with a direct address uses no relay at all, so there is nothing
    /// to refuse — the direct path is the one the restriction is not about.
    #[test]
    fn a_peer_with_a_direct_address_is_dialled() {
        let spec = RelayModeSpec::parse(Some("custom"), Some(OWN_RELAY), None)
            .unwrap()
            .unwrap();
        let restriction = spec.dial_restriction().unwrap();
        let addr = EndpointAddr::new(node_id()).with_ip_addr("192.0.2.1:443".parse().unwrap());

        assert!(restriction.permits(&addr).is_ok());
    }
}
