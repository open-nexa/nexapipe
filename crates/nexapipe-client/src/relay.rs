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

use std::sync::OnceLock;

use anyhow::{anyhow, bail};
use iroh::{RelayConfig, RelayMap, RelayMode, RelayUrl};

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
        auth_token: Option<String>,
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
            .map(str::to_string);
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
            Self::Pinned => RelayMode::Custom(RelayMap::from_iter([RelayConfig::from(
                pinned_relay_url(),
            )])),
            Self::Custom { url, auth_token } => {
                let config = RelayConfig::from(url.clone());
                let config = match auth_token {
                    Some(token) => config.with_auth_token(token.clone()),
                    None => config,
                };
                RelayMode::Custom(RelayMap::from_iter([config]))
            }
        }
    }

    /// Relay URLs this mode permits, when the set is closed.
    ///
    /// `None` means "not restricted". Used by the caller to build an
    /// `AddrFilter` that drops relay addresses outside the set, which is the only
    /// way to stop this endpoint dialling an N0 relay a *peer* advertises.
    pub fn allowed_relay_urls(&self) -> Option<Vec<RelayUrl>> {
        match self {
            Self::Disabled => Some(Vec::new()),
            Self::Default => None,
            Self::Pinned => Some(vec![pinned_relay_url()]),
            Self::Custom { url, .. } => Some(vec![url.clone()]),
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

    #[test]
    fn nothing_configured_defers_to_the_caller() {
        assert_eq!(RelayModeSpec::parse(None, None, None).unwrap(), None);
        assert_eq!(RelayModeSpec::parse(Some(""), None, None).unwrap(), None);
        assert_eq!(RelayModeSpec::parse(Some("  "), None, None).unwrap(), None);
    }

    #[test]
    fn a_url_without_a_mode_is_custom() {
        let spec = RelayModeSpec::parse(None, Some(OWN_RELAY), None).unwrap().unwrap();
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
        assert!(err.to_string().contains("requires a non-empty relay_url"), "{err}");
    }

    #[test]
    fn custom_rejects_an_n0_relay() {
        for url in [
            "https://aps1-1.relay.n0.iroh.link.",
            "https://use1-1.relay.n0.iroh.link",
            "https://relay.n0.iroh.link.",
        ] {
            let err = RelayModeSpec::parse(Some("custom"), Some(url), None).unwrap_err();
            assert!(err.to_string().contains("n0-operated relay"), "{url}: {err}");
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
                auth_token: Some("secret".into()),
            }
        );
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
        let allowed = spec.allowed_relay_urls().expect("custom is a closed set");
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].to_string(), "https://relay.example.com/");
    }

    #[test]
    fn default_is_unrestricted() {
        assert!(RelayModeSpec::Default.allowed_relay_urls().is_none());
    }
}
