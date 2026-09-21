//! Status payloads shared by the Tauri command surface and the service IPC channel.
//!
//! These types replace the packed string the status command used to return (`"true:tun"`), which
//! forced the frontend to split on `:` and made the mode vocabulary drift between the two
//! backends. There is now exactly one definition, serialized identically in both directions.

use serde::{Deserialize, Serialize};

use nexapipe_client::LinkKind;

use crate::proxy::manager::ProxyMode;

/// How the proxy is currently forwarding traffic.
///
/// `Starting` and `Stopped` describe the absence of a live mode rather than a mode of their own,
/// but the UI renders all four on a single status line, so they live in one enum instead of
/// forcing the frontend to combine two fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyModeKind {
    /// Accepted as well: a service binary built before this refactor sent `format!("{:?}")`,
    /// i.e. TitleCase. Keeping the alias means an already-installed service keeps answering
    /// correctly until it is restarted on the new binary, instead of failing to deserialize and
    /// silently degrading to process mode.
    #[serde(alias = "Tun")]
    Tun,
    #[serde(alias = "LocalProxy")]
    LocalProxy,
    Starting,
    Stopped,
}

impl From<ProxyMode> for ProxyModeKind {
    fn from(mode: ProxyMode) -> Self {
        match mode {
            ProxyMode::Tun => ProxyModeKind::Tun,
            ProxyMode::LocalProxy => ProxyModeKind::LocalProxy,
        }
    }
}

/// The result of `get_proxy_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStatus {
    /// Whether traffic is actually being forwarded. See [`ProxyStatus::starting`]: a manager that
    /// exists but has no mode yet is *not* running.
    pub running: bool,
    pub mode: ProxyModeKind,
}

impl ProxyStatus {
    /// The manager exists and is bringing the tunnel up.
    ///
    /// Both backends used to disagree here — process mode reported `running: false`, service mode
    /// reported `running: true` for the same situation. The process-mode reading is the honest
    /// one: nothing is being forwarded yet, so the UI must not claim it is.
    pub fn starting() -> Self {
        Self {
            running: false,
            mode: ProxyModeKind::Starting,
        }
    }

    /// No manager at all: the proxy has never been started, or has been stopped.
    pub fn stopped() -> Self {
        Self {
            running: false,
            mode: ProxyModeKind::Stopped,
        }
    }

    /// The manager has reached a live mode.
    pub fn running_with(mode: ProxyMode) -> Self {
        Self {
            running: true,
            mode: mode.into(),
        }
    }
}

/// How one configured node currently reaches its backend.
///
/// `link` is the **runtime** answer read off the path iroh actually selected, not the
/// configured relay mode: a node may be allowed to use a relay and still connect directly,
/// which is exactly what the user wants to see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointLink {
    /// The ticket or endpoint ID exactly as the node was configured, so the UI can match a link
    /// to the node it came from. A ticket is opaque to the frontend, so the resolved endpoint
    /// ID alone would not be enough to key on.
    pub connection: String,
    /// The backend's endpoint ID; a ticket resolves to the node it names.
    pub endpoint_id: String,
    /// `direct`, `relay`, or `unknown` when the backend has no selected path yet.
    pub link: LinkKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_mode_vocabularies() {
        for (raw, expected) in [
            (r#""tun""#, ProxyModeKind::Tun),
            (r#""Tun""#, ProxyModeKind::Tun),
            (r#""local_proxy""#, ProxyModeKind::LocalProxy),
            (r#""LocalProxy""#, ProxyModeKind::LocalProxy),
            (r#""starting""#, ProxyModeKind::Starting),
            (r#""stopped""#, ProxyModeKind::Stopped),
        ] {
            let parsed: ProxyModeKind = serde_json::from_str(raw).unwrap();
            assert_eq!(parsed, expected, "failed to parse {raw}");
        }
    }

    #[test]
    fn serializes_modes_in_snake_case() {
        let status = ProxyStatus::running_with(ProxyMode::LocalProxy);
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"running":true,"mode":"local_proxy"}"#
        );
    }

    /// The frontend keys nodes off `connection` and reads `link` as one of three fixed
    /// spellings, so the wire shape has to stay put.
    #[test]
    fn serializes_endpoint_links() {
        let link = EndpointLink {
            connection: "node1ticket".to_string(),
            endpoint_id: "0123456789abcdef".to_string(),
            link: LinkKind::Relay,
        };
        assert_eq!(
            serde_json::to_string(&link).unwrap(),
            r#"{"connection":"node1ticket","endpoint_id":"0123456789abcdef","link":"relay"}"#
        );
    }
}
