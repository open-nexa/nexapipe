use serde::{Deserialize, Serialize};

/// What the OS gave us to hold the master key in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// The keychain took it: the master key never touches the filesystem.
    Keychain,
    /// No keychain would take it, so it is a `0600` file beside the credentials.
    /// Weaker — another process running as this user can read it — which is why
    /// [`status`](super::store::status) reports it instead of leaving it implied.
    File,
}

impl KeySource {
    /// What [`status`](super::store::status) hands to the frontend.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Keychain => "keychain",
            KeySource::File => "file",
        }
    }
}

/// Which credentials a caller may name, so a typo or an unexpected shape fails at
/// the command boundary instead of becoming an entry nothing ever reads back.
///
/// Keys are built by [`secret_key`] rather than by the caller, and every one of
/// them names the node it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// A node's TOTP secret.
    TotpSecret,
    /// A node's one-time enrollment token.
    EnrollmentToken,
    /// A node's own Ed25519 key: the private half, as 64 hex characters.
    ///
    /// A credential like the secret beside it, and a stronger one — the server
    /// holds the public half and nobody else holds this one, so what the
    /// desktop keeps here is the only copy there is. It never leaves the
    /// machine, and the app has no way to show it: there is nothing to read
    /// off a screen, which is the whole point of a key.
    DeviceKey,
    /// The bearer token a custom relay asks for. Not per-node: it is a global setting.
    RelayToken,
    /// The ticket a node reaches its server by. An address-bearing invite string,
    /// which is a credential and not configuration: it names an endpoint *and*
    /// carries whatever the server put in it, so anyone holding it can connect.
    Ticket,
    /// The bare Node ID a node reaches its server by. Weaker than a ticket on its
    /// own — it names a node without carrying a way to reach it — but it is still
    /// what a node is, and it is what an invite of that kind hands out.
    EndpointId,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::TotpSecret => "totp",
            CredentialKind::EnrollmentToken => "enrollment",
            CredentialKind::DeviceKey => "devicekey",
            CredentialKind::RelayToken => "relay",
            CredentialKind::Ticket => "ticket",
            CredentialKind::EndpointId => "endpoint",
        }
    }
}

/// Characters of a masked value kept at the front, and at the back.
///
/// Enough to recognise a value the user has seen before — which node this is,
/// which of two similar tickets it is not — and not enough to reconstruct it.
/// The same eight and four the UI used to keep, minus the rule that a short
/// value was shown whole.
const MASK_HEAD: usize = 8;
const MASK_TAIL: usize = 4;

/// What stands in for the rest.
const MASK_MIDDLE: &str = "••••";

/// The longest value that keeps nothing at all.
///
/// A TOTP secret is 16 base32 characters, so 16 is not an arbitrary line: it is
/// the length at which "just the first few characters" is most of the value.
/// Everything at or below it is replaced whole rather than trimmed, because the
/// mask is not there to make a secret harder to read over somebody's shoulder —
/// it is there so a secret is never on the screen at all.
const MASK_WHOLE: usize = 16;

/// The projection of a credential that is safe to render: enough to recognise,
/// not enough to use.
///
/// Computed here rather than in the renderer, because a mask the renderer
/// computes is not one: to shorten a value it already holds, and what it holds
/// is the whole thing, one devtools panel away from whoever is looking. A
/// surface that needs the value itself asks for it through the reveal path
/// instead, which is a deliberate act and, once the lock is in, an authenticated
/// one.
///
/// Empty in, empty out: "no credential" and "a credential so short it is all
/// bullets" must stay tellable apart, and that is the caller's call to make.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return String::new();
    }

    if chars.len() <= MASK_WHOLE {
        // Length is not the secret, so it is kept — up to a point, past which
        // counting bullets stops being informative and starts being decoration.
        return "•".repeat(chars.len().min(MASK_HEAD));
    }

    let head: String = chars.iter().take(MASK_HEAD).collect();
    let tail: String = chars.iter().skip(chars.len() - MASK_TAIL).collect();
    format!("{head}{MASK_MIDDLE}{tail}")
}

/// The key a credential is filed under.
///
/// Built here and not by the caller so the two sides cannot disagree about the
/// spelling: a secret written under one spelling and read under another is a
/// secret that is simply gone.
pub fn secret_key(kind: CredentialKind, node_id: &str) -> String {
    match kind {
        CredentialKind::RelayToken => format!("{}:global", kind.as_str()),
        _ => format!("{}:{}", kind.as_str(), node_id),
    }
}
