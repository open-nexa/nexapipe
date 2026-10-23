//! The credentials a client holds.
//!
//! A client is a person: it has a secret, a name, and the hosts it may
//! reach. The secret is the one thing here that must never be written down
//! in the clear, and the rest is what a deployment configures.

use nexapipe_proto::secret::{SecretBytes, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::acl::ClientAcl;
use super::device::DeviceAuth;
use super::step::{StepVerdict, accept_step};
use super::{decode_base32_secret, default_created_at, default_unnamed_device_allowed, unix_now};

/// Client authentication information
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Base32-encoded secret key
    ///
    /// A [`SecretString`]: this is a working credential for as long as the
    /// server runs, and it is wiped when the entry is replaced or the config
    /// is dropped. The file it came from is written back unchanged — the
    /// wrapper changes where the bytes live, not what they say.
    pub secret: SecretString,
    /// When this client was created
    #[serde(default = "default_created_at")]
    pub created_at: String,
    /// Host patterns this client may reach; `None` means every route.
    ///
    /// The patterns use the same spelling as a route's `host_pattern` — an
    /// exact name or a `*.suffix` wildcard, case-insensitively — and are
    /// folded into a [`ClientAcl`] when a connection authenticates. An empty
    /// list denies every host: `allow_hosts = []` is "this client may
    /// connect and nothing else", not "no restriction".
    #[serde(default)]
    pub allow_hosts: Option<Vec<String>>,
    /// Ports this client may reach; `None` means every port.
    ///
    /// The other half of `allow_hosts`, and it answers a question the host
    /// list cannot: a host that serves three services on three ports is one
    /// name and three things to reach, and a client that may have the name
    /// does not automatically get all three.
    ///
    /// Checked where the client names a port: the tunnel preface carries one,
    /// and an HTTP request's `Host` header may. A request that names no port
    /// is not checked, because there is no port to hold against it.
    ///
    /// The tunnel is where the list separates services: the preface names the
    /// port the client wants, and that is the port the proxy dials. The HTTP
    /// path routes by host alone, so a port named in a `Host` header is
    /// checked but is not the port the request is served from — two services
    /// of one host are told apart by the tunnel, not by this list.
    ///
    /// An empty list denies every port that is checked: `allow_ports = []` is
    /// "this client may connect and reach nothing it names a port for", not
    /// "no restriction".
    #[serde(default)]
    pub allow_ports: Option<Vec<u16>>,
    /// Whether `allow_ports` is checked against the port the request is
    /// *served from*, rather than the one the client names.
    ///
    /// The two are different ports, and the difference is the whole point.
    /// A client asks for `https://api.example.com` and the proxy serves it
    /// from `http://127.0.0.1:18080`; the port the client names is a virtual
    /// one, the port the request goes to is the backend's. Checking the
    /// client's port checked a number the request never reaches — and a
    /// request that named no port at all was not checked on any port.
    ///
    /// Off by default, because turning it on changes what an existing
    /// configuration allows: a client limited to port 443 whose route's
    /// backend listens on 18080 is refused. That is the correct answer, and it
    /// is not the answer a deployed configuration was written against — so an
    /// operator opts in, having looked at where their backends actually
    /// listen.
    ///
    /// **The port checked is the one the request is served from** — the
    /// backend the pool picked, not the route it came from. A route with two
    /// backends on two ports is therefore half usable by such a client: the
    /// requests that land on the allowed port are served and the ones that
    /// land on the other are refused. That is the rule this flag states, and
    /// it is the one an allow-list of ports is written for.
    #[serde(default)]
    pub allow_ports_strict: bool,
    /// A one-time enrollment token waiting to be exchanged for a new secret.
    ///
    /// `None` means no enrollment is outstanding, so a client with no token
    /// cannot talk the server into issuing one: enrollment is only ever opened
    /// by `--generate-invite --registration`, which writes it here.
    ///
    /// A [`SecretString`]: an unspent token is a credential, and it is wiped
    /// when it is spent or when the config is dropped.
    #[serde(default)]
    pub pending_enrollment: Option<SecretString>,
    /// Credentials issued to individual devices under this client.
    ///
    /// A device here has a secret of its own, and the `secret` above is the
    /// credential of the device that has no name — which is every device that
    /// existed before this table could be written, and why an empty table
    /// changes nothing about how such a client authenticates.
    ///
    /// What the table is for is being able to lose one entry without touching
    /// the others: a device whose secret is struck out here is the only one
    /// that has to be re-enrolled, where rotating the one `secret` re-enrolls
    /// every device at once.
    ///
    /// A device that names no device answers with the client's `secret`, so a
    /// client that wants per-device revocation has to stop handing that one
    /// out.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub devices: HashMap<String, DeviceAuth>,
    /// Whether a peer that names no device may still answer with the `secret`
    /// above.
    ///
    /// Revoking a device strikes one entry out of `devices` and leaves this
    /// secret standing, so a client that has been handing it out — every
    /// install that enrolled before the table existed, and every invite link
    /// shared since — keeps a credential no revocation can reach: whoever has
    /// it only has to omit the device name to go on authenticating. Setting
    /// this to `false` is what makes per-device revocation mean something for
    /// such a client; leaving it `true` keeps the behaviour it has always had.
    #[serde(default = "default_unnamed_device_allowed")]
    pub unnamed_device_allowed: bool,
    /// Last successful authentication time (Unix timestamp)
    #[serde(default)]
    pub last_used: Option<u64>,
    /// The last TOTP step this client's own secret was accepted on.
    ///
    /// The step, not the code: a code changes every thirty seconds, and what
    /// is worth remembering is the **step** — a code from an earlier step is
    /// still inside the acceptance window, and this is what refuses it.
    ///
    /// This is the memory of the **unnamed** device — the client answering
    /// with its own `secret`. A named device keeps its own, under its own
    /// entry, because the two are different credentials and a step accepted
    /// for one says nothing about the other.
    #[serde(default)]
    pub last_used_step: Option<u64>,
    /// Number of failed attempts
    #[serde(default)]
    pub failed_attempts: u32,
    /// Lockout expiry time (Unix timestamp)
    #[serde(default)]
    pub locked_until: Option<u64>,
    /// How many times in a row a guess at the pending enrollment token was wrong.
    ///
    /// A counter of its own, and not [`Self::failed_attempts`]: a client id is
    /// not a secret — it is in the invite link, in `nexapipe client list` and in
    /// whatever the operator pasted into a ticket — so anybody who knows one
    /// can send enrollment attempts at a client that is waiting to enroll.
    /// Counting those against the client's own counter meant a stranger could
    /// lock out the devices that had already enrolled, over a credential those
    /// devices were never sent. This one counts what is spent on the token
    /// instead.
    ///
    /// It has its own window as well — [`Self::enrollment_locked_until`] — so
    /// the token keeps a ceiling on guessing, and the ceiling is not paid for
    /// by the client's authentication.
    #[serde(default)]
    pub enrollment_failed_attempts: u32,
    /// When the enrollment lockout runs out, as a Unix timestamp.
    ///
    /// The enrollment slot's own lockout, separate from
    /// [`Self::locked_until`] for the reason the counter above is separate.
    #[serde(default)]
    pub enrollment_locked_until: Option<u64>,
}

/// Handwritten so `secret` and `pending_enrollment` stay out of logs.
///
/// The whole config — this struct included — is logged at debug level whenever
/// it is parsed, and both fields are live credentials: the seed is half of a
/// client's second factor, and the token is the whole of it until someone
/// spends it. `Serialize` still round-trips both, which is what the config file
/// needs; only the `Debug` view is redacted.
impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("allow_hosts", &self.allow_hosts)
            .field("allow_ports", &self.allow_ports)
            .field("allow_ports_strict", &self.allow_ports_strict)
            .field(
                "pending_enrollment",
                &crate::config::redacted(&self.pending_enrollment),
            )
            .field("devices", &self.devices)
            .field("unnamed_device_allowed", &self.unnamed_device_allowed)
            .field("last_used", &self.last_used)
            .field("last_used_step", &self.last_used_step)
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_until", &self.locked_until)
            .field(
                "enrollment_failed_attempts",
                &self.enrollment_failed_attempts,
            )
            .field("enrollment_locked_until", &self.enrollment_locked_until)
            .finish()
    }
}

impl ClientAuth {
    /// Check if client is currently locked out
    pub fn is_locked_out(&self) -> bool {
        self.locked_until.is_some_and(|until| unix_now() < until)
    }

    /// Whether the client's own secret may be used on this step, and the
    /// memory that goes with the answer.
    ///
    /// This is the **unnamed** device's memory — the client answering with
    /// its own `secret`. A named device keeps its own, under its own entry.
    pub fn accept_step(&mut self, step: u64) -> StepVerdict {
        accept_step(&mut self.last_used_step, step)
    }

    /// Clears a lockout whose time has run out.
    ///
    /// Without this the counter stays where `record_failure` left it — at or
    /// above `max_attempts` — so the first mistake after a lockout expires locks
    /// the client out again immediately, and every lockout after the first is
    /// one attempt long.
    pub fn refresh_lockout(&mut self) {
        let now = unix_now();
        if self.locked_until.is_some_and(|until| until <= now) {
            self.locked_until = None;
            self.failed_attempts = 0;
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&mut self, max_attempts: u32, lockout_duration: u64) {
        self.failed_attempts += 1;
        if self.failed_attempts >= max_attempts {
            self.locked_until = Some(unix_now() + lockout_duration);
        }
    }

    /// Whether the enrollment slot is locked out.
    ///
    /// The enrollment's own lockout, not the client's: a client that is
    /// waiting to enroll and a client whose devices have already enrolled are
    /// two situations, and only the first is what a guess at a token touches.
    pub fn is_enrollment_locked_out(&self) -> bool {
        self.enrollment_locked_until
            .is_some_and(|until| unix_now() < until)
    }

    /// Clears an enrollment lockout whose time has run out.
    ///
    /// The same rule as [`Self::refresh_lockout`], for the enrollment's own
    /// counter: without this the count stays where the last refusal left it,
    /// so the first mistake after the window ends locks the slot out again
    /// immediately, and every lockout after the first is one attempt long.
    pub fn refresh_enrollment_lockout(&mut self) {
        let now = unix_now();
        if self
            .enrollment_locked_until
            .is_some_and(|until| until <= now)
        {
            self.enrollment_locked_until = None;
            self.enrollment_failed_attempts = 0;
        }
    }

    /// Clears the enrollment counters once the token has been spent.
    ///
    /// The token is gone after a successful enrollment, so the guesses at it
    /// are spent too: keeping the count would leave the next invite — which
    /// replaces this token, not extends it — starting one mistake away from a
    /// lockout earned by a token that no longer exists.
    pub fn record_enrollment_success(&mut self) {
        self.enrollment_failed_attempts = 0;
        self.enrollment_locked_until = None;
    }

    /// Records a guess at the pending enrollment token that was wrong.
    ///
    /// The enrollment's own counter, so the client this is about goes on
    /// authenticating: the devices that already hold a credential are not
    /// paying for somebody guessing at a token they were never sent.
    pub fn record_enrollment_failure(&mut self, max_attempts: u32, lockout_duration: u64) {
        self.enrollment_failed_attempts += 1;
        if self.enrollment_failed_attempts >= max_attempts {
            self.enrollment_locked_until = Some(unix_now() + lockout_duration);
        }
    }

    /// Reset failed attempts on successful authentication
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
        self.last_used = Some(unix_now());
    }

    /// Note that this device authenticated just now, and report whether the
    /// stamp moved.
    ///
    /// The client-level [`Self::record_success`] does not reach a device: a
    /// device is a credential of its own, so "which of these devices is still
    /// in use, and which can be revoked without touching a live one" — the
    /// question the device table exists to answer — was left unanswered for
    /// every named device, and `client list` reported "never used" for all of
    /// them forever.
    ///
    /// `false` means the device is not in the table, or its stamp is already
    /// this second. The caller uses it to decide whether a write is owed:
    /// `unix_now` is whole seconds, so a device reconnecting inside the same
    /// second costs nothing.
    pub fn record_device_success(&mut self, device: &str) -> bool {
        self.record_device_success_at(device, unix_now())
    }

    /// The same, with the second handed in.
    ///
    /// Split out so that a test can ask about a second of its own choosing:
    /// the rule is "a whole second", and a test that asks the wall clock for
    /// it is a test that fails whenever the two calls land either side of a
    /// second boundary — which is exactly what happened under a full test
    /// run, where the process is descheduled between them.
    pub(super) fn record_device_success_at(&mut self, device: &str, now: u64) -> bool {
        let Some(entry) = self.devices.get_mut(device) else {
            return false;
        };
        let moved = entry.last_used != Some(now);
        entry.last_used = Some(now);
        moved
    }

    /// Decode the Base32 secret into bytes.
    ///
    /// The stored spelling is normalised first. An invite puts the secret
    /// through `otpauth::normalize_secret`, which tolerates lower case and `=`
    /// padding, so a secret written either of those ways in the config has to
    /// work as well — otherwise it fails to decode here and the client is stuck
    /// at "Invalid Base32 secret" with nothing saying the spelling is why.
    pub fn decode_secret(&self) -> Result<SecretBytes, anyhow::Error> {
        decode_base32_secret(self.secret.as_str())
    }

    /// The host authorization for a connection authenticated as this client.
    ///
    /// Built once per connection, not consulted per stream, so a reload that
    /// removes the client — or its `allow_hosts` — does not change what a
    /// connection already holding its credentials may reach.
    pub fn acl(&self) -> ClientAcl {
        ClientAcl::from_hosts_and_ports(self.allow_hosts.as_deref(), self.allow_ports.as_deref())
            .with_strict_ports(self.allow_ports_strict)
    }
}
