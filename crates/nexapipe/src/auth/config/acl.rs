//! Which hosts a client may reach.
//!
//! The list is folded into a credential when a connection authenticates, so
//! that what is checked is the state the authentication saw and not the
//! state the configuration may have become since.

/// Which hosts, and which ports, one authenticated client may reach.
///
/// 2FA answers *who* may connect; this answers *what they may touch once they
/// have*. Without it, one client's secret is a key to every route and every
/// backend, so a single leaked enrollment is a full-backend compromise.
///
/// The two questions are separate because they answer different things. A host
/// is a name; a port is a service on that name, and a client that may have
/// the name does not automatically get every service on it. `allow_hosts` says
/// which names, `allow_ports` says which services.
///
/// A client with neither configured is unrestricted — the historical
/// behaviour, kept as the default so existing configs mean what they meant.
///
/// The patterns are folded and matched by the same rules a route's
/// `host_pattern` uses ([`crate::routes::host_matches`]), so an entry here
/// authorizes exactly the hosts the corresponding route entry would serve.
///
/// A denial is always reported to the client the way "no route" is — 404,
/// `Status::NoRoute`, or a hang-up — never a 403, which would confirm to a
/// compromised client that the host it asked for exists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientAcl {
    /// The folded host patterns. `None` means every host.
    hosts: Option<Vec<String>>,
    /// The ports this client may reach. `None` means every port.
    ports: Option<Vec<u16>>,
    /// Whether the port list is also checked against the port a request is
    /// actually served from.
    ///
    /// See [`ClientAuth::allow_ports_strict`]. Off means the historical
    /// behaviour: the port list is checked against the port the client
    /// *named*, and a request that named none is not checked at all.
    strict_ports: bool,
}

impl ClientAcl {
    /// An ACL that permits everything.
    ///
    /// The same as the default, and named because "the default" says where the
    /// value came from rather than what it means.
    pub fn unrestricted() -> Self {
        ClientAcl::default()
    }

    /// Folds `hosts` into an ACL. `None` is unrestricted; an empty list
    /// restricts to nothing.
    pub fn from_hosts(hosts: Option<&[String]>) -> Self {
        ClientAcl::from_hosts_and_ports(hosts, None)
    }

    /// Folds `hosts` and `ports` into an ACL.
    ///
    /// `None` for either is unrestricted on that axis; an empty list
    /// restricts to nothing on it. The two are independent: a client may be
    /// limited to one host and every port, or every host and one port.
    pub fn from_hosts_and_ports(hosts: Option<&[String]>, ports: Option<&[u16]>) -> Self {
        ClientAcl {
            hosts: hosts.map(|hosts| {
                hosts
                    .iter()
                    // Folded as a pattern, not as a host: a spelling that
                    // would fold into the catch-all keeps its own shape, so an
                    // allow-list can never end up authorizing every host.
                    .map(|h| crate::routes::normalize_pattern(h).into_owned())
                    .collect()
            }),
            ports: ports.map(|ports| ports.to_vec()),
            strict_ports: false,
        }
    }

    /// Whether the port list is also checked against the port a request is
    /// served from.
    ///
    /// A builder rather than a constructor argument, because the flag is
    /// about *how* the list is applied rather than about what it contains —
    /// and every existing caller wants the historical answer.
    pub fn with_strict_ports(mut self, strict: bool) -> Self {
        self.strict_ports = strict;
        self
    }

    /// Whether the client may reach a service on `port`.
    ///
    /// The port here is the one the request is **served from** — the
    /// backend's — not the one the client named. Only asked when the ACL is
    /// strict; otherwise the port list is checked where the client names a
    /// port, and this has nothing to add.
    pub fn allows_backend_port(&self, port: u16) -> bool {
        if !self.strict_ports {
            return true;
        }
        self.allows_port(port)
    }

    /// Whether `host` may be reached by a client governed by this ACL.
    ///
    /// The host half on its own: what a route lookup asks, where the port is
    /// not the client's to choose.
    pub fn allows(&self, host: &str) -> bool {
        match &self.hosts {
            None => true,
            Some(patterns) => {
                let host = crate::routes::normalize_host(host);
                patterns
                    .iter()
                    .any(|pattern| crate::routes::host_matches(pattern, &host))
            }
        }
    }

    /// Whether this client may reach `port`.
    ///
    /// The port half on its own, for the places that have a port and no host:
    /// a tunnel preface names both, but a check that only knows the port
    /// still has to be able to ask about it.
    pub fn allows_port(&self, port: u16) -> bool {
        match &self.ports {
            None => true,
            Some(ports) => ports.contains(&port),
        }
    }

    /// Whether `host` on `port` may be reached by a client governed by this
    /// ACL.
    ///
    /// Both halves have to say yes. A port the client named and the ACL does
    /// not list is a refusal, and it is refused the same way a host is: as
    /// "no route", so the difference cannot be used to probe what exists.
    pub fn allows_target(&self, host: &str, port: u16) -> bool {
        self.allows(host) && self.allows_port(port)
    }

    /// Whether this ACL says anything about ports at all.
    ///
    /// A client with no `allow_ports` is not limited by one, and a place that
    /// has no port to check — a TLS passthrough, where the route picks the
    /// port and the client never names one — asks this rather than guessing.
    pub fn limits_ports(&self) -> bool {
        self.ports.is_some()
    }
}
