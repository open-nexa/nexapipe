//! How the proxy reaches the world: the resolvers, the relay, the discovery.
//!
//! These are the settings that describe the network around the proxy rather
//! than the proxy itself — where a name is resolved, which relay carries the
//! traffic, how the endpoint is found, and what this device calls itself.

use super::*;

use jni::EnvUnowned;
use jni::objects::{JClass, JString};
use jni::sys::jint;

use crate::jni_log;

/// Kotlin obtains the system DNS from ConnectivityManager.getLinkProperties().dnsServers and
/// passes it as a comma-separated IP string (e.g. "192.168.1.1,8.8.8.8"). This function parses it
/// into SocketAddr (port fixed to 53, UDP) and stores it in CUSTOM_DNS_SERVERS. nativeStartIroh
/// reads it before bind. Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsServers(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    dns_servers: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_dns_servers(env, dns_servers)
    })
}

/// Kotlin pre-resolves iroh infrastructure domains (dns.iroh.link, *.relay.n0.iroh.link) via the
/// system DNS (which may use DoT/Private DNS to bypass the GFW) and passes them in the format
/// "domain=ip1,ip2;domain2=ip3,ip4". This function parses and stores them in DNS_OVERRIDES.
/// OverrideResolver returns the pre-resolved IPs directly for these domains, bypassing hickory's
/// UDP DNS queries (the GFW drops UDP DNS responses for iroh.link domains).
/// This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/`<z32>`) reach iroh's pkarr server and fetch
/// the target node's EndpointInfo (relay URL + direct addr), even if DNS TXT is blocked by the GFW.
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDnsOverride(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    overrides: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| set_dns_override(env, overrides))
}

/// Configure the relay mode, custom URL and, for a relay that asks for one, the bearer token.
/// relay_mode: "pinned"/"default"/"disabled"/"custom". relay_url and relay_auth_token are only
/// used when relay_mode="custom".
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetRelayConfig(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    relay_mode: JString,
    relay_url: JString,
    relay_auth_token: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        set_relay_config(env, relay_mode, relay_url, relay_auth_token)
    })
}

/// Configure whether this endpoint may use n0's address lookup.
///
/// discovery_mode: "n0" (the default — a Node ID is looked up through
/// dns.iroh.link) or "none" (no lookup at all; a peer then has to bring an
/// address of its own, which is what a ticket carries).
///
/// Must be called before nativeStartIroh.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDiscoveryMode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    discovery_mode: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        if env.exception_check() {
            jni_log!("JNI exception pending before nativeSetDiscoveryMode");
            env.exception_clear();
            return -1;
        }

        let mode_str = match discovery_mode.try_to_string(env) {
            Ok(s) => s,
            Err(_) => {
                jni_log!("Failed to get discovery_mode string from JNI");
                return -1;
            }
        };

        jni_log!("[DEBUG:jni] nativeSetDiscoveryMode: mode='{mode_str}'");

        if let Ok(mut mode) = DISCOVERY_MODE.lock() {
            *mode = mode_str;
        }
        0
    })
}

/// Names this device, once, for every **enrollment** it spends.
///
/// deviceId: printable ASCII without spaces, as `SettingsManager.deviceId()`
/// generates it.
///
/// An enrollment is where a name is asked for: what comes back is filed under
/// it on the server, and `nativeTakeIssuedCredential` hands the name back so
/// Kotlin can keep it beside the secret and send it from then on. Credentials
/// acquired any other way are answered unnamed, because a name the server's
/// table does not carry is refused rather than falling back — see
/// `two_factor_auth` — and the pairs an install already holds were issued to
/// the client, not to a device.
///
/// Must be called before nativeStartProxy. Its own entry point rather than one
/// more argument on the 2FA calls, which already have enough of them and which
/// every credential would then have to answer for itself.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeSetDeviceId(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    device_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        if env.exception_check() {
            jni_log!("JNI exception pending before nativeSetDeviceId");
            env.exception_clear();
            return -1;
        }
        let name = read_jstring(env, &device_id).unwrap_or_default();
        jni_log!("[DEBUG:jni] nativeSetDeviceId: {} chars", name.trim().len());
        // A poisoned lock is a failure, not a silent skip. Skipping it left the
        // name unset while this returned 0, so Kotlin believed the device had
        // been named and went on connecting unnamed — which on a server that
        // refuses unnamed peers is a connection that keeps failing for a reason
        // nothing on either side reported.
        let Ok(mut slot) = DEVICE_ID.lock() else {
            jni_log!("[DEBUG:jni] nativeSetDeviceId: the device id lock is poisoned");
            return -1;
        };
        *slot = Some(name);
        0
    })
}
fn set_dns_servers(env: &mut Env<'_>, dns_servers: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetDnsServers");
        env.exception_clear();
        return -1;
    }

    let dns_str = match dns_servers.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get DNS servers string from JNI");
            return -1;
        }
    };

    // Parse the comma-separated IP list. Kotlin passes bare IPs (no port), so we always append port 53.
    let servers: Vec<SocketAddr> = dns_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeSetDnsServers: parsed {} servers from '{}'",
        servers.len(),
        dns_str
    );

    match CUSTOM_DNS_SERVERS.lock() {
        Ok(mut guard) => {
            *guard = servers;
        }
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS mutex");
            return -1;
        }
    }
    0
}

fn set_dns_override(env: &mut Env<'_>, overrides: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetDnsOverride");
        env.exception_clear();
        return -1;
    }

    let overrides_str = match overrides.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get DNS overrides string from JNI");
            return -1;
        }
    };

    // Parse the "domain=ip1,ip2;domain2=ip3,ip4" format.
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for entry in overrides_str.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '=');
        let domain = match parts.next() {
            Some(d) => crate::domains::fold_domain(d),
            None => continue,
        };
        if domain.is_empty() {
            continue;
        }
        let ips_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let ips: Vec<IpAddr> = ips_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        if ips.is_empty() {
            jni_log!(
                "[DEBUG:jni] nativeSetDnsOverride: no valid IPs for domain '{}'",
                domain
            );
            continue;
        }
        jni_log!(
            "[DEBUG:jni] nativeSetDnsOverride: {} -> {} IPs {:?}",
            domain,
            ips.len(),
            ips
        );
        map.insert(domain, ips);
    }

    jni_log!(
        "[DEBUG:jni] nativeSetDnsOverride: parsed {} override entries from '{}'",
        map.len(),
        overrides_str
    );

    match DNS_OVERRIDES.lock() {
        Ok(mut guard) => {
            *guard = map;
        }
        Err(_) => {
            jni_log!("Failed to lock DNS_OVERRIDES mutex");
            return -1;
        }
    }
    0
}

fn set_relay_config(
    env: &mut Env<'_>,
    relay_mode: JString,
    relay_url: JString,
    relay_auth_token: JString,
) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeSetRelayConfig");
        env.exception_clear();
        return -1;
    }

    let mode_str = match relay_mode.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get relay_mode string from JNI");
            return -1;
        }
    };

    let url_str = relay_url.try_to_string(env).unwrap_or_default();

    let token_str = relay_auth_token.try_to_string(env).unwrap_or_default();

    jni_log!(
        "[DEBUG:jni] nativeSetRelayConfig: mode='{}', url='{}', auth_token={}",
        mode_str,
        url_str,
        if token_str.is_empty() { "none" } else { "set" }
    );

    if let Ok(mut mode) = RELAY_MODE.lock() {
        *mode = mode_str;
    }
    if let Ok(mut url) = CUSTOM_RELAY_URL.lock() {
        *url = url_str;
    }
    if let Ok(mut token) = RELAY_AUTH_TOKEN.lock() {
        *token = SecretString::new(token_str);
    }
    0
}

/// Custom DNS Resolver that wraps the hickory resolver and returns pre-resolved IPs for specific domains.
///
/// The GFW drops UDP DNS responses for `iroh.link` domains, causing hickory resolution to time out.
/// This resolver returns Kotlin's pre-resolved IPs directly for domains in `DNS_OVERRIDES`
/// (Kotlin uses the system DNS, which may go through DoT/Private DNS to bypass the GFW); all other
/// domains still go through hickory.
pub(crate) struct OverrideResolver {
    inner: DnsResolver,
    overrides: HashMap<String, Vec<IpAddr>>,
    nameservers: Vec<SocketAddr>,
}

impl OverrideResolver {
    pub(crate) fn new(
        nameservers: Vec<SocketAddr>,
        overrides: HashMap<String, Vec<IpAddr>>,
    ) -> Self {
        let inner = if nameservers.is_empty() {
            DnsResolver::new()
        } else {
            // `NameserverConfig` keeps its fields private, so the port has to
            // be re-applied after the protocol constructor defaults it to 53.
            DnsResolver::builder()
                .add_nameserver_configs(
                    nameservers
                        .iter()
                        .map(|a| NameserverConfig::udp(a.ip()).with_port(a.port())),
                )
                .build()
        };
        Self {
            inner,
            overrides,
            nameservers,
        }
    }

    /// The addresses an override holds for `host`, if it holds any.
    ///
    /// The name is folded before the lookup: iroh asks for the fully-qualified
    /// spelling — every relay hostname it dials ends in a dot — and an override
    /// stored without the dot would otherwise never be found, and the query
    /// would fall through to the resolver the override exists to avoid.
    fn override_for(&self, host: &str) -> Option<&Vec<IpAddr>> {
        self.overrides.get(&crate::domains::fold_domain(host))
    }
}

impl fmt::Debug for OverrideResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverrideResolver")
            .field(
                "override_domains",
                &self.overrides.keys().collect::<Vec<_>>(),
            )
            .field("nameservers", &self.nameservers)
            .finish()
    }
}

impl Resolver for OverrideResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        if let Some(ips) = self.override_for(&host) {
            let ipv4s: Vec<Ipv4Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                })
                .collect();
            if !ipv4s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv4 addrs",
                    host,
                    ipv4s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv4(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv4s: Vec<Ipv4Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv4s.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        if let Some(ips) = self.override_for(&host) {
            let ipv6s: Vec<Ipv6Addr> = ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(*v6),
                    _ => None,
                })
                .collect();
            if !ipv6s.is_empty() {
                jni_log!(
                    "[DEBUG:jni] DNS override hit for {} -> {} IPv6 addrs",
                    host,
                    ipv6s.len()
                );
                return Box::pin(
                    async move { Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>) },
                );
            }
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_ipv6(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let ipv6s: Vec<Ipv6Addr> = result
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    _ => None,
                })
                .collect();
            Ok(Box::new(ipv6s.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let result = inner.lookup_txt(host.clone(), DNS_LOOKUP_TIMEOUT).await?;
            let v: Vec<TxtRecordData> = result.collect();
            Ok(Box::new(v.into_iter()) as BoxIter<TxtRecordData>)
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(OverrideResolver::new(
            self.nameservers.clone(),
            self.overrides.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An override is stored and looked up under the same name, whatever
    /// spelling either side uses: a name and the same name with a trailing
    /// dot are the same name, and so is the same name in another case.
    ///
    /// The trailing dot is not a corner case: every relay hostname iroh dials
    /// is fully qualified, and it is iroh that asks the resolver for it.
    #[test]
    fn an_override_is_found_however_the_name_is_spelled() {
        assert_eq!(
            crate::domains::fold_domain("APS1-1.relay.n0.iroh.link."),
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link")
        );
        assert_eq!(
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link."),
            "aps1-1.relay.n0.iroh.link"
        );
        assert_eq!(
            crate::domains::fold_domain(" dns.iroh.link. "),
            "dns.iroh.link"
        );
    }

    /// The lookup finds an override that was stored under the name without the
    /// dot, when the query carries it: iroh asks for the fully-qualified
    /// spelling, and an override that is not found is an override that does
    /// not exist.
    #[test]
    fn an_override_stored_without_the_dot_is_found_with_it() {
        let mut overrides: HashMap<String, Vec<IpAddr>> = HashMap::new();
        overrides.insert(
            crate::domains::fold_domain("aps1-1.relay.n0.iroh.link"),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        );
        let resolver = OverrideResolver::new(Vec::new(), overrides);

        let qualified = resolver.override_for("aps1-1.relay.n0.iroh.link.");
        let plain = resolver.override_for("aps1-1.relay.n0.iroh.link");
        let other = resolver.override_for("other.example.com");

        assert!(
            qualified.is_some(),
            "the fully-qualified spelling finds the override"
        );
        assert!(plain.is_some(), "the plain spelling finds it too");
        assert!(
            other.is_none(),
            "a name that was never overridden is not overridden"
        );
    }
}
