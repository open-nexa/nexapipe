//! The proxy's own lifecycle: what the app starts, and what it stops.
//!
//! The endpoint, the proxy on top of it, and the connections in between. What
//! the app asks of the proxy is here; what the proxy is asked is in
//! [`super::credentials`], [`super::routing`] and [`super::network`].

use super::*;

use jni::EnvUnowned;
use jni::objects::JClass;
use jni::sys::{jint, jstring};

use crate::jni_log;

use super::credentials::{
    current_two_factor_auth, node_device_key_for, node_enrollment_snapshot, node_has_two_factor,
    node_two_factor_snapshot, two_factor_auth,
};
use super::network::OverrideResolver;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeInit(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jint {
    with_env_or(&mut unowned_env, -1, native_init)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartIroh(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        start_iroh(env)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartProxy(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jint {
    with_env_or(&mut unowned_env, -1, start_proxy)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopProxy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // The body drives the runtime through three `block_on`s. Unwinding out of
    // an `extern "system"` frame is a native crash on Android rather than
    // something the JVM can turn into an exception, so it is caught here.
    catching_panic("nativeStopProxy", stop_proxy).unwrap_or(-1)
}

/// Closes and forgets every cached backend connection, keeping the iroh endpoint.
///
/// This is the Android network-switch recovery step. A connection opened on the previous
/// network is not closed as far as QUIC is concerned — its `close_reason()` is still `None`
/// while its path is dead — so the pool keeps handing it out and every proxied request fails
/// or hangs, even though the tunnel itself was rebuilt correctly. Dropping them makes the next
/// request dial on the current network; `nativePreconnect` then fills the pool again.
///
/// The endpoint is deliberately left alone: it is shared with the running TUN proxy, and
/// rebinding it would pull a working tunnel apart.
///
/// Returns 0 when the connections were dropped, -1 when nothing has been started yet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDropConnections(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // The body drives the runtime, and unwinding out of an `extern "system"`
    // frame is a native crash on Android rather than something the JVM can
    // turn into an exception. So the catch is around the whole body, not
    // around the one part of it that blocks.
    catching_panic("nativeDropConnections", drop_connections).unwrap_or(-1)
}

/// The body of `nativeDropConnections`, split out so the catch has something
/// to wrap.
fn drop_connections() -> jint {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativeDropConnections: runtime not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: state not initialized");
                return -1;
            }
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativeDropConnections: failed to lock state");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] nativeDropConnections: no endpoint group yet");
                return -1;
            }
        }
    };

    runtime.block_on(async move { endpoint_group.drop_connections().await });

    jni_log!("[DEBUG:jni] nativeDropConnections: dropped every cached connection");
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeDestroy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // The teardown drives the runtime through several `block_on`s, so it is
    // caught for the same reason as the rest: an unwind out of this frame is
    // a native crash on Android rather than something the JVM can report.
    catching_panic("nativeDestroy", destroy).unwrap_or(-1)
}

/// The body of `nativeDestroy`, split out so the catch has something to wrap.
fn destroy() -> jint {
    jni_log!("[DEBUG:jni] nativeDestroy called (full teardown: endpoint + proxy)");
    // Phase 1: briefly lock ENDPOINT, bump the generation and take the endpoint out so the next
    // nativeStartIroh rebuilds it. nativeStartIroh's bind() doesn't hold the ENDPOINT lock, so this
    // won't deadlock against startIroh.
    let endpoint = {
        if let Ok(mut guard) = ENDPOINT.lock() {
            ENDPOINT_GEN.fetch_add(1, Ordering::AcqRel);
            let ep = guard.take();
            jni_log!(
                "[DEBUG:jni] Endpoint released (generation bumped), present={}",
                ep.is_some()
            );
            ep
        } else {
            jni_log!("[DEBUG:jni] Failed to lock ENDPOINT, continuing with proxy cleanup");
            None
        }
    };
    // Phase 2+3: stop the endpoint_group / conn_pool (without touching ENDPOINT).
    // The same body `nativeStopProxy` runs, and stopped the same way: the
    // catch around it is the one that entry point uses.
    let result = catching_panic("nativeStopProxy", stop_proxy).unwrap_or(-1);

    // Phase 4: explicitly close the endpoint. conn_pool.close_all() now only closes the pool's own
    // endpoint (new()); the shared global endpoint is closed here.
    if let Some(ep) = endpoint
        && let Some(r) = get_runtime()
    {
        // Caught for the same reason as above: closing blocks on the
        // runtime, and an unwind out of this frame is a crash. This one is
        // its own catch because a failure here must not cost the teardown
        // the rest of it already did.
        let _ = catching_panic("nativeDestroy", || {
            r.block_on(async {
                let _ = tokio::time::timeout(CLOSE_ALL_TIMEOUT, ep.close()).await;
            })
        });
        jni_log!("[DEBUG:jni] Endpoint closed");
    }
    result
}
fn native_init(env: &mut Env<'_>) -> jint {
    // Only the Android half needs the environment; elsewhere the parameter is
    // accepted so the entry point can be written once.
    #[cfg(not(target_os = "android"))]
    let _ = env;

    #[cfg(target_os = "android")]
    {
        // The VM this thread is attached to, asked for through `Env` rather
        // than read out of the JNI function table by hand: 0.22's `sys`
        // bindings group those slots by the JNI version they arrived in, so
        // there is no flat `GetJavaVM` field to call any more.
        //
        // `JavaVM::singleton()` would read tidier but it is still empty at this
        // point — jni records the VM the first time it hands out an `Env`, and
        // this runs before anything has. Going through `Env` is what fills it.
        //
        // Still checked rather than unwrapped: a null VM handed to the context
        // is a crash the first time anything logs, and this runs before there
        // is a logger to say so.
        if let Ok(vm) = env.get_java_vm() {
            let raw_vm = vm.get_raw();
            if !raw_vm.is_null() {
                // SAFETY: `raw_vm` is the VM this thread is attached to, which
                // is what ndk_context wants; it outlives the process.
                unsafe {
                    ndk_context::initialize_android_context(raw_vm as *mut _, std::ptr::null_mut());
                }
            }
        }
        // `Info` by default, not `Debug`: the debug logs along the data path
        // print request headers and payload previews, and logcat is readable
        // by anything with adb. Raise the level here to bring them back, and
        // only on a build you are debugging.
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("NexaVpnService"),
        );
    }

    // Chained rather than installed: whatever hook the host process already had
    // — the JVM's, or another library's — is still the one that decides what a
    // panic does to the process. `set_hook` on its own deletes it, so a host
    // that crash-reports through its own hook would silently stop reporting.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let msg = match panic_info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match panic_info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "Unknown panic",
            },
        };
        let location = panic_info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        jni_log!("RUST PANIC: {}{}", msg, location);
        previous_hook(panic_info);
    }));

    // Four workers left two cores idle on every modern phone and made the TUN pump,
    // the QUIC driver and the smoltcp runner compete for the same threads. Scale with the
    // device instead, but keep a floor (4) and a ceiling (8) so a 16-core phone does not
    // spread the data path across enough threads to hurt cache locality.
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 8);
    let rt = Builder::new_multi_thread()
        .thread_name("nexapipe-worker")
        .worker_threads(worker_threads)
        .enable_all()
        .build();
    jni_log!(
        "[DEBUG:jni] tokio runtime worker_threads={}",
        worker_threads
    );

    match rt {
        Ok(rt) => {
            let _ = RUNTIME.set(rt);
        }
        Err(e) => {
            jni_log!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    }
    let _ = init_state();
    0
}

fn start_iroh(env: &mut Env<'_>) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartIroh");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    // The reason left behind by an earlier failure is not the reason for this
    // one: the caller reads it after a failed start, and a stale one is a
    // reason for something that did not happen. The attempt below writes its
    // own.
    clear_last_error();

    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    // Fast path: if an endpoint already exists, return immediately. Holds the lock briefly without crossing any await.
    {
        if let Ok(guard) = ENDPOINT.lock()
            && let Some(ep) = guard.as_ref()
        {
            let id = ep.id().to_string();
            return match env.new_string(id) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
        }
    }

    // Don't hold the ENDPOINT lock during bind() to avoid deadlocking with nativeStopProxy.
    let gen_before = ENDPOINT_GEN.load(Ordering::Acquire);

    // Read the system DNS servers injected by Kotlin plus the pre-resolved iroh infrastructure IPs.
    // Hold the lock briefly to clone, then release immediately, without crossing await.
    let custom_dns: Vec<SocketAddr> = CUSTOM_DNS_SERVERS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let dns_overrides: HashMap<String, Vec<IpAddr>> =
        DNS_OVERRIDES.lock().map(|g| g.clone()).unwrap_or_default();

    let bind_result: Result<Endpoint, ()> = runtime.block_on(async move {
        // Read the relay config injected by Kotlin (set by nativeSetRelayConfig).
        // An empty mode means Kotlin has not injected one yet -> "pinned", which is what the
        // UI defaults to. Anything else either resolves or is a hard error; no mode is ever
        // silently substituted for the one that was asked for.
        let cfg_mode = RELAY_MODE.lock().map(|g| g.clone()).unwrap_or_default();
        let cfg_url = CUSTOM_RELAY_URL
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let cfg_token = RELAY_AUTH_TOKEN
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let relay =
            match RelayModeSpec::parse(Some(&cfg_mode), Some(&cfg_url), Some(cfg_token.as_str())) {
                Ok(spec) => spec.unwrap_or(RelayModeSpec::Pinned),
                Err(e) => {
                    // The reason is what the user has to act on, and the log
                    // line is behind the debug level: without this the app
                    // says "could not start iroh" and nothing else.
                    set_last_error(format!("invalid relay configuration: {e}"));
                    jni_log!("[iroh] invalid relay configuration: {e}");
                    return Err(());
                }
            };
        if !relay.uses_url() && !cfg_url.is_empty() {
            jni_log!(
                "[iroh] ignoring relay_url {:?}: mode {} does not use one",
                cfg_url,
                cfg_mode
            );
        }
        jni_log!("[iroh] relay: {}", relay.describe());
        // Whether this endpoint may ask n0 where a peer is. It is the one piece
        // of n0's infrastructure a relay setting does not reach, so it gets a
        // setting of its own.
        let cfg_discovery = DISCOVERY_MODE.lock().map(|g| g.clone()).unwrap_or_default();
        // An empty value means nothing has been injected yet, which falls back to "n0" —
        // the same reading an unset setting gets everywhere else. Only a value that
        // names a mode wrongly is an error.
        let discovery = match DiscoveryMode::parse_or_default(&cfg_discovery) {
            Ok(mode) => mode,
            Err(e) => {
                // The reason is what the user has to act on, and the log
                // line is behind the debug level: without this the app says
                // "could not start iroh" and nothing else.
                set_last_error(format!("invalid discovery configuration: {e}"));
                jni_log!("[iroh] invalid discovery configuration: {e}");
                return Err(());
            }
        };
        jni_log!("[iroh] discovery: {}", discovery.describe());
        // Which relay a *peer* may be dialled through. `custom` says this
        // endpoint uses one relay and no other, and that has to hold for the
        // peer too — iroh's `relay_mode` only bounds the relay this endpoint
        // registers with, so a peer naming somebody else's relay would
        // otherwise be dialled through it. A peer named only by a Node ID is
        // dialled while the lookup above is on — the Android app names every
        // peer that way — and refused once the lookup is off.
        let restriction = relay.dial_restriction(discovery);
        if let Some(restriction) = &restriction {
            let covered = restriction.describe();
            jni_log!("[iroh] peers are dialled through {covered}");
        }
        let mut builder = Endpoint::builder(presets::N0)
            .alpns(crate::connection_pool::alpns(
                nexapipe_proto::protocol::Protocol::Legacy,
            ))
            .relay_mode(relay.relay_mode());
        builder = discovery.apply(builder);
        if let Some(restriction) = restriction {
            builder = builder.hooks(restriction);
        }
        // Always wrap hickory with OverrideResolver:
        // - For iroh infrastructure domains in DNS_OVERRIDES (dns.iroh.link, *.relay.n0.iroh.link),
        //   return Kotlin's pre-resolved IPs directly, bypassing the GFW's blocking of iroh.link
        //   UDP DNS responses. This lets pkarr resolve (HTTPS to dns.iroh.link/pkarr/<z32>) reach the
        //   pkarr server and fetch the target node's EndpointInfo; relay domains can also reach the
        //   relay server.
        // - All other domains go through hickory + the system DNS servers (custom_dns).
        //   Even if custom_dns is empty, OverrideResolver internally falls back to DnsResolver::new().
        jni_log!(
            "[DEBUG:jni] Building OverrideResolver: {} DNS servers, {} override domains {:?}",
            custom_dns.len(),
            dns_overrides.len(),
            dns_overrides.keys().collect::<Vec<_>>()
        );
        let override_resolver = OverrideResolver::new(custom_dns.clone(), dns_overrides);
        let dns_resolver = DnsResolver::custom(override_resolver);
        // One inner TCP connection == one QUIC bi-stream, so the per-stream receive window is
        // the throughput ceiling of every proxied connection. iroh's 1.25 MB default caps a
        // 200 ms path at roughly 50 Mbps; see crate::transport for the full rationale.
        let (transport, tuning) = crate::transport::transport_config_with_tuning();
        jni_log!("[DEBUG:jni] QUIC transport tuning: {}", tuning.describe());
        let builder = builder
            .dns_resolver(dns_resolver)
            .transport_config(transport);

        match tokio::time::timeout(IROH_BIND_TIMEOUT, builder.bind()).await {
            Ok(Ok(ep)) => Ok(ep),
            Ok(Err(e)) => {
                // The reason the caller shows the user: "could not start iroh"
                // on its own names nothing they can act on.
                set_last_error(format!("failed to start the iroh endpoint: {e}"));
                jni_log!("Failed to start iroh endpoint: {}", e);
                Err(())
            }
            Err(_) => {
                set_last_error(format!(
                    "the iroh endpoint did not start within {}s",
                    IROH_BIND_TIMEOUT.as_secs()
                ));
                jni_log!(
                    "iroh endpoint bind timed out after {}s",
                    IROH_BIND_TIMEOUT.as_secs()
                );
                Err(())
            }
        }
    });
    let ep = match bind_result {
        Ok(ep) => ep,
        Err(()) => return std::ptr::null_mut(),
    };

    // Re-lock to commit: if a stop happened in between (generation changed), discard the late endpoint;
    // if a concurrent startIroh already wrote one, return its id; otherwise write our own.
    let node_id = match ENDPOINT.lock() {
        Ok(mut guard) => {
            let gen_now = ENDPOINT_GEN.load(Ordering::Acquire);
            if gen_now != gen_before {
                jni_log!("endpoint generation changed during bind, discarding late endpoint");
                drop(ep); // Stray late result of an isolated bind: discard it; don't revive a released tunnel.
                return std::ptr::null_mut();
            }
            if let Some(existing) = guard.as_ref() {
                existing.id().to_string()
            } else {
                let id = ep.id().to_string();
                *guard = Some(ep);
                id
            }
        }
        Err(_) => {
            jni_log!("Failed to lock endpoint mutex on commit");
            return std::ptr::null_mut();
        }
    };

    match env.new_string(node_id) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn start_proxy(env: &mut Env<'_>) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartProxy");
        env.exception_clear();
        return -1;
    }

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            set_last_error("Native runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            set_last_error("Native state not initialized");
            return -1;
        }
    };

    let nodes: Vec<NodeConfig>;
    let domain_mappings: Vec<DomainMapping>;

    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state mutex (poisoned)");
                return -1;
            }
        };
        nodes = guard.nodes.clone();
        domain_mappings = guard.domain_mappings.clone();
    }

    // Pre-flight: every configured endpoint ID must parse. Checked before anything is bound, so a
    // malformed ID is reported as a malformed ID (and not retried as if the port were taken).
    if let Some(message) = first_invalid_node_id(&domain_mappings, &nodes) {
        jni_log!("[DEBUG:jni] nativeStartProxy rejected: {}", message);
        set_last_error(message);
        return RESULT_CONFIG_ERROR;
    }
    clear_last_error();

    jni_log!("[DEBUG:jni] nativeStartProxy called (no local listener)");

    // Fail fast: refuse to continue when there is no endpoint. Otherwise we'd fall into the
    // "one bind() per node" branch (connection_pool.rs, no timeout, scales with backend count) and
    // reintroduce the hang.
    let ep = match get_endpoint() {
        Some(ep) => ep,
        None => {
            jni_log!("[DEBUG:jni] No iroh endpoint available; call nativeStartIroh first");
            set_last_error("No iroh endpoint available; call nativeStartIroh first");
            return -1;
        }
    };

    // The catch here is around the work that blocks; the entry point has
    // another one around its whole body, so a panic anywhere in here stops
    // at one of the two rather than at the `extern "system"` boundary.
    let result = catching_panic("nativeStartProxy", || {
        runtime.block_on(async move {


            let endpoint_group: EndpointGroup = if !domain_mappings.is_empty() {
                jni_log!(
                    "[DEBUG:jni] Using domain_mappings ({} entries)",
                    domain_mappings.len()
                );
                match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_domain_mappings_and_endpoint(
                        domain_mappings,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                }
            } else if !nodes.is_empty() {
                jni_log!("[DEBUG:jni] Using nodes ({} entries)", nodes.len());

                // The destinations themselves are handed to the TUN proxy
                // separately (nativeStartTunProxy), so only their presence is
                // checked here: a node without a domain is a configuration
                // error either way, and saying so beats coming up "connected"
                // over a tunnel that has nothing to route.
                if nodes.iter().all(|node| node.domains.is_empty()) {
                    jni_log!("No domains configured for nodes");
                    return Err("No domains configured for nodes".to_string());
                }

                match tokio::time::timeout(
                    START_PROXY_TIMEOUT,
                    EndpointGroup::new_with_nodes_and_endpoint(
                        nodes,
                        None,
                        LoadBalancingStrategy::RoundRobin,
                        ep.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(eg)) => eg,
                    Ok(Err(e)) => {
                        jni_log!("Failed to create endpoint group: {}", e);
                        return Err(format!("Failed to create endpoint group: {}", e));
                    }
                    Err(_) => {
                        jni_log!(
                            "Endpoint group creation timed out after {}s",
                            START_PROXY_TIMEOUT.as_secs()
                        );
                        return Err("Endpoint group creation timed out".to_string());
                    }
                }
            } else {
                jni_log!("No nodes or domain mappings configured");
                return Err("No nodes or domain mappings configured".to_string());
            };

            // 2FA: push the Kotlin-injected credentials to the connection group; new connections run the auth handshake first.
            // The global pair goes to every pool first, then each endpoint's own
            // credentials override it. An endpoint with no entry of its own —
            // and an empty secret counts as an explicit "none" — ends up with
            // no credentials, so it never opens an auth stream against a server
            // that does not expect one.
            if let Some(auth) = current_two_factor_auth() {
                endpoint_group.set_two_factor(Some(auth)).await;
            }
            for (node_id, cfg) in node_two_factor_snapshot() {
                // Passed along, not preferred: the key is the credential only
                // where the record has no secret, and `two_factor_auth` is what
                // decides that. A key the server never recorded (an older
                // server ignored the offer) must not shadow the secret it
                // issued instead.
                let key = node_device_key_for(&node_id);
                endpoint_group
                    .set_two_factor_for(&node_id, two_factor_auth(&cfg, key.as_ref()))
                    .await;
            }
            // Enrollment last, and only where no credentials were registered: enrolling
            // rotates that client's secret, so a node that already has one must not spend a
            // token again — every other device enrolled from the same code would be locked
            // out by it.
            for (node_id, (client_id, token)) in node_enrollment_snapshot() {
                if node_has_two_factor(&node_id) {
                    continue;
                }
                // Named where the token is spent, which is the only moment a
                // name means anything: it is what makes the credential that
                // comes back this phone's alone, and enrolling without one is
                // how a device ends up sharing the client's secret — the thing
                // that makes revoking one rotate every other one.
                let name = device_id();
                let enrollment = Enrollment::new(&client_id, token.as_str());
                let enrollment = match &name {
                    Some(name) => enrollment.with_device(name),
                    None => enrollment,
                };
                // A device key is offered here rather than asked for: the server
                // records the public half under the device's name and issues no
                // secret at all, so the private half never has to be anywhere
                // but this device. A server that predates keys ignores the offer
                // and issues a secret as it always has, which is what the
                // credential then is.
                //
                // Only with a name, because the server refuses a key that names
                // no device — and a refusal that reads as a bad token would be a
                // lie: the token was fine and the device had no name.
                let enrollment = match (&name, node_device_key_for(&node_id)) {
                    (Some(_), Some(key)) => enrollment.with_key(key),
                    _ => enrollment,
                };
                endpoint_group
                    .set_enrollment_for(&node_id, Some(enrollment))
                    .await;
                jni_log!("[DEBUG:jni] enrollment armed for node '{}'", node_id);
            }

            let endpoint_group_arc = Arc::new(endpoint_group);

            // The backends are asked whether they still answer, on a timer, for
            // as long as this group is up. A phone changes network far more
            // often than a server does, and without this the group only ever
            // dialled at startup: a backend that went away — or a tunnel that
            // stopped working after a switch to cellular — was noticed by the
            // request that needed it, which on Android is an app that has
            // already timed out.
            endpoint_group_arc.start_health_probe();

            // Deliberately no local TCP listener here. On Android the tunnel is
            // reached through the TUN fd (nativeStartTunProxy) alone; a
            // listener on 127.0.0.1 is reachable by every other app on the
            // device and would hand them an already-authenticated tunnel
            // without anything asking the user. It is not part of the data
            // path, so there is nothing that has to replace it.

            // Write back to state: re-lock and verify it wasn't cleared by a concurrent stop.
            {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        jni_log!("Failed to lock state mutex (poisoned)");
                        return Err("Failed to update state".to_string());
                    }
                };
                if guard.endpoint_group.is_some() {
                    jni_log!(
                        "[DEBUG:jni] State already has an endpoint group (concurrent start/stop), aborting"
                    );
                    return Err("Proxy already running".to_string());
                }
                guard.endpoint_group = Some(endpoint_group_arc);
            }

            Ok(())
        })
    });

    match result {
        Some(Ok(_)) => {
            jni_log!("[DEBUG:jni] nativeStartProxy returning success");
            0
        }
        Some(Err(e)) => {
            jni_log!("[DEBUG:jni] Proxy start error: {}", e);
            let code = if e.contains("Parse error") || e.contains("No nodes or domain mappings") {
                RESULT_CONFIG_ERROR
            } else {
                -1
            };
            set_last_error(e);
            code
        }
        None => {
            // The reason was left behind by the catch that took the panic.
            jni_log!("[DEBUG:jni] Panic occurred during proxy start");
            -1
        }
    }
}

fn stop_proxy() -> jint {
    jni_log!("[DEBUG:jni] nativeStopProxy called (proxy-only, keeping iroh endpoint)");

    // Note: this function only stops endpoint_group / conn_pool, and does not touch the global
    // ENDPOINT. This way the connect path can call it before rebuilding the endpoint group
    // without tearing down the endpoint that ensureIrohStarted already built.
    // For a full teardown (including the endpoint), use nativeDestroy.
    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    // Phase 1.5: stop the TUN proxy first (must happen before endpoint_group.close_all()).
    // The TUN proxy's TCP connection tasks hold an Arc<EndpointGroup> clone; closing first would
    // make them access an already-closed connection pool. shutdown() aborts and waits for the
    // tasks to finish, ensuring the fd is closed.
    #[cfg(all(feature = "tun-proxy", target_os = "android"))]
    {
        let tun_proxy = {
            let mut guard = match state.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    // See the note on the lock below: the TUN fd is only closed by
                    // the proxy this is about to take out, so abandoning the
                    // cleanup because another thread once panicked leaves it open
                    // for the life of the process.
                    jni_log!(
                        "[WARN:jni] State lock poisoned, recovering the guard to close the TUN proxy"
                    );
                    poisoned.into_inner()
                }
            };
            guard.tun_proxy.take()
        }; // guard dropped
        if let Some(tp) = tun_proxy {
            if let Some(r) = get_runtime() {
                tp.shutdown(r);
                jni_log!("[DEBUG:jni] TUN proxy shutdown complete");
            } else {
                // No runtime — just abort; Drop will call stop().
                jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            }
            // tp dropped here (if not consumed by shutdown)
        }
    }

    // Phase 2: lock state, take the resources out (fields set to None), drop the guard immediately, then enter any block_on.
    let (endpoint_group, conn_pool) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // A poisoned lock means some thread panicked while holding it,
                // which is exactly when the resources it guards most need
                // closing. Recovering the guard is the only way to reach them:
                // returning here used to leave the endpoint group and the
                // connection pool in place, so the endpoint was never closed
                // and a later start inherited half of a stopped one.
                jni_log!("[WARN:jni] State lock poisoned, recovering the guard to finish the stop");
                poisoned.into_inner()
            }
        };
        jni_log!(
            "[DEBUG:jni] Stop: endpoint_group exists = {}, conn_pool exists = {}",
            guard.endpoint_group.is_some(),
            guard.conn_pool.is_some()
        );
        (guard.endpoint_group.take(), guard.conn_pool.take())
    }; // guard dropped here -- no longer holding the state lock.

    let runtime = get_runtime();

    // Phase 3: close the endpoint group / pool, each with its own timeout, without holding the state lock.
    if let Some(r) = runtime {
        if let Some(group) = endpoint_group.as_ref() {
            r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, group.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] endpoint_group close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] endpoint_group close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
        if let Some(pool) = conn_pool.as_ref() {
            r.block_on(async {
                match tokio::time::timeout(CLOSE_ALL_TIMEOUT, pool.close_all()).await {
                    Ok(_) => jni_log!("[DEBUG:jni] conn_pool close_all done"),
                    Err(_) => jni_log!(
                        "[DEBUG:jni] conn_pool close_all timed out after {}s",
                        CLOSE_ALL_TIMEOUT.as_secs()
                    ),
                }
            });
        }
    }

    jni_log!("[DEBUG:jni] nativeStopProxy returning after cleanup");
    0
}
