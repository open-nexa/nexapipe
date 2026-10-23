//! The TUN: the tunnel device, and the addresses it hands out.
//!
//! The tunnel is Android's half — it needs the device's own permission to
//! open the descriptor — and the virtual addresses are what the names inside
//! the tunnel resolve to.

/// The blocks the tunnel may claim, comma-separated: `198.18.0.0,198.19.0.0,…`.
///
/// The list lives in the client library so both clients walk the same one: the
/// desktop walks it to find a block the host will let it bind, and Android
/// walks it to find a block the network the phone is on will let it claim.
/// Two lists would drift, and a drift here is a tunnel whose two halves claim
/// different addresses.
///
/// Returns null when the answer could not be built, which Kotlin reads as "no
/// list" rather than as an empty one.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeVirtualBlockCandidates(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        let list = crate::virtual_block::TUN_BASE_CANDIDATES
            .iter()
            .map(|base| base.to_string())
            .collect::<Vec<_>>()
            .join(",");
        jni_log!("[DEBUG:jni] nativeVirtualBlockCandidates: {list}");
        match env.new_string(list) {
            Ok(encoded) => encoded.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Sets the block the tunnel claims and reports the addresses inside it.
///
/// `base` is the block's network address (`198.18.0.0`). The answer is a
/// `key=value;key=value` list — the shape the other answers in this file use —
/// naming the block, the interface address, the DNS server, the legacy proxy
/// address and the IPv6 half:
///
/// ```text
/// base=198.18.0.0;network=198.18.0.0/24;interface=198.18.0.1;dns=198.18.0.2;proxy=198.18.0.3;ipv6=fd00:198:18:0::;ipv6Interface=fd00:198:18:0::1
/// ```
///
/// Kotlin configures the VPN's addresses and routes from it, and the Rust side
/// hands out the per-domain addresses from the same block, so the two cannot
/// disagree about which addresses the tunnel claims — a disagreement being a
/// tunnel that comes up and carries nothing.
///
/// A `base` that is not an address is ignored rather than fatal: the block is
/// the caller's decision, and a caller that got it wrong is answered with the
/// block that is actually in use, which is the answer it needs either way.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeVirtualBlock(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    base: JString,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        virtual_block(env, base)
    })
}

/// Start the TUN proxy: process the TUN fd's TCP/UDP traffic on the Rust side with smoltcp.
///
/// Must be called after `nativeStartProxy` (endpoint_group already created) and after the VPN is
/// established. Kotlin transfers fd ownership to Rust via `ParcelFileDescriptor.detachFd()`.
///
/// Arguments:
/// - `tun_fd`: the TUN file descriptor (return value of detachFd)
/// - `proxy_domains`: comma-separated list of proxied domains
///
/// Returns 0 on success, -1 on failure.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        start_tun_proxy(env, _class, tun_fd, proxy_domains)
    })
}

/// Stop the TUN proxy: abort all background tasks and close the dup'd fd.
///
/// Called by `NexaVpnService.stopVPN()` before closing the TUN fd.
/// `nativeDestroy` also reaches it indirectly via `nativeStopProxy` (Phase 1.5).
///
/// The body is wrapped in `catching_panic` because it is the one TUN entry
/// point with no `with_env_or` around it: `nativeStartTunProxy` gets its unwind
/// barrier from that helper, while this one takes an `EnvUnowned` and does not
/// touch the environment at all. Unwinding out of an `extern "system"` frame is
/// a native crash on Android rather than something the JVM can report, so a
/// panic while joining the runtime's tasks would take the process down on the
/// one path that runs while the user is turning the VPN off.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    match catching_panic("nativeStopTunProxy", stop_tun_proxy) {
        Some(code) => code,
        None => -1,
    }
}
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn virtual_block(env: &mut Env<'_>, base: JString) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeVirtualBlock");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    match base.try_to_string(env) {
        Ok(text) => match text.trim().parse::<Ipv4Addr>() {
            Ok(address) => crate::virtual_block::set(address),
            Err(e) => jni_log!("[WARN:jni] nativeVirtualBlock: '{text}' is not an address: {e}"),
        },
        Err(e) => {
            jni_log!("[WARN:jni] nativeVirtualBlock: could not read the block: {e}");
            return std::ptr::null_mut();
        }
    }

    let encoded = crate::virtual_block::encoded();
    jni_log!("[DEBUG:jni] nativeVirtualBlock: {encoded}");

    match env.new_string(encoded) {
        Ok(encoded) => encoded.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The body of `nativeStartTunProxy`, split out so the catch has something to
/// wrap and nothing else inside it has to care.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn start_tun_proxy(
    env: &mut Env<'_>,
    _class: JClass,
    tun_fd: jint,
    proxy_domains: JString,
) -> jint {
    // The descriptor is ours from this line on. The JNI boundary is where the
    // ownership transfers, and it transfers exactly once: the Kotlin side has
    // detached the descriptor from its `ParcelFileDescriptor` and handed the
    // number over, so this side closes it — on the failure paths, by dropping
    // it; on the success path, by duplicating it and letting the original go.
    //
    // It has to be taken **here**, before the first `return`: every early
    // return below would otherwise leak it, and the Kotlin side must not close
    // it either, because by the time it sees a failure code this function has
    // already taken it.
    if tun_fd < 0 {
        jni_log!("[tun-proxy] nativeStartTunProxy was given an invalid descriptor");
        return -1;
    }
    let tun_fd_raw = tun_fd;
    let tun_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd) };

    if env.exception_check() {
        jni_log!("JNI exception pending before nativeStartTunProxy");
        env.exception_clear();
        return -1;
    }

    // Parse the proxied domains (comma-separated).
    let proxy_domains_str = match proxy_domains.try_to_string(env) {
        Ok(s) => s,
        Err(_) => {
            jni_log!("Failed to get proxy_domains string from JNI");
            return -1;
        }
    };
    let proxy_domains_list: Vec<String> = proxy_domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    jni_log!(
        "[DEBUG:jni] nativeStartTunProxy: fd={}, proxy_domains={} items",
        tun_fd_raw,
        proxy_domains_list.len()
    );

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("Runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("State not initialized");
            return -1;
        }
    };

    // Clone the endpoint_group from ProxyState (created by nativeStartProxy).
    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for endpoint_group");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!("[DEBUG:jni] endpoint_group is None — nativeStartProxy not called yet?");
                return -1;
            }
        }
    };

    // Read the system DNS server list (set by nativeSetDnsServers).
    let custom_dns_servers = match CUSTOM_DNS_SERVERS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            jni_log!("Failed to lock CUSTOM_DNS_SERVERS");
            return -1;
        }
    };

    // Check whether a tun_proxy is already running.
    {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy check");
                return -1;
            }
        };
        if guard.tun_proxy.is_some() {
            jni_log!("[DEBUG:jni] TUN proxy already running, stopping old one first");
            drop(guard);
            let _ = stop_tun_proxy();
        }
    }

    // Enter the runtime context (TunProxy::new spawns tasks via tokio::spawn internally).
    let _enter_guard = runtime.enter();

    let tun_proxy = match TunProxy::new(
        tun_fd,
        endpoint_group,
        proxy_domains_list,
        custom_dns_servers,
    ) {
        Ok(tp) => tp,
        Err(e) => {
            jni_log!("[DEBUG:jni] Failed to create TUN proxy: {}", e);
            return -1;
        }
    };

    // Store it in ProxyState.
    {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("Failed to lock state for tun_proxy storage");
                // tun_proxy dropped → stop() called → tasks aborted + fd closed
                return -1;
            }
        };
        guard.tun_proxy = Some(tun_proxy);
    }

    jni_log!("[DEBUG:jni] nativeStartTunProxy returning success");
    0
}

/// The same gate as the entry point above, and it has to be repeated rather
/// than inherited: `cfg` does not propagate into a function body, so a free
/// function that reads `ProxyState::tun_proxy` needs its own. Without it this
/// still compiles for every `jni` build that is not an Android one — which is
/// exactly what the release archives build (`--features jni,local-proxy` on
/// eight non-Android targets), and the combination no CI job compiles.
#[cfg(all(feature = "tun-proxy", target_os = "android"))]
fn stop_tun_proxy() -> jint {
    jni_log!("[DEBUG:jni] nativeStopTunProxy called");

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] State not initialized, nothing to stop");
            return 0;
        }
    };

    let tun_proxy = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // The fd this takes out is closed only by dropping or shutting
                // down the proxy, so the guard is recovered rather than the
                // stop abandoned.
                jni_log!(
                    "[WARN:jni] State lock poisoned, recovering the guard to stop the TUN proxy"
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
            jni_log!("[DEBUG:jni] No runtime, aborting TUN proxy without join");
            // tp dropped here → stop() called via Drop
        }
    } else {
        jni_log!("[DEBUG:jni] No TUN proxy to stop");
    }

    0
}
