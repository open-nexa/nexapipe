//! What the app asks about the proxy while it runs: the last error, the
//! links, the traffic.

use super::*;

use crate::jni_log;

use jni::EnvUnowned;
use jni::objects::JClass;
use jni::sys::jstring;

/// Returns the reason behind the last failed native call, and clears it.
///
/// The start entry points return only an int, so this is how Kotlin learns what actually went
/// wrong (a malformed node ID, an occupied port, ...). Returns null when there is nothing to
/// report.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTakeLastError(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        read_last_error(env)
    })
}

/// How each configured backend is currently reached, and how far away it is: one
/// `<endpointId>=<kind>/<rttMs>` entry per backend, joined with `;`, where `kind` is `direct`,
/// `relay` or `unknown` and `rttMs` is the round-trip time in milliseconds, or `-` when iroh has
/// no sample yet.
///
/// This is the *runtime* answer, read off the paths iroh actually selected — not the relay URL
/// from the configuration, which only names a relay that may be used. A backend that has never
/// connected reports `unknown`.
///
/// Returns null when there is no endpoint group yet (nothing was started), so Kotlin can tell
/// "nothing to report" from "asked and answered".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeLinkKinds(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        link_kinds(env)
    })
}

/// What each backend has carried, and how many flows are open to it right now: one
/// `<endpointId>=<sent>/<received>/<active>` entry per node, joined with `;`. That is the entry
/// shape [`Java_com_nexa_pipe_IrohProxy_nativeLinkKinds`] already uses, so Kotlin parses both
/// answers the same way and lines them up per node.
///
/// The three numbers are cumulative bytes / open-flow count since this group was built, not
/// rates: a caller wanting a rate has to sample twice. The key is the raw endpoint ID, again as
/// `nativeLinkKinds` reports it. A node the group has carried nothing for is absent rather than
/// zero, which a caller showing per-node figures has to say rather than leave looking like
/// "down". Counters reset when the proxy is stopped and started again, so a drop between two
/// samples is a restart, not negative throughput.
///
/// Sorted by node ID so a UI polling it does not see the entries change places between polls.
///
/// Returns null when there is no endpoint group yet (nothing was started), so Kotlin can tell
/// "nothing to report" from "asked and answered".
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeTraffic(
    mut unowned_env: EnvUnowned,
    _class: JClass,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| traffic(env))
}
fn read_last_error(env: &mut Env<'_>) -> jstring {
    let message = match take_last_error() {
        Some(message) => message,
        None => return std::ptr::null_mut(),
    };
    match env.new_string(message) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn link_kinds(env: &mut Env<'_>) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => return std::ptr::null_mut(),
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.link_statuses().await })
    }));

    let statuses = match result {
        Ok(statuses) => statuses,
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeLinkKinds");
            return std::ptr::null_mut();
        }
    };

    let encoded = statuses
        .iter()
        .map(|(id, status)| crate::connection_pool::encode_link_status(id, status))
        .collect::<Vec<_>>()
        .join(";");

    jni_log!("[DEBUG:jni] nativeLinkKinds: {}", encoded);

    match env.new_string(encoded) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn traffic(env: &mut Env<'_>) -> jstring {
    let runtime = match get_runtime() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let endpoint_group = {
        let state = match get_state() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => return std::ptr::null_mut(),
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        runtime.block_on(async move { endpoint_group.traffic_snapshot() })
    }));

    let volumes = match result {
        Ok(volumes) => volumes,
        Err(_) => {
            jni_log!("[DEBUG:jni] Panic occurred during nativeTraffic");
            return std::ptr::null_mut();
        }
    };

    let mut entries: Vec<(String, String)> = volumes
        .iter()
        .map(|(id, volume)| {
            (
                id.to_string(),
                format!("{}/{}/{}", volume.sent, volume.received, volume.active),
            )
        })
        .collect();
    // HashMap iteration order is not stable, and a poll that reorders entries reads as nodes
    // moving around in the UI.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let encoded = entries
        .iter()
        .map(|(id, values)| format!("{}={}", id, values))
        .collect::<Vec<_>>()
        .join(";");

    jni_log!("[DEBUG:jni] nativeTraffic: {}", encoded);

    match env.new_string(encoded) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
