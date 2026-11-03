//! The routing table the app edits: the nodes, and the names they serve.
//!
//! A node is a peer the proxy dials; a domain is a name that goes to one of
//! them. The two are edited from the same place, because a name without a node
//! to go to is not a route.

use super::*;

use iroh::EndpointAddr;
use iroh_tickets::endpoint::EndpointTicket;
use jni::EnvUnowned;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};

use crate::jni_log;

/// Whether a ticket names the endpoint with this Node ID.
///
/// Android keys everything — 2FA, device keys, link readings — by Node ID,
/// while a ticket carries only addresses and an identity inside them. This is
/// how a ticket-backed node is found again when the node is removed.
fn ticket_names_id(ticket: &str, node_id: &str) -> bool {
    ticket.parse::<EndpointTicket>().ok().is_some_and(|parsed| {
        let addr: EndpointAddr = parsed.into();
        addr.id.to_string() == node_id
    })
}

/// Validates a node ID with the exact parser the connection path uses.
///
/// Returns null when it parses, otherwise the parser's reason. Callers use this for pre-flight
/// checks and to give immediate feedback while the user edits a node.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeValidateNodeId(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        validate_node_id(env, node_id)
    })
}

/// Pre-connect / warm-up: establish one iroh connection per configured backend
/// and cache it in the connection pool, so the first real request does not pay
/// the QUIC/relay handshake latency. Must be called after `nativeStartProxy`
/// (which creates the `EndpointGroup`). Returns the number of backends warmed,
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativePreconnect(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // The body drives the runtime, and unwinding out of an `extern "system"`
    // frame is a native crash on Android rather than something the JVM can
    // turn into an exception. So the catch is around the whole body, not
    // around the one part of it that blocks.
    catching_panic("nativePreconnect", preconnect).unwrap_or(-1)
}

/// The body of `nativePreconnect`, split out so the catch has something to
/// wrap.
fn preconnect() -> jint {
    jni_log!("[DEBUG:jni] nativePreconnect called");

    let runtime = match get_runtime() {
        Some(r) => r,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: runtime not initialized");
            return -1;
        }
    };

    let state = match get_state() {
        Some(s) => s,
        None => {
            jni_log!("[DEBUG:jni] nativePreconnect: state not initialized");
            return -1;
        }
    };

    let endpoint_group = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(_) => {
                jni_log!("[DEBUG:jni] nativePreconnect: failed to lock state (poisoned)");
                return -1;
            }
        };
        match guard.endpoint_group.clone() {
            Some(eg) => eg,
            None => {
                jni_log!(
                    "[DEBUG:jni] nativePreconnect: endpoint_group is None - call nativeStartProxy first"
                );
                return -1;
            }
        }
    };

    let count = runtime.block_on(async move {
        match tokio::time::timeout(PRECONNECT_TIMEOUT, endpoint_group.preconnect_report()).await {
            Ok(report) => {
                // A backend that answered and then refused the connection
                // for missing 2FA is counted as unreachable, which on its
                // own reads like "server down". Say what actually happened:
                // the credentials are missing on this side.
                if report.any_auth_required() && !report.any_reachable() {
                    jni_log!("[DEBUG:jni] nativePreconnect: backend requires 2FA");
                    set_last_error(AUTH_REQUIRED_MESSAGE);
                }
                report.reachable.len() as jint
            }
            Err(_) => {
                jni_log!("[DEBUG:jni] nativePreconnect timed out");
                -1
            }
        }
    });

    jni_log!(
        "[DEBUG:jni] nativePreconnect finished: {} backend(s) warmed",
        count
    );
    count
}

/// Resolves an endpoint ticket to the Node ID it names.
///
/// The Android node list is keyed by Node ID — 2FA, device keys, domain
/// mappings and link readings all meet on it — so a ticket invite has to be
/// reduced to that ID before it can be stored. The addresses stay in the
/// ticket; only the identity comes back here. Returns null for anything that
/// is not a ticket.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeResolveTicket(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    ticket: JString,
) -> jstring {
    with_env_or(&mut unowned_env, std::ptr::null_mut(), |env| {
        resolve_ticket(env, ticket)
    })
}

fn resolve_ticket(env: &mut Env<'_>, ticket: JString) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeResolveTicket");
        env.exception_clear();
        return std::ptr::null_mut();
    }
    let ticket_str = match ticket.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let Ok(parsed) = ticket_str.trim().parse::<EndpointTicket>() else {
        return std::ptr::null_mut();
    };
    let addr: EndpointAddr = parsed.into();
    match env.new_string(addr.id.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
    domains: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| add_node(env, node_id, domains))
}

/// Adds a node named by a full ticket rather than a bare Node ID.
///
/// It is the ticket that goes into `NodeConfig.server_ticket`: handing iroh a
/// Node ID *and* a ticket makes the address lookup take the ID and discard the
/// addresses, which is precisely what `discovery = "none"` cannot afford.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddTicketNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    ticket: JString,
    domains: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        add_ticket_node(env, ticket, domains)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveNode(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    node_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| remove_node(env, node_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeClearNodes(
    _env: EnvUnowned,
    _class: JClass,
) -> jint {
    // Nothing in this body can fail on its own — it takes a lock and clears
    // two lists — but the frame it runs in cannot survive an unwind, so the
    // catch is here all the same: a panic must be a failed call rather than a
    // dead process.
    catching_panic("nativeClearNodes", clear_nodes).unwrap_or(-1)
}

/// The body of `nativeClearNodes`, split out so the catch has something to
/// wrap.
fn clear_nodes() -> jint {
    let state = match get_state() {
        Some(s) => s,
        None => return 0,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    guard.nodes.clear();
    guard.domain_mappings.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomainMapping(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
    node_id: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        add_domain_mapping(env, domain, node_id)
    })
}

/// Maps a domain to a peer named by a ticket. This is the path the app
/// actually uses: the routing table is built from domain mappings, not from
/// `nativeAddNode`, so a ticket-backed endpoint has to be reachable here too.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddTicketDomainMapping(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
    ticket: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| {
        add_ticket_domain_mapping(env, domain, ticket)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeAddDomain(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| add_domain(env, domain))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_nexa_pipe_IrohProxy_nativeRemoveDomain(
    mut unowned_env: EnvUnowned,
    _class: JClass,
    domain: JString,
) -> jint {
    with_env_or(&mut unowned_env, -1, |env| remove_domain(env, domain))
}
fn validate_node_id(env: &mut Env<'_>, node_id: JString) -> jstring {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeValidateNodeId");
        env.exception_clear();
        return std::ptr::null_mut();
    }

    let node_id = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let reason = match node_id_error(node_id.trim()) {
        Some(reason) => reason,
        None => return std::ptr::null_mut(),
    };

    match env.new_string(reason) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn add_node(env: &mut Env<'_>, node_id: JString, domains: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddNode");
        env.exception_clear();
        return -1;
    }

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let domains_str = match domains.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let domains_list: Vec<String> = domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if domains_list.is_empty() {
        jni_log!("Warning: Domains list is empty for node: {}", node_id_str);
    }

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // Re-adding a node updates it instead of appending a second entry. `nodes`
    // becomes one pool per backend, so a duplicate would hand that backend two
    // pools — double the weight in the balancer, two sets of health checks —
    // and the list would grow every time the UI re-applies the same settings.
    if let Some(existing) = guard
        .nodes
        .iter_mut()
        .find(|n| n.server_node_id.as_deref() == Some(node_id_str.as_str()))
    {
        if !domains_list.is_empty() {
            existing.domains = domains_list;
        }
        return 0;
    }

    let node_config = NodeConfig {
        server_node_id: Some(node_id_str),
        server_ticket: None,
        domains: domains_list,
    };

    guard.nodes.push(node_config);
    0
}

fn add_ticket_node(env: &mut Env<'_>, ticket: JString, domains: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddTicketNode");
        env.exception_clear();
        return -1;
    }

    let ticket_str = match ticket.try_to_string(env) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return -1,
    };
    let domains_str = match domains.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // Refuse a string that is not a ticket here rather than at connect time:
    // a bad ticket would otherwise be dialled as a (very long) Node ID.
    if ticket_str.parse::<EndpointTicket>().is_err() {
        jni_log!("nativeAddTicketNode: not a valid endpoint ticket");
        return -1;
    }

    let domains_list: Vec<String> = domains_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if let Some(existing) = guard
        .nodes
        .iter_mut()
        .find(|n| n.server_ticket.as_deref() == Some(ticket_str.as_str()))
    {
        if !domains_list.is_empty() {
            existing.domains = domains_list;
        }
        return 0;
    }

    guard.nodes.push(NodeConfig {
        server_node_id: None,
        server_ticket: Some(ticket_str),
        domains: domains_list,
    });
    0
}

fn add_domain_mapping(env: &mut Env<'_>, domain: JString, node_id: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddDomainMapping");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // A mapping is the pair (domain, node), so re-adding the same pair is not a
    // second route — it is the same one again. Without this the list grew on
    // every re-apply, and every duplicate made the lookup walk further for
    // nothing.
    let already_mapped = guard.domain_mappings.iter().any(|m| {
        m.domain == domain_str && m.server_node_id.as_deref() == Some(node_id_str.as_str())
    });
    if already_mapped {
        return 0;
    }

    let domain_mapping = DomainMapping {
        domain: domain_str,
        server_node_id: Some(node_id_str),
        server_ticket: None,
    };

    guard.domain_mappings.push(domain_mapping);
    0
}

fn add_ticket_domain_mapping(env: &mut Env<'_>, domain: JString, ticket: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddTicketDomainMapping");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let ticket_str = match ticket.try_to_string(env) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return -1,
    };
    if ticket_str.parse::<EndpointTicket>().is_err() {
        jni_log!("nativeAddTicketDomainMapping: not a valid endpoint ticket");
        return -1;
    }

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let already_mapped = guard
        .domain_mappings
        .iter()
        .any(|m| m.domain == domain_str && m.server_ticket.as_deref() == Some(ticket_str.as_str()));
    if already_mapped {
        return 0;
    }

    guard.domain_mappings.push(DomainMapping {
        domain: domain_str,
        server_node_id: None,
        server_ticket: Some(ticket_str),
    });
    0
}

fn remove_node(env: &mut Env<'_>, node_id: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeRemoveNode");
        env.exception_clear();
        return -1;
    }

    let node_id_str = match node_id.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // A node can be named by a Node ID or by a ticket. Both spellings have to
    // go, from the nodes and from the domain mappings the app actually
    // routes through — a deleted endpoint must not keep routing traffic on a
    // running tunnel.
    guard.nodes.retain(|n| {
        n.server_node_id.as_deref() != Some(node_id_str.as_str())
            && n.server_ticket
                .as_deref()
                .is_none_or(|ticket| !ticket_names_id(ticket, &node_id_str))
    });
    guard.domain_mappings.retain(|m| {
        m.server_node_id.as_deref() != Some(node_id_str.as_str())
            && m.server_ticket
                .as_deref()
                .is_none_or(|ticket| !ticket_names_id(ticket, &node_id_str))
    });
    0
}

fn add_domain(env: &mut Env<'_>, domain: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeAddDomain");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.domains.contains(&domain_str) {
        guard.domains.push(domain_str);
    }
    0
}

fn remove_domain(env: &mut Env<'_>, domain: JString) -> jint {
    if env.exception_check() {
        jni_log!("JNI exception pending before nativeRemoveDomain");
        env.exception_clear();
        return -1;
    }

    let domain_str = match domain.try_to_string(env) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let state = match get_state() {
        Some(s) => s,
        None => return -1,
    };

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.domains.retain(|d| d != &domain_str);
    0
}
