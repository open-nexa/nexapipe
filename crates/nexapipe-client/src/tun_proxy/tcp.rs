//! The TCP half of the tunnel.
//!
//! A flow that arrives in the stack is a connection the app opened, and it
//! becomes a bi-stream to the server the address names. The slot it takes is
//! the ceiling on how many of them there may be at once.

use super::*;

/// Take one of [`MAX_TCP_FLOWS`] slots for a connection, or refuse it.
///
/// Refusing means dropping the stream the caller is holding, which closes it:
/// the application sees a connection that ends, rather than one that is
/// accepted and then never opens a tunnel. The permit is owned, so it can be
/// moved into a spawned task and is given back when that task ends — a flow
/// that dies before its tunnel opens still returns its slot.
fn take_tcp_slot(ctx: &TunContext, warned_full: &AtomicBool) -> Option<OwnedSemaphorePermit> {
    match ctx.tcp_flow_slots.clone().try_acquire_owned() {
        Ok(permit) => {
            warned_full.store(false, Ordering::Relaxed);
            Some(permit)
        }
        Err(_) => {
            if !warned_full.swap(true, Ordering::Relaxed) {
                jni_log!(
                    "[tun-proxy] {} TCP flows are open, refusing new connections until one ends",
                    MAX_TCP_FLOWS
                );
            }
            None
        }
    }
}

/// Accept TCP connections from the stack and route each one by destination address.
pub(super) async fn run_tcp_acceptor(mut listener: SmolTcpListener, ctx: TunContext) {
    // Logged once each time the ceiling is reached, not once per refused
    // connection: a browser working through a page opens hundreds, and one
    // line saying the limit was hit is the whole story.
    let warned_full = AtomicBool::new(false);

    while !ctx.stopped.load(Ordering::Acquire) {
        let Some((stream, client_addr, server_addr)) = listener.next().await else {
            jni_log!("[tun-proxy] TCP listener stream ended");
            break;
        };

        let dest_ip = server_addr.ip();
        let dest_port = server_addr.port();
        jni_log!(
            "[tun-proxy] TCP accept: dest={}:{}, client={}",
            dest_ip,
            dest_port,
            client_addr
        );

        // A per-domain address was handed out for A, for AAAA, or for both, and
        // the packet says which one the application used. The legacy address
        // and the mapping's IPv4 pool are the two things the v4 branch below
        // still has to tell apart.
        let dest_ip = match dest_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => {
                let Some(domain) = ctx.ip_mapping.lookup_domain_v6(&v6) else {
                    jni_log!("[tun-proxy] TCP to {v6}:{dest_port} has no domain mapping, dropping");
                    continue;
                };
                let Some(slot) = take_tcp_slot(&ctx, &warned_full) else {
                    continue;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    // Held for as long as the flow runs: dropped with the task,
                    // however the task ends.
                    let _slot = slot;
                    serve_tcp_flow(stream, ctx, domain, dest_port).await;
                });
                continue;
            }
        };

        // Legacy address: applications that cached a DNS answer from before the
        // per-domain addresses existed still connect to the legacy proxy
        // address, so those connections keep the payload-sniffing path
        // (SNI / Host header) instead of being dropped. DNS answers only live
        // 60 s, so this is a short tail.
        // (Android only — the desktop never handed out a fixed proxy address.)
        if ctx.legacy_proxy_ip == Some(dest_ip) {
            let Some(slot) = take_tcp_slot(&ctx, &warned_full) else {
                continue;
            };
            // Read before the stream moves: `client_addr_hint` needs it whole,
            // and the flow this opens is listed with where it came from.
            let peer = Some(client_addr_hint(&stream));
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _slot = slot;
                if let Err(e) = handle_local_connection(
                    stream,
                    ctx.proxy_domains.clone(),
                    ctx.endpoint_group.clone(),
                    peer,
                )
                .await
                {
                    jni_log!("[tun-proxy] handle_local_connection error: {}", e);
                }
            });
            continue;
        }

        let Some(domain) = ctx.ip_mapping.lookup_domain(&dest_ip) else {
            jni_log!("[tun-proxy] TCP to {dest_ip}:{dest_port} has no domain mapping, dropping");
            continue;
        };

        let Some(slot) = take_tcp_slot(&ctx, &warned_full) else {
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            serve_tcp_flow(stream, ctx, domain, dest_port).await;
        });
    }
    jni_log!("[tun-proxy] TCP acceptor task exiting");
}

/// Carry one TCP flow between the application's smoltcp socket and a server route.
///
/// Nothing is sniffed: the domain came from the destination address, so a raw
/// binary protocol on any port works as well as TLS on 443.
///
/// The domain is the shared name the address mapping handed out, so a flow
/// that starts costs a reference count rather than a copy of the name.
async fn serve_tcp_flow(
    stream: SmolTcpStream,
    ctx: TunContext,
    domain: std::sync::Arc<str>,
    port: u16,
) {
    // The tunnel is opened before any payload is read, so the application sees
    // the connection go quiet rather than being told a connection exists that
    // the server has no route for.
    let (pooled, mut tunnel_send, mut tunnel_recv) =
        match l4::open_tcp(&ctx.endpoint_group, &domain, port).await {
            Ok(tunnel) => tunnel,
            Err(e) => {
                jni_log!("[tun-proxy] TCP {}:{} refused: {}", domain, port, e);
                return;
            }
        };

    jni_log!(
        "[tun-proxy] TCP flow {} -> {}:{}",
        client_addr_hint(&stream),
        domain,
        port
    );

    // One TCP flow is what an application would call a connection, so it is
    // what the counters call one: open until this task ends, whatever ends it.
    let flow = pooled.enter_flow(FlowMeta {
        kind: FlowKind::TunTcp,
        target: Some(format!("{domain}:{port}")),
        source: Some(client_addr_hint(&stream)),
    });
    let count_to_tunnel = flow.counter();
    let count_from_tunnel = flow.counter();

    let (mut app_read, mut app_write) = tokio::io::split(stream);

    let app_to_tunnel = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match app_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tunnel_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    count_to_tunnel.record_sent(n as u64);
                }
                Err(e) => {
                    jni_log!("[tun-proxy] TCP {}:{} app read error: {}", domain, port, e);
                    break;
                }
            }
        }
        // Half-close: the application said it is done sending, and the backend
        // needs to hear that (an HTTP request without a length ends this way).
        let _ = tunnel_send.finish();
    };

    let tunnel_to_app = async {
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            match tunnel_recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if app_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    count_from_tunnel.record_received(n as u64);
                }
                Err(e) => {
                    jni_log!(
                        "[tun-proxy] TCP {}:{} tunnel read error: {}",
                        domain,
                        port,
                        e
                    );
                    break;
                }
            }
        }
        // smoltcp's `poll_shutdown` returns `Pending` until the FIN has been
        // acknowledged, so this is bounded: sending the FIN is what matters, and
        // waiting forever for an application that has already gone away is not.
        let _ = tokio::time::timeout(Duration::from_secs(5), app_write.shutdown()).await;
    };

    // The third branch: this flow is not one of the tasks `stop()` knows about,
    // so nothing aborts it — and a flow that outlives the proxy keeps a pooled
    // connection checked out of a group nobody can close. Watching the flag is
    // what returns it. Polled, because there is nothing to await on a bool, and
    // a wake-up per flow is far cheaper than a connection stuck until the app
    // gives up on it.
    //
    // No idle timeout on top of that, unlike the UDP flows: a TCP connection
    // may legitimately sit quiet for minutes, and only the applications at
    // either end can say when it is finished.
    //
    // **Both halves, not whichever ends first.** A TCP half-close is a
    // request, not an ending: an application that writes its request and then
    // shuts down its write side is saying "I am done sending", and the
    // backend's reply still has to arrive. Racing the two halves and dropping
    // the loser cut that reply off — the FIN above was propagated correctly
    // and then the select ended the flow before the reply could come back.
    //
    // The total bound is the one the copy loop was always meant to have:
    // `STREAM_SECS`, an hour. It matches the server's own `l4_flow` default,
    // so the two ends of the tunnel give up at about the same moment, and it
    // is what keeps a half-closed flow from holding its resources for the
    // life of the process.
    let stream_budget = crate::deadline::Deadlines::default().stream;
    let both_halves = async {
        tokio::join!(app_to_tunnel, tunnel_to_app);
    };
    tokio::select! {
        _ = both_halves => (),
        _ = wait_for_stop(ctx.stopped.clone()) => (),
        // Asked to end, which is the fourth way out and the only one that is
        // somebody's decision rather than something that happened to the socket.
        // It lands here rather than anywhere else because this select is the
        // only thing that owns both halves.
        _ = flow.cancelled() => (),
        _ = tokio::time::sleep(stream_budget) => {
            jni_log!(
                "[tun-proxy] TCP {}:{} ran for {:?} and was abandoned",
                domain,
                port,
                stream_budget
            );
        }
    }

    // Dropping both halves closes the smoltcp socket (its `Drop` sends, at most,
    // a FIN; the flow is over either way).
}

/// The application's address, for the log line. Only valid before `split`.
fn client_addr_hint(stream: &SmolTcpStream) -> String {
    // `local_addr` is the *source* address here; see the naming trap in
    // `run_tcp_acceptor`.
    stream.local_addr().to_string()
}
