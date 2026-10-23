//! The connection the local proxy accepted, and what it does with it.
//!
//! The first byte says what the connection is: a TLS hello is a tunnel, a
//! request line is a request. From there the connection is either a `CONNECT`
//! tunnel, a WebSocket, or an ordinary HTTP exchange.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};
use crate::http::{is_websocket_request_static, parse_http_request_legacy};

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::http_head::{HeaderOutcome, read_http_header, redacted_headers, request_line_end};
use super::plaintext::handle_plain_request;
use super::tls::handle_tls_tunnel;
use super::tunnel::TunnelTasks;
use super::websocket::handle_websocket_upgrade;
use super::{STREAM_BUF_SIZE, should_proxy_domain, write_proxy_error};

pub(crate) async fn handle_local_connection<S>(
    mut stream: S,
    proxy_domains: Arc<Vec<String>>,
    endpoint_group: Arc<EndpointGroup>,
    // Where the bytes came from, as whatever accepted the socket named it.
    // `None` when the caller has no address to give — a stream that was never
    // a socket, or a caller that never saw one.
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] New local connection received");

    // Step 1: Read the first chunk of data to determine protocol (HTTP vs TLS)
    //
    // Shares the header budget with the loop below rather than having its own
    // thirty seconds: this is the first read *of* that header, so giving it a
    // separate budget would let a client spend twice the intended time before
    // the first byte of its request line was counted against anything.
    let header_budget = crate::deadline::Deadlines::default().header;
    let first_byte_deadline = tokio::time::Instant::now() + header_budget;
    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];

    let n = match tokio::time::timeout_at(first_byte_deadline, stream.read(&mut temp_buf)).await {
        Ok(Ok(0)) => {
            jni_log!("[DEBUG:local-proxy] Empty request, closing connection");
            return Ok(());
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            jni_log!("[DEBUG:local-proxy] Read error: {}", e);
            return Ok(());
        }
        Err(_) => {
            jni_log!("[DEBUG:local-proxy] Read timeout, closing connection");
            return Ok(());
        }
    };

    request_buf.extend_from_slice(&temp_buf[..n]);

    // Check if this is a TLS connection. The predicate is the protocol
    // crate's, the same one the server asks: a hello is a hello on both
    // sides, and a client that spelled the byte out itself would be free to
    // disagree with the server about what a TLS connection is.
    if !request_buf.is_empty() && nexapipe_proto::tls::is_tls_handshake(request_buf[0]) {
        jni_log!("[DEBUG:local-proxy] Detected TLS ClientHello, handling as raw tunnel via SNI");
        let header_buf = std::mem::take(&mut temp_buf);
        return handle_tls_tunnel(
            stream,
            request_buf,
            header_buf,
            endpoint_group,
            proxy_domains,
            peer,
        )
        .await;
    }

    // Step 2: HTTP — read the complete request head (up to \r\n\r\n).
    //
    // `first_byte_deadline`, not a fresh instant: the budget was taken once,
    // before the first read above, and it covers the whole head. Taking it again
    // here would hand the caller two budgets — thirty seconds to send a first
    // byte and thirty more to finish the header — which is exactly the doubling
    // the first read's comment says this avoids.
    //
    // The per-read timeouts this replaces re-armed on each read, so a client
    // sending one byte of `Host:` before each expiry kept the connection, the
    // task and the slot for as long as it liked — the read that arrived *was*
    // the renewal.
    // The same buffer the first read used: one buffer for the whole head,
    // rather than one for the first read and another for the rest of it.
    let header_end = match read_http_header(
        &mut stream,
        &mut request_buf,
        &mut temp_buf,
        first_byte_deadline,
    )
    .await
    {
        HeaderOutcome::Complete(header_end) => header_end,
        HeaderOutcome::Closed => return Ok(()),
    };

    let request = match parse_http_request_legacy(&request_buf[..header_end]) {
        Ok(req) => {
            jni_log!(
                "[DEBUG:local-proxy] Parsed HTTP request: {} {}",
                req.method(),
                req.uri()
            );
            req
        }
        Err(e) => {
            jni_log!("[DEBUG:local-proxy] Failed to parse HTTP request: {}", e);
            jni_log!(
                "[DEBUG:local-proxy] First 16 bytes: {:?}",
                &request_buf[..std::cmp::min(request_buf.len(), 16)]
            );
            return Ok(());
        }
    };

    if request.method().as_str() == "CONNECT" {
        // `CONNECT host:port` is authority-form (RFC 9110 9.3.6). The port used to be
        // dropped here (`uri.split(':').next()`), which is why this branch only ever
        // worked for 443/TLS: everything else reached the server as a request line with
        // no port, matched no route, and was silently forwarded to `default_backend`.
        let target = request.uri().to_string();
        let Some((host, port)) = crate::l4::parse_connect_target(&target) else {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT without a usable host:port: '{}'",
                target
            );
            return write_proxy_error(&mut stream, "400 Bad Request").await;
        };

        if !should_proxy_domain(&host, &proxy_domains) {
            jni_log!(
                "[DEBUG:local-proxy] CONNECT '{}' is not a proxied domain, refusing",
                target
            );
            return write_proxy_error(&mut stream, "403 Forbidden").await;
        }

        // Open the tunnel *before* answering 200. `200 Connection Established` promises
        // that the far side is up, so the client has to still be able to receive an HTTP
        // error when it is not — which is why the answer comes after the L4 handshake
        // and not before it.
        let (pooled_conn, mut send, mut recv) =
            match crate::l4::open_tcp(&endpoint_group, &host, port).await {
                Ok(tunnel) => tunnel,
                Err(e) => {
                    jni_log!(
                        "[DEBUG:local-proxy] CONNECT {}:{} failed: {}",
                        host,
                        port,
                        e
                    );
                    return write_proxy_error(&mut stream, "502 Bad Gateway").await;
                }
            };

        // One tunnel is one flow for as long as this handler lives, however it
        // ends: EOF, either direction failing, or this task being cancelled
        // because the proxy stopped.
        //
        // The counters are the *flow's* rather than the connection's, which is
        // what lets a reader ask how much this connection has moved as opposed
        // to how much the backend has. Two halves of one copy loop each carry a
        // clone of the same guard, so the two directions land in one total.
        let flow = pooled_conn.enter_flow(FlowMeta {
            kind: FlowKind::Connect,
            target: Some(format!("{host}:{port}")),
            source: peer.clone(),
        });
        let count_to_backend = flow.counter();
        let count_from_backend = flow.counter();

        // **The bytes that came with the head are the tunnel's first payload.**
        //
        // The head reader keeps everything it read, so a client that wrote the
        // CONNECT head and the first bytes of the tunnel in one go has both in
        // the buffer by the time the head is complete. This branch used to
        // read the socket again from there and drop them: the copy loop below
        // starts at the socket, and the socket had already given these up.
        //
        // The ordinary HTTP path forwards them (see below); this one did not,
        // and the difference was a tunnel that began in the middle of whatever
        // the client had sent — a TLS client that pipelined its first record
        // into the CONNECT got a stream the far side could not read.
        let carried = &request_buf[header_end..];
        if !carried.is_empty() {
            if let Err(e) = send.write_all(carried).await {
                jni_log!(
                    "[DEBUG:local-proxy] CONNECT: writing the bytes that came with the head failed: {}",
                    e
                );
                return Ok(());
            }
            count_to_backend.record_sent(carried.len() as u64);
        }

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        client_write
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Spawn bidirectional forwarding as separate tasks to keep each
        // task's async state machine small (avoids deep nesting that causes
        // stack overflow on tokio worker threads).
        //
        // The buffer the head was read into becomes the client half's buffer:
        // a connection holds two of them — one per direction — rather than
        // three.
        let header_buf = std::mem::take(&mut temp_buf);
        let mut client_task = tokio::spawn(async move {
            let mut buf = header_buf;
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => {
                        // The client is done sending. That is a half-close, not
                        // the end of the conversation: the server may still
                        // have a reply on the way, and the reply has to reach
                        // the client.
                        //
                        // Propagated as a FIN, so the server sees what it
                        // would see from a socket whose write side the client
                        // had shut down. Dropping the stream instead would
                        // reset it, and a reset is not a half-close.
                        let _ = send.finish();
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = send.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel client_to_iroh write error: {}", e);
                            break;
                        }
                        count_to_backend.record_sent(n as u64);
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel client_to_iroh read error: {}", e);
                        break;
                    }
                }
            }
        });

        let mut backend_task = tokio::spawn(async move {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) => break,
                    Ok(Some(n)) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client write error: {}", e);
                            break;
                        }
                        if let Err(e) = client_write.flush().await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Tunnel iroh_to_client flush error: {}", e);
                            break;
                        }
                        count_from_backend.record_received(n as u64);
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Tunnel iroh_to_client read error: {}", e);
                        break;
                    }
                }
            }
            // The server is done sending. That is a half-close, and the client
            // has to hear it: the write side towards the client is shut down,
            // so the client sees an end of stream the way it would see it
            // from a socket.
            //
            // Without this the client waits for an answer that is not coming.
            // Joining the two directions is right, but joining them is not the
            // same as leaving the client hanging: the direction that ended has
            // to be handed on to the peer. The read side stays open, so a
            // client that still has something to say can say it.
            let _ = client_write.shutdown().await;
        });

        // Lives until this handler returns, and dies with it if it is aborted
        // first — which is the only moment that matters: `stop()` cancels the
        // task running this function, and the two halves above have to go with
        // it or the tunnel outlives the proxy it belongs to.
        let _tasks = TunnelTasks(vec![
            client_task.abort_handle(),
            backend_task.abort_handle(),
        ]);

        // **Both directions, and each of them for as long as it lasts.**
        //
        // A TCP half-close is a request, not an ending: a client that writes
        // its request and then shuts down its write side is saying "I am done
        // sending", and the server's reply still has to arrive. Racing the two
        // directions and aborting the loser dropped that reply on the floor and
        // reset the connection under the client.
        //
        // The bound is the one the copy loop was always meant to have:
        // `STREAM_SECS`, an hour. It matches the server's own `l4_flow`
        // default, so the two ends of the tunnel give up at about the same
        // moment, and it is what keeps a half-closed tunnel from holding its
        // resources for the life of the process.
        let stream_budget = crate::deadline::Deadlines::default().stream;
        tokio::select! {
            _ = async {
                let _ = (&mut client_task).await;
                let _ = (&mut backend_task).await;
            } => (),
            _ = flow.cancelled() => (),
            _ = tokio::time::sleep(stream_budget) => {
                jni_log!(
                    "[DEBUG:local-proxy] CONNECT tunnel to {}:{} ran for {:?} and was abandoned",
                    host,
                    port,
                    stream_budget
                );
            }
        }

        // Both, whichever branch won: the half that is still running is the one
        // that outlived its reason to, and the `TunnelTasks` guard above aborts
        // whatever is left when this handler returns.
        client_task.abort();
        backend_task.abort();

        return Ok(());
    }

    // A request that names more than one host is refused here, the same rule
    // the server applies. The route and the access check read the first `Host`
    // header and the backend would be handed all of them, so the request that
    // is authorised and the request that is served would be two different
    // requests — and the failure showed up as the server's 400, which looks
    // like a proxy bug rather than a request that cannot be answered.
    if request.headers().get_all("host").iter().count() > 1 {
        jni_log!(
            "[local-proxy] refusing a request that names more than one host: {}",
            redacted_headers(request.headers())
        );
        return write_proxy_error(&mut stream, "400 Bad Request").await;
    }

    let mut target_host = None;
    for header in request.headers().get_all("host") {
        if let Ok(h) = header.to_str() {
            // The authority is split the way the server splits it, so
            // `[::1]:8080` keeps its address. An empty port is dropped, as the
            // server drops it: `example.com:` is `example.com`.
            let (h, _port) = nexapipe_proto::host_and_port(h);
            jni_log!("[DEBUG:local-proxy] Found Host header: '{}'", h);
            if should_proxy_domain(h, &proxy_domains) {
                target_host = Some(h.to_string());
                break;
            }
        }
    }

    if target_host.is_none() {
        jni_log!("[DEBUG:local-proxy] No matching Host header found");
        return Ok(());
    }

    let host = target_host.unwrap();
    jni_log!(
        "[DEBUG:local-proxy] Getting connection for domain: '{}'",
        host
    );

    // WebSocket upgrade: rewrite the request line to use an absolute "http://"
    // URI. When a browser connects through a normal HTTP proxy it sends
    // "GET http://host/path HTTP/1.1" (absolute-form request-target per
    // RFC 7230 §5.3.2). The backend uses this to recognize that the stream
    // should be kept alive for bidirectional data flow after the HTTP upgrade,
    // rather than treating it as a one-shot HTTP exchange.
    if is_websocket_request_static(&request) {
        jni_log!("[DEBUG:local-proxy] WebSocket request, rewriting to absolute URI");
        jni_log!(
            "[DEBUG:local-proxy] WebSocket request details: uri={}, host={}, headers={}",
            request.uri(),
            host,
            redacted_headers(request.headers())
        );

        // Find the first line (request line)
        let first_line_end = request_line_end(&request_buf[..header_end]);

        if first_line_end > 0 {
            return handle_websocket_upgrade(
                stream,
                &request,
                &request_buf,
                header_end,
                first_line_end,
                temp_buf,
                &host,
                &endpoint_group,
                peer,
            )
            .await;
        }

        // Fallback: if we couldn't rewrite, just connect normally
        jni_log!("[DEBUG:local-proxy] WebSocket URI rewrite failed, falling back to regular HTTP");
    }

    handle_plain_request(
        stream,
        request,
        request_buf,
        header_end,
        temp_buf,
        &host,
        &endpoint_group,
        peer,
    )
    .await
}
