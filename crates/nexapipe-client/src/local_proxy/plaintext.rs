//! The ordinary HTTP path: one request, one answer.
//!
//! The head of the request says what may follow it, and the list of proxied
//! domains has already said which host the request is for. What is left is
//! the exchange itself: the request goes out, the answer comes back, and the
//! connection carries nothing else.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};
use crate::http::Body;

use nexapipe_proto::protocol::Protocol;

use std::sync::Arc;

use ::http::Request;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::http_head::{filter_request_headers, redacted_headers};
use super::response::{ResponseRelay, relay_the_response};
use super::tunnel::{TunnelTasks, open_stream_with_retry};
use super::{RESPONSE_IDLE, TRAILING_BYTES_CEILING, write_proxy_error};

/// The ordinary HTTP exchange: the request goes out, the answer comes back.
///
/// The arguments are the ones the handler read off the socket and worked out:
/// the head, the host it names, and the connection to answer on.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_plain_request<S>(
    mut stream: S,
    request: Request<()>,
    request_buf: Vec<u8>,
    header_end: usize,
    mut temp_buf: Vec<u8>,
    host: &str,
    endpoint_group: &Arc<EndpointGroup>,
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Regular HTTP path
    //
    // **The bytes that came with the head are the body's, or they are a
    // second request.**
    //
    // The head says which: a request that declares a body has one, and the
    // bytes that came with the head are its first ones. A request that
    // declares no body has none, so the bytes that came with the head are
    // the head of another request.
    //
    // The server serves keep-alive requests on one stream, so a second
    // request that reaches it is answered by it — while the list of proxied
    // domains, which is the boundary the user believes they have, was
    // consulted about the first request only. A name the user excluded would
    // go through the tunnel anyway.
    //
    // So the second request is refused here rather than forwarded: the
    // refusal says what happened, and it happens before anything is on its
    // way to the backend. Letting the server answer it would leave the
    // boundary in the server's hands, where the user's list is not the rule
    // that applies.
    let mut body = Body::declared(&request);
    let carried = &request_buf[header_end..];
    let carried_body = body.take(carried);
    if carried_body < carried.len() {
        jni_log!(
            "[local-proxy] refusing a request that carries a second request: {} bytes of another \
             request came with the head of this one",
            carried.len() - carried_body
        );
        return write_proxy_error(&mut stream, "400 Bad Request").await;
    }

    // The hop-by-hop headers go, and so do the cache validation headers that
    // would make the origin answer with a 304 and an empty body.
    let filtered_headers = filter_request_headers(&request_buf[..header_end], false);
    let mut request_to_send = filtered_headers;
    request_to_send.extend_from_slice(&request_buf[header_end..]);

    jni_log!(
        "[DEBUG:local-proxy] Forwarding {} bytes to backend, Host: {}",
        request_to_send.len(),
        host
    );
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(endpoint_group, host, Some(&request_to_send), Protocol::Http)
            .await?;

    // The helper wrote the request — headers and whatever body had already
    // arrived — before this line was reached. Counting the copy loop alone
    // would therefore be counting everything except a large upload, which for
    // a POST is most of it.
    let flow = pooled_conn.enter_flow(FlowMeta {
        kind: FlowKind::Http,
        target: Some(host.to_string()),
        source: peer.clone(),
    });
    flow.record_sent(request_to_send.len() as u64);
    let count_to_backend = flow.counter();
    let count_from_backend = flow.counter();

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // The buffer the head was read into becomes the client half's buffer: a
    // connection holds two of them — one per direction — rather than three.
    let header_buf = std::mem::take(&mut temp_buf);
    let client_to_backend = async move {
        let mut buf = header_buf;
        loop {
            // The request is out: the head has gone, and the body with it.
            // Nothing else may follow it on this connection.
            if body.is_complete() {
                break;
            }
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // **Only the body's own bytes go on.**
                    //
                    // The bytes past the body are not the body's: they are
                    // the head of another request, and the list of proxied
                    // domains was consulted about the first one only. So
                    // they are not relayed — the connection is refused
                    // instead, which is what the refusal at the head does
                    // with a request that arrives carrying another one.
                    let body_bytes = body.take(&buf[..n]);
                    if body_bytes > 0 {
                        if let Err(e) = send.write_all(&buf[..body_bytes]).await {
                            #[cfg(feature = "tracing")]
                            tracing::debug!("Client to backend write error: {}", e);
                            break;
                        }
                        count_to_backend.record_sent(body_bytes as u64);
                    }
                    if body_bytes < n {
                        jni_log!(
                            "[local-proxy] refusing a second request on a connection that carries one \
                             request: {} bytes of another request came after the body",
                            n - body_bytes
                        );
                        break;
                    }
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Client read error: {}", e);
                    break;
                }
            }
        }
        // The request is over, and the server is told so. The stream it
        // serves the request on ends with the answer, and the connection
        // this handler holds ends with it: one request, one connection.
        let _ = send.finish();

        // **What the client sent after its request is read and thrown away.**
        //
        // The connection carries one request, so the bytes that came after
        // it are not part of the exchange — but they are still in the socket,
        // and the socket is closed when the answer is on its way.
        //
        // A socket that is closed with unread data in it is reset rather
        // than closed, and a reset costs the client the answer it was
        // already sent: Windows throws away the data that was received and
        // not yet read when the reset arrives. The request was served, and
        // the client is entitled to the answer — so the bytes are read away
        // here, before the answer is written, and the socket closes with
        // nothing left in it.
        //
        // The reading stops at the end of the stream or at the ceiling; a
        // client that keeps sending is not read forever. The handler aborts
        // this task when the answer has been relayed, which is what ends a
        // reading that is still waiting for a client that will not close.
        let mut thrown_away = 0usize;
        while thrown_away < TRAILING_BYTES_CEILING {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => thrown_away += n,
                Err(_) => break,
            }
        }
    };

    let backend_to_client = async move {
        let outcome = relay_the_response(&mut recv, &mut client_write, RESPONSE_IDLE, &mut |n| {
            count_from_backend.record_received(n as u64)
        })
        .await;
        if matches!(outcome, ResponseRelay::Quiet) {
            jni_log!(
                "[DEBUG:local-proxy] The backend went quiet for {:?} and the response was cut",
                RESPONSE_IDLE
            );
        }
    };
    // END regular HTTP closures

    // Regular HTTP request-response handling
    jni_log!("[DEBUG:local-proxy] Detected HTTP request, using request-response mode");
    jni_log!(
        "[DEBUG:local-proxy] Request headers: {}",
        redacted_headers(request.headers())
    );
    let client_task = tokio::spawn(client_to_backend);
    let mut backend_task = tokio::spawn(backend_to_client);
    // See the CONNECT branch: the client half is aborted below on the normal
    // path, and both go when the proxy is stopped mid-request.
    let _tasks = TunnelTasks(vec![
        client_task.abort_handle(),
        backend_task.abort_handle(),
    ]);

    // Wait for the backend response to be fully relayed back to the client.
    // We must NOT wait for the client to close its TCP connection first:
    // HTTP clients routinely keep the connection alive (keep-alive) after
    // reading the response, so client_task would block indefinitely and the
    // iroh connection would never be returned to the pool -- which defeats
    // pre-connect/connection warm-up and leaks pooled connections.
    //
    // **There is no clock of its own here.** The bound is the quiet window
    // inside the relay: a response that keeps arriving keeps the exchange
    // alive however long it takes, and only a backend that has gone quiet
    // for a whole window ends it. The bound that used to sit here was a
    // total one -- sixty seconds from the moment the request went out --
    // which cut a response that was still arriving and left the client with
    // a truncated body rather than an error.
    //
    // The cancel switch is still here: being asked to end has to be able to
    // cut the exchange short rather than wait out the window.
    tokio::select! {
        _ = &mut backend_task => (),
        _ = flow.cancelled() => (),
    }

    // Response has been delivered; stop the client->backend relay so the pooled
    // iroh connection is released immediately. Aborting also closes the client
    // TCP socket (HTTP/1.1 allows the server to close after the response),
    // so a keep-alive client socket can't pin this task.
    //
    // **One request, one connection.** The client is told so by the close:
    // the request it sent is the only one this connection carries, and a
    // client that wants another one opens another connection. The list of
    // proxied domains is checked per request, and this is what makes the
    // check mean what it says.
    client_task.abort();

    jni_log!("[DEBUG:local-proxy] Connection closed");
    Ok(())
}
