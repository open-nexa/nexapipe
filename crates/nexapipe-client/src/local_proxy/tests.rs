//! The tests of the local proxy.
//!
//! They live in their own file because there are more of them than there is
//! code to test, and because a file that is mostly tests hides the code it is
//! testing.
use super::http_head::{MAX_REQUEST_HEADER, header_over_limit};
use super::*;
use crate::LoadBalancingStrategy;
use iroh::Endpoint;
use iroh::endpoint::presets;
use std::time::Duration;

/// A header whose name says its value is a credential is not printed.
///
/// The list used to be five exact names, so a header an application
/// invented for its own token — `X-Auth-Token`, `X-Api-Key`,
/// `X-Session-Id` — was printed in the clear, and the dump is a debug log
/// that reaches logcat. The names are matched by what they carry rather
/// than by what they are.
#[test]
fn a_header_that_carries_a_credential_is_not_printed() {
    let mut headers = ::http::HeaderMap::new();
    for name in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-session-id",
        "x-custom-secret",
        "x-user-password",
        "x-aws-credential",
    ] {
        headers.insert(
            ::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            ::http::HeaderValue::from_static("the value"),
        );
    }
    headers.insert(
        ::http::HeaderName::from_static("content-type"),
        ::http::HeaderValue::from_static("application/json"),
    );

    let dumped = redacted_headers(&headers);

    assert!(
        !dumped.contains("the value"),
        "a credential reached the dump: {dumped}"
    );
    assert!(
        dumped.contains("content-type: \"application/json\""),
        "a header that carries no credential is still what makes the dump useful: {dumped}"
    );
}

/// The WebSocket debug buffer has a ceiling, and it is a ceiling.
///
/// A peer that sends a frame header and then nothing would grow the
/// buffer without end, and the check has to be **before** the append: a
/// check after it would let the last chunk take the buffer past the line,
/// which is how a ceiling stops being one.
#[test]
fn the_websocket_debug_buffer_does_not_grow_past_its_ceiling() {
    let chunk = vec![0u8; 32 * 1024];

    let mut buffer = Vec::new();
    loop {
        let kept = ws_frame_buffer_append(&mut buffer, &chunk);
        // The size is checked after **every** call, including the one
        // that refuses the chunk: an implementation that appended before
        // it checked would grow past the ceiling on exactly that call,
        // and a check that only ran on the calls that kept the chunk
        // would never see it.
        assert!(
            buffer.len() <= WS_FRAME_BUFFER_LIMIT,
            "the buffer grew past its ceiling: {} bytes",
            buffer.len()
        );
        if !kept {
            break;
        }
    }

    assert_eq!(
        buffer.len(),
        WS_FRAME_BUFFER_LIMIT,
        "the buffer filled to the ceiling and stopped there"
    );
}

/// The bytes that fit are kept.
#[test]
fn the_websocket_debug_buffer_keeps_what_fits() {
    let mut buffer = Vec::new();

    assert!(ws_frame_buffer_append(&mut buffer, &[1, 2, 3]));
    assert_eq!(buffer, vec![1, 2, 3]);
}

/// A proxy listening on an ephemeral port, with no backends behind it.
///
/// Enough for the accept loop, which in these tests never gets as far as
/// dialling one. Built through `shared` rather than `new` because the test
/// needs the address `new` keeps to itself.
/// The refusal is the constructor's, not only the predicate's.
///
/// A bind that reaches the network has to fail, and it has to fail with a
/// message that names the way out — the predicate on its own says
/// nothing about what a caller is supposed to do about it.
#[tokio::test]
async fn a_non_loopback_bind_is_refused_by_the_constructor() {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");
    let group = EndpointGroup::new_with_nodes_and_endpoint(
        Vec::new(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .expect("a group with no backend still builds");

    // `0.0.0.0` is the address every interface answers on, and it is what
    // the socket becomes — so the refusal is judged by what was bound
    // rather than by what was asked for.
    let err = match LocalProxy::new("0.0.0.0:0", Vec::new(), Arc::new(group)).await {
        Ok(_) => panic!("a bind that reaches the network is refused"),
        Err(e) => e,
    };
    let message = err.to_string();
    assert!(
        message.contains("expose"),
        "the message has to name the way out of it: {message}"
    );
}

/// The same bind, with the opt-in: it is allowed, because that is what
/// the opt-in is for.
#[tokio::test]
async fn the_opt_in_binds_a_non_loopback_address() {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");
    let group = EndpointGroup::new_with_nodes_and_endpoint(
        Vec::new(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .expect("a group with no backend still builds");

    let proxy = LocalProxy::new_exposed("0.0.0.0:0", Vec::new(), Arc::new(group))
        .await
        .expect("the opt-in is the way to bind elsewhere");
    proxy.stop();
}

async fn listening_proxy() -> (LocalProxy, std::net::SocketAddr) {
    listening_proxy_for(&[]).await
}

/// A proxy that serves the domains it is given, and no backends behind it.
///
/// The domains matter: a request that names one goes on to dial, so a
/// refusal has to be the client's own rather than the absence of a route.
async fn listening_proxy_for(domains: &[&str]) -> (LocalProxy, std::net::SocketAddr) {
    let ep = Endpoint::builder(presets::N0)
        .bind()
        .await
        .expect("binding a local endpoint needs no network");
    let group = EndpointGroup::new_with_nodes_and_endpoint(
        Vec::new(),
        None,
        LoadBalancingStrategy::RoundRobin,
        ep,
    )
    .await
    .expect("a group with no backend still builds");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback listener needs no network");
    let addr = listener
        .local_addr()
        .expect("a bound listener has an address");
    (
        LocalProxy::shared(
            Arc::new(listener),
            Arc::new(group),
            domains.iter().map(|d| d.to_string()).collect(),
        ),
        addr,
    )
}

fn spawn_run(proxy: &LocalProxy) -> JoinHandle<Result<(), ClientError>> {
    let proxy = proxy.clone();
    tokio::spawn(async move { proxy.run().await })
}

/// The ALPN the tunnel speaks. The same bytes the client uses.
const ALPN: &[u8] = b"nexapipe";

/// The host the application asks for.
const HOST: &str = "db.test";

/// The port it asks for.
const PORT: u16 = 5432;

/// A request that names more than one host is refused here.
///
/// The route and the access check read the first `Host` header and the
/// backend would be handed all of them, so the request that is authorised
/// and the request that is served would be two different requests.
///
/// The server refuses it with a 400; refusing it at the client says the
/// same thing without a round trip, and says it where the user can act on
/// it — a 400 from the far end looks like a proxy bug.
#[tokio::test]
async fn a_request_that_names_more_than_one_host_is_refused() {
    let (proxy, addr) = listening_proxy_for(&["db.test"]).await;
    let runner = spawn_run(&proxy);

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: db.test\r\nHost: other.test\r\n\r\n")
        .await
        .expect("the request is written");

    let mut answer = Vec::new();
    let _read = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.read_to_end(&mut answer),
    )
    .await
    .expect("the client read never returned")
    .expect("the client read failed");

    proxy.stop();
    let _ = runner.await;

    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 400"),
        "the request was refused with: {answer}"
    );
}

/// The far side of the tunnel: a server that waits for the client's
/// half-close before it answers.
///
/// This is the shape of a request/response protocol carried over a
/// connection the client may half-close: the server reads until the client
/// is done sending, and only then writes the reply. The reply cannot be
/// written before the FIN arrives, because the server does not know the
/// request is finished until then.
async fn serve_a_tunnel_that_answers_after_the_fin(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            // The L4 preface, then the status byte the client waits for.
            let mut header = [0u8; 4];
            if recv.read_exact(&mut header).await.is_err() {
                return;
            }
            let mut rest = vec![0u8; usize::from(header[3]) + 2];
            if recv.read_exact(&mut rest).await.is_err() {
                return;
            }
            if send.write_all(&[0x00]).await.is_err() {
                return;
            }

            // Read until the client is done sending. This is the half-close
            // the reply depends on.
            let mut buf = vec![0u8; 4096];
            loop {
                match recv.read(&mut buf).await {
                    Ok(None) | Err(_) => break,
                    Ok(Some(n)) => {
                        if n == 0 {
                            break;
                        }
                    }
                }
            }

            // Only now the reply.
            let _ = send.write_all(b"the reply").await;
            let _ = send.finish();
            // The connection is held open for a moment. Dropping it here
            // would close the tunnel, and a close discards whatever the
            // peer has not read yet -- the reply included.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });
    }
}

/// The far side of a tunnel that closes: the server accepts, answers the
/// preface, and then ends the conversation without waiting for anything
/// from the client.
///
/// This is the shape of a server that has nothing more to say — an origin
/// that closed the connection, or a tunnel whose budget ran out. The
/// client has to learn that, the way it learns it from a socket.
async fn serve_a_tunnel_that_closes(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            // The L4 preface, then the status byte the client waits for.
            let mut header = [0u8; 4];
            if recv.read_exact(&mut header).await.is_err() {
                return;
            }
            let mut rest = vec![0u8; usize::from(header[3]) + 2];
            if recv.read_exact(&mut rest).await.is_err() {
                return;
            }
            if send.write_all(&[0x00]).await.is_err() {
                return;
            }

            // And then the conversation is over: a FIN, not a reset.
            let _ = send.finish();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });
    }
}

/// A client that half-closes still receives the reply.
///
/// A TCP half-close is a request, not an ending: a client that writes its
/// request and then shuts down its write side is saying "I am done
/// sending", and the server's reply still has to arrive. The two halves of
/// the copy were raced, and whichever lost was aborted — so the reply was
/// cut off and the connection reset under the client.
///
/// The far side here waits for the FIN before it answers, so the reply
/// cannot be out before the half-close: the test fails against the old
/// code, and it fails in the way that matters — the client never gets the
/// bytes.
#[tokio::test]
async fn a_half_closed_client_still_receives_the_reply() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_answers_after_the_fin(server));

    // This side: an endpoint, a pool over it, and the proxy.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The application: a tunnel, a request, and then a half-close.
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .expect("the CONNECT goes out");
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .expect("the answer comes");
        answer.push(byte[0]);
        if answer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "the tunnel should be established: {:?}",
        String::from_utf8_lossy(&answer)
    );

    stream
        .write_all(b"the request")
        .await
        .expect("the request goes out");
    // The half-close: the client is done sending, and the server has to
    // hear that.
    stream.shutdown().await.expect("the write side closes");

    let mut reply = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut reply),
    )
    .await;
    assert!(
        read.is_ok(),
        "the reply never arrived: the tunnel was cut off at the half-close"
    );
    assert_eq!(
        reply, b"the reply",
        "the reply did not survive the half-close"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// A `ClientHello` that arrives in pieces is still a hello.
///
/// The record's length is in its first five bytes, so a hello whose first
/// read carried fewer than five had nothing to measure — and the reading
/// stopped there, because the loop that reads the rest was inside the
/// check. The truncated hello was then parsed as if it were the whole one,
/// which is a hello with no name in it, and the session was closed with no
/// retry and no tunnel.
///
/// The stream here hands over three bytes and the rest a moment later, which
/// is what a path that segments the first record does.
#[tokio::test]
async fn a_hello_that_arrives_in_pieces_is_still_proxied() {
    use tokio::io::AsyncWriteExt;

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_reads_the_hello(server, seen.clone()));

    // This side: an endpoint, a pool over it, and the group over that.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let endpoint_group = crate::endpoint_group::EndpointGroup::new_with_single_pool(pool).await;

    // The hello, in two pieces: three bytes, and the rest a moment later.
    let hello = hello_with_server_names(&[(0x00, HOST)]);
    let (mut far, near) = tokio::io::duplex(4096);
    let rest = hello[3..].to_vec();
    let writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        far.write_all(&rest)
            .await
            .expect("the rest of the hello goes out");
        // Held open: the tunnel's copy loop reads from this end.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    super::tls::handle_tls_tunnel(
        near,
        hello[..3].to_vec(),
        vec![0u8; super::STREAM_BUF_SIZE],
        Arc::new(endpoint_group),
        Arc::new(vec![HOST.to_string()]),
        None,
    )
    .await
    .expect("the hello is proxied");

    // The far side must see the whole hello: the client read the name out of
    // it and forwarded all of it.
    let forwarded = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let bytes = seen.lock().expect("the lock is not held").clone();
            if bytes.len() >= hello.len() {
                break bytes;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the hello never reached the far side");
    assert_eq!(
        forwarded, hello,
        "the far side did not get the hello the client was given"
    );

    writer.abort();
}

/// The far side of a tunnel that records what the client forwards.
///
/// The tunnel carries a preface and then the bytes, so the preface is read
/// and what comes after it is recorded. The status byte the client waits for
/// is written first, or the client never opens the tunnel.
async fn serve_a_tunnel_that_records_the_payload(
    endpoint: Endpoint,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            // The L4 preface, then the status byte the client waits for.
            let mut header = [0u8; 4];
            if recv.read_exact(&mut header).await.is_err() {
                return;
            }
            let mut rest = vec![0u8; usize::from(header[3]) + 2];
            if recv.read_exact(&mut rest).await.is_err() {
                return;
            }
            if send.write_all(&[0x00]).await.is_err() {
                return;
            }

            // Everything after the preface is the payload.
            let mut buf = vec![0u8; 4096];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while let Ok(Ok(Some(n))) = tokio::time::timeout_at(deadline, recv.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                seen.lock()
                    .expect("the lock is not held")
                    .extend_from_slice(&buf[..n]);
            }

            // Held open for a moment: a close discards whatever the peer has
            // not read yet.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
    }
}

/// The bytes that came with the CONNECT head reach the tunnel.
///
/// The head reader keeps everything it read, so a client that wrote the
/// CONNECT head and the first bytes of the tunnel in one go has both in the
/// buffer by the time the head is complete. The CONNECT branch used to read
/// the socket again from there and drop them — the copy loop starts at the
/// socket, and the socket had already given these up.
///
/// The ordinary HTTP path forwards them; this branch did not, and the
/// difference was a tunnel that began in the middle of whatever the client
/// had sent. A TLS client that pipelined its first record into the CONNECT
/// got a stream the far side could not read.
#[tokio::test]
async fn the_bytes_that_came_with_the_connect_head_reach_the_tunnel() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// What the client sends with the head.
    const PAYLOAD: &[u8] = b"PAYLOAD-AFTER-THE-HEAD";

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_records_the_payload(
        server,
        seen.clone(),
    ));

    // This side: an endpoint, a pool over it, and the proxy.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The head and the payload, in one write: what a client that pipelines
    // its first record into the CONNECT does.
    let mut request = format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").into_bytes();
    request.extend_from_slice(PAYLOAD);

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(&request)
        .await
        .expect("the CONNECT goes out");

    // The far side records what the proxy forwarded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if seen
            .lock()
            .expect("the lock is not held")
            .windows(PAYLOAD.len())
            .any(|w| w == PAYLOAD)
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let seen = seen.lock().expect("the lock is not held").clone();
    assert!(
        seen.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
        "the bytes that came with the CONNECT head never reached the tunnel: {:?}",
        String::from_utf8_lossy(&seen)
    );

    proxy.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
}

/// The far side of a WebSocket tunnel: it records what the client forwarded
/// and answers the upgrade.
///
/// A WebSocket tunnel carries the request and then the frames, so what the
/// far side reads is the request and whatever came with it. The upgrade is
/// answered as soon as the head is complete, so the client is not left
/// waiting for an answer that was never going to come.
async fn serve_a_tunnel_that_answers_an_upgrade(
    endpoint: Endpoint,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            let mut buf = vec![0u8; 4096];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut recorded: Vec<u8> = Vec::new();
            while let Ok(Ok(Some(n))) = tokio::time::timeout_at(deadline, recv.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                recorded.extend_from_slice(&buf[..n]);
                if recorded.windows(4).any(|w| w == b"\r\n\r\n") {
                    let _ = send
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              Upgrade: websocket\r\n\
                              Connection: Upgrade\r\n\r\n",
                        )
                        .await;
                    // One more read: the bytes that came with the head may be
                    // in a read of their own.
                    let mut more = vec![0u8; 4096];
                    if let Ok(Ok(Some(n))) =
                        tokio::time::timeout(Duration::from_secs(1), recv.read(&mut more)).await
                    {
                        recorded.extend_from_slice(&more[..n]);
                    }
                    break;
                }
            }
            seen.lock()
                .expect("the lock is not held")
                .extend_from_slice(&recorded);

            // Held open for a moment: a close discards whatever the peer has
            // not read yet.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
    }
}

/// The bytes that came with the upgrade head reach the tunnel.
///
/// The head reader keeps everything it read, so a client that wrote the
/// upgrade request and its first frame in one go has both in the buffer by
/// the time the head is complete. The WebSocket branch used to send only the
/// head and then read the socket again — so the first frame was gone, and a
/// browser that coalesced the two lost it.
#[tokio::test]
async fn the_bytes_that_came_with_the_websocket_head_reach_the_tunnel() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// What the client sends with the head.
    const PAYLOAD: &[u8] = b"FIRST-FRAME";

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![nexapipe_proto::protocol::ALPN_HTTP.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_answers_an_upgrade(server, seen.clone()));

    // This side: an endpoint, a pool over it, and the proxy.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![nexapipe_proto::protocol::ALPN_HTTP.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The upgrade and the first frame, in one write.
    let mut request = format!(
        "GET /chat HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(PAYLOAD);

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(&request)
        .await
        .expect("the upgrade goes out");

    // The far side records what the proxy forwarded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if seen
            .lock()
            .expect("the lock is not held")
            .windows(PAYLOAD.len())
            .any(|w| w == PAYLOAD)
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let seen = seen.lock().expect("the lock is not held").clone();
    assert!(
        seen.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
        "the bytes that came with the upgrade head never reached the tunnel: {:?}",
        String::from_utf8_lossy(&seen)
    );

    proxy.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
}

/// A tunnel the server closes is closed for the client too.
///
/// The other half of the half-close: a server that ends the conversation
/// says so with a FIN, and the client has to see it the way it would see
/// it from a socket — as an end of stream, not as a hang and not as a
/// reset.
///
/// Joining the two directions is right, but joining them is not the same
/// as leaving the client waiting: the direction that ended has to be
/// handed on to the peer, or the peer is left waiting for an answer that
/// is not coming. The write side towards the client is shut down when
/// the server's side ends, which is what turns "the server is gone" into
/// the EOF the client is waiting for — and the read side stays open, so
/// a client that still has something to say can say it.
#[tokio::test]
async fn a_tunnel_the_server_closes_is_closed_for_the_client() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // The far side: it closes the tunnel.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_closes(server));

    // This side: an endpoint, a pool over it, and the proxy.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The application: a tunnel, and then it waits for the other end.
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(format!("CONNECT {HOST}:{PORT} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .expect("the CONNECT goes out");
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .expect("the answer comes");
        answer.push(byte[0]);
        if answer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "the tunnel should be established: {:?}",
        String::from_utf8_lossy(&answer)
    );

    // The far side closes. The client has to be told.
    let mut rest = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(
        read.is_ok(),
        "the client was never told that the tunnel closed: it is still waiting"
    );
    assert!(
        read.is_ok_and(|r| r.is_ok()),
        "the client saw a reset rather than an end of stream"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// The cap is what turns memory into a bounded quantity: every connection
/// allocates a `STREAM_BUF_SIZE` buffer, so an accept loop that takes every
/// caller lets anything on the loopback interface spend this process's
/// memory one connection at a time.
///
/// The refused socket is closed without a byte being read — it must not be
/// queued, because a queued caller holds the buffer while it waits.
#[tokio::test]
async fn connections_beyond_the_cap_are_refused() {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let (proxy, addr) = listening_proxy().await;
    let runner = spawn_run(&proxy);

    // Hold the whole budget open. A connection that has sent nothing sits in
    // the handler waiting for a request, which is the state being counted.
    let mut held = Vec::with_capacity(MAX_CONCURRENT_CONNECTIONS);
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        held.push(TcpStream::connect(addr).await.expect("the caller connects"));
    }

    // `track_connection` runs straight after each accept, so the number of
    // tracked handles is the number being served. Waiting for it to reach the
    // cap is what makes the next connection a refusal rather than a race.
    let deadline = Instant::now() + Duration::from_secs(10);
    while proxy.connections.lock().unwrap().len() < MAX_CONCURRENT_CONNECTIONS {
        assert!(
            Instant::now() < deadline,
            "the accept loop took only {} of {} connections",
            proxy.connections.lock().unwrap().len(),
            MAX_CONCURRENT_CONNECTIONS
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // One over the budget: closed immediately, with nothing read from it.
    let mut extra = TcpStream::connect(addr).await.expect("the caller connects");
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
        .await
        .expect("a refusal closes the socket instead of leaving it open");
    assert_eq!(
        closed.expect("a refusal is a close, not an error"),
        0,
        "a connection beyond the cap must be closed, not queued"
    );

    // And the budget is released: once a caller hangs up, its slot comes back.
    drop(held.pop());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut probe = TcpStream::connect(addr).await.expect("the caller connects");
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(200), probe.read(&mut buf)).await {
            // A timeout means the connection was accepted and is waiting for
            // a request: the slot came back.
            Err(_) => break,
            Ok(Ok(0)) => {
                assert!(
                    Instant::now() < deadline,
                    "no slot was released after a connection ended"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(Ok(n)) => panic!("nothing is ever sent to a fresh connection, got {n} bytes"),
            Ok(Err(e)) => panic!("a fresh connection is not reset: {e}"),
        }
    }

    proxy.stop();
    runner.abort();
}

/// A caller that trickles its request head forever is closed, rather than
/// holding its connection, its task and its slot open indefinitely.
///
/// The shape of this test is the point: a byte goes out well inside the
/// deadline, over and over, for longer than the deadline itself. Under a
/// per-read timeout every one of those bytes reset the clock and the read
/// would still be running at the end; under a phase deadline the instant was
/// taken once and the trickle renews nothing.
///
/// Drives `read_http_header` over a `duplex` pair rather than a real socket
/// so the budget can be milliseconds instead of the production thirty
/// seconds — which is why the deadline is a parameter of that function.
#[tokio::test]
async fn a_trickling_request_head_is_closed_rather_than_waited_on() {
    use tokio::io::AsyncWriteExt;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    let (mut client, mut server) = tokio::io::duplex(4096);

    // A request line that never terminates, so the reader stays in the loop
    // for the whole run.
    let trickle = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut sends = 0usize;
        // Twice the deadline: comfortably past the point where a per-read
        // timeout would have renewed forever, while each individual send
        // stays inside the budget.
        while started.elapsed() < Duration::from_millis(400) {
            if client.write_all(b"G").await.is_err() {
                break;
            }
            sends += 1;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        sends
    });

    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];
    let started = std::time::Instant::now();
    let outcome = read_http_header(&mut server, &mut request_buf, &mut temp_buf, deadline).await;

    assert_eq!(
        outcome,
        HeaderOutcome::Closed,
        "a head that trickles past its deadline must be closed, not waited on"
    );
    assert!(
        started.elapsed() < Duration::from_millis(350),
        "it expired on the deadline rather than when the peer stopped: {:?}",
        started.elapsed()
    );

    let sends = trickle.await.unwrap_or(0);
    assert!(
        sends > 1,
        "the test did not actually trickle: {sends} sends"
    );
}

/// A head that arrives complete is read as one, and the deadline is not
/// charged to a request that needed no waiting.
#[tokio::test]
async fn a_head_that_arrives_whole_is_complete_at_once() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let (mut client, mut server) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let _ = client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await;
        // Held open so the read cannot end at EOF and be mistaken for a
        // complete head by accident.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut request_buf = Vec::new();
    let mut temp_buf = vec![0u8; STREAM_BUF_SIZE];
    match read_http_header(&mut server, &mut request_buf, &mut temp_buf, deadline).await {
        HeaderOutcome::Complete(end) => {
            assert_eq!(
                &request_buf[..end],
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
            );
        }
        HeaderOutcome::Closed => panic!("a complete head must not be reported as closed"),
    }
}

/// `stop()` has to reach a loop that is parked in `accept()`, not one that
/// happens to look at a flag on the way past: with nothing to wake it, the
/// task stays on the listener for as long as the process lives.
#[tokio::test]
async fn stop_wakes_a_loop_that_is_waiting_for_a_connection() {
    let (proxy, _addr) = listening_proxy().await;
    let runner = spawn_run(&proxy);

    // Long enough that the loop is definitely inside `accept()`.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    proxy.stop();

    assert!(
        tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
            .await
            .is_ok(),
        "run() never returned after stop()"
    );
}

/// The handlers outlive `run()`, so a proxy that only stops the loop would
/// leave them holding pooled connections. Stopping has to end them too.
#[tokio::test]
async fn stop_ends_the_connections_it_accepted() {
    let (proxy, addr) = listening_proxy().await;
    let runner = spawn_run(&proxy);

    // A client that connects and then says nothing: the handler parks in
    // its first read, which is the state that used to survive stop().
    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");

    let tracked = tokio::time::timeout(tokio::time::Duration::from_secs(2), async {
        loop {
            if proxy.connections.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(tracked.is_ok(), "the accepted connection was never tracked");

    proxy.stop();
    assert!(
        tokio::time::timeout(tokio::time::Duration::from_secs(2), runner)
            .await
            .is_ok(),
        "run() never returned after stop()"
    );
    assert!(
        proxy.connections.lock().unwrap().is_empty(),
        "stop() must drop the handles it aborted"
    );

    // Aborting the handler drops its socket, so the peer sees EOF instead
    // of waiting out the handler's read timeout.
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(tokio::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("the client read never returned")
        .expect("the client read failed");
    assert_eq!(read, 0, "the handler kept its socket open after stop()");
}

/// The ALPN a TLS tunnel is spoken with. The same bytes the server
/// offers for it.
const TLS_ALPN: &[u8] = b"nexapipe/tls";

/// A TLS `ClientHello` carrying the given `server_name` entries.
///
/// Each entry is a name type and the name itself. The reader takes the
/// entry of type `host_name` wherever it is in the list: RFC 6066 allows
/// a list, and a hello that puts another type first still has its host
/// name behind it.
fn hello_with_server_names(entries: &[(u8, &str)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name_type, name) in entries {
        let bytes = name.as_bytes();
        list.push(*name_type);
        list.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        list.extend_from_slice(bytes);
    }

    let mut extension = Vec::new();
    extension.extend_from_slice(&0u16.to_be_bytes()); // extension type: server_name
    extension.extend_from_slice(&((2 + list.len()) as u16).to_be_bytes()); // extension length
    extension.extend_from_slice(&(list.len() as u16).to_be_bytes()); // list length
    extension.extend_from_slice(&list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
    body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
    body.push(1); // compression_methods length
    body.push(0); // null compression
    body.extend_from_slice(&(extension.len() as u16).to_be_bytes()); // extensions length
    body.extend_from_slice(&extension);

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x01, 0x00]; // a handshake record
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// The far side of a TLS tunnel: it accepts the connection and reads the
/// `ClientHello` the client forwards.
///
/// A TLS tunnel carries the hello itself — there is no preface in front
/// of it — so what the far side reads is the hello, and the bytes it
/// collected are what the test looks at.
async fn serve_a_tunnel_that_reads_the_hello(
    endpoint: Endpoint,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            let Ok((_send, mut recv)) = connection.accept_bi().await else {
                return;
            };

            let mut buf = vec![0u8; 4096];
            // The hello may arrive in more than one read: a QUIC stream
            // hands over what it has, and a helper that read once saw a
            // truncated hello — which passed under one feature set and
            // failed under another, where the timing was different.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while let Ok(Ok(Some(n))) = tokio::time::timeout_at(deadline, recv.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                seen.lock()
                    .expect("the lock is not held")
                    .extend_from_slice(&buf[..n]);
            }

            // Held open for a moment: a close discards whatever the peer
            // has not read yet.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
    }
}

/// A hello whose host name is behind another entry type is proxied.
///
/// The client used to read the first entry of the `server_name` list and
/// give up if it was not of the type it reads, so a hello that put
/// another type first resolved to no name on the client — while the
/// server, which walks the whole list, found the host name behind it.
/// The client closed a connection the server would have served.
///
/// The far side here reads what the client forwards, and the hello is
/// what it must find: a client that read no name at all forwards
/// nothing, because it closes the connection before it opens the tunnel.
#[tokio::test]
async fn a_tls_hello_whose_host_name_is_behind_another_entry_type_is_proxied() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_reads_the_hello(server, seen.clone()));

    // This side: an endpoint, a pool over it, and the proxy.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The application: a hello whose host name is behind another type.
    let hello = hello_with_server_names(&[(0x01, "not-a-host-name"), (0x00, HOST)]);
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream.write_all(&hello).await.expect("the hello goes out");

    // The far side must see the hello: the client read the name, matched
    // it against the domains it proxies, and forwarded the hello. Every
    // byte of it, because the hello may arrive in more than one read.
    let forwarded = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let bytes = seen.lock().expect("the lock is not held").clone();
            if bytes.len() >= hello.len() {
                break bytes;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the hello never reached the far side");
    assert_eq!(
        forwarded, hello,
        "the far side did not get the hello the client was given"
    );

    proxy.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
}

/// A hello whose name is not a name is closed, not logged.
///
/// The name is written to the log on every path that names it, and a
/// `\r\n` in it lets a client append lines of its own to the log. The
/// server refused such a name; the client read it and carried on, so the
/// name it read went straight into the log.
///
/// The client proxies **every** host here — the catch-all is what makes
/// the test about the name and not about the list: a name that is not a
/// name is refused whatever the operator asked for, and a name the
/// operator did ask for is not what saves it.
///
/// The far side must see nothing: a client that refused the hello opens
/// no tunnel at all.
#[tokio::test]
async fn a_tls_hello_whose_name_is_not_a_name_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    // The far side.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_a_tunnel_that_reads_the_hello(server, seen.clone()));

    // This side: an endpoint, a pool over it, and the proxy. Every host
    // is proxied, so nothing but the name itself can refuse the hello.
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![TLS_ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec!["*".to_string()], pool)
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy's address");
    let runner = spawn_run(&proxy);

    // The application: a hello whose name carries a line break.
    let hello = hello_with_server_names(&[(0x00, "evil\r\nInjected: yes")]);
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream.write_all(&hello).await.expect("the hello goes out");

    // The connection is closed, and nothing was forwarded.
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("the client was never closed")
        .expect("the client read failed");
    assert_eq!(read, 0, "the client was left waiting on a refused hello");

    assert!(
        seen.lock().expect("the lock is not held").is_empty(),
        "a hello with a name that is not a name was forwarded"
    );

    proxy.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
}

/// The cap is on the header, not on the whole request: a short header
/// followed by a body larger than the cap is an ordinary upload, and used
/// to be refused for being one.
#[test]
fn the_header_limit_ignores_the_body() {
    let mut request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    request.extend(std::iter::repeat_n(b'x', MAX_REQUEST_HEADER * 4));

    let header_end = header_terminator(&request);

    assert!(!header_over_limit(&request, header_end));
}

/// A header that arrives whole in one read never enters the read loop, so
/// the first read is measured as well — otherwise the cap only ever applied
/// to a header split across two.
#[test]
fn an_oversized_header_is_refused_even_when_it_is_complete() {
    let mut request = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEADER));
    request.extend_from_slice(b"\r\n\r\n");

    let header_end = header_terminator(&request).expect("the terminator is written above");

    assert!(header_over_limit(&request, Some(header_end)));
}

/// Until a terminator arrives, everything read is header as far as anyone
/// can tell — which is the case that bounds a peer that never ends one.
#[test]
fn a_header_that_never_ends_is_still_capped() {
    let request: Vec<u8> = std::iter::repeat_n(b'a', MAX_REQUEST_HEADER + 1).collect();

    assert!(header_over_limit(&request, None));
    assert!(!header_over_limit(&request[..MAX_REQUEST_HEADER], None));
}

/// Where the header ends in `request`, if it ends at all.
fn header_terminator(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// The headers a request keeps, as one string.
fn kept_headers(request: &[u8]) -> String {
    String::from_utf8(filter_request_headers(request, false)).expect("the headers are ASCII")
}

/// The headers a request keeps, as one string, with the upgrade kept.
fn kept_headers_with_upgrade(request: &[u8]) -> String {
    String::from_utf8(filter_request_headers(request, true)).expect("the headers are ASCII")
}

/// A request line that ends with a bare LF still ends there.
///
/// The headers after it are the headers, and the first of them is the
/// `Host` one — the one that says which name the request is for. A walk
/// that took the first `\r\n` instead would step over it, and the server
/// substitutes the backend's address for a request that arrives without
/// one: a request for a name would then be served by the wrong site.
#[test]
fn a_bare_lf_request_line_does_not_take_the_first_header_with_it() {
    let request = b"GET /chat HTTP/1.1\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
    let end = request_line_end(request);

    assert_eq!(
        &request[end + 1..],
        b"Host: example.com\r\nUpgrade: websocket\r\n\r\n",
        "the headers after the request line are still there"
    );
}

/// The ordinary spelling, with the carriage return, is the same answer.
#[test]
fn a_crlf_request_line_ends_where_it_did() {
    let request = b"GET /chat HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let end = request_line_end(request);

    assert_eq!(
        &request[end + 1..],
        b"Host: example.com\r\n\r\n",
        "the headers after the request line are still there"
    );
}

/// The hop-by-hop headers do not cross the tunnel.
///
/// `Proxy-Authorization` is the one that matters most: it is a credential
/// for *this* proxy, and forwarding it hands it to a third-party server.
#[test]
fn the_hop_by_hop_headers_do_not_cross_the_tunnel() {
    let request = b"GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Proxy-Authorization: Basic c2VjcmV0\r\n\
                    Proxy-Authenticate: Basic\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Keep-Alive: timeout=5\r\n\
                    Te: trailers\r\n\
                    Trailer: Expires\r\n\
                    Accept: */*\r\n\r\n";

    let kept = kept_headers(request).to_ascii_lowercase();

    for header in [
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-connection",
        "keep-alive",
        "te:",
        "trailer:",
    ] {
        assert!(!kept.contains(header), "{header} was forwarded:\n{kept}");
    }
    assert!(kept.contains("host: example.com"), "{kept}");
    assert!(kept.contains("accept: */*"), "{kept}");
}

/// `Connection` nominates the names that are hop-by-hop for this message,
/// so a header it names must not be forwarded either.
#[test]
fn a_header_connection_nominates_does_not_cross_the_tunnel() {
    let request = b"GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Connection: X-Secret, close\r\n\
                    X-Secret: the-password\r\n\
                    Accept: */*\r\n\r\n";

    let kept = kept_headers(request);

    assert!(!kept.to_ascii_lowercase().contains("x-secret"), "{kept}");
    assert!(kept.contains("Accept: */*"), "{kept}");
}

/// The framing of the body is carried over verbatim, so the header that
/// describes it stays: a chunked body with nothing saying it is chunked is
/// a request the backend cannot read.
#[test]
fn the_transfer_encoding_stays_because_the_body_stays() {
    let request = b"POST / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Accept: */*\r\n\r\n";

    let kept = kept_headers(request);

    assert!(
        kept.to_ascii_lowercase().contains("transfer-encoding"),
        "{kept}"
    );
}

/// The upgrade is the point of a WebSocket request, so it stays.
#[test]
fn the_upgrade_stays_when_the_request_is_one() {
    let request = b"GET /ws HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    let kept = kept_headers_with_upgrade(request).to_ascii_lowercase();

    assert!(kept.contains("upgrade: websocket"), "{kept}");
    assert!(kept.contains("connection: upgrade"), "{kept}");
    assert!(kept.contains("sec-websocket-key:"), "{kept}");
}

/// The request line is not a header, even when it carries a colon: it is
/// the one line that must survive the filter untouched.
#[test]
fn the_request_line_is_not_mistaken_for_a_header() {
    let request = b"GET /a:b HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let kept = kept_headers(request);

    assert!(kept.starts_with("GET /a:b HTTP/1.1\r\n"), "{kept}");
}

/// The local proxy hands out the tunnel of a connection that has already
/// authenticated, so it is loopback-only unless the caller says otherwise.
#[test]
fn the_local_proxy_is_loopback_only_unless_the_caller_says_otherwise() {
    let loopback: SocketAddr = "127.0.0.1:8080".parse().expect("an address");
    let v6_loopback: SocketAddr = "[::1]:8080".parse().expect("an address");
    let lan: SocketAddr = "192.168.1.10:8080".parse().expect("an address");
    let any: SocketAddr = "0.0.0.0:8080".parse().expect("an address");
    let any_v6: SocketAddr = "[::]:8080".parse().expect("an address");

    assert!(may_bind_local_proxy(loopback, false));
    assert!(may_bind_local_proxy(v6_loopback, false));

    for bound in [lan, any, any_v6] {
        assert!(
            !may_bind_local_proxy(bound, false),
            "{bound} is reachable from the network"
        );
        assert!(
            may_bind_local_proxy(bound, true),
            "{bound} needs the explicit opt-in"
        );
    }
}

/// A conditional request loses the headers that would make the origin
/// answer with a 304 and an empty body.
#[test]
fn a_conditional_request_loses_its_cache_headers() {
    let request = b"GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n\
                    If-None-Match: \"a-long-etag-value\"\r\n\
                    Accept: */*\r\n\r\n";

    let kept = kept_headers(request);

    assert!(
        !kept.to_ascii_lowercase().contains("if-modified-since"),
        "{kept}"
    );
    assert!(
        !kept.to_ascii_lowercase().contains("if-none-match"),
        "{kept}"
    );
    assert!(kept.contains("Host: example.com"), "{kept}");
    assert!(kept.contains("Accept: */*"), "{kept}");
}

/// The shortest forms of `If-None-Match` are the ones a length guard for
/// the *longer* header name lets through — and they are exactly the
/// requests the origin answers with a 304 and an empty body.
#[test]
fn the_shortest_if_none_match_is_stripped() {
    for value in ["*", "\"\"", "\"e\""] {
        let request =
            format!("GET / HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {value}\r\n\r\n");

        let kept = kept_headers(request.as_bytes());

        assert!(
            !kept.to_ascii_lowercase().contains("if-none-match"),
            "`If-None-Match: {value}` is {value:?} — {kept}"
        );
        assert!(kept.contains("Host: example.com"), "{kept}");
    }
}

/// The header name is a name, not a string to match exactly: a client that
/// spells it in another case is still asking for a conditional response.
#[test]
fn the_cache_header_is_stripped_whatever_its_case() {
    for name in ["if-none-match", "IF-NONE-MATCH", "If-None-Match"] {
        let request = format!("GET / HTTP/1.1\r\n{name}: *\r\n\r\n");

        let kept = kept_headers(request.as_bytes());

        assert!(
            !kept
                .to_ascii_lowercase()
                .contains(name.to_ascii_lowercase().as_str()),
            "{name} was kept: {kept}"
        );
        assert!(kept.starts_with("GET / HTTP/1.1"), "{kept}");
    }
}

/// Only the two cache-validation headers are stripped: a header that
/// merely starts with the same letters is somebody else's.
#[test]
fn a_header_that_merely_looks_like_one_is_kept() {
    let request = b"GET / HTTP/1.1\r\n\
                    X-If-None-Match: *\r\n\
                    If-None-Match-Extra: *\r\n\r\n";

    let kept = kept_headers(request);

    assert!(kept.contains("X-If-None-Match: *"), "{kept}");
    assert!(kept.contains("If-None-Match-Extra: *"), "{kept}");
}

/// The far side: an HTTP server over an iroh bi-stream that reports the
/// size of the head it received and of the body that followed it.
async fn serve_an_http_backend(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut head = Vec::new();
                    loop {
                        let n = match recv.read(&mut buf).await {
                            Ok(Some(n)) => n,
                            Ok(None) | Err(_) => return,
                        };
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head_end = head
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(head.len());
                    let mut body = head[head_end..].to_vec();
                    let mut want = 0usize;
                    for line in head[..head_end].split(|b| *b == b'\n') {
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
                            want = String::from_utf8_lossy(&line[15..])
                                .trim()
                                .parse()
                                .unwrap_or(0);
                        }
                    }
                    while body.len() < want {
                        let n = match recv.read(&mut buf).await {
                            Ok(Some(n)) => n,
                            Ok(None) | Err(_) => break,
                        };
                        body.extend_from_slice(&buf[..n]);
                    }
                    let answer = format!("head={} body={}", head_end, body.len());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                        answer.len(),
                        answer
                    );
                    let _ = send.write_all(response.as_bytes()).await;
                    let _ = send.finish();
                });
            }
        });
    }
}

/// The proxy in front of that backend.
async fn proxy_over(server_addr: iroh::EndpointAddr) -> (LocalProxy, std::net::SocketAddr) {
    let client = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("this side binds");
    let pool = crate::IrohConnectionPool::new_with_endpoint(client, server_addr);
    let proxy = LocalProxy::new_with_single_pool("127.0.0.1:0", vec![HOST.to_string()], pool)
        .await
        .expect("the proxy binds");
    let addr = proxy.local_addr().expect("the proxy's address");
    (proxy, addr)
}

/// A head that does not fit in one `STREAM_BUF_SIZE` buffer arrives whole.
///
/// The head is read into the buffer that then becomes a copy loop's
/// buffer, so a head larger than the buffer is the case where reading it
/// and handing it on could go wrong: the bytes either stop at the buffer
/// or arrive whole.
#[tokio::test]
async fn a_head_larger_than_the_stream_buffer_arrives_whole() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_an_http_backend(server));

    let (proxy, proxy_addr) = proxy_over(server_addr).await;
    let runner = spawn_run(&proxy);

    // A head that does not fit in one buffer, and stays under the cap.
    let padding = "p".repeat(STREAM_BUF_SIZE + 4096);
    let request = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nx-big: {padding}\r\n\r\n");
    assert!(
        request.len() > STREAM_BUF_SIZE,
        "the head must be larger than the buffer"
    );
    assert!(request.len() < MAX_REQUEST_HEADER, "and under the cap");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request goes out");
    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the answer never arrived");
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the request was not served: {answer}"
    );
    assert!(
        answer.contains(&format!("head={}", request.len())),
        "the head did not arrive whole: {answer}"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// The body that follows the head is forwarded.
///
/// The buffer that held the head's bytes becomes a copy loop's buffer, and
/// the body arrives in the same stream. A body that arrives in the same
/// read as the head, and a body that arrives later, are both the body's
/// own bytes and neither may be lost.
#[tokio::test]
async fn a_body_after_the_head_is_forwarded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_an_http_backend(server));

    let (proxy, proxy_addr) = proxy_over(server_addr).await;
    let runner = spawn_run(&proxy);

    let body = vec![b'z'; 100_000];
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(&body);

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(&bytes)
        .await
        .expect("the request goes out");
    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the answer never arrived");
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the request was not served: {answer}"
    );
    assert!(
        answer.contains(&format!("body={}", body.len())),
        "the body did not arrive whole: {answer}"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// A second request that came with the head is refused.
///
/// The list of proxied domains is consulted about the first request, and the
/// server serves keep-alive requests on one stream — so a second request that
/// reaches the server is answered by it, and the list was never consulted
/// about it. The bytes that came with the head are refused when they are
/// another request rather than a body.
#[tokio::test]
async fn a_second_request_that_came_with_the_head_is_refused() {
    let (proxy, addr) = listening_proxy_for(&[HOST]).await;
    let runner = spawn_run(&proxy);

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    client
        .write_all(
            format!(
                "GET /a HTTP/1.1\r\nHost: {HOST}\r\n\r\nGET /b HTTP/1.1\r\nHost: other.test\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("the request is written");

    let mut answer = Vec::new();
    let _read = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.read_to_end(&mut answer),
    )
    .await
    .expect("the client read never returned")
    .expect("the client read failed");

    proxy.stop();
    let _ = runner.await;

    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 400"),
        "the request was refused with: {answer}"
    );
}

/// A request that declares no body has no body, whatever its method says.
///
/// RFC 9112 §6.3 gives a message with no framing header a body of zero
/// bytes, so the bytes that came with the head are another request's head.
/// A length of zero says the same thing.
#[tokio::test]
async fn a_request_without_a_declared_length_has_no_body() {
    let (proxy, addr) = listening_proxy_for(&[HOST]).await;
    let runner = spawn_run(&proxy);

    for head in [
        format!("POST /a HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
        format!("POST /a HTTP/1.1\r\nHost: {HOST}\r\ncontent-length: 0\r\n\r\n"),
    ] {
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the proxy is listening");
        client
            .write_all(head.as_bytes())
            .await
            .expect("the request is written");
        client
            .write_all(b"GET /b HTTP/1.1\r\nHost: other.test\r\n\r\n")
            .await
            .expect("the second request is written");

        let mut answer = Vec::new();
        let _read = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            client.read_to_end(&mut answer),
        )
        .await
        .expect("the client read never returned")
        .expect("the client read failed");

        let answer = String::from_utf8_lossy(&answer);
        assert!(
            answer.starts_with("HTTP/1.1 400"),
            "a request that declares no body was answered with: {answer}"
        );
    }

    proxy.stop();
    let _ = runner.await;
}

/// A body that is longer than it declares is a second request.
///
/// The length is what the request says about its body, and the bytes past
/// it are not the body's: they are the head of another request.
#[tokio::test]
async fn a_body_longer_than_it_declares_is_refused() {
    let (proxy, addr) = listening_proxy_for(&[HOST]).await;
    let runner = spawn_run(&proxy);

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    client
        .write_all(
            format!(
                "POST /a HTTP/1.1\r\nHost: {HOST}\r\ncontent-length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\n\
                 Host: other.test\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("the request is written");

    let mut answer = Vec::new();
    let _read = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        client.read_to_end(&mut answer),
    )
    .await
    .expect("the client read never returned")
    .expect("the client read failed");

    proxy.stop();
    let _ = runner.await;

    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 400"),
        "the request was refused with: {answer}"
    );
}

/// The bytes that came with the head are the body's when the head says the
/// request has one.
///
/// The two cases are told apart by the head, and the head is what says it: a
/// request that declares a body has one, and the bytes that came with the
/// head are its first ones. A body that arrives with the head is forwarded
/// like any other body.
#[tokio::test]
async fn a_body_that_came_with_the_head_is_forwarded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_an_http_backend(server));

    let (proxy, proxy_addr) = proxy_over(server_addr).await;
    let runner = spawn_run(&proxy);

    // The head and the body, in one write.
    let body = b"the body";
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(&request)
        .await
        .expect("the request goes out");

    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the answer never arrived");
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the request was not served: {answer}"
    );
    assert!(
        answer.contains(&format!("body={}", body.len())),
        "the body did not arrive whole: {answer}"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// A body that is shorter than it declares is still the body's.
///
/// The length says how much may follow the head, not that all of it is there
/// already: the first bytes of a body are the body's, and the rest of it may
/// come later.
#[tokio::test]
async fn a_body_shorter_than_it_declares_is_still_the_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_an_http_backend(server));

    let (proxy, proxy_addr) = proxy_over(server_addr).await;
    let runner = spawn_run(&proxy);

    // The head and the first bytes of the body, in one write.
    let body = b"hello world";
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: {HOST}\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(b"hello");

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(&request)
        .await
        .expect("the request goes out");
    // And the rest of it, later.
    stream
        .write_all(b" world")
        .await
        .expect("the rest of the body goes out");

    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the answer never arrived");
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the request was not served: {answer}"
    );
    assert!(
        answer.contains(&format!("body={}", body.len())),
        "the body did not arrive whole: {answer}"
    );

    proxy.stop();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), runner).await;
}

/// The far side: an HTTP server over an iroh bi-stream that records every
/// byte it is given and answers the first head it reads.
///
/// The answer is late, so a test can send a second request while the first
/// one is still waiting for it.
async fn serve_an_http_backend_that_records(
    endpoint: Endpoint,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
    delay: Duration,
) {
    while let Some(incoming) = endpoint.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(connection) = accepting.await else {
                return;
            };
            loop {
                let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                    return;
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut head = Vec::new();
                    loop {
                        let n = match recv.read(&mut buf).await {
                            Ok(Some(n)) => n,
                            Ok(None) | Err(_) => return,
                        };
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen.lock()
                        .expect("the lock is not held")
                        .extend_from_slice(&head);

                    // The answer, late enough for the test to send another
                    // request while this one is waiting for it.
                    tokio::time::sleep(delay).await;
                    let _ = send
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                    let _ = send.finish();

                    // And everything else the proxy sends is recorded.
                    loop {
                        let n = match recv.read(&mut buf).await {
                            Ok(Some(n)) => n,
                            Ok(None) | Err(_) => break,
                        };
                        seen.lock()
                            .expect("the lock is not held")
                            .extend_from_slice(&buf[..n]);
                    }
                });
            }
        });
    }
}

/// A second request that arrives after the head is not relayed.
///
/// The copy loop keeps forwarding whatever the client sends, so a client
/// that sends its second request a moment later — after the first one is on
/// its way — would get it through as well. The connection carries one
/// request, and the bytes past the body's are refused.
#[tokio::test]
async fn a_second_request_sent_while_the_first_one_is_waiting_is_not_relayed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .expect("the far side binds");
    let server_addr = server.addr();
    tokio::spawn(serve_an_http_backend_that_records(
        server,
        seen.clone(),
        Duration::from_millis(500),
    ));

    let (proxy, proxy_addr) = proxy_over(server_addr).await;
    let runner = spawn_run(&proxy);

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    stream
        .write_all(format!("GET /a HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes())
        .await
        .expect("the first request goes out");

    // The second request, once the head is behind us and the first answer
    // is still to come.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = stream
        .write_all(b"GET /b HTTP/1.1\r\nHost: other.test\r\n\r\n")
        .await;

    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
    assert!(read.is_ok(), "the answer never arrived");
    let answer = String::from_utf8_lossy(&answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the first request was not served: {answer}"
    );

    let seen = seen.lock().expect("the lock is not held").clone();
    assert!(
        !String::from_utf8_lossy(&seen).contains("other.test"),
        "a second request went through without the list being consulted about it: {:?}",
        String::from_utf8_lossy(&seen)
    );

    proxy.stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
}
/// A backend that goes quiet ends the response, and the exchange with it.
///
/// The bound is a **quiet window** and not a total: a backend that stops
/// talking for a whole window is cut, and it is cut at the *gap* — not at
/// some total measured from the moment the request went out. A backend that
/// has been silent for two minutes is dead, not slow.
///
/// The clock is paused, so "a whole window" is exact rather than
/// approximate, and the test does not sit out the window to find out.
#[tokio::test(start_paused = true)]
async fn a_backend_that_goes_quiet_ends_the_response() {
    let (mut backend, mut origin) = tokio::io::duplex(4096);

    // The origin answers and then says nothing more. Its side stays open:
    // the backend is quiet, not gone.
    tokio::spawn(async move {
        let _ = origin
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nthe first chunk")
            .await;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });

    let mut relayed = Vec::new();
    let outcome = relay_the_response(&mut backend, &mut relayed, RESPONSE_IDLE, &mut |_| {}).await;

    assert!(
        matches!(outcome, ResponseRelay::Quiet),
        "a backend that went quiet must end the exchange: {outcome:?}"
    );
    assert_eq!(
        relayed, b"HTTP/1.1 200 OK\r\n\r\nthe first chunk",
        "the bytes that did arrive have to reach the client"
    );
}

/// A backend that keeps sending is not cut off, however long it takes.
///
/// The bound is a quiet window and not a clock over the whole exchange, so a
/// response that keeps arriving keeps the exchange alive: the total here is
/// several times the window, and every gap between two chunks is shorter
/// than it. A total bound would have cut this exchange in the middle.
#[tokio::test(start_paused = true)]
async fn a_backend_that_keeps_sending_is_not_cut_off() {
    let (mut backend, mut origin) = tokio::io::duplex(4096);

    /// How many chunks the origin sends.
    const CHUNKS: usize = 10;
    /// The gap between two chunks: shorter than the window, so no chunk is
    /// ever late.
    const GAP: Duration = Duration::from_secs(30);

    tokio::spawn(async move {
        for i in 0..CHUNKS {
            let _ = origin.write_all(format!("chunk {i}\n").as_bytes()).await;
            tokio::time::sleep(GAP).await;
        }
        let _ = origin.shutdown().await;
    });

    let mut relayed = Vec::new();
    let outcome = relay_the_response(&mut backend, &mut relayed, RESPONSE_IDLE, &mut |_| {}).await;

    assert!(
        matches!(outcome, ResponseRelay::Complete),
        "a backend that kept sending must not be cut off: {outcome:?}"
    );
    let relayed = String::from_utf8_lossy(&relayed);
    for i in 0..CHUNKS {
        assert!(
            relayed.contains(&format!("chunk {i}\n")),
            "the chunk {i} did not arrive: {relayed}"
        );
    }
    assert!(
        CHUNKS as u64 * GAP.as_secs() > RESPONSE_IDLE.as_secs(),
        "the exchange has to outlast the window, or the test proves nothing"
    );
}
