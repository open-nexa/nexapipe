//! A TLS session, carried through the tunnel as bytes.
//!
//! The tunnel does not read it and does not end it: the bytes go to the peer
//! and come back, and the session is the client's and the peer's.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::ClientError;
use crate::endpoint_group::EndpointGroup;
use crate::flow::{FlowKind, FlowMeta};

use nexapipe_proto::protocol::Protocol;

use std::sync::Arc;

use super::STREAM_BUF_SIZE;
use super::should_proxy_domain;
use super::tunnel::open_stream_with_retry;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What a read of the `ClientHello` gave.
enum HelloRead {
    /// More bytes arrived.
    More,
    /// The stream ended.
    Ended,
    /// The read failed.
    Failed,
    /// The deadline passed.
    TimedOut,
}

/// Reads more of the `ClientHello`.
///
/// The deadline is the hello's, and it covers the whole hello rather than
/// each read: a peer that dribbles a byte at a time must not hold the
/// connection open by renewing the deadline on every read.
async fn read_more_of_the_hello<S>(
    stream: &mut S,
    data: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> HelloRead
where
    S: AsyncRead + Unpin,
{
    let mut extra = [0u8; 4096];
    match tokio::time::timeout_at(deadline, stream.read(&mut extra)).await {
        Ok(Ok(0)) => HelloRead::Ended,
        Ok(Ok(n)) => {
            data.extend_from_slice(&extra[..n]);
            HelloRead::More
        }
        Ok(Err(_)) => HelloRead::Failed,
        Err(_) => {
            jni_log!(
                "[DEBUG:local-proxy] TLS ClientHello took longer than its deadline, \
                 closing connection"
            );
            HelloRead::TimedOut
        }
    }
}

/// Handle a raw TLS tunnel connection via SNI extraction.
///
/// When a client connects to the VPN's virtual proxy IP on port 443, it sends
/// a TLS ClientHello directly (since it doesn't know there's an HTTP proxy in
/// between). This function extracts the SNI hostname from the ClientHello,
/// establishes an iroh tunnel to the appropriate backend, and forwards raw TCP
/// data bidirectionally — no HTTP parsing involved.
pub(crate) async fn handle_tls_tunnel<S>(
    mut stream: S,
    initial_data: Vec<u8>,
    // The buffer the ClientHello was read into, handed over rather than
    // allocated again: a connection holds two 32 KiB buffers — one per
    // direction of the copy loop — rather than three.
    header_buf: Vec<u8>,
    endpoint_group: Arc<EndpointGroup>,
    proxy_domains: Arc<Vec<String>>,
    // Where the bytes came from; see `handle_local_connection`.
    peer: Option<String>,
) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    jni_log!("[DEBUG:local-proxy] TLS tunnel mode");

    // Ensure we have enough data for the full TLS record (ClientHello)
    // Record header is 5 bytes: content_type(1) + version(2) + length(2)
    //
    // Bounded as a whole rather than per read: the record length is known once
    // the header is in, so this loop's job is to fetch a known number of bytes,
    // and a client that sends the five header bytes and then one byte of record
    // every few seconds would otherwise hold the connection open indefinitely —
    // this read had no bound at all before.
    let mut data = initial_data;
    let hello_deadline =
        tokio::time::Instant::now() + crate::deadline::Deadlines::default().tls_hello;

    // **The record's head first.**
    //
    // The record's length is in its first five bytes, so a hello that has
    // not arrived that far yet cannot be measured — and a first read of one
    // to four bytes used to end the reading there, because the loop that
    // reads the rest was inside the check. The truncated hello was then
    // parsed as if it were the whole one, which is a hello with no name in
    // it, and the session was closed with no retry.
    while data.len() < 5 {
        match read_more_of_the_hello(&mut stream, &mut data, hello_deadline).await {
            HelloRead::More => {}
            HelloRead::Ended | HelloRead::Failed => break,
            HelloRead::TimedOut => return Ok(()),
        }
    }

    if data.len() >= 5 {
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let total_needed = 5 + record_len;
        while data.len() < total_needed {
            match read_more_of_the_hello(&mut stream, &mut data, hello_deadline).await {
                HelloRead::More => {}
                HelloRead::Ended | HelloRead::Failed => break,
                HelloRead::TimedOut => return Ok(()),
            }
        }
    }

    // Extract SNI from TLS ClientHello
    let sni = match nexapipe_proto::tls::extract_sni(&data) {
        Some(sni) => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: extracted SNI '{}'", sni);
            sni
        }
        None => {
            jni_log!("[DEBUG:local-proxy] TLS tunnel: could not extract SNI from ClientHello");
            return Ok(());
        }
    };

    if !should_proxy_domain(&sni, &proxy_domains) {
        jni_log!(
            "[DEBUG:local-proxy] TLS tunnel: SNI '{}' not in proxy domains, closing",
            sni
        );
        return Ok(());
    }

    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: establishing iroh tunnel for '{}'",
        sni
    );

    // Open a fresh iroh bi-stream and forward the initial TLS ClientHello. If
    // the pooled connection is stale, open_bi / write fails and we retry on a
    // fresh connection.
    jni_log!(
        "[DEBUG:local-proxy] TLS tunnel: forwarding initial {} bytes",
        data.len()
    );
    let (pooled_conn, mut send, mut recv) =
        open_stream_with_retry(&endpoint_group, &sni, Some(&data), Protocol::Tls).await?;

    // Same accounting as the HTTP path: the helper already wrote the
    // ClientHello it was handed.
    let flow = pooled_conn.enter_flow(FlowMeta {
        kind: FlowKind::TlsPassthrough,
        target: Some(sni.clone()),
        source: peer.clone(),
    });
    flow.record_sent(data.len() as u64);
    let count_to_backend = flow.counter();
    let count_from_backend = flow.counter();

    let (mut client_read, mut client_write) = tokio::io::split(stream);

    // Bidirectional raw data forwarding (TCP tunnel)
    //
    // The buffer the ClientHello was read into becomes the client half's
    // buffer: a connection holds two of them — one per direction — rather
    // than three.
    let client_to_iroh = async move {
        let mut buf = header_buf;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel client->iroh write error: {}",
                            e
                        );
                        break;
                    }
                    count_to_backend.record_sent(n as u64);
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel client read error: {}", e);
                    break;
                }
            }
        }
    };

    let iroh_to_client = async {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(None) => break,
                Ok(Some(n)) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        jni_log!(
                            "[DEBUG:local-proxy] TLS tunnel iroh->client write error: {}",
                            e
                        );
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        jni_log!("[DEBUG:local-proxy] TLS tunnel flush error: {}", e);
                        break;
                    }
                    count_from_backend.record_received(n as u64);
                }
                Err(e) => {
                    jni_log!("[DEBUG:local-proxy] TLS tunnel backend read error: {}", e);
                    break;
                }
            }
        }
    };

    jni_log!("[DEBUG:local-proxy] TLS tunnel: bidirectional forwarding started");
    tokio::select! {
        _ = client_to_iroh => (),
        _ = iroh_to_client => (),
        _ = flow.cancelled() => (),
    }

    jni_log!("[DEBUG:local-proxy] TLS tunnel closed");
    Ok(())
}
