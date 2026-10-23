use super::client::IpcReadError;
use super::{require_loopback, require_tun_name, require_tun_subnet, ServiceRunner};
use crate::error::codes;
use crate::service::ipc::MAX_IPC_LINE;

/// The interface name reaches a PowerShell script in the service, which runs as
/// LocalSystem. A name that is not a name must never get that far, and a name
/// that is one must still be accepted — the default is "nexa-tun".
#[test]
fn an_interface_name_that_is_not_a_name_is_refused() {
    for accepted in [
        "nexa-tun",
        "nexa_tun",
        "tun.0",
        "TUN-0",
        "a",
        "0",
        &"a".repeat(64),
    ] {
        assert!(
            require_tun_name(accepted).is_ok(),
            "{accepted:?} is a name and must be accepted"
        );
    }

    for refused in [
        "",
        "ne'; whoami #",
        "ne`n",
        "ne$(whoami)",
        "ne; whoami",
        "ne\nmore",
        "ne\r\nmore",
        "ne x",
        "ne/x",
        "-ne",
        ".",
        "..",
        "naïve",
        &"a".repeat(65),
    ] {
        assert!(
            require_tun_name(refused).is_err(),
            "{refused:?} is not a name and must be refused"
        );
    }
}

/// The error has to say what the rule is without repeating the value: the name
/// is caller-supplied text, and a message that quotes it quotes whatever the
/// caller put there.
#[test]
fn a_refused_interface_name_says_the_rule_and_not_the_value() {
    let hostile = "ne'; a-secret";
    let err = require_tun_name(hostile).expect_err("a name with a quote is refused");
    let detail = err.detail.unwrap_or_default();

    assert_eq!(err.code, codes::PROXY_START_FAILED);
    assert!(
        detail.contains("64"),
        "the rule is not in the message: {detail}"
    );
    assert!(
        detail.contains(&format!("{} characters long", hostile.chars().count())),
        "the shape is not in the message: {detail}"
    );
    assert!(
        !detail.contains(hostile) && !detail.contains("a-secret"),
        "the message repeats the value: {detail}"
    );
}

/// A caller that has not authenticated yet must not be able to make this
/// buffer grow, which is the whole reason the reader is capped.
#[tokio::test]
async fn an_oversized_ipc_line_is_refused_without_buffering_it() {
    let hostile = vec![b'x'; MAX_IPC_LINE + 100];
    let mut buf = Vec::new();

    let err = ServiceRunner::read_ipc_line(&mut hostile.as_slice(), &mut buf)
        .await
        .expect_err("a line over the limit is an error");

    assert!(matches!(err, IpcReadError::TooLong(_)), "{err}");
    assert!(
        buf.len() <= MAX_IPC_LINE,
        "the oversized line must never be buffered"
    );
}

/// A caller that takes the challenge and then says nothing must not be able to hold a task
/// and a socket open for as long as it likes: this process runs elevated, so a handful of
/// such connections is enough to leave it answering nobody.
///
/// The clock is paused rather than waited out, so the service's own deadline is what is
/// exercised — and the test finishes when the runtime advances to it, not ten seconds later.
#[tokio::test(start_paused = true)]
async fn a_client_that_never_authenticates_is_dropped() {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    // The transport the IPC really runs over, not a stand-in: the service
    // and the desktop speak over a Unix-domain socket on Unix, and that is
    // the socket whose peer the kernel can name.
    let (mut client, mut server) = crate::service::ipc::connected_pair().await;

    let manager: Arc<tokio::sync::RwLock<Option<Arc<crate::proxy::ProxyManager>>>> =
        Arc::new(tokio::sync::RwLock::new(None));
    let handler =
        tokio::spawn(async move { ServiceRunner::handle_client(&mut server, manager, None).await });

    // The service speaks first. Take the challenge and then send nothing at all.
    let mut challenge = Vec::new();
    BufReader::new(&mut client)
        .read_until(b'\n', &mut challenge)
        .await
        .expect("the challenge is readable");
    assert!(!challenge.is_empty(), "the service opens with a challenge");

    // Nothing more is ever written. The drop has to be a close the caller can see, not a
    // silently abandoned task.
    let mut rest = Vec::new();
    client
        .read_to_end(&mut rest)
        .await
        .expect("a dropped client is closed, not reset");

    handler
        .await
        .expect("the handler ends")
        .expect("dropping an unauthenticated client is not an error");
}

/// The reply has to end the line it is written on: `IpcClient::exchange` reads a *line*, so
/// a response sent without its terminator is one the caller never receives — it sits in the
/// socket buffer while `read_line` waits for a byte that never comes, until the connection
/// dies and the call is reported as `service.io_error` instead of an answer.
#[tokio::test]
async fn a_response_ends_the_line_the_client_is_reading() {
    use crate::service::ipc::IpcResponse;

    let (client, mut server) = crate::service::ipc::connected_pair().await;

    ServiceRunner::write_response(&mut server, &IpcResponse::Ok)
        .await
        .expect("the response is written");

    let mut line = String::new();
    let read =
        tokio::io::AsyncBufReadExt::read_line(&mut tokio::io::BufReader::new(client), &mut line)
            .await
            .expect("the caller reads the reply");

    assert!(
        read > 0,
        "the reply must arrive without waiting for a close"
    );
    assert_eq!(line.trim(), "\"Ok\"");
}

#[tokio::test]
async fn one_line_is_returned_without_its_terminator() {
    let mut input: &[u8] = b"{\"GetStatus\":null}\r\n";
    let mut buf = Vec::new();

    let n = ServiceRunner::read_ipc_line(&mut input, &mut buf)
        .await
        .expect("a complete line reads cleanly");

    assert_eq!(n, buf.len());
    assert_eq!(&buf, b"{\"GetStatus\":null}");
}

#[tokio::test]
async fn a_truncated_line_is_handed_back_at_end_of_stream() {
    let mut input: &[u8] = b"{\"GetStatus\":null}";
    let mut buf = Vec::new();

    let n = ServiceRunner::read_ipc_line(&mut input, &mut buf)
        .await
        .expect("end of stream is not an error");

    assert_eq!(n, buf.len());
}

#[test]
fn loopback_is_the_only_allowed_local_proxy_address() {
    assert!(require_loopback("127.0.0.1:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_ok());
    assert!(require_loopback("[::1]:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_ok());
    assert!(require_loopback("0.0.0.0:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
    assert!(require_loopback("10.0.0.5:8080", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
    assert!(require_loopback("not-an-addr", codes::SERVICE_LOCAL_ADDR_NOT_LOOPBACK).is_err());
}

#[test]
fn the_dns_server_stays_inside_the_tun_network() {
    // The default block (198.18.0.0/24) and the legacy one (10.0.0.0/24) are both
    // candidates — a config saved against the old default keeps working.
    assert!(require_tun_subnet("198.18.0.254:53").is_ok());
    assert!(require_tun_subnet("10.0.0.254:53").is_ok());
    assert!(require_tun_subnet("10.0.0.1:53").is_ok());
    assert!(require_tun_subnet("100.100.0.254:53").is_ok());
    assert!(require_tun_subnet("8.8.8.8:53").is_err());
    assert!(require_tun_subnet("127.0.0.1:53").is_err());
    assert!(require_tun_subnet("10.0.1.1:53").is_err());
    assert!(require_tun_subnet("198.19.1.1:53").is_err());
    assert!(require_tun_subnet("[::1]:53").is_err());
}
