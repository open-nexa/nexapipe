//! The request handling: what a request on the plaintext listener is answered
//! with.

use crate::http;
use crate::http::BackendClients;
use crate::log;
use crate::routes::RoutingTable;
use hyper::body::Incoming;
use std::sync::Arc;

use super::access::{response_has_body, with_request_id};

pub(super) async fn proxy_handler(
    req: hyper::Request<Incoming>,
    config: Arc<RoutingTable>,
    clients: Arc<BackendClients>,
    remote_addr: String,
    request_id: String,
) -> Result<hyper::Response<http::ProxyBody>, anyhow::Error> {
    let start = std::time::Instant::now();
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    // Filled in on the span the caller opened around this handler, which was
    // created before the request was read and so could not know these.
    let span = tracing::Span::current();
    crate::log::record_request_on_span(&span, &method, &uri);

    // A request that names more than one host has two destinations, and the
    // two halves of this proxy would resolve them differently: the route and
    // the access check read the first one, and the backend is handed all of
    // them. hyper accepts two `Host` headers and passes them both on, so
    // this is the only place the plaintext listener can catch it.
    //
    // RFC 9110 §7.2 asks for a 400, and that is what this is.
    if http::names_more_than_one_host(req.headers()) {
        tracing::warn!(
            "Refusing a request from {} that carries more than one Host header",
            remote_addr
        );
        span.record("status", 400u64);
        let duration = start.elapsed();
        crate::metrics::METRICS.record_request(
            hyper::StatusCode::BAD_REQUEST.as_u16(),
            duration.as_millis() as u64,
        );
        // The refusal is a line in the access log, the way every other answer
        // this handler gives is. A request that was turned away is exactly the
        // line an operator goes looking for, and the tunnel path already logs
        // its own 400 for the same request; leaving this one out of the log
        // would make the same client's probe visible on one listener and
        // invisible on the other.
        log::log_access(
            &request_id,
            &remote_addr,
            &method,
            &uri,
            hyper::StatusCode::BAD_REQUEST.as_u16(),
            duration.as_millis() as u64,
            0,
            // No handshake on this listener, so no identity to name.
            None,
        );
        return Ok(with_request_id(
            http::create_error_response(
                hyper::StatusCode::BAD_REQUEST,
                "a request may carry only one Host header",
            ),
            &request_id,
        ));
    }

    if http::is_websocket_request(&req) {
        tracing::debug!("WebSocket request detected");
        span.record("status", 426u64);
        return Ok(with_request_id(
            http::create_error_response(
                hyper::StatusCode::UPGRADE_REQUIRED,
                "WebSocket not supported via HTTP server",
            ),
            &request_id,
        ));
    }

    let response = match http::proxy_request(&clients, req, config.clone()).await {
        Ok(resp) => resp,
        Err(e) => {
            // The detail goes to the log, not to the client: `e` is an
            // internal one — a backend URL that would not parse, the address
            // of the backend that did not answer — and a proxy sitting in
            // front of a private network is not the place to publish those.
            tracing::error!("Proxy request failed: {}", e);
            let duration = start.elapsed();
            // Recorded where the answer is decided, not inside `log_access`:
            // the L4 path calls that too, and what it counts there is a flow,
            // not a request.
            crate::metrics::METRICS.record_request(
                hyper::StatusCode::BAD_GATEWAY.as_u16(),
                duration.as_millis() as u64,
            );
            span.record("status", 502u64);
            log::log_access(
                &request_id,
                &remote_addr,
                &method,
                &uri,
                hyper::StatusCode::BAD_GATEWAY.as_u16(),
                duration.as_millis() as u64,
                0,
                // The plaintext listener does not authenticate: no 2FA runs
                // here, so there is no client and no device to name.
                None,
            );
            return Ok(with_request_id(
                http::create_error_response(hyper::StatusCode::BAD_GATEWAY, "Bad Gateway"),
                &request_id,
            ));
        }
    };

    let duration = start.elapsed();
    let status = response.status().as_u16();
    crate::metrics::METRICS.record_request(status, duration.as_millis() as u64);
    span.record("status", status as u64);
    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    // Two different claims below, and deliberately so.
    //
    // `log_access` prints what the header says, because that is what it has
    // always printed and people parse that field. The metric counts what this
    // listener actually put on the wire. For most responses those are the same
    // number — which is why taking both from here was worth doing — but a HEAD,
    // a 1xx, a 204 and a 304 describe a representation without sending one, and
    // every one of them keeps `Content-Length` while doing it (RFC 9110 s6.4.1,
    // s8.3). Counting those bytes would say NexaPipe served something it never
    // wrote, which is worse than the two disagreeing.
    let delivered = if response_has_body(&method, status) {
        content_length
    } else {
        0
    };
    crate::metrics::METRICS.record_bytes_sent(delivered as u64);

    log::log_access(
        &request_id,
        &remote_addr,
        &method,
        &uri,
        status,
        duration.as_millis() as u64,
        content_length,
        // No handshake on this listener, so no identity: the line the same
        // request would get on the authenticated one carries the two fields
        // this one cannot answer.
        None,
    );

    Ok(with_request_id(response, &request_id))
}
