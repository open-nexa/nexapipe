//! The retry loop: one request, asked of one backend after another.
//!
//! A failure that says the backend is unreachable counts against it, and the
//! next backend is somebody else's — the one that just failed is the one most
//! likely to fail again.

use std::sync::Arc;

use hyper::Method;
use hyper::Request;

use super::Context;
use super::body::RequestBody;
use crate::http::forward::Answer;
use crate::routes::{BackendInfo, BackendLookup};

/// The retry loop, and the answer it produced.
#[allow(clippy::too_many_arguments)]
pub(in crate::http) async fn forward(
    ctx: &Arc<Context>,
    request: &Request<()>,
    request_target: &str,
    method: &Method,
    host: Option<(&str, Option<u16>)>,
    path: &str,
    backend_info: BackendInfo,
    body: &RequestBody,
    started: std::time::Instant,
) -> Result<Answer, crate::http::body::ProxyFailure> {
    let attempts = ctx.config.retry().attempts;
    let backoff = ctx.config.retry().backoff;
    // The backends that already failed this request. A retry asks somebody
    // else, because the one that just failed is the one most likely to fail
    // again.
    let mut tried: Vec<String> = Vec::new();
    let mut attempt = 0u32;
    let mut backend = backend_info;

    loop {
        let result = crate::http::forward::proxy_to_backend(
            &ctx.clients,
            ctx.config.timeouts(),
            request,
            &backend,
            body,
            &ctx.request_id,
        )
        .await;

        let failure = match result {
            Ok(answer) => {
                // The backend answered, so it is up: the circuit is told, and a
                // backend that was out of rotation comes back into it.
                backend.report_success();
                let status = answer.status().as_u16();
                crate::metrics::METRICS
                    .record_request(status, started.elapsed().as_millis() as u64);
                // **The lease moves out of the backend info and into the
                // answer's body.** The work against that backend is not over
                // when the response head arrives: a body that is still
                // streaming is a backend that is still busy, and the balancer
                // counts a backend as busy until the flow releases its lease.
                // The backend info is dropped when this function returns, so a
                // lease left in it would be released with the head — and
                // `least_conn` would see an idle backend while it was still
                // working. The plaintext path has always kept the lease with
                // the body; see `LeasedBody`.
                let lease = backend.take_lease();
                // The access line is written by the answer's body, when the
                // answer is over: the bytes it reports are the bytes that
                // reached the client, and they are not known until then.
                return Ok(answer.with_lease(lease).with_report(
                    crate::http::server::AccessReport {
                        request_id: ctx.request_id.clone(),
                        // The span of the request being answered: the line is
                        // written when the body is over, and it belongs to
                        // this request rather than to the stream.
                        span: tracing::Span::current(),
                        peer: ctx.peer.clone(),
                        method: method.as_str().to_string(),
                        request_target: request_target.to_string(),
                        status,
                        started,
                        who: ctx.who.clone(),
                    },
                ));
            }
            Err(failure) => failure,
        };

        // Only a failure that says the backend is unreachable counts against
        // it. A response that broke halfway is a different thing: the backend
        // did answer.
        if failure.backend_is_down() {
            backend.report_failure();
        }

        // Two questions, and the failure answers both: may this be tried
        // again at all, and is there another backend to try it on.
        if attempt >= attempts || !failure.retry.may_retry(method) {
            return Err(failure);
        }

        // A body that has been **read** is gone: its bytes came off the
        // client's stream and there is no second copy of them, so the request
        // cannot be tried again.
        if !body.may_retry() {
            return Err(crate::http::body::ProxyFailure::from(anyhow::anyhow!(
                "the request has a body that cannot be read a second time, so it is not tried \
                 again: {}",
                failure.error
            )));
        }

        attempt += 1;

        tracing::warn!(
            "Request to {} failed ({}); trying another backend ({attempt}/{attempts})",
            backend.url,
            failure.error,
        );

        tried.push(backend.url.to_string());
        let next = match host {
            Some((h, port)) => {
                ctx.config
                    .get_backend_with_acl_excluding(h, path, port, ctx.acl.as_deref(), &tried)
                    .await
            }
            None => BackendLookup::NoRoute,
        };
        match next.backend() {
            Some(info) => backend = info,
            // Nobody else to ask. The failure is the answer: the pool being
            // empty is a consequence of it, not a new fact.
            None => return Err(failure),
        }

        if !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
    }
}
