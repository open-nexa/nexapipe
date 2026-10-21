//! The client asking "is this name one of mine?".
//!
//! The question is asked for every `CONNECT` the local proxy accepts and for
//! every DNS query the TUN hijacks, and the answer walks the whole list of
//! names the client was given. It is the one place in the client where a
//! long list of patterns is paid for on every request.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use nexapipe_client::should_proxy_domain;
use std::hint::black_box;
use std::time::Instant;

/// How many names a client is given.
///
/// The list a client is configured with is a handful of domains for most
/// people and a long list for a proxy that serves a lot of sites. Fifty is
/// the shape worth measuring: a list long enough that the walk is the work.
const PATTERNS: usize = 50;

/// The name the question is asked about: one that is in the list, so the
/// answer costs a full walk.
const HOST: &str = "api.example.com";

/// The patterns, as a client is configured with them.
fn patterns() -> Vec<String> {
    (0..PATTERNS)
        .map(|i| format!("site{i}.example.net"))
        .chain(std::iter::once(HOST.to_string()))
        .collect()
}

fn domain_match(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("domain_match");

    group.bench_function("in_the_list", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                // The list is made before the clock starts: what is measured is
                // the walk over it, not the making of it.
                let patterns = patterns();

                let start = Instant::now();
                for _ in 0..iters {
                    black_box(should_proxy_domain(HOST, &patterns));
                }
                start.elapsed()
            })
        })
    });

    group.bench_function("not_in_the_list", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let patterns = patterns();

                let start = Instant::now();
                for _ in 0..iters {
                    black_box(should_proxy_domain("nowhere.example.org", &patterns));
                }
                start.elapsed()
            })
        })
    });

    group.finish();
}

criterion_group!(benches, domain_match);
criterion_main!(benches);
