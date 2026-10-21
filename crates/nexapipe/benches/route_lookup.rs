//! The routing table's lookup: which route serves this request.
//!
//! Every request asks the table, and the table walks its routes until one
//! matches. What the walk costs is the per-route match; what taking the route
//! it found costs is the copy that used to come with it — the route was
//! copied out of the table, four or five allocations, and thrown away as soon
//! as the backend was picked.
//!
//! The table is built once and the lookup is the public one a request makes.
//! The backends are never dialled: the bench measures the lookup, and the
//! health state it reads is the same in every run.
//!
//! See `docs/benchmarks.md` for how to run this and what the numbers mean.

use criterion::{Criterion, criterion_group, criterion_main};
use nexapipe::config::RouteMode;
use nexapipe::lb::LoadBalancingStrategy;
use nexapipe::routes::{Route, RoutingTable};
use std::hint::black_box;
use std::time::Instant;

/// How many routes the table holds.
///
/// A table is one route per host a proxy serves, and the walk goes over all
/// of them until one matches. Fifty is the shape worth measuring.
const ROUTES: usize = 50;

/// The host the request asks for: the one the last route serves, so the walk
/// goes over the whole table.
const HOST: &str = "target.test";

/// The path the request asks for.
const PATH: &str = "/api/v1/things";

/// A table of routes, the one that matches last.
fn table() -> RoutingTable {
    let mut routes: Vec<Route> = (0..ROUTES)
        .map(|i| {
            Route::new(
                &format!("site{i}.test"),
                "/*",
                true,
                vec!["http://127.0.0.1:1".to_string()],
                LoadBalancingStrategy::RoundRobin,
                RouteMode::Http,
                None,
            )
        })
        .collect();
    routes.push(Route::new(
        HOST,
        "/*",
        true,
        vec!["http://127.0.0.1:1".to_string()],
        LoadBalancingStrategy::RoundRobin,
        RouteMode::Http,
        None,
    ));
    RoutingTable::new(routes)
}

fn route_lookup(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("a benchmark runtime");

    let mut group = c.benchmark_group("route_lookup");

    group.bench_function("a_matching_host", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                // The table is built before the clock starts: what is measured
                // is the lookup, not the making of the table.
                let table = table();

                let start = Instant::now();
                for _ in 0..iters {
                    black_box(table.get_backend_with_acl(HOST, PATH, None, None).await);
                }
                start.elapsed()
            })
        })
    });

    group.bench_function("a_host_nothing_serves", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async move {
                let table = table();

                let start = Instant::now();
                for _ in 0..iters {
                    black_box(
                        table
                            .get_backend_with_acl("nowhere.test", PATH, None, None)
                            .await,
                    );
                }
                start.elapsed()
            })
        })
    });

    group.finish();
}

criterion_group!(benches, route_lookup);
criterion_main!(benches);
