//! Criterion benchmarks for peer route synchronization
//!
//! Measures PeerRouteIndex performance at scale:
//! - Index build cost (paid once when route table changes)
//! - Per-heartbeat hash check (O(clusters), the fast path)
//! - Multi-child heartbeat wave (build once, N hash checks)
//! - Extreme scale: up to 1M routes from 10K clusters

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use lattice_cell::peer_routes::PeerRouteIndex;
use lattice_cell::route_reconciler::TaggedRoute;
use lattice_crd::crd::ClusterRoute;

// =============================================================================
// Fixtures
// =============================================================================

/// Generate N routes spread across `num_clusters` clusters.
fn generate_tagged_routes(num_routes: usize, num_clusters: usize) -> Vec<TaggedRoute> {
    let mut routes = Vec::with_capacity(num_routes);
    for i in 0..num_routes {
        let cluster_idx = i % num_clusters;
        let svc_idx = i / num_clusters;
        let cluster = format!("cluster-{}", cluster_idx);

        routes.push((
            cluster,
            ClusterRoute {
                service_name: format!("svc-{}", svc_idx),
                service_namespace: format!("ns-{}", svc_idx % 20),
                hostname: format!("svc-{}.cluster-{}.example.com", svc_idx, cluster_idx),
                address: format!(
                    "10.{}.{}.{}",
                    cluster_idx % 256,
                    svc_idx / 256,
                    svc_idx % 256
                ),
                port: 443,
                protocol: "HTTPS".to_string(),
                allowed_services: vec![
                    format!("cluster-{}/*/gateway", (cluster_idx + 1) % num_clusters),
                    format!("cluster-{}/prod/api", (cluster_idx + 2) % num_clusters),
                    "*".to_string(),
                ],
                service_ports: BTreeMap::from([
                    ("http".to_string(), 8080),
                    ("grpc".to_string(), 9090),
                    ("metrics".to_string(), 9100),
                ]),
            },
        ));
    }
    routes
}

// =============================================================================
// Benchmarks: Index build (paid once when route table changes)
// =============================================================================

fn bench_index_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_build");
    group.sample_size(10);

    for (num_routes, num_clusters) in [
        (1_000, 20),
        (10_000, 100),
        (100_000, 1_000),
        (500_000, 5_000),
        (1_000_000, 10_000),
    ] {
        let tagged = generate_tagged_routes(num_routes, num_clusters);

        group.bench_with_input(
            BenchmarkId::new("build", format!("{}r_{}c", num_routes, num_clusters)),
            &(),
            |b, _| {
                b.iter(|| {
                    black_box(PeerRouteIndex::build(&tagged));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Per-heartbeat hash check (O(clusters))
// =============================================================================

fn bench_heartbeat_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_heartbeat");
    group.sample_size(10);

    for (num_routes, num_clusters) in [
        (1_000, 20),
        (10_000, 100),
        (100_000, 1_000),
        (500_000, 5_000),
        (1_000_000, 10_000),
    ] {
        let tagged = generate_tagged_routes(num_routes, num_clusters);
        let index = PeerRouteIndex::build(&tagged);

        group.bench_with_input(
            BenchmarkId::new(
                "hash_excluding",
                format!("{}r_{}c", num_routes, num_clusters),
            ),
            &(),
            |b, _| {
                b.iter(|| {
                    black_box(index.hash_excluding("cluster-0"));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Multi-child heartbeat wave
//
// Build index once, then N children each do a hash check.
// This is the realistic hot path after a route table change.
// =============================================================================

fn bench_multi_child(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_wave");
    group.sample_size(10);

    for (num_routes, num_clusters, num_children) in [
        (5_000, 50, 50),
        (25_000, 200, 200),
        (100_000, 500, 500),
        (500_000, 1_000, 1_000),
    ] {
        let tagged = generate_tagged_routes(num_routes, num_clusters);

        group.bench_with_input(
            BenchmarkId::new(
                "build_plus_heartbeats",
                format!("{}r_{}children", num_routes, num_children),
            ),
            &(),
            |b, _| {
                b.iter(|| {
                    let index = PeerRouteIndex::build(&tagged);
                    for child_idx in 0..num_children {
                        let child_name = format!("cluster-{}", child_idx);
                        black_box(index.hash_excluding(&child_name));
                    }
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Extreme scale — 1M routes
// =============================================================================

fn bench_extreme(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_extreme");
    group.sample_size(10);

    let tagged_1m = generate_tagged_routes(1_000_000, 10_000);

    // Build cost at 1M
    group.bench_function("build_1m", |b| {
        b.iter(|| {
            black_box(PeerRouteIndex::build(&tagged_1m));
        });
    });

    // Single heartbeat at 1M (after build)
    let index_1m = PeerRouteIndex::build(&tagged_1m);

    group.bench_function("heartbeat_1m", |b| {
        b.iter(|| {
            black_box(index_1m.hash_excluding("cluster-0"));
        });
    });

    // 100 children at 1M (heartbeats only, index pre-built)
    group.bench_function("100_heartbeats_1m", |b| {
        b.iter(|| {
            for child_idx in 0..100 {
                let child_name = format!("cluster-{}", child_idx);
                black_box(index_1m.hash_excluding(&child_name));
            }
        });
    });

    // Peer routes payload build on mismatch (the slow path)
    group.bench_function("peer_routes_for_1m", |b| {
        b.iter(|| {
            black_box(index_1m.peer_routes_for("cluster-0"));
        });
    });

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_index_build,
    bench_heartbeat_hash,
    bench_multi_child,
    bench_extreme,
);
criterion_main!(benches);
