//! Criterion benchmarks for peer route synchronization
//!
//! Measures the peer route sync pipeline at scale, comparing the legacy
//! approach (recompute everything per heartbeat) vs the indexed approach
//! (pre-compute on route change, O(clusters) per heartbeat).
//!
//! Benchmark groups:
//! - Legacy full pipeline (convert → filter → hash) — the old O(routes) path
//! - Index build cost — paid once when route table changes
//! - Indexed heartbeat — the fast O(clusters) path
//! - Multi-child: N children processing heartbeats against same index
//! - Extreme scale: up to 1M routes

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use lattice_crd::crd::ClusterRoute;
use lattice_cell::peer_routes::{
    hash_peer_routes, peer_routes_for, tagged_to_proto, PeerRouteIndex,
};
use lattice_cell::route_reconciler::TaggedRoute;

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
                address: format!("10.{}.{}.{}", cluster_idx % 256, svc_idx / 256, svc_idx % 256),
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
// Benchmarks: Legacy pipeline (old approach — O(routes) per heartbeat)
// =============================================================================

fn bench_legacy_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_legacy");
    group.sample_size(10);

    for (num_routes, num_clusters) in [
        (1_000, 20),
        (10_000, 100),
        (100_000, 1_000),
        (1_000_000, 10_000),
    ] {
        let tagged = generate_tagged_routes(num_routes, num_clusters);

        group.bench_with_input(
            BenchmarkId::new("pipeline", format!("{}r_{}c", num_routes, num_clusters)),
            &(),
            |b, _| {
                b.iter(|| {
                    let proto = tagged_to_proto(&tagged);
                    let peers = peer_routes_for(&proto, "cluster-0");
                    black_box(hash_peer_routes(&peers));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Index build (paid once when route table changes)
// =============================================================================

fn bench_index_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_index_build");
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
// Benchmarks: Indexed heartbeat (O(clusters) per heartbeat)
// =============================================================================

fn bench_indexed_heartbeat(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_indexed_heartbeat");
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

        // Hash check only (the common fast path — no mismatch)
        group.bench_with_input(
            BenchmarkId::new("hash_check", format!("{}r_{}c", num_routes, num_clusters)),
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
// Benchmarks: Multi-child heartbeat wave — the key comparison
//
// Legacy: each child does convert + filter + hash over ALL routes
// Indexed: build index once, each child just combines per-cluster hashes
// =============================================================================

fn bench_multi_child(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_multi_child");
    group.sample_size(10);

    for (num_routes, num_clusters, num_children) in [
        (5_000, 50, 50),
        (25_000, 200, 200),
        (100_000, 500, 500),
        (500_000, 1_000, 1_000),
    ] {
        let tagged = generate_tagged_routes(num_routes, num_clusters);

        // Legacy: O(children × routes)
        group.bench_with_input(
            BenchmarkId::new(
                "legacy",
                format!("{}r_{}children", num_routes, num_children),
            ),
            &(),
            |b, _| {
                b.iter(|| {
                    let proto = tagged_to_proto(&tagged);
                    for child_idx in 0..num_children {
                        let child_name = format!("cluster-{}", child_idx);
                        let peers = peer_routes_for(&proto, &child_name);
                        black_box(hash_peer_routes(&peers));
                    }
                });
            },
        );

        // Indexed: O(routes) build + O(children × clusters) heartbeats
        group.bench_with_input(
            BenchmarkId::new(
                "indexed",
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
// Benchmarks: Extreme scale — head-to-head at 1M routes
// =============================================================================

fn bench_extreme(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_route_extreme");
    group.sample_size(10);

    let tagged_1m = generate_tagged_routes(1_000_000, 10_000);

    // Legacy: single child at 1M
    group.bench_function("legacy_1m_single", |b| {
        b.iter(|| {
            let proto = tagged_to_proto(&tagged_1m);
            let peers = peer_routes_for(&proto, "cluster-0");
            black_box(hash_peer_routes(&peers));
        });
    });

    // Indexed: build at 1M
    group.bench_function("indexed_1m_build", |b| {
        b.iter(|| {
            black_box(PeerRouteIndex::build(&tagged_1m));
        });
    });

    // Indexed: heartbeat at 1M (after build)
    let index_1m = PeerRouteIndex::build(&tagged_1m);
    group.bench_function("indexed_1m_heartbeat", |b| {
        b.iter(|| {
            black_box(index_1m.hash_excluding("cluster-0"));
        });
    });

    // Indexed: 100 children at 1M
    group.bench_function("indexed_1m_100children", |b| {
        b.iter(|| {
            for child_idx in 0..100 {
                let child_name = format!("cluster-{}", child_idx);
                black_box(index_1m.hash_excluding(&child_name));
            }
        });
    });

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_legacy_pipeline,
    bench_index_build,
    bench_indexed_heartbeat,
    bench_multi_child,
    bench_extreme,
);
criterion_main!(benches);
