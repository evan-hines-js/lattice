//! Criterion benchmarks for ServiceCompiler::compile()
//!
//! Measures end-to-end compilation performance across service configurations,
//! scaled to find the ceiling for a 5000-node K8s cluster (10K–50K services).
//!
//! Benchmark groups:
//! - Baseline: minimal service
//! - With mesh: service dependencies and bilateral agreements at scale
//! - With secrets: secret resources with Cedar permit-all policy at scale
//! - With ingress: Gateway API resources
//! - Full: all features combined at extreme scale
//! - Wave: compile N services sequentially (reconciliation burst)

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use lattice_cedar::PolicyEngine;
use lattice_crd::crd::{
    CertIssuerRef, ContainerSpec, DependencyDirection, IngressSpec, IngressTls, LatticeService,
    LatticeServiceSpec, MonitoringConfig, PortSpec, ProviderType, ResourceParams, ResourceSpec,
    ResourceType, RouteKind, RouteSpec, SecretParams, ServicePortsSpec, WorkloadSpec,
};
use lattice_graph::ServiceGraph;
use lattice_service::compiler::ServiceCompiler;

// =============================================================================
// Fixtures
// =============================================================================

fn simple_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:latest".to_string(),
        command: Some(vec!["/usr/sbin/nginx".to_string()]),
        ..Default::default()
    }
}

fn default_ports() -> ServicePortsSpec {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );
    ServicePortsSpec { ports }
}

fn make_service(name: &str, namespace: &str, spec: LatticeServiceSpec) -> LatticeService {
    LatticeService {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

fn baseline_spec() -> LatticeServiceSpec {
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), simple_container());

    LatticeServiceSpec {
        workload: WorkloadSpec {
            containers,
            service: Some(default_ports()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn mesh_spec(num_deps: usize, num_callers: usize) -> LatticeServiceSpec {
    let mut spec = baseline_spec();

    for i in 0..num_deps {
        spec.workload.resources.insert(
            format!("dep-{}", i),
            ResourceSpec {
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
    }
    for i in 0..num_callers {
        spec.workload.resources.insert(
            format!("caller-{}", i),
            ResourceSpec {
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );
    }

    spec
}

fn secrets_spec(num_secrets: usize, keys_per_secret: usize) -> LatticeServiceSpec {
    let mut spec = baseline_spec();

    for i in 0..num_secrets {
        let keys = if keys_per_secret > 0 {
            Some((0..keys_per_secret).map(|k| format!("key-{}", k)).collect())
        } else {
            None
        };

        spec.workload.resources.insert(
            format!("secret-{}", i),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(format!("path/to/secret-{}", i)),
                params: ResourceParams::Secret(SecretParams {
                    provider: "vault-prod".to_string(),
                    keys,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }

    spec
}

fn ingress_spec() -> LatticeServiceSpec {
    let mut spec = baseline_spec();
    spec.ingress = Some(IngressSpec {
        gateway_class: None,
        routes: BTreeMap::from([(
            "public".to_string(),
            RouteSpec {
                kind: RouteKind::HTTPRoute,
                hosts: vec!["api.example.com".to_string()],
                port: None,
                listen_port: None,
                rules: None,
                tls: Some(IngressTls {
                    secret_name: None,
                    issuer_ref: Some(CertIssuerRef {
                        name: "letsencrypt-prod".to_string(),
                        kind: None,
                    }),
                }),
                advertise: None,
            },
        )]),
    });
    spec
}

fn full_spec(num_deps: usize, num_callers: usize, num_secrets: usize) -> LatticeServiceSpec {
    let mut spec = mesh_spec(num_deps, num_callers);

    for i in 0..num_secrets {
        spec.workload.resources.insert(
            format!("secret-{}", i),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(format!("path/to/secret-{}", i)),
                params: ResourceParams::Secret(SecretParams {
                    provider: "vault-prod".to_string(),
                    keys: Some((0..3).map(|k| format!("key-{}", k)).collect()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }

    spec.ingress = Some(IngressSpec {
        gateway_class: None,
        routes: BTreeMap::from([(
            "public".to_string(),
            RouteSpec {
                kind: RouteKind::HTTPRoute,
                hosts: vec!["api.example.com".to_string()],
                port: None,
                listen_port: None,
                rules: None,
                tls: Some(IngressTls {
                    secret_name: None,
                    issuer_ref: Some(CertIssuerRef {
                        name: "letsencrypt-prod".to_string(),
                        kind: None,
                    }),
                }),
                advertise: None,
            },
        )]),
    });

    spec
}

/// Populate the service graph with bilateral agreements for a target service
fn setup_graph(graph: &ServiceGraph, namespace: &str, spec: &LatticeServiceSpec) {
    graph.put_service(namespace, "target", spec);

    for (name, res) in &spec.workload.resources {
        if res.type_ == ResourceType::Service && res.direction.is_outbound() {
            let mut dep = baseline_spec();
            dep.workload.resources.insert(
                "target".to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
            graph.put_service(namespace, name, &dep);
        }
        if res.type_ == ResourceType::Service && res.direction.is_inbound() {
            let mut caller = baseline_spec();
            caller.workload.resources.insert(
                "target".to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
            graph.put_service(namespace, name, &caller);
        }
    }
}

/// Populate the graph with N background services + bilateral agreements for target.
/// Simulates compiling one service in a graph of N total services.
fn setup_graph_with_background(
    graph: &ServiceGraph,
    namespace: &str,
    target_spec: &LatticeServiceSpec,
    background_count: usize,
) {
    // Register background services (they just exist in the graph)
    for i in 0..background_count {
        let bg_spec = baseline_spec();
        graph.put_service(namespace, &format!("bg-svc-{}", i), &bg_spec);
    }

    // Register the target and its bilateral agreements
    setup_graph(graph, namespace, target_spec);
}

fn cedar_permit_all_secrets() -> PolicyEngine {
    PolicyEngine::with_policies(
        r#"permit(
            principal,
            action == Lattice::Action::"AccessSecret",
            resource
        );"#,
    )
    .expect("valid cedar policy")
}

// =============================================================================
// Benchmarks: Existing (preserved with original scale)
// =============================================================================

fn bench_baseline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_baseline");

    let graph = ServiceGraph::new("lattice.test");
    let cedar = PolicyEngine::new();
    let spec = baseline_spec();
    graph.put_service("default", "target", &spec);
    let service = make_service("target", "default", spec);
    let compiler = ServiceCompiler::new(
        &graph,
        "bench-cluster",
        ProviderType::Docker,
        &cedar,
        MonitoringConfig::default(),
    );

    group.bench_function("minimal", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(compiler.compile(&service).await.unwrap());
            });
        });
    });

    group.finish();
}

fn bench_mesh(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_mesh");

    for (deps, callers) in [(2, 2), (5, 5), (10, 10), (20, 10), (50, 50), (100, 100), (200, 100)] {
        let graph = ServiceGraph::new("lattice.test");
        let cedar = PolicyEngine::new();
        let spec = mesh_spec(deps, callers);
        setup_graph(&graph, "default", &spec);
        let service = make_service("target", "default", spec);
        let compiler = ServiceCompiler::new(
            &graph,
            "bench-cluster",
            ProviderType::Docker,
            &cedar,
            MonitoringConfig::default(),
        );

        group.bench_with_input(
            BenchmarkId::new("deps_callers", format!("{}d_{}c", deps, callers)),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_secrets(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_secrets");

    for (num_secrets, keys) in [(1, 3), (5, 3), (10, 5), (25, 5), (50, 10), (100, 10)] {
        let graph = ServiceGraph::new("lattice.test");
        let cedar = cedar_permit_all_secrets();
        let spec = secrets_spec(num_secrets, keys);
        graph.put_service("default", "target", &spec);
        let service = make_service("target", "default", spec);
        let compiler = ServiceCompiler::new(
            &graph,
            "bench-cluster",
            ProviderType::Docker,
            &cedar,
            MonitoringConfig::default(),
        );

        group.bench_with_input(
            BenchmarkId::new("count_keys", format!("{}s_{}k", num_secrets, keys)),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_ingress(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_ingress");

    let graph = ServiceGraph::new("lattice.test");
    let cedar = PolicyEngine::new();
    let spec = ingress_spec();
    graph.put_service("default", "target", &spec);
    let service = make_service("target", "default", spec);
    let compiler = ServiceCompiler::new(
        &graph,
        "bench-cluster",
        ProviderType::Docker,
        &cedar,
        MonitoringConfig::default(),
    );

    group.bench_function("with_tls", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(compiler.compile(&service).await.unwrap());
            });
        });
    });

    group.finish();
}

fn bench_full(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_full");

    for (deps, callers, secrets) in [
        (5, 5, 3),
        (10, 10, 5),
        (20, 10, 10),
        (50, 50, 25),
        (100, 100, 50),
        (200, 100, 100),
    ] {
        let graph = ServiceGraph::new("lattice.test");
        let cedar = cedar_permit_all_secrets();
        let spec = full_spec(deps, callers, secrets);
        setup_graph(&graph, "default", &spec);
        let service = make_service("target", "default", spec);
        let compiler = ServiceCompiler::new(
            &graph,
            "bench-cluster",
            ProviderType::Docker,
            &cedar,
            MonitoringConfig::default(),
        );

        group.bench_with_input(
            BenchmarkId::new("full", format!("{}d_{}c_{}s", deps, callers, secrets)),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Compile in a large graph (5000-node cluster territory)
//
// The service being compiled has a fixed spec, but the graph it sits in
// has thousands of other services. This measures whether graph size affects
// compile time (it shouldn't for explicit edges, but will for depends_all).
// =============================================================================

fn bench_compile_in_large_graph(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_large_graph");
    group.sample_size(10);

    for bg_count in [100, 1_000, 5_000, 10_000, 25_000] {
        let graph = ServiceGraph::new("lattice.test");
        let cedar = cedar_permit_all_secrets();
        let spec = full_spec(10, 10, 5);
        setup_graph_with_background(&graph, "default", &spec, bg_count);
        let service = make_service("target", "default", spec);
        let compiler = ServiceCompiler::new(
            &graph,
            "bench-cluster",
            ProviderType::Docker,
            &cedar,
            MonitoringConfig::default(),
        );

        group.bench_with_input(
            BenchmarkId::new("bg_services", bg_count),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Reconciliation wave — compile N services sequentially
//
// Simulates a controller restart where every service gets recompiled.
// Each service is independent with its own bilateral agreements.
// =============================================================================

fn bench_compile_wave(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_wave");
    group.sample_size(10);

    for wave_size in [10, 50, 100, 500] {
        let graph = ServiceGraph::new("lattice.test");
        let cedar = cedar_permit_all_secrets();

        // Register wave_size independent services, each with 5 deps + 3 secrets
        let mut services = Vec::with_capacity(wave_size);
        for i in 0..wave_size {
            let name = format!("svc-{}", i);
            let spec = full_spec(5, 5, 3);
            // Register target + its bilateral agreements under unique names
            graph.put_service("default", &name, &spec);
            for (dep_name, res) in &spec.workload.resources {
                if res.type_ == ResourceType::Service && res.direction.is_outbound() {
                    let mut dep = baseline_spec();
                    dep.workload.resources.insert(
                        name.clone(),
                        ResourceSpec {
                            direction: DependencyDirection::Inbound,
                            ..Default::default()
                        },
                    );
                    graph.put_service("default", dep_name, &dep);
                }
            }
            services.push(make_service(&name, "default", spec));
        }

        let compiler = ServiceCompiler::new(
            &graph,
            "bench-cluster",
            ProviderType::Docker,
            &cedar,
            MonitoringConfig::default(),
        );

        group.bench_with_input(
            BenchmarkId::new("services", wave_size),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        for svc in &services {
                            black_box(compiler.compile(svc).await.unwrap());
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_baseline,
    bench_mesh,
    bench_secrets,
    bench_ingress,
    bench_full,
    bench_compile_in_large_graph,
    bench_compile_wave,
);
criterion_main!(benches);
