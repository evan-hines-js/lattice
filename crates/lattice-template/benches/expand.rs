//! Criterion benchmarks for template expansion
//!
//! Measures end-to-end expand() performance across realistic template shapes,
//! scaled to find the ceiling for a 5000-node K8s cluster (10K–50K services).
//!
//! Benchmark groups:
//! - Helm values expansion at increasing scale
//! - Secret-heavy templates (Collect, ESO, Resolve modes)
//! - $secret directive processing
//! - No-op fast path (plain values, no templates)
//! - Extreme scale: what a reconciliation wave looks like at 10K–50K services

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::{json, Value};

use lattice_template::{expand, ExpandOptions, SecretMode, TemplateContext};

// =============================================================================
// Fixtures
// =============================================================================

fn collect_opts() -> ExpandOptions {
    ExpandOptions {
        secret_mode: SecretMode::Collect,
        name_prefix: "bench-svc".into(),
    }
}

fn eso_opts() -> ExpandOptions {
    ExpandOptions {
        secret_mode: SecretMode::EsoTemplate,
        name_prefix: "bench-svc".into(),
    }
}

fn resolve_opts(secrets: BTreeMap<String, BTreeMap<String, String>>) -> ExpandOptions {
    ExpandOptions {
        secret_mode: SecretMode::Resolve(secrets),
        name_prefix: "bench-svc".into(),
    }
}

/// Context with N resources, each with 3 outputs (host, port, name).
/// At extreme scale this simulates a service that can reference many
/// other services' outputs in its templates.
fn rich_context(num_resources: usize) -> TemplateContext {
    let mut builder = TemplateContext::builder()
        .set("metadata.name", "bench-service")
        .set("metadata.namespace", "production")
        .group(
            "cluster",
            [
                ("name", "prod-us-east"),
                ("region", "us-east-1"),
                ("environment", "production"),
            ],
        );

    for i in 0..num_resources {
        let host = format!("resource-{}.svc.cluster.local", i);
        let name = format!("resource-{}", i);
        builder = builder.resource(
            &format!("resource-{}", i),
            [
                ("host", host.as_str()),
                ("port", "5432"),
                ("name", name.as_str()),
            ],
        );
    }

    builder.build()
}

/// Realistic service Helm values with N containers, each referencing
/// num_deps resource outputs plus metadata/cluster context.
fn helm_values(num_containers: usize, num_deps: usize) -> Value {
    let mut containers = Vec::new();
    for c in 0..num_containers {
        let mut env = serde_json::Map::new();
        for i in 0..num_deps {
            env.insert(
                format!("RESOURCE_{}_HOST", i),
                json!(format!("${{resources.resource-{}.host}}", i)),
            );
            env.insert(
                format!("RESOURCE_{}_PORT", i),
                json!(format!("${{resources.resource-{}.port}}", i)),
            );
        }
        env.insert("SERVICE_NAME".to_string(), json!("${metadata.name}"));
        env.insert("NAMESPACE".to_string(), json!("${metadata.namespace}"));
        env.insert("REGION".to_string(), json!("${cluster.region}"));
        env.insert("ENV".to_string(), json!("${cluster.environment}"));

        containers.push(json!({
            "name": format!("container-{}", c),
            "image": "app:latest",
            "env": env,
            "resources": {
                "limits": { "cpu": "1", "memory": "512Mi" },
                "requests": { "cpu": "100m", "memory": "128Mi" }
            },
            "volumeMounts": [
                { "name": "config", "mountPath": "/etc/config" },
                { "name": "data", "mountPath": "/data" }
            ]
        }));
    }

    let mut config_data = serde_json::Map::new();
    for i in 0..num_deps {
        config_data.insert(
            format!("resource_{}_url", i),
            json!(format!(
                "postgresql://${{resources.resource-{}.host}}:${{resources.resource-{}.port}}/db",
                i, i
            )),
        );
    }

    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "${metadata.name}",
            "namespace": "${metadata.namespace}",
            "labels": {
                "app": "${metadata.name}",
                "region": "${cluster.region}",
                "env": "${cluster.environment}"
            }
        },
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": containers,
                    "volumes": [
                        { "name": "config", "configMap": { "name": "${metadata.name}-config" } }
                    ]
                }
            }
        },
        "configData": config_data
    })
}

/// Template with secret references — each secret adds 3 env vars (user, pass, DSN)
fn secret_heavy_values(num_secrets: usize, num_context_deps: usize) -> Value {
    let mut env = serde_json::Map::new();
    for i in 0..num_secrets {
        env.insert(
            format!("SECRET_{}_USER", i),
            json!(format!("${{secret.cred-{}.username}}", i)),
        );
        env.insert(
            format!("SECRET_{}_PASS", i),
            json!(format!("${{secret.cred-{}.password}}", i)),
        );
        env.insert(
            format!("SECRET_{}_DSN", i),
            json!(format!(
                "postgres://${{secret.cred-{}.username}}:${{secret.cred-{}.password}}@${{resources.resource-{}.host}}:5432/db",
                i, i, i % num_context_deps.max(1)
            )),
        );
    }

    json!({
        "containers": [{
            "name": "app",
            "env": env,
            "image": "app:latest"
        }]
    })
}

/// Template with $secret directives (object replacement), each with N keys
fn directive_values(num_directives: usize, keys_per_directive: usize) -> Value {
    let mut helm = serde_json::Map::new();
    for i in 0..num_directives {
        let mut secret_keys = serde_json::Map::new();
        for k in 0..keys_per_directive {
            secret_keys.insert(
                format!("key-{}", k),
                json!(format!("${{cred-{}.key-{}}}", i, k)),
            );
        }
        helm.insert(
            format!("auth-{}", i),
            json!({
                "existingSecret": {
                    "$secret": secret_keys
                }
            }),
        );
    }

    Value::Object(helm)
}

/// Plain values with zero template syntax (fast path test)
fn plain_values(num_nodes: usize) -> Value {
    // Build a flat-ish tree with the target number of string nodes
    let mut map = serde_json::Map::new();
    for i in 0..num_nodes {
        if i % 10 == 0 {
            // Every 10th node is a nested object
            let mut inner = serde_json::Map::new();
            inner.insert("value".to_string(), json!("plain string no templates"));
            inner.insert("number".to_string(), json!(42));
            inner.insert("bool".to_string(), json!(true));
            map.insert(format!("group-{}", i), Value::Object(inner));
        } else {
            map.insert(
                format!("key-{}", i),
                json!("plain string value with no templates at all"),
            );
        }
    }
    Value::Object(map)
}

fn make_secrets(num: usize) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut secrets = BTreeMap::new();
    for i in 0..num {
        let mut keys = BTreeMap::new();
        keys.insert("username".to_string(), format!("user-{}", i));
        keys.insert("password".to_string(), format!("pass-{}", i));
        secrets.insert(format!("cred-{}", i), keys);
    }
    secrets
}

// =============================================================================
// Benchmarks: Helm values expansion at increasing scale
// =============================================================================

fn bench_helm_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_helm");

    // (containers, deps) — models realistic service complexity
    for (containers, deps) in [
        (1, 3),    // Simple service: 1 container, 3 deps
        (3, 5),    // Typical service: 3 sidecars, 5 deps
        (5, 10),   // Complex service: 5 containers, 10 deps
        (10, 20),  // Heavy service: 10 containers, 20 deps
        (20, 50),  // Extreme service: 20 containers, 50 deps
        (50, 100), // Absurd but possible: 50 containers, 100 deps
    ] {
        let ctx = rich_context(deps);
        let template = helm_values(containers, deps);

        group.bench_with_input(
            BenchmarkId::new("containers_deps", format!("{}c_{}d", containers, deps)),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &collect_opts()).unwrap());
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Secret-heavy templates across all three modes
// =============================================================================

fn bench_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_secrets");

    for num_secrets in [3, 10, 25, 50, 100, 250] {
        let ctx = rich_context(50);
        let template = secret_heavy_values(num_secrets, 50);
        let secrets = make_secrets(num_secrets);

        // Collect mode (leaves ${secret.*} in place)
        group.bench_with_input(
            BenchmarkId::new("collect", num_secrets),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &collect_opts()).unwrap());
                });
            },
        );

        // ESO template mode (replaces with {{ .key }}, escapes user Go templates)
        group.bench_with_input(
            BenchmarkId::new("eso", num_secrets),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &eso_opts()).unwrap());
                });
            },
        );

        // Resolve mode (substitutes actual values)
        let opts = resolve_opts(secrets);
        group.bench_with_input(
            BenchmarkId::new("resolve", num_secrets),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &opts).unwrap());
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: $secret directive processing
// =============================================================================

fn bench_directives(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_directives");

    for (count, keys) in [(3, 3), (10, 3), (25, 5), (50, 10), (100, 5)] {
        let ctx = TemplateContext::new();
        let template = directive_values(count, keys);

        group.bench_with_input(
            BenchmarkId::new("count_keys", format!("{}d_{}k", count, keys)),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &collect_opts()).unwrap());
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: No-op fast path (plain values, no ${} at all)
// =============================================================================

fn bench_noop_fast_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_noop");

    for num_nodes in [10, 100, 1_000, 10_000] {
        let ctx = TemplateContext::new();
        let template = plain_values(num_nodes);

        group.bench_with_input(
            BenchmarkId::new("nodes", num_nodes),
            &(),
            |b, _| {
                b.iter(|| {
                    let mut val = template.clone();
                    black_box(expand(&mut val, &ctx, &collect_opts()).unwrap());
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Extreme scale — reconciliation wave simulation
//
// In a 5000-node cluster with 10K–50K services, the operator processes
// services in waves. Each service gets its own expand() call. This bench
// measures what N consecutive expand() calls cost with realistic templates.
// =============================================================================

fn bench_extreme_wave(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_extreme");
    group.sample_size(10);

    // Simulate expanding templates for N services in a reconciliation wave.
    // Each service has a 3-container template with 5 deps (typical).
    let ctx = rich_context(100);
    let template = helm_values(3, 5);

    for wave_size in [100, 500, 1_000, 5_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("wave", wave_size),
            &wave_size,
            |b, &wave_size| {
                b.iter(|| {
                    for _ in 0..wave_size {
                        let mut val = template.clone();
                        black_box(expand(&mut val, &ctx, &collect_opts()).unwrap());
                    }
                });
            },
        );
    }

    // Same wave but with secrets (ESO mode) — the expensive path
    let secret_template = secret_heavy_values(10, 50);

    for wave_size in [100, 500, 1_000, 5_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("wave_eso", wave_size),
            &wave_size,
            |b, &wave_size| {
                b.iter(|| {
                    for _ in 0..wave_size {
                        let mut val = secret_template.clone();
                        black_box(expand(&mut val, &ctx, &eso_opts()).unwrap());
                    }
                });
            },
        );
    }

    // Worst case: large template (20 containers × 50 deps) in a wave
    let heavy_ctx = rich_context(200);
    let heavy_template = helm_values(20, 50);

    for wave_size in [100, 500, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("wave_heavy", wave_size),
            &wave_size,
            |b, &wave_size| {
                b.iter(|| {
                    for _ in 0..wave_size {
                        let mut val = heavy_template.clone();
                        black_box(expand(&mut val, &heavy_ctx, &collect_opts()).unwrap());
                    }
                });
            },
        );
    }

    group.finish();
}

// Context creation cost at scale — if the operator builds a new context per
// service (it does), this matters at 50K services.
fn bench_context_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_context_build");

    for num_resources in [5, 50, 200, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("resources", num_resources),
            &num_resources,
            |b, &num_resources| {
                b.iter(|| {
                    black_box(rich_context(num_resources));
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
    bench_helm_expansion,
    bench_secrets,
    bench_directives,
    bench_noop_fast_path,
    bench_extreme_wave,
    bench_context_creation,
);
criterion_main!(benches);
