# Lattice Autoscaling v1

> **Generalized autoscaling with KEDA ScaledObjects for LatticeService workloads.**
>
> Today, every LatticeService with `replicas.max` gets a ScaledObject hardcoded to CPU 80%.
> This is wrong for GPU inference (scale on queue depth), memory-bound workloads,
> and anything where CPU utilization is not the right signal. v1 generalizes the
> autoscaling spec so users declare what to scale on and at what threshold.

---

## Problem

The service compiler hardcodes a single ScaledObject trigger:

```rust
// crates/lattice-service/src/workload/mod.rs:1359-1367
triggers: vec![ScaledObjectTrigger {
    type_: "resource".to_string(),
    metadata: BTreeMap::from([
        ("type".to_string(), "Utilization".to_string()),
        ("value".to_string(), "80".to_string()),
    ]),
    metric_type: Some("Utilization".to_string()),
    name: Some("cpu".to_string()),
}],
```

Users cannot:
- Change the CPU threshold (80% is too aggressive for bursty workloads)
- Scale on memory pressure
- Scale on custom metrics (vLLM queue depth, request latency, active connections)
- Use multiple signals (scale on CPU *or* queue depth, whichever triggers first)

## Solution

1. Add an `autoscaling` field to `ReplicaSpec` with user-defined metrics
2. The compiler translates each metric into the correct KEDA ScaledObject trigger
3. Default to CPU 80% when `autoscaling` is empty (backwards compatible)
4. Deploy KEDA on all clusters; ScaledObjects query VictoriaMetrics for custom metrics

KEDA ScaledObjects query VictoriaMetrics via Prometheus-compatible endpoints and
manage scaling for all metric types, including vLLM inference queue depth, token
throughput, and latency.

---

## CRD Changes

### ReplicaSpec (extended)

```rust
// crates/lattice-common/src/crd/service.rs

/// Replica scaling specification
pub struct ReplicaSpec {
    /// Minimum replicas (default: 1)
    pub min: u32,

    /// Maximum replicas (enables ScaledObject when set)
    pub max: Option<u32>,

    /// Autoscaling metrics. Defaults to [{metric: "cpu", target: 80}] if empty.
    /// ScaledObject scales when ANY trigger exceeds its target (OR logic).
    pub autoscaling: Vec<AutoscalingMetric>,
}

/// A single autoscaling metric
pub struct AutoscalingMetric {
    /// Metric name: "cpu", "memory", or a custom metric name
    /// (e.g. "vllm_num_requests_waiting", "http_requests_per_second")
    pub metric: String,

    /// Target value:
    /// - For "cpu" and "memory": percentage (e.g. 80 = 80% utilization)
    /// - For custom metrics: average value per pod (e.g. 5 = scale when avg > 5)
    pub target: u32,
}
```

### YAML Examples

```yaml
# Existing behavior (no change needed, fully backwards compatible)
replicas:
  min: 1
  max: 4
# → ScaledObject with cpu resource trigger at 80% (default)

# Lower CPU threshold for bursty workloads
replicas:
  min: 2
  max: 10
  autoscaling:
    - metric: cpu
      target: 60

# GPU inference — scale on vLLM queue depth
replicas:
  min: 1
  max: 8
  autoscaling:
    - metric: vllm_num_requests_waiting
      target: 5

# Multi-signal: scale on CPU or queue depth (whichever fires first)
replicas:
  min: 1
  max: 8
  autoscaling:
    - metric: cpu
      target: 70
    - metric: vllm_num_requests_waiting
      target: 5

# Memory-bound workload
replicas:
  min: 2
  max: 6
  autoscaling:
    - metric: memory
      target: 75
```

---

## Compiler Changes

### Trigger Type Mapping

The compiler maps metric names to KEDA ScaledObject trigger types:

| Metric Name | KEDA Trigger Type | Metric Type | Example |
|---|---|---|---|
| `cpu` | `resource` | `Utilization` | 80 → scale at 80% CPU |
| `memory` | `resource` | `Utilization` | 75 → scale at 75% memory |
| anything else | `prometheus` | `AverageValue` | 5 → scale when avg > 5 |

`resource` triggers use the built-in Kubernetes metrics-server. `prometheus`
triggers query VictoriaMetrics via its Prometheus-compatible endpoint.

### compile_scaled_object Changes

```rust
// crates/lattice-service/src/workload/mod.rs

fn compile_scaled_object(
    name: &str,
    namespace: &str,
    spec: &LatticeServiceSpec,
) -> ScaledObject {
    // Default to CPU 80% if no autoscaling metrics specified
    let metrics = if spec.replicas.autoscaling.is_empty() {
        vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 80,
        }]
    } else {
        spec.replicas.autoscaling.clone()
    };

    let triggers = metrics.iter().map(|m| match m.metric.as_str() {
        "cpu" | "memory" => ScaledObjectTrigger {
            type_: "resource".to_string(),
            name: Some(m.metric.clone()),
            metric_type: Some("Utilization".to_string()),
            metadata: BTreeMap::from([
                ("type".to_string(), "Utilization".to_string()),
                ("value".to_string(), m.target.to_string()),
            ]),
        },
        _ => ScaledObjectTrigger {
            type_: "prometheus".to_string(),
            name: Some(m.metric.clone()),
            metric_type: Some("AverageValue".to_string()),
            metadata: BTreeMap::from([
                ("serverAddress".to_string(), VICTORIAMETRICS_URL.to_string()),
                ("query".to_string(), format!(
                    "avg({}{{namespace=\"{}\",pod=~\"{}-.*\"}})",
                    m.metric, namespace, name
                )),
                ("threshold".to_string(), m.target.to_string()),
            ]),
        },
    }).collect();

    ScaledObject {
        api_version: "keda.sh/v1alpha1".to_string(),
        kind: "ScaledObject".to_string(),
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: ScaledObjectSpec {
            scale_target_ref: /* unchanged */,
            min_replica_count: Some(spec.replicas.min),
            max_replica_count: Some(spec.replicas.max.unwrap_or(spec.replicas.min)),
            triggers,
        },
    }
}
```

### New Structs in workload/mod.rs

```rust
/// A single KEDA ScaledObject trigger
pub struct ScaledObjectTrigger {
    /// Trigger type: "resource" or "prometheus"
    pub type_: String,
    /// Optional trigger name (used in metric naming)
    pub name: Option<String>,
    /// Metric type: "Utilization" or "AverageValue"
    pub metric_type: Option<String>,
    /// Trigger-specific metadata (keys vary by trigger type)
    pub metadata: BTreeMap<String, String>,
}

/// ScaledObject spec
pub struct ScaledObjectSpec {
    pub scale_target_ref: ScaleTargetRef,
    pub min_replica_count: Option<u32>,
    pub max_replica_count: Option<u32>,
    pub triggers: Vec<ScaledObjectTrigger>,
}
```

---

## Infrastructure: KEDA

All autoscaling is handled by KEDA ScaledObjects. Resource metrics (`cpu`/`memory`)
use KEDA's built-in `resource` trigger type. Custom metrics use KEDA's `prometheus`
trigger type, querying VictoriaMetrics via its Prometheus-compatible endpoint. KEDA is
deployed on all clusters as part of the standard bootstrap.

### Default Metrics

For vLLM / TGI workloads, KEDA ScaledObjects query the following metrics from VictoriaMetrics:

| Prometheus Metric | ScaledObject Trigger Metric | What It Measures |
|---|---|---|
| `vllm:num_requests_waiting` | `vllm_num_requests_waiting` | Requests queued for inference |
| `vllm:avg_prompt_throughput_toks_per_s` | `vllm_prompt_throughput` | Token throughput |
| `vllm:avg_generation_throughput_toks_per_s` | `vllm_generation_throughput` | Generation speed |
| `tgi_queue_size` | `tgi_queue_size` | TGI request queue |

Users can also expose their own application metrics via Prometheus and reference
them in the `autoscaling` spec — no Lattice changes needed.

---

## Validation

```rust
// In LatticeServiceSpec::validate()

// Validate autoscaling metrics
for metric in &self.replicas.autoscaling {
    if metric.target == 0 {
        return Err(anyhow!("autoscaling target must be > 0"));
    }
    if (metric.metric == "cpu" || metric.metric == "memory") && metric.target > 100 {
        return Err(anyhow!(
            "autoscaling target for {} must be <= 100 (percentage)",
            metric.metric
        ));
    }
}

// Autoscaling without max replicas is a no-op (warn? error?)
if !self.replicas.autoscaling.is_empty() && self.replicas.max.is_none() {
    return Err(anyhow!(
        "autoscaling metrics require replicas.max to be set"
    ));
}
```

---

## Files Changed

| File | Change |
|---|---|
| `crates/lattice-common/src/crd/service.rs` | Add `autoscaling: Vec<AutoscalingMetric>` to `ReplicaSpec`, add `AutoscalingMetric` struct |
| `crates/lattice-service/src/workload/mod.rs` | Replace `compile_hpa` with `compile_scaled_object`, add `ScaledObjectTrigger`, `ScaledObjectSpec` structs |
| `crates/lattice-infra/src/bootstrap/mod.rs` | Add `pub mod keda;` |
| `crates/lattice-infra/src/bootstrap/keda.rs` | New — helm template for KEDA |
| `versions.toml` | Pin `KEDA_VERSION` |

---

## What v1 Does NOT Include

- **Scale-to-zero** — Min replicas is always >= 1. Cold starts on GPU workloads
  (30-120s model load) make scale-to-zero impractical for production inference.
  Revisit with Knative if demand emerges.
- **Custom KEDA trigger rules** — v1 ships with sensible defaults for vLLM/TGI.
  Advanced users who need custom trigger configurations can create KEDA ScaledObjects
  directly. A `metricsConfig` CRD field is a v2 concern.

---

## Implementation Phases

### Phase A: CRD + Compiler (no new infra)

1. Add `AutoscalingMetric` struct and `autoscaling` field to `ReplicaSpec`
2. Add `ScaledObjectTrigger`, `ScaledObjectSpec` to workload module
3. Replace `compile_hpa` with `compile_scaled_object` to generate KEDA ScaledObjects
4. Map `cpu`/`memory` to KEDA `resource` triggers, custom metrics to `prometheus` triggers
5. Default to CPU 80% when `autoscaling` is empty
6. Add validation rules
7. Update tests

**Result**: Users can configure CPU/memory thresholds. Custom metrics compile
correctly into ScaledObject prometheus triggers querying VictoriaMetrics.

### Phase B: KEDA Bootstrap

1. Add `keda.rs` to bootstrap module
2. Pin version in `versions.toml`
3. Include in standard cluster bootstrap path
4. Configure default KEDA ScaledObject triggers for vLLM/TGI

**Result**: All clusters get KEDA automatically. Custom metrics
like `vllm_num_requests_waiting` work end-to-end with KEDA ScaledObjects.
