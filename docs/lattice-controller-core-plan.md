# lattice-controller-core Refactoring Plan

## Motivation

LatticeService, LatticeJob, and LatticeModel all independently implement the same controller infrastructure. A duplication survey across the actual code reveals concrete, extractable patterns — not vague similarities.

This plan is scoped to a **post-LatticeModel** refactoring pass. Nothing here blocks LatticeModel implementation.

---

## Duplication Survey Results

| Pattern | Job | Service | Severity |
|---|---|---|---|
| `ensure_namespace()` | `lattice-job/src/controller.rs:378` | `lattice-service/src/controller.rs:243` | **Exact duplicate** — only field manager string differs |
| CRD discovery struct | `JobDiscoveredCrds` (4 CRDs) | `DiscoveredCrds` (5 CRDs) | 3 of 4 fields identical (`external_secret`, `mesh_member`, `tracing_policy_namespaced`) |
| Context struct | `JobContext` (6 fields) | `ServiceContext` (8 fields) | 5 fields identical (`client`, `graph`, `cluster_name`, `provider_type`, `cedar`) |
| Layered apply | 2-layer `apply_layers()` | 3-layer `apply_compiled_service()` | Layer 1 (infrastructure) is identical; layer 2+ diverges |
| Controller builder | `build_job_controllers()` | `build_service_controllers()` | Same skeleton: create context → build `Controller` → `shutdown_on_signal` → `run` → `for_each(log_reconcile_result)` |
| Status update | Simple merge patch | Rich builder + idempotency guard | Different complexity; guard logic is extractable |
| Reconcile state machine | 3-phase linear | 4-phase with dependency checks | Domain-specific; **not extractable** |
| Graph register/cleanup | Multi-entry (per task/role) | Single entry (per service) | Domain-specific; **not extractable** |
| Error types | `JobError` (specialized) | `Error` (common) | Already separated correctly |

---

## What to Extract

### Tier 1: Extract immediately (zero risk, eliminates exact duplicates)

#### 1a. `ensure_namespace` → `lattice-common::kube_utils`

Currently duplicated verbatim in both controllers.

```rust
// crates/lattice-common/src/kube_utils.rs

/// Ensure a namespace exists via server-side apply (idempotent).
pub async fn ensure_namespace(client: &Client, name: &str, manager: &str) -> Result<(), Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": name }
    });
    api.patch(name, &PatchParams::apply(manager), &Patch::Apply(&ns)).await?;
    Ok(())
}
```

**Changes:**
- Add to `crates/lattice-common/src/kube_utils.rs`
- Delete local copy from `crates/lattice-job/src/controller.rs:378-394`
- Delete local copy from `crates/lattice-service/src/controller.rs:243-265`
- Both callers become: `ensure_namespace(&client, namespace, "lattice-job-controller").await?`

#### 1b. `pod_template_to_json` → `lattice-workload`

Lives only in `lattice-job/src/compiler.rs:122-213` today, but `lattice-model` needs the same function. Move it to the crate that owns `CompiledPodTemplate`.

```rust
// crates/lattice-workload/src/pod_template.rs

/// Convert a CompiledPodTemplate to JSON for Volcano task/role templates.
pub fn pod_template_to_json(pt: CompiledPodTemplate) -> Result<serde_json::Value, serde_json::Error> {
    // ... existing implementation, unchanged
}
```

**Changes:**
- New file `crates/lattice-workload/src/pod_template.rs`
- Re-export from `crates/lattice-workload/src/lib.rs`
- Delete from `crates/lattice-job/src/compiler.rs`
- `lattice-job` calls `lattice_workload::pod_template_to_json`
- `lattice-model` calls `lattice_workload::pod_template_to_json`

---

### Tier 2: Extract after LatticeModel lands (consolidate the pattern once 3 consumers exist)

#### 2a. `CommonDiscoveredCrds` — shared CRD discovery base

All three controllers discover the same 3 CRDs, then each adds its own:

| Controller | Shared CRDs | Controller-specific CRDs |
|---|---|---|
| Service | external_secret, mesh_member, tracing_policy_namespaced | scaled_object, vm_service_scrape |
| Job | external_secret, mesh_member, tracing_policy_namespaced | volcano_job |
| Model | external_secret, mesh_member, tracing_policy_namespaced | model_serving |

```rust
// crates/lattice-common/src/discovered_crds.rs

use kube::discovery::ApiResource;
use kube::Client;

/// CRDs shared by all workload controllers (Service, Job, Model).
pub struct CommonDiscoveredCrds {
    pub external_secret: Option<ApiResource>,
    pub mesh_member: Option<ApiResource>,
    pub tracing_policy_namespaced: Option<ApiResource>,
}

impl CommonDiscoveredCrds {
    /// Discover shared CRDs in a single API discovery pass.
    pub async fn discover(client: &Client) -> Self {
        use kube::discovery::Discovery;
        let discovery = match Discovery::new(client.clone()).run().await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "API discovery failed");
                return Self { external_secret: None, mesh_member: None, tracing_policy_namespaced: None };
            }
        };
        Self {
            external_secret: find_discovered_resource(&discovery, "external-secrets.io", "ExternalSecret"),
            mesh_member: find_discovered_resource(&discovery, "lattice.dev", "LatticeMeshMember"),
            tracing_policy_namespaced: find_discovered_resource(&discovery, "cilium.io", "TracingPolicyNamespaced"),
        }
    }
}
```

Each controller wraps this:

```rust
// crates/lattice-job/src/controller.rs
pub struct JobDiscoveredCrds {
    pub common: CommonDiscoveredCrds,
    pub volcano_job: Option<ApiResource>,
}

// crates/lattice-model/src/controller.rs
pub struct ModelDiscoveredCrds {
    pub common: CommonDiscoveredCrds,
    pub model_serving: Option<ApiResource>,
}
```

**Benefit:** One discovery pass serves all controllers. Today, `DiscoveredCrds::discover()` runs full API discovery, then `JobDiscoveredCrds::from_shared()` runs a second discovery just for Volcano. With `CommonDiscoveredCrds`, the operator does one pass and distributes results.

#### 2b. Shared layer-1 apply helper

Layer 1 (infrastructure) is identical across all three controllers:

```
ConfigMaps → Secrets → ExternalSecrets → PVCs → ServiceAccounts → MeshMembers → TracingPolicies
```

```rust
// crates/lattice-common/src/apply_infra.rs (or extend kube_utils.rs)

use crate::kube_utils::ApplyBatch;

/// Resources common to all workload controller layer-1 applies.
pub struct InfraResources<'a> {
    pub config: &'a CompiledConfig,
    pub mesh_members: &'a [LatticeMeshMember],
    pub tracing_policies: &'a [TracingPolicyNamespaced],
    pub service_accounts: Vec<(&'a str, &'a str)>,  // (name, namespace) pairs
}

/// Apply layer-1 infrastructure resources.
pub async fn apply_infra_layer(
    client: &Client,
    namespace: &str,
    resources: &InfraResources<'_>,
    crds: &CommonDiscoveredCrds,
    manager: &str,
) -> Result<usize, Error> {
    let params = PatchParams::apply(manager).force();
    let mut batch = ApplyBatch::new(client.clone(), namespace, &params);

    // ServiceAccounts
    for (sa_name, _) in &resources.service_accounts {
        let sa = serde_json::json!({
            "apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": { "name": sa_name, "namespace": namespace },
            "automountServiceAccountToken": false
        });
        let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());
        batch.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
    }

    // ConfigMaps, Secrets, PVCs, ExternalSecrets, MeshMembers, TracingPolicies
    // ... (same code currently in both controllers)

    batch.run("layer-1-infrastructure").await
}
```

**Changes:**
- Extract from `lattice-job/src/controller.rs:296-355`
- Extract from `lattice-service/src/controller.rs:380-460` (the matching subset)
- Both callers become: `apply_infra_layer(&client, namespace, &infra, &crds.common, "lattice-job-controller").await?`

#### 2c. `WorkloadControllerContext` — shared context fields

5 of 6 `JobContext` fields and 5 of 8 `ServiceContext` fields are identical.

```rust
// crates/lattice-common/src/controller_context.rs

/// Fields shared by all workload controllers.
pub struct WorkloadControllerBase {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
}
```

Each controller composes this:

```rust
pub struct JobContext {
    pub base: WorkloadControllerBase,
    pub crds: Arc<JobDiscoveredCrds>,
    volcano_api: OnceLock<ApiResource>,
}

pub struct ModelContext {
    pub base: WorkloadControllerBase,
    pub crds: Arc<ModelDiscoveredCrds>,
    model_serving_api: OnceLock<ApiResource>,
}

pub struct ServiceContext {
    pub base: WorkloadControllerBase,
    pub monitoring: MonitoringConfig,
    pub extension_phases: Vec<Arc<dyn CompilerPhase>>,
    // ...
}
```

**Benefit:** Constructor signatures shrink. `build_*_controllers()` functions in `controller_runner.rs` take a shared base and add controller-specific fields.

---

### Tier 3: Consider but don't rush (diminishing returns)

#### 3a. Generic lazy CRD resolver

Both `JobContext` and `ModelContext` use the same `OnceLock<ApiResource>` + lazy discovery pattern for their Volcano CRD. This could become:

```rust
pub struct LazyCrdResolver {
    cached: OnceLock<ApiResource>,
    group: &'static str,
    kind: &'static str,
}

impl LazyCrdResolver {
    pub fn new(group: &'static str, kind: &'static str) -> Self { ... }
    pub fn seed(&self, ar: ApiResource) { let _ = self.cached.set(ar); }
    pub async fn resolve(&self, client: &Client) -> Option<&ApiResource> { ... }
}
```

**Verdict:** Nice but only 2 consumers. Wait until a 3rd CRD needs lazy resolution.

#### 3b. Status update abstraction

Service uses a rich builder pattern with idempotency guards; Job uses a simple function. An abstraction would either be too generic (losing type safety) or too complex for what Job needs.

**Verdict:** Keep separate. The idempotency guard (`is_status_unchanged`) could be a standalone utility, but the builders are too domain-specific.

#### 3c. Controller builder factory in `controller_runner.rs`

The `build_*_controllers()` functions share boilerplate but differ in watches, context construction, and number of sub-controllers. A generic factory would need so many type parameters it wouldn't simplify anything.

**Verdict:** Keep as-is. The repetition is small and readable.

---

## What NOT to Extract

| Pattern | Reason |
|---|---|
| Reconcile state machines | Domain-specific. Job is 3-phase linear, Service is 4-phase with dependency checks, Model is 4-phase with rolling updates. Forcing these into one abstraction adds complexity for no benefit. |
| Graph register/cleanup | Job registers per-task, Service registers per-service, Model registers per-role. The ServiceGraph API is already the shared abstraction. |
| Error types | Correctly separated already. Each controller's errors carry domain context (`TaskCompilation` vs `RoleCompilation`). |
| Compiler orchestration | The for-each-task/role loop is 10 lines and differs in what it iterates over. Not worth abstracting. |

---

## Implementation Order

| Phase | Task | Risk | LOC delta |
|---|---|---|---|
| **Phase 1** (do during LatticeModel impl) | Extract `ensure_namespace` to `kube_utils` | None | -20 (net removal) |
| **Phase 1** (do during LatticeModel impl) | Move `pod_template_to_json` to `lattice-workload` | None | -90 (net removal) |
| **Phase 2** (after LatticeModel merges) | Extract `CommonDiscoveredCrds` | Low | ~+60 new, -40 removed |
| **Phase 2** (after LatticeModel merges) | Extract `apply_infra_layer` | Low | ~+80 new, -120 removed |
| **Phase 2** (after LatticeModel merges) | Extract `WorkloadControllerBase` | Low | ~+30 new, -30 removed |
| **Phase 3** (if needed) | `LazyCrdResolver` generic | None | ~+40 new, -20 removed |

Phase 1 items should be done as part of the LatticeModel PR — they're prerequisites anyway (pod_template_to_json) or trivial wins (ensure_namespace).

Phase 2 is a standalone refactoring PR after LatticeModel lands, when all three consumers exist and the shared patterns are verified.

Phase 3 is optional and can wait indefinitely.

---

## File Map

After full refactoring, the new/changed files:

```
crates/lattice-common/src/
├── kube_utils.rs              # + ensure_namespace(client, name, manager)
├── discovered_crds.rs         # NEW: CommonDiscoveredCrds
├── apply_infra.rs             # NEW: apply_infra_layer() + InfraResources
└── controller_context.rs      # NEW: WorkloadControllerBase

crates/lattice-workload/src/
├── pod_template.rs            # NEW: pod_template_to_json (moved from lattice-job)
└── lib.rs                     # + pub mod pod_template; pub use ...

crates/lattice-job/src/
├── controller.rs              # - ensure_namespace (use common)
│                              # - layer1 infra apply (use apply_infra_layer)
│                              # - JobContext fields → JobContext { base, crds, volcano_api }
└── compiler.rs                # - pod_template_to_json (use lattice_workload)

crates/lattice-service/src/
├── controller.rs              # - ensure_namespace (use common)
│                              # - layer1 infra apply (use apply_infra_layer)
│                              # - ServiceContext fields → ServiceContext { base, monitoring, ... }

crates/lattice-model/src/
├── controller.rs              # Uses all shared abstractions from day 1
└── compiler.rs                # Uses lattice_workload::pod_template_to_json
```
