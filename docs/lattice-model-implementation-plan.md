# LatticeModel Implementation Plan

## Overview

Implement the `LatticeModel` controller and Volcano ModelServing compiler, following the established `LatticeJob` pattern. `LatticeModel` compiles to Kthena's `ModelServing` resource (from `workload.serving.volcano.sh/v1alpha1`) instead of a Volcano `VCJob`, enabling disaggregated LLM inference serving with prefill/decode roles, gang scheduling, rolling updates, and self-healing recovery.

The CRD type definition already exists at `crates/lattice-common/src/crd/model_serving.rs`. This plan covers the controller, compiler, Volcano ModelServing types, operator wiring, CRD installation, and tests.

---

## Architecture

```
LatticeModel CRD (lattice.dev/v1alpha1)
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  lattice-model crate (controller + compiler)            │
│                                                         │
│  compile_model()                                        │
│    ├─ For each role (prefill, decode, ...):             │
│    │   ├─ WorkloadCompiler → pod template + config      │
│    │   ├─ lattice_tetragon → TracingPolicyNamespaced    │
│    │   └─ Collect LatticeMeshMember                     │
│    │                                                    │
│    └─ lattice_volcano::compile_model_serving()          │
│         → ModelServing resource                         │
│                                                         │
│  reconcile() state machine:                             │
│    Pending → Loading → Serving                          │
│                └─ Failed (on error)                     │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Volcano / Kthena                                       │
│  ModelServing (workload.serving.volcano.sh/v1alpha1)    │
│    ├─ ServingGroup (template)                           │
│    │   ├─ Role: prefill (replicas, pod template)        │
│    │   ├─ Role: decode  (replicas, pod template)        │
│    │   └─ GangPolicy (minRoleReplicas)                  │
│    └─ RecoveryPolicy, RolloutStrategy                   │
└─────────────────────────────────────────────────────────┘
```

### Mapping: LatticeModel → Kthena ModelServing

| LatticeModel field | ModelServing field | Notes |
|---|---|---|
| `spec.schedulerName` | `spec.schedulerName` | Default: `"volcano"` |
| `spec.recoveryPolicy` | `spec.recoveryPolicy` | `RoleRecreate` / `ServingGroupRecreate` / `None` |
| `spec.restartGracePeriodSeconds` | — | Mapped to role-level probe `initialDelaySeconds` or annotation |
| `spec.roles` (BTreeMap) | `spec.template.roles` (map) | Each role compiled through WorkloadCompiler |
| `spec.roles[x].replicas` | `spec.template.roles[x].replicas` | Role-level replica count |
| `spec.roles[x].workerReplicas` | Entry/Worker split within role | Entry pod (index 0) + N-1 workers |
| `spec.roles[x].workload` | Pod template in `spec.template.roles[x].template` | Via WorkloadCompiler |
| `spec.roles[x].runtime` | Merged into pod template | Sidecars, sysctls, hostNetwork, etc. |
| `spec.ingress` | Separate: Lattice ingress resources | Same as LatticeService |

---

## Step 1: Extend Volcano Types in `lattice-volcano`

**Files to modify:** `crates/lattice-volcano/src/types.rs`, `crates/lattice-volcano/src/lib.rs`
**New file:** `crates/lattice-volcano/src/model_serving_compiler.rs`

### 1a. Add ModelServing types to `types.rs`

```rust
/// Kthena ModelServing resource (workload.serving.volcano.sh/v1alpha1)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServing {
    pub api_version: String,    // "workload.serving.volcano.sh/v1alpha1"
    pub kind: String,           // "ModelServing"
    pub metadata: ModelServingMetadata,
    pub spec: ModelServingSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
    pub scheduler_name: String,
    pub template: ServingGroupTemplate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_strategy: Option<RolloutStrategy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServingGroupTemplate {
    pub roles: BTreeMap<String, ModelServingRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gang_policy: Option<GangPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingRole {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
    /// Pod template (pre-serialized JSON from WorkloadCompiler)
    pub template: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GangPolicy {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_role_replicas: BTreeMap<String, u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RolloutStrategy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_strategy_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update_configuration: Option<RollingUpdateConfiguration>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable_replicas: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge_replicas: Option<u32>,
}
```

### 1b. Add `compile_model_serving()` in new file `model_serving_compiler.rs`

```rust
pub fn compile_model_serving(
    model: &LatticeModel,
    role_pod_templates: &BTreeMap<String, serde_json::Value>,
) -> ModelServing { ... }
```

Follows the same pattern as `compile_vcjob`:
- Sets owner reference to LatticeModel (controller=true, blockOwnerDeletion=true)
- Maps each role to a `ModelServingRole` with its compiled pod template
- Computes `gang_policy.min_role_replicas` from role replica counts
- Sets `recovery_policy` from model spec
- Uses `api_version: "workload.serving.volcano.sh/v1alpha1"`, `kind: "ModelServing"`

### 1c. Re-export from `lib.rs`

```rust
mod model_serving_compiler;
pub use model_serving_compiler::compile_model_serving;
pub use types::{ModelServing, ModelServingSpec, ...};
```

---

## Step 2: Create `lattice-model` Crate

**New directory:** `crates/lattice-model/`

```
crates/lattice-model/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── compiler.rs
    ├── controller.rs
    └── error.rs
```

### 2a. `Cargo.toml`

Mirror `lattice-job/Cargo.toml`:

```toml
[package]
name = "lattice-model"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "LatticeModel controller and compiler for model serving workloads"

[features]
fips = ["lattice-common/fips", "lattice-workload/fips", "aws-lc-rs/fips"]

[dependencies]
lattice-common = { workspace = true }
lattice-workload = { workspace = true }
lattice-tetragon = { workspace = true }
lattice-volcano = { workspace = true }
lattice-cedar = { workspace = true }
lattice-secret-provider = { workspace = true }
aws-lc-rs = { workspace = true }
kube = { workspace = true }
k8s-openapi = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
futures = { workspace = true }
chrono = { workspace = true }

[dev-dependencies]
tokio-test = { workspace = true }
serde_json = { workspace = true }
```

### 2b. `error.rs`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("compilation failed for role '{role}': {source}")]
    RoleCompilation {
        role: String,
        source: lattice_workload::CompilationError,
    },
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("{0}")]
    Common(#[from] lattice_common::Error),
    #[error("model has no roles")]
    NoRoles,
    #[error("missing namespace on LatticeModel")]
    MissingNamespace,
    #[error("Kthena ModelServing CRD (workload.serving.volcano.sh/ModelServing) not available")]
    KthenaCrdMissing,
}
```

### 2c. `compiler.rs`

Follows the same structure as `lattice-job/src/compiler.rs`:

```rust
pub struct CompiledModel {
    pub model_serving: ModelServing,
    pub config: CompiledConfig,
    pub mesh_members: Vec<LatticeMeshMember>,
    pub tracing_policies: Vec<TracingPolicyNamespaced>,
}

pub async fn compile_model(
    model: &LatticeModel,
    graph: &ServiceGraph,
    cluster_name: &str,
    provider_type: ProviderType,
    cedar: &PolicyEngine,
) -> Result<CompiledModel, ModelError> { ... }
```

The compilation loop iterates over `model.spec.roles` instead of `job.spec.tasks`:

- For each role (e.g., "prefill", "decode"):
  - Run `WorkloadCompiler::new(role_full_name, namespace, &role_spec.workload, &role_spec.runtime, provider_type)`
  - `.with_cedar(cedar).with_cluster_name(cluster_name).with_graph(graph)`
  - `.with_image_pull_secrets(&role_spec.runtime.image_pull_secrets)`
  - `.compile().await`
  - Convert `CompiledPodTemplate` → JSON via `pod_template_to_json()` (same helper as LatticeJob)
  - Compile Tetragon tracing policies
  - Collect mesh members
- Build `ModelServing` via `lattice_volcano::compile_model_serving(model, &role_pod_templates)`
- Return `CompiledModel`

The `pod_template_to_json` function should be extracted to a shared location (either `lattice-workload` or `lattice-volcano`) to avoid duplication between `lattice-job` and `lattice-model`.

### 2d. `controller.rs`

Follows the same pattern as `lattice-job/src/controller.rs`:

```rust
pub struct ModelDiscoveredCrds {
    pub external_secret: Option<ApiResource>,
    pub mesh_member: Option<ApiResource>,
    pub tracing_policy_namespaced: Option<ApiResource>,
    pub model_serving: Option<ApiResource>,
}

pub struct ModelContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub crds: Arc<ModelDiscoveredCrds>,
    model_serving_api: OnceLock<ApiResource>,
}
```

**State machine:**

```
Pending → Loading → Serving
    └──────→ Failed (on error at any transition)
```

- **Pending**: Compile model, register roles in graph, apply layer 1 (infrastructure), apply layer 2 (ModelServing), transition to Loading
- **Loading**: Check ModelServing status via dynamic API
  - If `Available` condition is True → transition to Serving
  - If pods are failing repeatedly → transition to Failed
  - Otherwise → requeue 15s
- **Serving**: Monitor ModelServing health
  - If `Available` condition becomes False → transition back to Loading
  - Detect spec changes: unlike LatticeJob (immutable), LatticeModel supports rolling updates — recompile and reapply
  - Requeue 60s
- **Failed**: Await change (user fixes spec or deletes)

**CRD Discovery:**

```rust
async fn discover_model_serving(client: &Client) -> Option<ApiResource> {
    // Discovery for "workload.serving.volcano.sh" group, kind "ModelServing"
    find_discovered_resource(&discovery, "workload.serving.volcano.sh", "ModelServing")
}
```

**Layered Resource Application** (same as LatticeJob):
- Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, ServiceAccounts, LatticeMeshMembers, TracingPolicies
- Layer 2: ModelServing

**Graph management:**
- `register_graph()`: Register each role as `{model_name}-{role_name}` in the ServiceGraph
- `cleanup_graph()`: Remove role entries on delete/failure

**Reconcile function signature:**

```rust
pub async fn reconcile(model: Arc<LatticeModel>, ctx: Arc<ModelContext>) -> Result<Action, ModelError>
pub fn error_policy(model: Arc<LatticeModel>, error: &ModelError, _ctx: Arc<ModelContext>) -> Action
```

**ModelServing status check:**

```rust
async fn check_model_serving_status(
    client: &Client,
    name: &str,
    namespace: &str,
    api: &ApiResource,
) -> Option<ModelServingPhaseResult> {
    // Read .status.conditions[] for type=Available
    // Available=True → Serving
    // Progressing=True, Available=False → Loading
    // Detect failure patterns
}
```

---

## Step 3: Wire into the Operator

### 3a. Add `lattice-model` to workspace `Cargo.toml`

```toml
[workspace]
members = [
    # ...existing...
    "crates/lattice-model",
]

[workspace.dependencies]
lattice-model = { path = "crates/lattice-model" }
```

### 3b. Add dependency to `lattice-operator`

In `crates/lattice-operator/Cargo.toml`:
```toml
lattice-model = { workspace = true }
```

### 3c. Add `build_model_controllers()` to `controller_runner.rs`

```rust
pub async fn build_model_controllers(
    client: Client,
    cluster_name: String,
    provider_type: ProviderType,
    cedar: Arc<PolicyEngine>,
    graph: Arc<ServiceGraph>,
    shared_crds: &DiscoveredCrds,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let crds = Arc::new(
        lattice_model::controller::ModelDiscoveredCrds::from_shared(
            &client,
            shared_crds.external_secret.clone(),
            shared_crds.mesh_member.clone(),
            shared_crds.tracing_policy_namespaced.clone(),
        )
        .await,
    );

    let ctx = Arc::new(lattice_model::controller::ModelContext::new(
        client.clone(),
        graph,
        cluster_name,
        provider_type,
        cedar,
        crds,
    ));

    let models: Api<LatticeModel> = Api::all(client);

    let model_ctrl = Controller::new(models, watcher_config())
        .shutdown_on_signal()
        .run(
            lattice_model::controller::reconcile,
            lattice_model::controller::error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Model"));

    tracing::info!("- LatticeModel controller");

    vec![Box::pin(model_ctrl)]
}
```

### 3d. Call from `main.rs`

In both `run_service_slice()` and `run_all_slices()`, add after `build_job_controllers`:

```rust
controllers.extend(
    controller_runner::build_model_controllers(
        client.clone(),
        cluster_name,
        provider_type,
        cedar.clone(),
        graph,  // Note: graph is consumed by build_job_controllers,
                // need to clone Arc before passing to jobs
        &crds,
    )
    .await,
);
```

**Important:** The `graph: Arc<ServiceGraph>` returned from `build_service_controllers` is currently consumed by `build_job_controllers`. Both job and model controllers need it. The `Arc` already supports shared ownership, but the current code moves it. Clone the `Arc` before passing to jobs:

```rust
let graph_for_jobs = graph.clone();
let graph_for_models = graph.clone();
controllers.extend(build_job_controllers(..., graph_for_jobs, ...).await);
controllers.extend(build_model_controllers(..., graph_for_models, ...).await);
```

### 3e. Install CRD at startup

In `crates/lattice-operator/src/startup/crds.rs`, add to `service_crds()`:

```rust
CrdDef {
    name: "latticemodels.lattice.dev",
    crd: LatticeModel::crd(),
},
```

Add `LatticeModel` to the import from `lattice_common::crd`.

---

## Step 4: Extract Shared `pod_template_to_json`

The `pod_template_to_json()` function in `lattice-job/src/compiler.rs` converts a `CompiledPodTemplate` to JSON. Both `lattice-job` and `lattice-model` need it.

**Option A (recommended):** Move to `lattice-workload` crate since it owns `CompiledPodTemplate`.

Add to `crates/lattice-workload/src/compiler.rs` (or a new `crates/lattice-workload/src/pod_template.rs`):

```rust
/// Convert a CompiledPodTemplate into a JSON Value suitable for Volcano task/role templates.
pub fn pod_template_to_json(pt: CompiledPodTemplate) -> Result<serde_json::Value, serde_json::Error> { ... }
```

Then update `lattice-job/src/compiler.rs` to use `lattice_workload::pod_template_to_json` and delete the local copy.

---

## Step 5: Enhance the CRD (Optional Additions)

The existing `LatticeModelSpec` in `model_serving.rs` is minimal. Consider adding these fields to align with Kthena's full capabilities:

### 5a. Gang policy configuration

```rust
pub struct LatticeModelSpec {
    // ...existing fields...

    /// Minimum role replicas for gang scheduling.
    /// Maps role name to minimum replica count. If not set, defaults
    /// to each role's full replica count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_role_replicas: Option<BTreeMap<String, u32>>,

    /// Rollout strategy for updates (RollingUpdate or Recreate)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_strategy: Option<RolloutStrategySpec>,

    /// Number of ServingGroup replicas (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,

    /// Priority class name for scheduling
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,
}
```

### 5b. Enhanced status

```rust
pub struct LatticeModelStatus {
    pub phase: ModelServingPhase,
    pub message: Option<String>,
    pub observed_generation: Option<i64>,
    pub available_replicas: Option<u32>,
    pub ready_roles: Option<BTreeMap<String, u32>>,
}
```

---

## Step 6: Tests

### 6a. Unit tests in `lattice-volcano` (ModelServing compilation)

- `single_role_model_serving` — single decode role compiles correctly
- `multi_role_model_serving` — prefill + decode roles both present
- `owner_reference_set` — LatticeModel owner ref on ModelServing
- `gang_policy_computed` — min_role_replicas set from role counts
- `recovery_policy_propagated` — recovery policy passed through
- `serialization_roundtrip` — serialize/deserialize ModelServing

### 6b. Unit tests in `lattice-model` (compiler)

- `compile_single_role_model` — end-to-end compile with WorkloadCompiler
- `compile_multi_role_model` — prefill + decode
- `empty_roles_returns_error` — NoRoles error
- `missing_namespace_returns_error` — MissingNamespace error
- `mesh_members_generated_per_role` — one mesh member per role
- `tracing_policies_generated_per_role` — tracing policy per role
- `config_resources_merged_across_roles` — ConfigMaps/Secrets merged

### 6c. Unit tests in `lattice-model` (controller)

- Test state transitions: Pending → Loading → Serving
- Test error transitions: Pending → Failed
- Test graph registration/cleanup
- Test immutability guard (if applicable) or rolling update detection

### 6d. Integration test (future)

Add `integration/model.rs` to the E2E test suite when Kthena is available in test clusters. For now, unit tests cover the compilation and controller logic.

---

## Step 7: Implementation Order

| # | Task | Crate | Depends on |
|---|------|-------|------------|
| 1 | Add ModelServing types to `lattice-volcano/src/types.rs` | lattice-volcano | — |
| 2 | Add `compile_model_serving()` to `lattice-volcano` | lattice-volcano | #1 |
| 3 | Extract `pod_template_to_json` to `lattice-workload` | lattice-workload, lattice-job | — |
| 4 | Create `lattice-model` crate with `error.rs` | lattice-model | — |
| 5 | Implement `compiler.rs` in `lattice-model` | lattice-model | #2, #3 |
| 6 | Implement `controller.rs` in `lattice-model` | lattice-model | #5 |
| 7 | Wire into operator (controller_runner, main, crds) | lattice-operator | #6 |
| 8 | Enhance CRD with gang policy and rollout fields | lattice-common | #7 |
| 9 | Add unit tests throughout | all | #1-#7 |

Steps 1-3 can be done in parallel. Steps 4-6 are sequential. Step 7 integrates everything. Step 8 is an enhancement that can be done incrementally.

---

## Key Design Decisions

**Why mirror LatticeJob's architecture?**
- Proven pattern in this codebase
- Same WorkloadCompiler reuse
- Same layered apply strategy
- Same graph/mesh/Cedar integration
- Consistent error handling and CRD discovery

**Why ModelServing instead of VCJob?**
- ModelServing is purpose-built for long-running inference (not batch)
- Supports rolling updates (VCJob doesn't)
- Recovery policies (RoleRecreate, ServingGroupRecreate) vs job restart
- Gang scheduling per-role (not per-task)
- Kthena ecosystem (ModelServer, ModelRoute) for inference routing

**Why Loading phase?**
- LLM model loading can take minutes (downloading weights, GPU memory allocation)
- Distinguishes "pods are running but model isn't ready" from "serving traffic"
- Maps to Kthena's `Progressing` condition before `Available`

**Mutable vs immutable spec?**
- LatticeJob: immutable once Running (batch jobs shouldn't change mid-execution)
- LatticeModel: mutable (rolling updates for serving workloads are expected)
- On spec change while Serving: recompile, reapply — ModelServing handles rolling update
