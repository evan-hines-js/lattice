# Lattice Operator - CLAUDE.md

## Project Overview

Lattice is a 100% CRD-driven Kubernetes operator for multi-cluster lifecycle management, similar to SpectroCloud. The operator manages cluster provisioning, configuration, and self-management through a **pivoting architecture**.

**Reference Implementation**: An Elixir POC exists at `/Users/evanhines/lattice/lattice` with architectural patterns (partially implemented). Use for reference but do not port directly - this Rust implementation is a fresh start with lessons learned.

**Configuration Examples**: CRD examples and cluster configurations at `/Users/evanhines/lattice/lattice-config/`

---

## Core Architectural Principle: Self-Managed Clusters via Pivoting

**CRITICAL**: Every cluster provisioned by Lattice MUST become fully self-managed. This is non-negotiable.

Lattice operates like Rancher - a management platform running on a "management cluster" that can provision and manage many workload clusters throughout its lifetime. The pivoting pattern applies to **all** cluster provisioning, not just installation.

### Pivot Flows

#### 1. Installation Flow (One-Time Bootstrap)

**This is the ONLY time ClusterResourceSets (CRS) are used.**

```
1. Bootstrap Phase
   - Create temporary bootstrap cluster (kind/docker)
   - Deploy Lattice operator + CAPI to bootstrap
   - Create LatticeCluster CRD for management cluster
   - CAPI provisions the management cluster
   - CRS installs Lattice agent onto management cluster

2. Pivot Phase
   - Management cluster agent connects back to bootstrap (outbound gRPC stream)
   - Export CAPI resources from bootstrap cluster
   - Send pivot command over gRPC stream
   - Agent imports CAPI resources into management cluster
   - Management cluster now manages its own lifecycle

3. Cleanup
   - Delete bootstrap cluster
   - Management cluster is self-managing and ready to provision workload clusters
```

#### 2. Runtime Flow (Ongoing - Every New Cluster)

**NO ClusterResourceSets. ALL traffic is OUTBOUND from workload clusters.**

```
1. User creates LatticeCluster CRD on management cluster
   - Management cluster runs Lattice operator + CAPI
   - Operator reconciles the new LatticeCluster

2. Provisioning Phase
   - Operator generates CAPI manifests (Cluster, MachineDeployment, etc.)
   - KubeadmControlPlane includes postKubeadmCommands that:
     a. Makes outbound HTTPS call to management cluster (registration webhook)
     b. Management cluster responds with agent bootstrap payload
     c. Agent is installed and starts
   - Agent establishes persistent outbound gRPC bidirectional stream to management cluster

3. Pivot Phase
   - Management cluster sends pivot command over existing gRPC stream
   - Agent exports CAPI resources from management cluster (via gRPC stream)
   - Agent imports CAPI resources locally
   - Agent confirms pivot complete over gRPC stream

4. Result
   - Workload cluster is fully self-managing
   - Agent maintains persistent outbound gRPC stream for:
     - Heartbeat/health reporting
     - Receiving commands from management cluster
     - Status updates
   - Management cluster no longer holds CAPI state for this cluster
```

### Network Architecture: Outbound-Only

**CRITICAL**: Workload clusters NEVER accept inbound connections. All communication is outbound.

**ClusterResourceSets (CRS) are ONLY used during installation** (bootstrap kind cluster → management cluster). For all runtime cluster provisioning, use kubeadm postKubeadmCommands webhook.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Management Cluster (Cell)                   │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                      Lattice                              │ │
│  │  - Operator: watches LatticeCluster CRDs, provisions new  │ │
│  │  - gRPC Server: accepts agent connections (bidirectional) │ │
│  │  - Registration Webhook: receives kubeadm callbacks       │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌─────────────┐                                               │
│  │    CAPI     │  (holds CAPI state until pivot)              │
│  └─────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
         ▲                                      ▲
         │ (1) kubeadm postKubeadmCommands      │ (2) persistent gRPC stream
         │     calls registration webhook       │     for bootstrap + pivot
         │     → returns agent bootstrap        │
         │                                      │
┌────────┴──────────────────────────────────────┴─────────────────┐
│                     Workload Cluster                            │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                      Lattice                              │ │
│  │  - Operator: watches OWN LatticeCluster CRD, self-manages │ │
│  │  - Agent: outbound gRPC stream to parent cell             │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌─────────────┐                                               │
│  │    CAPI     │  (post-pivot, manages own lifecycle)         │
│  └─────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Runtime Cluster Provisioning Flow (Detail)

```
1. User creates LatticeCluster CRD on management cluster

2. Lattice operator generates CAPI manifests with KubeadmControlPlane:
   - postKubeadmCommands includes curl to management cluster webhook
   - Webhook URL: https://<cell-host>/api/clusters/register

3. CAPI provisions infrastructure, kubeadm runs:
   - postKubeadmCommands calls webhook (OUTBOUND from new cluster)
   - Webhook returns: agent manifest + bootstrap token + parent gRPC endpoint
   - Agent installed, Cilium installed

4. Agent starts, establishes gRPC stream to parent (OUTBOUND):
   - Calls Connect() RPC, establishing bidirectional stream
   - Sends AgentReady message
   - Cell sends BootstrapCommand (remaining GitOps setup via Flux)
   - Agent sends BootstrapComplete message

5. Cell triggers pivot:
   - Exports CAPI resources for this cluster
   - Sends PivotCommand over gRPC stream with CAPI resources
   - Agent imports CAPI resources via clusterctl move
   - Agent sends PivotComplete message

6. Cluster is now self-managing:
   - Local LatticeCluster CRD is source of truth
   - Local CAPI reconciles cluster state
   - gRPC stream to parent is optional (health/monitoring only)
```

### Hierarchical Topology (Design for Future, v1 is Flat)

**v1 Implementation**: Single management cluster → workload clusters (flat topology)

**Future-proof design**: Architecture supports hierarchy where any cluster can become a "cell" (point of creation for child clusters).

```
                    Root Management Cluster
                    (cell: true)
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
      Regional Cell   Regional Cell   Workload Cluster
      (cell: true)    (cell: true)    (has CAPI, self-managing)
            │              │
      ┌─────┴─────┐   ┌────┴────┐
      ▼           ▼   ▼         ▼
   Workload   Workload  Workload  Workload
   Cluster    Cluster   Cluster   Cluster
```

**ALL clusters have after pivot**:
- **Lattice** (single binary - operator + agent combined)
- **CAPI** (for self-management - scaling, upgrades, node replacement)

**Lattice runs on every cluster and**:
- Watches its OWN `LatticeCluster` CRD and reconciles changes (add/remove nodes, scale, upgrade)
- Maintains outbound gRPC stream connection to parent cluster
- Reports health/heartbeat to parent

**Cell vs Leaf distinction**:
- **Cell** (`spec.cell` present): ALSO watches for NEW `LatticeCluster` CRDs and provisions child clusters
- **Leaf** (no `spec.cell`): Only manages itself, does not create new clusters

**Design principles to avoid boxing in**:
- `spec.cellRef` points to parent cluster (don't hardcode root)
- Agent connects to its direct parent, not a global endpoint
- Pivot logic doesn't assume single management cluster
- All clusters are structurally identical post-pivot (cell just has "create new clusters" mode enabled)

### Why Outbound-Only Matters

- **Firewall friendly**: Works behind corporate firewalls and NAT
- **Security**: No open ports on workload clusters to attack
- **Air-gapped compatible**: Only need egress to management cluster
- **Cloud agnostic**: Works regardless of cloud provider networking

### Why Pivoting Matters

- **No external dependencies**: Workload clusters don't depend on the management cluster for survival
- **Disaster recovery**: Each cluster can rebuild itself from its own state
- **Scalability**: Management cluster doesn't become a bottleneck as cluster count grows
- **Air-gapped support**: Workload clusters operate independently once provisioned
- **Blast radius**: Management cluster failure doesn't take down workload clusters

### Implementation Requirements

1. **CAPI Integration**: Use Cluster API for infrastructure abstraction
2. **clusterctl move**: Leverage `clusterctl move --to-directory` and `--from-directory` for resource export/import
3. **Registration Webhook**: HTTP endpoint on management cluster for kubeadm postKubeadmCommands to call
4. **Agent Architecture**: Lightweight agent on each cluster for:
   - Initiating outbound gRPC bidirectional stream to parent cluster
   - Heartbeat/health reporting via stream
   - Receiving pivot commands via stream
   - Local CAPI reconciliation after pivot
5. **Self-Healing**: Each cluster must be able to reconcile its own CAPI state post-pivot
6. **Idempotent Pivot**: Pivot operation must be safe to retry on failure
7. **Hierarchical Support**: Agent must connect to `spec.cellRef` parent, not hardcoded root

---

## Implementation Order (Minimal Surface First)

Implement CRDs in this order. **Do not move to the next CRD until the current one is fully implemented with E2E tests and meets coverage requirements.**

### Phase 1: LatticeCluster (Current Focus)
```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: mgmt
spec:
  provider:
    type: docker  # docker, aws, gcp, azure
    kubernetes:
      version: "1.35.0"
      certSANs: [...]
  nodes:
    controlPlane: 1
    workers: 2
  networking:
    default:
      cidr: "172.18.255.1/32"
  endpoints:  # If present, this cluster can have children
    host: 172.18.255.1
    service:
      type: LoadBalancer
```

**LatticeCluster must support**:
- Cluster provisioning via CAPI
- Node topology (control plane + workers)
- Provider abstraction (start with docker, then cloud providers)
- Networking configuration (Cilium LB-IPAM pools)
- Self-management via pivot
- Status tracking (Pending -> Provisioning -> Pivoting -> Ready -> Failed)

### Phase 2: LatticeEnvironment
- Environment definitions (prod, staging, dev)
- Cluster-to-environment mapping
- Namespace isolation

### Phase 3: LatticeServiceRegistration
- GitOps-based service deployment
- Flux integration (GitRepository + Kustomization)

### Phase 4: LatticeService
- Workload definitions (Score-compatible)
- Deployment strategies (rolling, canary)
- Service mesh integration

### Phase 5+: Supporting CRDs
- LatticeServiceConfig
- LatticeSecretBindings
- LatticeImageRegistry
- LatticeExternalService

---

## Rust Best Practices

### Project Structure
```
src/
├── lib.rs              # Library root
├── main.rs             # Binary entry point
├── crd/                # CRD definitions (use kube-derive)
│   ├── mod.rs
│   ├── cluster.rs      # LatticeCluster
│   └── ...
├── controller/         # Reconciliation logic
│   ├── mod.rs
│   ├── cluster.rs      # Cluster controller
│   └── ...
├── provider/           # Infrastructure providers
│   ├── mod.rs
│   ├── docker.rs
│   ├── aws.rs
│   └── ...
├── pivot/              # Pivoting logic
│   ├── mod.rs
│   ├── export.rs
│   └── import.rs
├── agent/              # Agent implementation
│   └── ...
└── error.rs            # Error types
```

### Dependencies (Recommended)
```toml
[dependencies]
# Kubernetes
kube = { version = "0.98", features = ["runtime", "derive", "client", "rustls-tls"] }
k8s-openapi = { version = "0.24", features = ["v1_32"] }

# Async runtime
tokio = { version = "1.43", features = ["full"] }

# Concurrency
crossbeam = "0.8"              # Scoped threads, lock-free structures
dashmap = "6.1"                # Concurrent HashMap
parking_lot = "0.12"           # Faster sync locks (for CPU-bound contexts)

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# Logging/tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# gRPC (for agent-cell communication)
tonic = { version = "0.13", features = ["tls", "transport"] }
prost = "0.13"
prost-types = "0.13"

# HTTP (for registration webhook)
axum = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }

# FIPS-validated crypto (see FIPS section)
rustls = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std"] }
aws-lc-rs = { version = "1.12", features = ["fips"] }

# Async utilities
async-trait = "0.1"
futures = "0.3"

# CLI
clap = { version = "4.5", features = ["derive"] }
```

### Code Style

1. **Error Handling**
   - Use `thiserror` for library errors with proper error types
   - Use `anyhow` sparingly, prefer typed errors
   - Never panic in library code; return `Result`
   - Use `?` operator, avoid `.unwrap()` except in tests

2. **Async Patterns**
   - Use `tokio` as the async runtime
   - Prefer `async fn` over manual futures
   - Use `tokio::select!` for concurrent operations
   - Implement graceful shutdown with cancellation tokens

3. **Type Safety**
   - Use newtypes for domain concepts (e.g., `ClusterName(String)`)
   - Leverage the type system to make invalid states unrepresentable
   - Use `#[non_exhaustive]` on public enums
   - Prefer `&str` over `String` in function signatures where possible

4. **Documentation**
   - Document all public APIs with `///` doc comments
   - Include examples in doc comments where helpful
   - Use `#![deny(missing_docs)]` in lib.rs

5. **Lifetimes and Borrowing**
   - Prefer borrowing over cloning
   - Use `Cow<'_, str>` when ownership is conditional
   - Avoid `'static` lifetimes unless truly needed

6. **Concurrency** (tokio async OR crossbeam)

   **Use tokio async for**:
   - I/O-bound operations (K8s API calls, gRPC, HTTP)
   - Controller reconciliation loops
   - Timers and delays
   - Channel-based message passing between tasks

   **Use crossbeam for**:
   - CPU-bound parallel processing
   - Lock-free data structures
   - Scoped threads when async isn't needed
   - High-performance concurrent queues

   ```rust
   // tokio for async I/O and coordination
   use tokio::sync::{mpsc, oneshot, RwLock, Mutex};
   use tokio::select;

   // crossbeam for CPU-bound work and lock-free structures
   use crossbeam::channel;          // Multi-producer multi-consumer
   use crossbeam::queue::ArrayQueue; // Lock-free bounded queue
   use crossbeam::scope;            // Scoped threads

   // Shared state patterns
   use std::sync::Arc;
   use tokio::sync::RwLock;         // Async-aware for I/O contexts
   use parking_lot::RwLock;         // Sync, faster for CPU-bound (with crossbeam)
   use dashmap::DashMap;            // Concurrent HashMap (either context)
   ```

   **Guidelines**:
   - Prefer message passing (`mpsc`, `oneshot`, crossbeam channels) over shared state
   - Use `Arc<RwLock<T>>` when shared state is necessary
   - Never hold locks across `.await` points (use tokio's async locks if needed)
   - Use `tokio::spawn` for concurrent async tasks
   - Use `crossbeam::scope` for parallel CPU work that needs to borrow data
   - For concurrent HashMaps, use `DashMap` (works in both async and sync contexts)

---

## FIPS Validation Requirements

**All cryptographic operations MUST use FIPS 140-2/140-3 validated implementations from day one.**

### Approved Libraries

1. **TLS**: Use `rustls` with `aws-lc-rs` (FIPS-validated) as the crypto provider
   ```toml
   rustls = { version = "...", features = ["aws-lc-rs"] }
   aws-lc-rs = { version = "...", features = ["fips"] }
   ```

2. **Hashing**: Use FIPS-approved algorithms only (SHA-256, SHA-384, SHA-512)
   - NO MD5, NO SHA-1 for security purposes

3. **Encryption**: AES-GCM or AES-CBC with HMAC
   - Use `aws-lc-rs` or `ring` with FIPS features

4. **Key Exchange**: ECDH with P-256, P-384, or X25519 (if FIPS-approved in your context)

5. **Signatures**: ECDSA with P-256/P-384 or RSA (2048+ bits)

### What to Avoid

- `ring` without FIPS features
- Pure Rust crypto implementations (dalek, etc.) unless FIPS-validated
- OpenSSL (unless specifically using FIPS module)
- Any algorithm not on NIST approved list

### Verification

- Document which FIPS certificate covers each crypto operation
- Include FIPS compliance in CI checks
- Test with FIPS-only mode enabled

---

## Test-Driven Development (TDD) Requirements

**MANDATORY: Every feature MUST be developed using TDD. No exceptions.**

### Coverage Requirements

**Target: 90-100% coverage. This is the goal for all code.**

**Hard Stop at 80%: If coverage drops below 80%, ALL implementation work MUST STOP until coverage is restored.**

| Category | Target | Hard Stop (work stops) |
|----------|--------|------------------------|
| Overall codebase | 90-100% | < 80% |
| Critical paths (pivot, provisioning, CAPI) | 95%+ | < 90% |
| New features | 90%+ before merge | < 90% |

The 80% threshold is not a target - it's the emergency brake. Aim for 90%+ on all code.

**CI must enforce these thresholds. PRs failing coverage checks cannot be merged.**

### Test Categories

1. **Unit Tests** (`#[cfg(test)]` modules)
   - Test individual functions and methods
   - Mock external dependencies
   - Fast execution (< 1 second per test)
   - Located alongside source code
   - Run with: `cargo test --lib`

2. **Integration Tests** (`tests/` directory)
   - Test module interactions
   - Use test fixtures and helpers
   - May use testcontainers for dependencies
   - Run with: `cargo test --test '*'`

3. **E2E Tests** (`tests/e2e/` directory)
   - Test complete workflows against real kind clusters
   - Test the full pivot flow end-to-end
   - Every user-facing feature needs at least one E2E test
   - Run with: `cargo test --test 'e2e_*'` or dedicated script

### TDD Workflow

```
1. Write a failing test that describes the desired behavior
2. Run the test - confirm it fails (RED)
3. Write minimal code to make the test pass
4. Run the test - confirm it passes (GREEN)
5. Refactor while keeping tests green (REFACTOR)
6. Check coverage - must stay above 80%
7. Repeat
```

**If you find yourself writing implementation code without a failing test first, STOP and write the test.**

### Mocking Libraries

Use these libraries for mocking and test utilities:

```toml
[dev-dependencies]
# Primary mocking library - generates mocks from traits
mockall = "0.13"

# Property-based testing
proptest = "1.5"

# Test fixtures and parameterized tests
rstest = "0.23"

# Async test utilities
tokio-test = "0.4"

# Containers for integration tests (PostgreSQL, kind clusters, etc.)
testcontainers = "0.23"

# Snapshot testing for complex outputs
insta = "1.41"

# Fake data generation
fake = { version = "3.0", features = ["derive"] }

# Coverage reporting
cargo-llvm-cov = "0.6"  # Install via: cargo install cargo-llvm-cov
```

### Mocking Strategy

```rust
use mockall::automock;
use async_trait::async_trait;

// 1. Define traits for external dependencies
#[cfg_attr(test, automock)]
#[async_trait]
pub trait KubeClient: Send + Sync {
    async fn get<T: Resource>(&self, name: &str, namespace: Option<&str>) -> Result<T>;
    async fn apply<T: Resource>(&self, resource: &T) -> Result<()>;
    async fn delete<T: Resource>(&self, name: &str, namespace: Option<&str>) -> Result<()>;
    async fn list<T: Resource>(&self, namespace: Option<&str>) -> Result<Vec<T>>;
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait CAPIClient: Send + Sync {
    async fn export_cluster(&self, name: &str, namespace: &str) -> Result<CAPIResources>;
    async fn import_cluster(&self, resources: &CAPIResources) -> Result<()>;
}

// 2. Use dependency injection
pub struct ClusterController<K: KubeClient, C: CAPIClient> {
    kube: K,
    capi: C,
}

// 3. In tests, inject mocks
#[tokio::test]
async fn test_reconcile_creates_capi_resources() {
    let mut mock_kube = MockKubeClient::new();
    let mut mock_capi = MockCAPIClient::new();

    mock_kube.expect_get::<LatticeCluster>()
        .returning(|_, _| Ok(sample_cluster()));

    mock_capi.expect_export_cluster()
        .times(1)
        .returning(|_, _| Ok(CAPIResources::default()));

    let controller = ClusterController::new(mock_kube, mock_capi);
    let result = controller.reconcile("test-cluster").await;

    assert!(result.is_ok());
}
```

### Test Fixtures with rstest

```rust
use rstest::{fixture, rstest};

#[fixture]
fn sample_cluster() -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some("test-cluster".to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec { type_: "docker".to_string(), .. },
            nodes: NodeSpec { control_plane: 1, workers: 2 },
            ..Default::default()
        },
        status: None,
    }
}

#[rstest]
#[case("docker", true)]
#[case("aws", true)]
#[case("invalid", false)]
fn test_provider_validation(#[case] provider: &str, #[case] expected_valid: bool) {
    let result = ProviderSpec::validate(provider);
    assert_eq!(result.is_ok(), expected_valid);
}
```

### Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn cluster_name_validation(name in "[a-z][a-z0-9-]{0,62}") {
        // Valid DNS names should always pass
        assert!(ClusterName::try_from(name).is_ok());
    }

    #[test]
    fn invalid_cluster_names_rejected(name in "[A-Z_!@#$%]+") {
        // Invalid characters should always fail
        assert!(ClusterName::try_from(name).is_err());
    }

    #[test]
    fn node_count_always_positive(cp in 1..10u32, workers in 0..100u32) {
        let spec = NodeSpec { control_plane: cp, workers };
        assert!(spec.total_nodes() > 0);
    }
}
```

### Coverage Commands

```bash
# Run tests with coverage
cargo llvm-cov --all-features --workspace

# Generate HTML report
cargo llvm-cov --all-features --workspace --html

# Fail if coverage below threshold (for CI)
cargo llvm-cov --all-features --workspace --fail-under-lines 80

# Show uncovered lines
cargo llvm-cov --all-features --workspace --show-missing-lines
```

---

## Controller Reconciliation Pattern

Follow the Kubernetes controller pattern with these principles:

### Reconciliation Loop

```rust
async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action> {
    // 1. Observe current state
    let current_state = observe_cluster(&cluster, &ctx).await?;

    // 2. Determine desired state
    let desired_state = compute_desired_state(&cluster)?;

    // 3. Calculate diff
    let actions = diff_states(&current_state, &desired_state);

    // 4. Apply changes (one step at a time for idempotency)
    for action in actions {
        apply_action(&action, &ctx).await?;
    }

    // 5. Update status
    update_status(&cluster, &current_state, &ctx).await?;

    // 6. Requeue if needed
    Ok(Action::requeue(Duration::from_secs(60)))
}
```

### Status Conditions

Use standard Kubernetes conditions:

```rust
pub struct ClusterCondition {
    pub type_: ConditionType,      // Ready, Provisioning, Pivoting, etc.
    pub status: ConditionStatus,    // True, False, Unknown
    pub reason: String,             // MachineCode for the condition
    pub message: String,            // Human-readable message
    pub last_transition_time: DateTime<Utc>,
}
```

### Error Handling in Controllers

```rust
fn error_policy(cluster: Arc<LatticeCluster>, error: &Error, _ctx: Arc<Context>) -> Action {
    // Log the error
    tracing::error!(?error, cluster = %cluster.name_any(), "reconciliation failed");

    // Exponential backoff
    Action::requeue(Duration::from_secs(5))
}
```

---

## Agent-Cell Communication

### gRPC Protocol (mTLS)

Agent initiates outbound gRPC bidirectional stream to parent cell. **All traffic is outbound from workload clusters.**

The gRPC stream is used for:
1. **Pivot orchestration** - Cell pushes PivotCommand with CAPI resources
2. **Bootstrap coordination** - After kubeadm webhook installs agent, remaining bootstrap pushed via stream
3. **Health/status reporting** - Agent pushes health UP to cell (optional, for UI/monitoring)

### Protocol Definition

```protobuf
syntax = "proto3";
package lattice.agent.v1;

// LatticeAgent service - agent connects to cell
service LatticeAgent {
  // Bidirectional stream for agent-cell communication
  // Agent initiates the connection (outbound from workload cluster)
  rpc Connect(stream AgentMessage) returns (stream CellCommand);
}

// Messages from Agent to Cell
message AgentMessage {
  string cluster_name = 1;
  oneof payload {
    AgentReady ready = 2;
    BootstrapComplete bootstrap_complete = 3;
    PivotComplete pivot_complete = 4;
    Heartbeat heartbeat = 5;
    ClusterHealth cluster_health = 6;
  }
}

message AgentReady {
  string agent_version = 1;
  string kubernetes_version = 2;
}

message BootstrapComplete {}

message PivotComplete {
  bool success = 1;
  string error_message = 2;  // Only set if success=false
}

message Heartbeat {
  AgentState state = 1;
  google.protobuf.Timestamp timestamp = 2;
}

message ClusterHealth {
  int32 ready_nodes = 1;
  int32 total_nodes = 2;
  repeated string conditions = 3;
}

enum AgentState {
  AGENT_STATE_UNKNOWN = 0;
  AGENT_STATE_PROVISIONING = 1;
  AGENT_STATE_PIVOTING = 2;
  AGENT_STATE_READY = 3;
  AGENT_STATE_DEGRADED = 4;
  AGENT_STATE_FAILED = 5;
}

// Commands from Cell to Agent
message CellCommand {
  oneof command {
    BootstrapCommand bootstrap = 1;
    PivotCommand pivot = 2;
    ReconcileCommand reconcile = 3;
    StatusRequest status_request = 4;
  }
}

message BootstrapCommand {
  // Flux GitRepository and Kustomization specs
  bytes flux_manifests = 1;
}

message PivotCommand {
  string cluster_name = 1;
  string capi_namespace = 2;
  // Serialized CAPI resources (Cluster, MachineDeployment, etc.)
  bytes capi_resources = 3;
}

message ReconcileCommand {
  // Trigger Flux reconciliation
}

message StatusRequest {
  // Request current cluster status
}
```

### Critical Design: Independence from Parent

**Every cluster MUST be 100% operational even if the parent cell is deleted.**

The gRPC stream to parent is for:
- Coordination during provisioning/pivot
- Optional health reporting for UI/monitoring
- Receiving optional commands (reconcile, etc.)

It is NOT required for:
- Self-management (scaling, upgrades, node replacement)
- CAPI reconciliation
- Running workloads
- Any critical cluster operations

If parent cell disappears:
- Agent logs warnings but continues operating
- Cluster continues self-managing via local CAPI
- Local LatticeCluster CRD is the source of truth
- No functionality loss except parent visibility

### Heartbeat State Machine

```
Agent States:
- Provisioning: Cluster infrastructure being created
- Pivoting: CAPI resources being imported
- Ready: Cluster operational and self-managing
- Degraded: Cluster has issues but operational
- Failed: Cluster in failed state
```

---

## File References

- **CRD Schema**: `/Users/evanhines/lattice/lattice-config/system/crds/lattice-crds.yaml`
- **Cluster Example**: `/Users/evanhines/lattice/lattice-config/clusters/mgmt/cluster.yaml`
- **Elixir POC Controllers**: `/Users/evanhines/lattice/lattice/apps/lattice_operator/lib/lattice_operator/controllers/`
- **Elixir Pivot Logic**: `/Users/evanhines/lattice/lattice/apps/lattice_agent/lib/lattice_agent/pivot_manager.ex`
- **Package Definitions**: `/Users/evanhines/lattice/lattice-config/packages/`

---

## Development Checklist

Before considering any feature complete:

- [ ] All tests written first (TDD)
- [ ] Unit test coverage >= 80%
- [ ] Integration tests passing
- [ ] At least one E2E test for the feature
- [ ] No `unwrap()` or `expect()` in non-test code (use proper error handling)
- [ ] All crypto uses FIPS-validated implementations
- [ ] Documentation complete (doc comments + any needed docs/)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code formatted (`cargo fmt`)
- [ ] Feature works in air-gapped scenario (no external runtime dependencies)

---

## Quick Reference: kube-rs Patterns

### CRD Definition
```rust
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeCluster",
    plural = "latticeclusters",
    shortname = "lc",
    status = "LatticeClusterStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#
)]
pub struct LatticeClusterSpec {
    pub provider: ProviderSpec,
    pub nodes: NodeSpec,
    pub networking: Option<NetworkingSpec>,
    pub cell: Option<ParentSpec>,
}
```

### Controller Setup
```rust
Controller::new(clusters, Config::default())
    .owns(machines, Config::default())
    .shutdown_on_signal()
    .run(reconcile, error_policy, ctx)
    .for_each(|res| async move {
        match res {
            Ok(o) => tracing::info!("reconciled {:?}", o),
            Err(e) => tracing::error!("reconcile failed: {:?}", e),
        }
    })
    .await;
```
