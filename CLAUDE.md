# Lattice Operator - CLAUDE.md

## Project Overview

Lattice is a Kubernetes operator for multi-cluster lifecycle management. It provisions clusters via CAPI and makes them **fully self-managing** through a pivoting architecture. After pivot, each cluster owns its CAPI resources and operates independently.

---

## Core Architecture: Self-Managed Clusters via Pivoting

**Every cluster provisioned by Lattice MUST become fully self-managed. This is non-negotiable.**

### Pivot Flow

```
1. Parent cluster creates LatticeCluster CRD
2. CAPI provisions infrastructure
3. kubeadm postKubeadmCommands calls parent's bootstrap webhook
4. Agent installed, establishes outbound gRPC stream to parent
5. Parent sends PivotCommand with CAPI resources over stream
6. Agent imports CAPI resources locally via clusterctl move
7. Cluster is now self-managing (parent can be deleted)
```

### Network Architecture: Outbound-Only

**Workload clusters NEVER accept inbound connections. All communication is outbound.**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Parent Cluster (Cell)                       │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Lattice Operator                                         │ │
│  │  - Watches LatticeCluster CRDs, provisions new clusters   │ │
│  │  - gRPC Server: accepts agent connections (bidirectional) │ │
│  │  - Bootstrap Webhook: kubeadm postKubeadmCommands target  │ │
│  │  - K8s API Proxy: streams watch requests to children      │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         ▲                                      ▲
         │ (1) kubeadm webhook call             │ (2) persistent gRPC stream
         │                                      │
┌────────┴──────────────────────────────────────┴─────────────────┐
│                     Child Cluster                               │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Lattice Operator                                         │ │
│  │  - Watches OWN LatticeCluster CRD, self-manages           │ │
│  │  - Agent: outbound gRPC stream to parent                  │ │
│  │  - CAPI: owns cluster lifecycle post-pivot                │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Independence from Parent

**Every cluster MUST be 100% operational even if the parent is deleted.**

The gRPC stream is for:
- Coordination during provisioning/pivot
- Optional health reporting
- K8s API proxy for parent visibility

It is NOT required for:
- Self-management (scaling, upgrades, node replacement)
- CAPI reconciliation
- Running workloads

### Why This Architecture

- **Outbound-only**: Firewall friendly, no attack surface on workload clusters
- **Self-managing**: Parent failure doesn't affect children
- **Scalable**: Parent doesn't become bottleneck as cluster count grows
- **Air-gapped**: Clusters operate independently once provisioned

---

## Security: Defense in Depth

### Service Mesh Bilateral Agreements

Traffic is only allowed when BOTH sides agree:
1. **Caller** declares outbound dependency (`resources.foo.direction: outbound`)
2. **Callee** allows inbound from caller (`resources.bar.direction: inbound`)

This generates:
- **Cilium CiliumNetworkPolicy** (L4 eBPF enforcement)
- **Istio AuthorizationPolicy** (L7 identity-based enforcement)

### Default-Deny Policies

- **Cilium**: `CiliumClusterwideNetworkPolicy` with no ingress rules (implicit deny)
- **Istio**: `AuthorizationPolicy` with empty `spec: {}` (deny all)
- System namespaces excluded: `kube-system`, `cilium-system`, `istio-system`, `lattice-system`, `cert-manager`, `capi-*`

### FIPS Requirements

All cryptographic operations MUST use FIPS 140-2/140-3 validated implementations:

```toml
rustls = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std"] }
aws-lc-rs = { version = "1.12", features = ["fips"] }
```

- TLS: `rustls` with `aws-lc-rs` backend
- Hashing: SHA-256/384/512 only (no MD5, no SHA-1)
- Signatures: ECDSA P-256/P-384 or RSA 2048+

---

## Rust Style Guide

### Error Handling

```rust
// Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("cluster not found: {0}")]
    NotFound(String),
    #[error("CAPI error: {0}")]
    Capi(#[from] CAPIError),
}

// Never panic in library code - return Result
// Use ? operator, avoid .unwrap() except in tests
```

### Async Patterns

```rust
// Use tokio for all async I/O
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::select;

// Prefer message passing over shared state
// Never hold locks across .await points
// Use cancellation tokens for graceful shutdown
```

### Type Safety

```rust
// Use newtypes for domain concepts
pub struct ClusterName(String);

// Make invalid states unrepresentable
pub enum ClusterPhase {
    Pending,
    Provisioning,
    Pivoting,
    Ready,
    Failed,
}

// Use #[non_exhaustive] on public enums
```

### Controller Pattern

```rust
async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action> {
    // 1. Observe current state
    let current = observe(&cluster, &ctx).await?;

    // 2. Compute desired state
    let desired = compute_desired(&cluster)?;

    // 3. Apply one change at a time (idempotent)
    if current != desired {
        apply_change(&current, &desired, &ctx).await?;
    }

    // 4. Update status
    update_status(&cluster, &ctx).await?;

    // 5. Requeue
    Ok(Action::requeue(Duration::from_secs(60)))
}
```

---

## Testing Requirements

### Coverage

- Target: 90%+ on all code
- Hard stop: Work halts if coverage drops below 80%
- Critical paths (pivot, provisioning): 95%+

### Test Categories

1. **Unit tests** (`#[cfg(test)]` modules) - Fast, mock dependencies
2. **Integration tests** (`tests/`) - Module interactions
3. **E2E tests** (`tests/kind_tests/`) - Full pivot flow against real clusters

### E2E Test Expectations

The E2E test (`pivot_e2e.rs`) validates:
- Bootstrap → management cluster pivot
- Management → workload cluster provisioning and pivot
- Workload cluster independence (delete parent, verify self-scaling)
- Service mesh bilateral agreements (exact match verification)
- Randomized large-scale mesh (20-30 services, 400+ connection tests)

---

## Agent-Cell Protocol

### gRPC Stream (mTLS, Outbound from Agent)

```protobuf
service LatticeAgent {
  rpc Connect(stream AgentMessage) returns (stream CellCommand);
}

// Agent → Cell
message AgentMessage {
  oneof payload {
    AgentReady ready = 1;
    PivotComplete pivot_complete = 2;
    Heartbeat heartbeat = 3;
  }
}

// Cell → Agent
message CellCommand {
  oneof command {
    PivotCommand pivot = 1;
    KubernetesRequest k8s_request = 2;
  }
}
```

### K8s API Proxy

Parent can access child's K8s API through the gRPC stream:
- Supports all verbs (get, list, watch, create, update, delete)
- Watch requests are streamed
- Path-based routing: `/clusters/{name}/api/...`

---

## Development Checklist

Before merging:

- [ ] Tests written first (TDD)
- [ ] Coverage >= 80% (target 90%+)
- [ ] No `.unwrap()` in non-test code
- [ ] All crypto uses FIPS implementations
- [ ] No clippy warnings
- [ ] Code formatted (`cargo fmt`)
