<p align="center">
  <img src="https://raw.githubusercontent.com/lattice-dev/lattice/main/docs/assets/lattice-logo.svg" alt="Lattice Logo" width="400">
</p>

<h1 align="center">Lattice</h1>

<p align="center">
  <strong>Self-Managing Kubernetes Clusters at Scale</strong>
</p>

<p align="center">
  <em>A CRD-driven operator for multi-cluster lifecycle management with automatic pivoting</em>
</p>

<p align="center">
  <a href="https://github.com/lattice-dev/lattice/actions"><img src="https://img.shields.io/github/actions/workflow/status/lattice-dev/lattice/ci.yml?branch=main&style=for-the-badge&logo=github&label=Build" alt="Build Status"></a>
  <a href="https://codecov.io/gh/lattice-dev/lattice"><img src="https://img.shields.io/codecov/c/github/lattice-dev/lattice?style=for-the-badge&logo=codecov&label=Coverage" alt="Coverage"></a>
  <a href="https://github.com/lattice-dev/lattice/releases"><img src="https://img.shields.io/github/v/release/lattice-dev/lattice?style=for-the-badge&logo=semantic-release&label=Release" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge&logo=apache" alt="License"></a>
</p>

<p align="center">
  <a href="https://kubernetes.io"><img src="https://img.shields.io/badge/Kubernetes-1.32+-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/Rust-2021-DEA584?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"></a>
  <a href="https://cilium.io"><img src="https://img.shields.io/badge/Cilium-Powered-F8C517?style=for-the-badge&logo=cilium&logoColor=black" alt="Cilium"></a>
  <a href="#fips-compliance"><img src="https://img.shields.io/badge/FIPS_140--3-Validated-00843D?style=for-the-badge&logo=nist&logoColor=white" alt="FIPS"></a>
</p>

---

## The Problem

Managing fleets of Kubernetes clusters creates **operational bottlenecks**:

- **Single point of failure**: Management clusters become critical infrastructure
- **Network complexity**: Inbound connections require complex firewall rules
- **Scaling limits**: Central control planes struggle with hundreds of clusters
- **Blast radius**: Management plane failures cascade to all managed clusters

## The Lattice Solution

Lattice provisions clusters that **manage themselves**. Each cluster receives its own Cluster API installation through an automated **pivot** process, eliminating dependency on centralized management.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│    1. PROVISION           2. PIVOT              3. SELF-MANAGE             │
│                                                                             │
│    ┌──────────┐          ┌──────────┐          ┌──────────┐                │
│    │   Cell   │ ──CAPI──▶│ Workload │ ◀─CAPI──▶│ Workload │                │
│    │ (Parent) │          │ Cluster  │          │ Cluster  │                │
│    └──────────┘          └──────────┘          └──────────┘                │
│         │                      │                     │                      │
│    Holds CAPI state      Receives CAPI         Owns its own                │
│    temporarily           resources             lifecycle                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### Self-Managing Clusters

Every cluster provisioned by Lattice becomes **fully autonomous**. After pivoting, clusters can scale nodes, upgrade Kubernetes versions, and recover from failures—all without phoning home.

### Outbound-Only Networking

Workload clusters never accept inbound connections. All communication flows **outbound** via persistent gRPC streams. Works behind NAT, corporate firewalls, and in air-gapped environments.

### Declarative Everything

Define your entire multi-cluster topology with CRDs:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: prod-us-west
spec:
  provider:
    type: aws
    kubernetes:
      version: "1.32.0"
  nodes:
    controlPlane: 3
    workers: 10
  cellRef: management
```

### Service Mesh Integration

First-class support for **Cilium** and **Istio**. Declare service dependencies and Lattice generates network policies automatically:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  image: myregistry/api-gateway:v2
  replicas: 3
  dependencies:
    - name: auth-service
      ports: [8080]
    - name: user-service
      ports: [8080]
  allowedCallers:
    - ingress-controller
```

### FIPS 140-3 Compliance

All cryptographic operations use **FIPS-validated** implementations via AWS-LC. Ready for FedRAMP, HIPAA, and government deployments out of the box.

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │          Management Cell                │
                         │  ┌─────────────────────────────────┐   │
                         │  │           Lattice               │   │
                         │  │  • Operator (watch CRDs)        │   │
                         │  │  • gRPC Server (agent streams)  │   │
                         │  │  • Webhook (kubeadm callbacks)  │   │
                         │  └─────────────────────────────────┘   │
                         │  ┌─────────┐  ┌─────────┐             │
                         │  │  CAPI   │  │ Cilium  │             │
                         │  └─────────┘  └─────────┘             │
                         └──────────────────┬──────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
              ▼                             ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│    Workload Cluster     │   │    Workload Cluster     │   │    Workload Cluster     │
│         (AWS)           │   │         (GCP)           │   │        (Azure)          │
│  ┌───────────────────┐  │   │  ┌───────────────────┐  │   │  ┌───────────────────┐  │
│  │      Lattice      │  │   │  │      Lattice      │  │   │  │      Lattice      │  │
│  │  Agent ──────────────────────────────────────────────────────▶ gRPC Stream   │  │
│  │  Operator (self)  │  │   │  │  Operator (self)  │  │   │  │  Operator (self)  │  │
│  └───────────────────┘  │   │  └───────────────────┘  │   │  └───────────────────┘  │
│  ┌───────┐ ┌────────┐   │   │  ┌───────┐ ┌────────┐   │   │  ┌───────┐ ┌────────┐   │
│  │ CAPI  │ │ Cilium │   │   │  │ CAPI  │ │ Cilium │   │   │  │ CAPI  │ │ Cilium │   │
│  └───────┘ └────────┘   │   │  └───────┘ └────────┘   │   │  └───────┘ └────────┘   │
└─────────────────────────┘   └─────────────────────────┘   └─────────────────────────┘
         ▲                             ▲                             ▲
         │                             │                             │
         └─────── Each cluster manages its own lifecycle ────────────┘
```

---

## Quick Start

### Prerequisites

- Docker 20.10+ with 8GB+ RAM available
- kubectl configured
- Rust 1.75+ (for building from source)

### Installation

```bash
# Install the Lattice CLI
curl -sSL https://get.lattice.dev | bash

# Bootstrap a management cluster (uses kind for local development)
lattice install --provider docker --name mgmt

# The installer will:
# 1. Create a temporary bootstrap cluster
# 2. Provision your management cluster
# 3. Pivot CAPI resources to the management cluster
# 4. Clean up the bootstrap cluster
```

### Create Your First Workload Cluster

```bash
# Apply a cluster definition
kubectl apply -f - <<EOF
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: dev-cluster
spec:
  provider:
    type: docker
    kubernetes:
      version: "1.32.0"
  nodes:
    controlPlane: 1
    workers: 2
  cellRef: mgmt
EOF

# Watch the provisioning progress
kubectl get latticeclusters -w

# Once Ready, the cluster is self-managing!
```

---

## Custom Resource Definitions

| CRD | Description | Status |
|-----|-------------|--------|
| `LatticeCluster` | Kubernetes cluster lifecycle | Stable |
| `LatticeService` | Workload deployment with dependency graph | Beta |
| `LatticeExternalService` | External service registration | Beta |
| `LatticeEnvironment` | Environment definitions | Alpha |
| `LatticeServiceConfig` | Configuration injection | Planned |

---

## Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Docker (CAPD) | Stable | Local development and testing |
| AWS (CAPA) | Beta | EKS and self-managed |
| GCP (CAPG) | Alpha | GKE and self-managed |
| Azure (CAPZ) | Alpha | AKS and self-managed |
| vSphere (CAPV) | Planned | On-premises deployments |

---

## How Pivoting Works

The pivot process transfers cluster ownership from parent to child:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           PIVOT SEQUENCE                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Cell provisions cluster via CAPI                                     │
│     └── Cluster, MachineDeployment, Machines created                    │
│                                                                          │
│  2. kubeadm completes, calls Cell webhook (OUTBOUND)                    │
│     └── Cell returns agent manifest + bootstrap token                   │
│                                                                          │
│  3. Agent starts, opens gRPC stream to Cell (OUTBOUND)                  │
│     └── Bidirectional stream for commands/status                        │
│                                                                          │
│  4. Cell executes pivot via clusterctl                                   │
│     └── clusterctl move --to-kubeconfig <agent-proxy>                   │
│                                                                          │
│  5. CAPI resources transferred directly to workload cluster             │
│     └── Uses K8s API proxy through agent gRPC stream                    │
│                                                                          │
│  6. Agent detects CAPI resources, confirms pivot complete               │
│     └── Local CAPI reconciles, gRPC stream optional for monitoring      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**After pivot, the parent Cell can be deleted without affecting workload clusters.**

---

## Service Graph & Network Policies

Lattice builds a **dependency graph** from your service declarations and generates least-privilege network policies:

```yaml
# Declare what your service needs
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: order-service
spec:
  dependencies:
    - name: inventory-db
      type: external
      ports: [5432]
    - name: payment-service
      ports: [443]
  allowedCallers:
    - api-gateway
    - admin-dashboard
```

Lattice automatically generates:
- **CiliumNetworkPolicy** or **AuthorizationPolicy** (Istio)
- Bilateral validation (both caller and callee must agree)
- Automatic policy updates when dependencies change

---

## Configuration

### Operator Flags

```bash
lattice operator \
  --metrics-addr=:8080 \
  --health-addr=:8081 \
  --leader-elect=true \
  --cell-host=lattice.example.com \
  --cell-port=9443
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LATTICE_LOG_LEVEL` | Log verbosity (trace, debug, info, warn, error) | `info` |
| `LATTICE_METRICS_PORT` | Prometheus metrics port | `8080` |
| `LATTICE_CELL_HOST` | Cell gRPC endpoint hostname | Required for cells |
| `LATTICE_TLS_CERT` | Path to TLS certificate | `/etc/lattice/tls/tls.crt` |
| `LATTICE_TLS_KEY` | Path to TLS private key | `/etc/lattice/tls/tls.key` |

---

## Observability

### Metrics

Lattice exposes Prometheus metrics at `/metrics`:

```promql
# Cluster provisioning duration
lattice_cluster_provision_duration_seconds{cluster="prod-us-west"}

# Active agent connections
lattice_agent_connections_active{cell="mgmt"}

# Pivot success rate
rate(lattice_pivot_total{status="success"}[5m])
```

### Tracing

OpenTelemetry traces are exported for:
- Reconciliation loops
- gRPC agent communication
- CAPI operations
- Pivot sequences

---

## FIPS Compliance

Lattice uses **aws-lc-rs** with FIPS 140-3 validated cryptography:

- TLS 1.3 with FIPS-approved cipher suites
- ECDSA P-256/P-384 for certificates
- AES-256-GCM for encryption at rest
- SHA-256/SHA-384 for hashing

Build with FIPS mode:

```bash
cargo build --release --features fips
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone the repository
git clone https://github.com/lattice-dev/lattice.git
cd lattice

# Run tests
cargo test

# Run with coverage
cargo llvm-cov --html

# Run E2E tests (requires Docker)
cargo test --features e2e
```

---

## Roadmap

- [x] LatticeCluster provisioning and pivot
- [x] Docker provider (CAPD)
- [x] Service graph and network policies
- [x] Cilium integration
- [ ] AWS provider (CAPA)
- [ ] Hierarchical cells (nested management)
- [ ] GitOps integration (Flux)
- [ ] Web UI dashboard
- [ ] Multi-tenancy

---

## Community

- **GitHub Discussions**: [github.com/lattice-dev/lattice/discussions](https://github.com/lattice-dev/lattice/discussions)
- **Slack**: [#lattice on Kubernetes Slack](https://kubernetes.slack.com/channels/lattice)
- **Twitter**: [@lattaborhood](https://twitter.com/latticedev)

---

## License

Lattice is licensed under the [Apache License 2.0](LICENSE).

---

<p align="center">
  <sub>Built with Rust, powered by Cluster API, secured by Cilium</sub>
</p>
