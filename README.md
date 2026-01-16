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

### Zero-Trust Service Mesh

Defense-in-depth with **bilateral agreements**. Traffic only flows when both caller and callee explicitly agree:

| Layer | Technology | Enforcement |
|-------|------------|-------------|
| L7 | Istio AuthorizationPolicy | mTLS identity-based (SPIFFE) |
| L4 | CiliumNetworkPolicy | eBPF kernel-level |
| Baseline | Default-Deny | Implicit deny-all at both layers |

### GitOps Native

Built-in Flux integration for declarative cluster and service management. Define your infrastructure in git, and Lattice keeps clusters in sync.

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
                         │  │  • K8s API Proxy                │   │
                         │  └─────────────────────────────────┘   │
                         │  ┌─────────┐  ┌─────────┐ ┌──────┐    │
                         │  │  CAPI   │  │ Cilium  │ │ Flux │    │
                         │  └─────────┘  └─────────┘ └──────┘    │
                         └──────────────────┬──────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
              ▼                             ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│    Workload Cluster     │   │    Workload Cluster     │   │    Workload Cluster     │
│         (AWS)           │   │      (Proxmox)          │   │      (OpenStack)        │
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
# Build the CLI and operator
cargo build --release

# Bootstrap a management cluster (uses kind for local development)
lattice install --config management.yaml

# The installer will:
# 1. Create a temporary bootstrap cluster
# 2. Provision your management cluster
# 3. Pivot CAPI resources to the management cluster
# 4. Clean up the bootstrap cluster
```

### Create a Management Cluster Configuration

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: management
  namespace: lattice-system
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap_provider: kubeadm  # or rke2 for FIPS
    config:
      docker: {}  # For local development
  nodes:
    control_plane: 1
    workers: 2
  endpoints:  # Makes this cluster a "cell" that can provision children
    host: "localhost"
    grpc_port: 50051
    bootstrap_port: 8443
    service:
      type: LoadBalancer
    gitops:
      url: "git@github.com:myorg/clusters.git"
      branch: main
      base_path: clusters
```

### Create Your First Workload Cluster

```bash
# Apply a cluster definition
kubectl apply -f - <<EOF
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: workload-1
  namespace: lattice-system
spec:
  provider:
    kubernetes:
      version: "1.32.0"
    config:
      docker: {}
  nodes:
    control_plane: 1
    workers: 3
EOF

# Watch the provisioning progress
kubectl get latticeclusters -w

# Phases: Pending → Provisioning → Pivoting → Ready
# Once Ready, the cluster is self-managing!
```

---

## CLI Reference

### Cluster Management

```bash
# List all clusters
lattice cluster list

# Show cluster hierarchy as tree
lattice cluster tree

# Add a new workload cluster
lattice cluster add workload.yaml --parent management

# Scale worker nodes
lattice cluster scale my-cluster --workers 5

# Upgrade Kubernetes version
lattice cluster upgrade my-cluster --k8s-version 1.33.0

# Delete a cluster
lattice cluster delete my-cluster --yes
```

### Service Management

```bash
# Register a service from git
lattice service register api \
  --git-url https://github.com/myorg/api-service \
  --git-path manifests \
  --branch main \
  --default-replicas 2

# List registered services
lattice service list

# Deploy service to a cluster
lattice placement create api \
  --cluster workload-1 \
  --replicas 3 \
  --env DATABASE_URL=postgres://...

# Scale a deployment
lattice placement scale api --cluster workload-1 --replicas 5
```

### GitOps (Flux)

```bash
# Set Flux version globally
lattice flux set-version v2.4.0

# Suspend GitOps on a cluster
lattice flux suspend workload-1

# Resume GitOps
lattice flux resume workload-1
```

### Validation

```bash
# Validate entire repository structure
lattice validate

# Validate specific file
lattice validate cluster.yaml
```

---

## Custom Resource Definitions

### LatticeCluster

Defines a Kubernetes cluster managed by Lattice:

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: production
  namespace: lattice-system
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap_provider: kubeadm  # or rke2 for FIPS
      cert_sans:
        - "api.prod.example.com"
    config:
      aws:
        region: us-east-1
        vpc_id: vpc-abc123
        control_plane:
          instance_type: m5.xlarge
          root_volume:
            size: 100
            type: gp3
        worker:
          instance_type: m5.2xlarge
  nodes:
    control_plane: 3
    workers: 10
  networking:
    default:
      cidr: "10.96.0.0/12"
  environment: production
  region: us-east-1
  # endpoints: present only on parent clusters (cells)
  endpoints:
    host: "api.lattice.example.com"
    grpc_port: 50051
    bootstrap_port: 8443
    service:
      type: LoadBalancer
    gitops:
      url: "git@github.com:myorg/clusters.git"
      branch: main
      base_path: clusters
```

**Status Fields:**
- `phase`: Pending → Provisioning → Pivoting → Ready / Failed
- `ready_control_plane`: Number of ready control plane nodes
- `ready_workers`: Number of ready worker nodes
- `pivot_complete`: Whether CAPI resources have been pivoted
- `bootstrap_complete`: Whether bootstrap webhook was called
- `endpoint`: Kubernetes API server endpoint

### LatticeService

Defines a workload with bilateral service mesh agreements:

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
  namespace: production
spec:
  environment: production
  containers:
    api:
      image: myorg/api-gateway:v1.2.3
      command: ["/app/server"]
      args: ["--port", "8080"]
      variables:
        LOG_LEVEL: info
        DATABASE_URL: "${resources.db.url}"  # Score-style placeholders
      resources:
        requests:
          cpu: "100m"
          memory: "256Mi"
        limits:
          cpu: "1"
          memory: "1Gi"
      liveness_probe:
        http_get:
          path: /healthz
          port: 8080
        initial_delay_seconds: 10
        period_seconds: 30
      readiness_probe:
        http_get:
          path: /ready
          port: 8080
        period_seconds: 5

  # Bilateral service agreements
  resources:
    # Outbound: This service calls auth-service
    auth:
      type: service
      direction: outbound
      id: auth-service

    # Inbound: frontend is allowed to call this service
    frontend-caller:
      type: service
      direction: inbound
      id: frontend

    # External dependency
    stripe:
      type: external_service
      direction: outbound
      id: stripe-api

    # Database
    db:
      type: postgres
      class: production

  service:
    ports:
      http:
        port: 80
        target_port: 8080
      grpc:
        port: 9090
        target_port: 9090
        protocol: TCP

  replicas:
    min: 2
    max: 10

  deploy:
    strategy: canary
    canary:
      step_weight: 10
      max_weight: 50
      interval: 1m
      threshold: 5
```

### LatticeExternalService

Defines external service endpoints:

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeExternalService
metadata:
  name: stripe-api
  namespace: production
spec:
  environment: production
  endpoints:
    api: "https://api.stripe.com:443"
    webhooks: "https://hooks.stripe.com:443"
  allowed_requesters:
    - api-gateway
    - payment-processor
    - "*"  # Wildcard to allow all (use sparingly)
  resolution: dns  # or static
  description: "Stripe payment processing API"
```

---

## Providers

| Provider | Status | API Version | Notes |
|----------|--------|-------------|-------|
| Docker (CAPD) | Stable | v1beta2 | Local development and testing |
| Proxmox (CAPMOX) | Stable | v1alpha1 | On-premises virtualization with kube-vip HA |
| AWS (CAPA) | Stable | v1beta2 | Full EKS-like self-managed clusters |
| OpenStack (CAPO) | Stable | v1beta1 | Private cloud (tested with OVH) |
| GCP (CAPG) | Planned | - | Google Cloud Platform |
| Azure (CAPZ) | Planned | - | Microsoft Azure |

### Provider Configuration Examples

#### Docker (Local Development)

```yaml
spec:
  provider:
    config:
      docker: {}
```

#### Proxmox (On-Premises)

```yaml
spec:
  provider:
    config:
      proxmox:
        source_node: pve1
        template_id: 9000
        storage: local-lvm
        format: raw
        bridge: vmbr0
        network_model: virtio
        cp_sockets: 2
        cp_cores: 2
        cp_memory_mib: 8192
        cp_disk_size_gb: 50
        worker_sockets: 2
        worker_cores: 4
        worker_memory_mib: 16384
        worker_disk_size_gb: 100
        ipv4_config:
          addresses: ["10.0.0.100/24"]
          gateway: "10.0.0.1"
        dns_servers: ["8.8.8.8", "8.8.4.4"]
```

#### AWS

```yaml
spec:
  provider:
    config:
      aws:
        region: us-east-1
        partition: aws  # aws, aws-cn, or aws-us-gov
        vpc_id: vpc-abc123
        subnet_ids:
          - subnet-123
          - subnet-456
        load_balancer:
          scheme: internet-facing
          type: nlb
        control_plane:
          instance_type: m5.xlarge
          iam_instance_profile: control-plane-profile
          root_volume:
            size: 100
            type: gp3
            iops: 3000
            throughput: 125
            encrypted: true
        worker:
          instance_type: m5.2xlarge
          root_volume:
            size: 200
            type: gp3
        bastion:
          enabled: true
          instance_type: t3.micro
        ssh_key_name: my-ssh-key
        tags:
          Environment: production
```

#### OpenStack

```yaml
spec:
  provider:
    config:
      openstack:
        cloud_name: mycloud
        external_network: public
        dns_nameservers:
          - "8.8.8.8"
        network:
          id: network-uuid
        subnet:
          id: subnet-uuid
        control_plane:
          flavor: m1.large
          image_filter:
            name: "ubuntu-22.04-kube-v1.32"
          root_volume:
            size: 50
            type: ssd
        worker:
          flavor: m1.xlarge
        bastion:
          enabled: true
          flavor: m1.small
        use_floating_ip: true
        managed_security_groups: true
```

---

## Security Model

### Bilateral Service Agreements

Traffic is only allowed when **both sides explicitly agree**:

```yaml
# api-gateway declares it calls auth-service
resources:
  auth:
    type: service
    direction: outbound
    id: auth-service

# auth-service declares api-gateway can call it
resources:
  api-gateway-caller:
    type: service
    direction: inbound
    id: api-gateway
```

This generates:
- **Istio AuthorizationPolicy**: SPIFFE principal-based rules (`spiffe://cluster/ns/namespace/sa/service`)
- **CiliumNetworkPolicy**: Label and port-based rules

If either side doesn't agree, traffic is blocked at both L4 and L7.

### Default-Deny Baseline

Both Cilium and Istio enforce default-deny policies:

- **CiliumClusterwideNetworkPolicy**: Implicit deny-all ingress (excludes system namespaces)
- **Istio AuthorizationPolicy**: Empty spec denies all traffic mesh-wide

System namespaces excluded from default-deny:
- `kube-system`
- `cilium-system`
- `istio-system`
- `lattice-system`
- `cert-manager`
- `flux-system`
- `capi-*`

### FIPS Compliance

All cryptographic operations use FIPS 140-3 validated implementations:

- **TLS**: rustls with aws-lc-rs backend
- **Hashing**: SHA-256/384/512 only (no MD5, no SHA-1)
- **Signatures**: ECDSA P-256/P-384 or RSA 2048+

Use RKE2 bootstrap provider for full FIPS compliance:

```yaml
spec:
  provider:
    kubernetes:
      bootstrap_provider: rke2
```

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

## Use Cases

### 1. Enterprise Multi-Tenant Platform

Deploy isolated workload clusters for different teams or customers:

```
Management Cluster
├── Team A Cluster (production)
├── Team A Cluster (staging)
├── Team B Cluster (production)
└── Team B Cluster (staging)
```

Each cluster is fully self-managing with its own CAPI resources, ensuring team isolation and independent lifecycle management.

### 2. Hybrid Cloud Deployment

Run management in AWS with workload clusters across providers:

```
AWS Management Cluster
├── AWS Workload Cluster (us-east-1)
├── AWS Workload Cluster (eu-west-1)
├── Proxmox Cluster (on-premises datacenter)
└── OpenStack Cluster (private cloud)
```

### 3. Edge Computing

Deploy lightweight clusters at edge locations with central management:

```
Central Management Cluster (AWS)
├── Edge Cluster (Store #1)
├── Edge Cluster (Store #2)
├── Edge Cluster (Store #3)
└── ...
```

Edge clusters operate independently even if connectivity to the parent is lost.

### 4. Disaster Recovery

Self-managing clusters continue operating if the parent fails:

- Parent provisions child cluster
- Child receives CAPI resources via pivot
- Parent can be deleted - child continues self-managing
- Child can scale, upgrade, and manage nodes independently

### 5. Secure Microservices Platform

Deploy services with automatic zero-trust networking:

```yaml
# Payment Service - only accessible by order-service
apiVersion: lattice.io/v1alpha1
kind: LatticeService
metadata:
  name: payment-service
spec:
  resources:
    order-access:
      type: service
      direction: inbound
      id: order-service
    stripe:
      type: external_service
      direction: outbound
      id: stripe-api
```

Lattice automatically generates Cilium and Istio policies ensuring payment-service is only reachable by order-service.

### 6. Air-Gapped Environments

Clusters operate independently post-pivot:

1. Bootstrap management cluster with external connectivity
2. Provision air-gapped workload clusters
3. Pivot CAPI resources
4. Disconnect from parent - clusters self-manage

### 7. Home Lab / Media Server

Run services with VPN integration for secure access:

```yaml
apiVersion: lattice.io/v1alpha1
kind: LatticeService
metadata:
  name: jellyfin
spec:
  containers:
    jellyfin:
      image: jellyfin/jellyfin:latest
  resources:
    nas:
      type: external_service
      direction: outbound
      id: home-nas

---
apiVersion: lattice.io/v1alpha1
kind: LatticeExternalService
metadata:
  name: home-nas
spec:
  endpoints:
    smb: "tcp://192.168.1.100:445"
  allowed_requesters:
    - jellyfin
  resolution: static
```

---

## GitOps Repository Structure

The CLI operates on a GitOps repository with this structure:

```
lattice-clusters/
├── cluster.yaml                 # Root management cluster
├── .lattice/
│   └── config.yaml             # Global configuration
├── registrations/
│   ├── api-service.yaml        # Service registrations
│   └── kustomization.yaml
├── children/
│   ├── production/
│   │   ├── cluster.yaml
│   │   ├── kustomization.yaml
│   │   ├── placements/
│   │   │   └── api-service.yaml
│   │   └── children/           # Nested hierarchy
│   └── staging/
│       └── cluster.yaml
└── docs/
```

---

## Scripts

### Build VM Template (Proxmox)

```bash
export PROXMOX_URL="https://10.0.0.97:8006"
export PROXMOX_TOKEN="root@pam!lattice"
export PROXMOX_SECRET="your-secret"
export PROXMOX_NODE="pve1"
export KUBERNETES_VERSION="1.32.0"

./scripts/proxmox-build-template.sh
```

### Build Docker Image

```bash
./scripts/docker-build.sh --tag ghcr.io/myorg/lattice:v1.0.0
```

### Run E2E Tests

```bash
./scripts/e2e-test.sh
```

---

## Development

### Build

```bash
cargo build --release
```

### Test

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'

# E2E tests (requires kind)
./scripts/e2e-test.sh
```

### Code Quality

```bash
# Format
cargo fmt

# Lint
cargo clippy

# Coverage
cargo tarpaulin --out Html
```

---

## Roadmap

- [x] LatticeCluster provisioning and pivot
- [x] Docker provider (CAPD)
- [x] Proxmox provider (CAPMOX)
- [x] AWS provider (CAPA)
- [x] OpenStack provider (CAPO)
- [x] Service graph and network policies
- [x] Cilium integration
- [x] Istio Ambient mode integration
- [x] GitOps integration (Flux)
- [x] Bilateral agreement security model
- [ ] GCP provider (CAPG)
- [ ] Azure provider (CAPZ)
- [ ] Web UI dashboard
- [ ] Multi-tenancy RBAC

---

## Community

- **GitHub Discussions**: [github.com/lattice-dev/lattice/discussions](https://github.com/lattice-dev/lattice/discussions)
- **Slack**: [#lattice on Kubernetes Slack](https://kubernetes.slack.com/channels/lattice)

---

## License

Lattice is licensed under the [Apache License 2.0](LICENSE).

---

<p align="center">
  <sub>Built with Rust, powered by Cluster API, secured by Cilium + Istio</sub>
</p>
