# Lattice GPU Cloud — Product Layer Design

## Purpose

This document is the implementation spec for the Lattice GPU Cloud product layer. The stack is:

- **Rust (Axum)** — Extends the existing `lattice-api` crate with product endpoints (tenants, billing, deployments). Owns all K8s/CRD interaction, PostgreSQL, Stripe, and background jobs.
- **React (Vite)** — SPA dashboard served as static files. Calls the Rust API. Zero Node.js in production.
- **CLI** — Talks to the same Rust API.

One backend, one frontend, two languages.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    React Dashboard (Vite SPA)                │
│                    Served as static files by Axum            │
│                                                             │
│  Pages: Dashboard, Deploy, Endpoint Detail, Jobs, Billing   │
│  Real-time: SSE for status updates, GPU utilization          │
└──────────────────────────┬───────────────────────────────────┘
                           │ fetch() to /api/v1/*
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Lattice API (Rust / Axum)                  │
│                    (extended lattice-api crate)               │
│                                                             │
│  Existing:                                                   │
│    GET  /healthz                                             │
│    GET  /kubeconfig                                          │
│    *    /clusters/{name}/api/*     (K8s API proxy)           │
│    *    /clusters/{name}/apis/*    (K8s API proxy)           │
│                                                             │
│  New product endpoints:                                      │
│    POST /api/v1/endpoints          Deploy model/service      │
│    POST /api/v1/jobs               Submit training job       │
│    GET  /api/v1/gpus               GPU availability          │
│    GET  /api/v1/billing/usage      Spend tracking            │
│    ...                                                       │
│                                                             │
│  Internal:                                                   │
│    PostgreSQL (SQLx)     — tenants, billing, usage records   │
│    Stripe (async-stripe) — invoicing, payment methods        │
│    Cedar                 — authorization (already exists)     │
│    Tokio tasks           — status sync, usage metering       │
│                                                             │
│  CRD construction happens HERE, not in the frontend.         │
│  The API translates product requests into K8s CRD            │
│  operations via the existing internal proxy machinery.       │
└──────────────────────────┬───────────────────────────────────┘
                           │ Internal (same process — direct K8s client)
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    GPU Clusters                              │
│                    (Self-managing via pivot)                  │
│                                                             │
│  Each cluster runs:                                          │
│    - Lattice operator (reconciles CRDs)                      │
│    - Volcano (GPU-aware scheduling)                          │
│    - Hami (GPU partitioning / vGPU)                          │
│    - Istio ambient mesh (tenant isolation)                   │
│    - ESO (secret injection)                                  │
│    - GPU monitor (anomaly detection, auto-drain)             │
│    - NVIDIA device plugin + NFD                              │
└──────────────────────────────────────────────────────────────┘
```

### Key Principles

1. **The Rust API owns all CRD construction.** The frontend and CLI send simple product-level requests (`deploy this model on 2x H100`). The API translates to LatticeModel/LatticeService/LatticeJob CRDs internally.
2. **No K8s knowledge in the frontend.** React never sees CRDs, manifests, or namespaces.
3. **Same API for dashboard and CLI.** Both consume `/api/v1/*`.
4. **PostgreSQL for product state.** Tenants, billing, API keys, usage records live in Postgres. Cluster state comes from K8s CRD status, synced into Postgres by background tasks.

---

## Rust API: New Modules

These are new modules added to the existing `lattice-api` crate (or a new `lattice-cloud` crate if preferred for separation).

### Dependencies to Add

```toml
# In workspace Cargo.toml or crate Cargo.toml
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono", "json"] }
async-stripe = { version = "0.39", features = ["runtime-tokio-hyper"] }
argon2 = "0.5"        # API key hashing
tower-http = { version = "0.6", features = ["fs", "cors"] }  # serve React static files
```

### Module Layout

```
crates/lattice-api/src/
├── lib.rs                    # existing
├── proxy/                    # existing K8s API proxy
├── auth/                     # existing OIDC + Cedar
│
├── cloud/                    # NEW: product layer
│   ├── mod.rs                # router setup
│   ├── db.rs                 # SQLx pool + migrations
│   ├── auth.rs               # API key middleware + tenant extraction
│   ├── tenants.rs            # Tenant CRUD handlers
│   ├── projects.rs           # Project CRUD + namespace creation
│   ├── api_keys.rs           # API key generation/revocation
│   ├── endpoints.rs          # Deploy/scale/stop/destroy handlers
│   ├── jobs.rs               # Submit/cancel/logs handlers
│   ├── artifacts.rs          # Job artifact listing + presigned URLs
│   ├── gpus.rs               # GPU availability + pricing
│   ├── billing.rs            # Usage summary, invoices
│   ├── stripe.rs             # Stripe customer/invoice/webhook handlers
│   ├── crd_builder.rs        # Translates product requests → CRD JSON
│   ├── status_sync.rs        # Background: polls CRD status → updates Postgres
│   ├── usage_meter.rs        # Background: records GPU-seconds per minute
│   ├── gpu_pool_sync.rs      # Background: syncs available GPUs from cluster status
│   ├── invoice_finalizer.rs  # Background: monthly Stripe invoice generation
│   └── sse.rs                # SSE endpoint for real-time status pushes
│
├── models/                   # NEW: SQLx models
│   ├── mod.rs
│   ├── tenant.rs
│   ├── project.rs
│   ├── api_key.rs
│   ├── endpoint.rs
│   ├── job.rs
│   ├── artifact.rs
│   ├── gpu_region.rs
│   ├── gpu_pool.rs
│   ├── invoice.rs
│   └── usage_record.rs
│
└── migrations/               # NEW: SQLx migrations
    ├── 001_create_tenants.sql
    ├── 002_create_projects.sql
    ├── ...
```

---

## Data Model

### Entity Relationship

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   Tenant    │────<│   Project    │────<│   ApiKey      │
└─────────────┘     └──────────────┘     └───────────────┘
      │                    │
      │              ┌─────┴──────┐
      │              │            │
      │        ┌─────▼────┐ ┌────▼─────┐
      │        │ Endpoint  │ │   Job    │
      │        └──────────┘ └──────────┘
      │                          │
      │                    ┌─────▼────┐
      │                    │ Artifact  │
      │                    └──────────┘
      │
┌─────▼──────┐
│  Invoice   │────< UsageRecord
└────────────┘

┌──────────────┐     ┌───────────────┐
│  GpuRegion   │────<│   GpuPool     │
└──────────────┘     └───────────────┘
```

### Database Schema

PostgreSQL. Managed by SQLx migrations.

```sql
-- Tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    stripe_customer_id VARCHAR(255),
    tier VARCHAR(50) NOT NULL DEFAULT 'free'
        CHECK (tier IN ('free', 'starter', 'pro', 'enterprise')),
    status VARCHAR(50) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'closed')),
    spending_limit_cents INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Projects
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(63) NOT NULL,
    region VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'archived')),
    namespace VARCHAR(253) NOT NULL UNIQUE,
    cluster VARCHAR(253) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);

-- API Keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- Endpoints (deployed models and services)
CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    name VARCHAR(63) NOT NULL,
    endpoint_type VARCHAR(20) NOT NULL CHECK (endpoint_type IN ('model', 'service')),

    -- Model-specific
    model_uri VARCHAR(1024),
    inference_engine VARCHAR(50),

    -- Common GPU config
    gpu_model VARCHAR(100) NOT NULL,
    gpu_count INTEGER NOT NULL,
    gpu_memory VARCHAR(20),     -- Hami vGPU memory slice
    gpu_compute INTEGER,        -- Hami vGPU compute %

    -- Scaling
    replicas INTEGER NOT NULL DEFAULT 1,
    min_replicas INTEGER,
    max_replicas INTEGER,

    -- Container config (service type)
    image VARCHAR(1024),
    command TEXT[],
    port INTEGER NOT NULL DEFAULT 8000,
    env JSONB NOT NULL DEFAULT '{}',

    -- Status (synced from CRD status by background task)
    status VARCHAR(50) NOT NULL DEFAULT 'creating'
        CHECK (status IN ('creating', 'loading', 'running', 'scaling', 'failed', 'stopped')),
    url VARCHAR(1024),
    error TEXT,
    current_replicas INTEGER NOT NULL DEFAULT 0,

    -- Cost
    hourly_rate_cents INTEGER,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, name)
);

-- Jobs (training and batch)
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    name VARCHAR(63) NOT NULL,
    framework VARCHAR(50),
    image VARCHAR(1024) NOT NULL,
    command TEXT[] NOT NULL,
    gpu_model VARCHAR(100) NOT NULL,
    gpu_count INTEGER NOT NULL,
    gpu_memory VARCHAR(20),
    gpu_compute INTEGER,
    worker_count INTEGER NOT NULL DEFAULT 1,
    env JSONB NOT NULL DEFAULT '{}',

    -- Status (synced from CRD status)
    status VARCHAR(50) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    gpu_seconds INTEGER NOT NULL DEFAULT 0,
    cost_cents INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Artifacts (job outputs)
CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES jobs(id),
    name VARCHAR(1024) NOT NULL,
    size_bytes BIGINT NOT NULL,
    content_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
    storage_uri VARCHAR(2048) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GPU Regions (admin-managed)
CREATE TABLE gpu_regions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    cluster_name VARCHAR(253) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'full', 'maintenance'))
);

-- GPU Pools (synced from cluster status)
CREATE TABLE gpu_pools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region_id UUID NOT NULL REFERENCES gpu_regions(id),
    gpu_model VARCHAR(100) NOT NULL,
    total_gpus INTEGER NOT NULL,
    available_gpus INTEGER NOT NULL,
    rate_cents_per_hour INTEGER NOT NULL,
    cpu_rate_cents_per_hour INTEGER NOT NULL,
    memory_rate_cents_per_gib_hour INTEGER NOT NULL,
    hami_enabled BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(region_id, gpu_model)
);

-- Invoices
CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'finalized', 'paid', 'void')),
    subtotal_cents INTEGER NOT NULL DEFAULT 0,
    stripe_invoice_id VARCHAR(255),
    finalized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Usage Records (per-minute metering)
CREATE TABLE usage_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES invoices(id),
    endpoint_id UUID REFERENCES endpoints(id),
    job_id UUID REFERENCES jobs(id),
    resource_type VARCHAR(20) NOT NULL CHECK (resource_type IN ('endpoint', 'job')),
    gpu_model VARCHAR(100) NOT NULL,
    gpu_count INTEGER NOT NULL,
    gpu_seconds INTEGER NOT NULL,
    cpu_seconds INTEGER NOT NULL DEFAULT 0,
    memory_gib_seconds INTEGER NOT NULL DEFAULT 0,
    cost_cents INTEGER NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_usage_invoice ON usage_records(invoice_id);
CREATE INDEX idx_usage_recorded ON usage_records(recorded_at);
```

---

## API Endpoints

All product endpoints are under `/api/v1/`. Authentication is via API key (`Authorization: Bearer lk_...`) or OIDC token.

The Rust API handles:
1. Authenticate request (API key hash lookup or OIDC validation)
2. Load tenant + project context
3. Validate request
4. For deploy/scale/stop: construct CRD JSON internally, apply to cluster via existing K8s client
5. Store/update record in PostgreSQL
6. Return product-level response (no CRD details exposed)

### Endpoints (deployed GPU workloads)

```
POST   /api/v1/endpoints              Deploy a new endpoint
GET    /api/v1/endpoints              List endpoints in project
GET    /api/v1/endpoints/:id          Get endpoint details + status
PATCH  /api/v1/endpoints/:id          Update (scale, env vars)
POST   /api/v1/endpoints/:id/stop     Stop (scale to 0)
POST   /api/v1/endpoints/:id/start    Start (resume)
DELETE /api/v1/endpoints/:id          Destroy endpoint
GET    /api/v1/endpoints/:id/logs     Stream logs (SSE)
```

### Jobs (batch training)

```
POST   /api/v1/jobs                   Submit a job
GET    /api/v1/jobs                   List jobs
GET    /api/v1/jobs/:id               Get job status
POST   /api/v1/jobs/:id/cancel        Cancel running job
GET    /api/v1/jobs/:id/logs          Stream logs (SSE)
GET    /api/v1/jobs/:id/artifacts     List artifacts
GET    /api/v1/jobs/:id/artifacts/:aid/download  Presigned download URL
```

### Projects

```
POST   /api/v1/projects               Create project
GET    /api/v1/projects                List projects
DELETE /api/v1/projects/:id            Archive project
```

### API Keys

```
POST   /api/v1/api-keys               Create key (returns plaintext once)
GET    /api/v1/api-keys                List keys (prefix only)
DELETE /api/v1/api-keys/:id            Revoke key
```

### GPU Availability (public, no auth required)

```
GET    /api/v1/gpus                    List available GPU models by region
GET    /api/v1/gpus/pricing            Current pricing by GPU model
```

### Billing

```
GET    /api/v1/billing/usage           Current period usage summary
GET    /api/v1/billing/invoices        List invoices
GET    /api/v1/billing/invoices/:id    Get invoice detail
```

### Real-time

```
GET    /api/v1/events                  SSE stream (endpoint status changes, spend updates)
```

### Stripe Webhook

```
POST   /api/v1/webhooks/stripe         Stripe webhook receiver (payment events)
```

---

## Request/Response Examples

### Deploy a model endpoint

```
POST /api/v1/endpoints
Content-Type: application/json
Authorization: Bearer lk_abc123def456...

{
    "project_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "name": "llama-70b",
    "type": "model",
    "model_uri": "hf://meta-llama/Llama-3-70B",
    "inference_engine": "vllm",
    "gpu_model": "H100-SXM",
    "gpu_count": 2,
    "replicas": 1,
    "max_replicas": 4,
    "env": {
        "VLLM_TENSOR_PARALLEL_SIZE": "2"
    }
}

Response 201:
{
    "id": "ep_xyz789",
    "name": "llama-70b",
    "type": "model",
    "status": "creating",
    "url": null,
    "gpu_model": "H100-SXM",
    "gpu_count": 2,
    "replicas": 1,
    "hourly_rate_cents": 700,
    "created_at": "2026-03-27T10:00:00Z"
}
```

**What the Rust API does internally:**

1. Validates tenant has budget (Postgres query)
2. Computes `hourly_rate_cents` from `gpu_pools` table
3. Builds a `LatticeModel` CRD using existing Rust types:

```rust
// In crd_builder.rs — uses the actual CRD types from lattice-common
fn build_lattice_model(req: &DeployModelRequest, project: &Project) -> LatticeModel {
    LatticeModel {
        metadata: ObjectMeta {
            name: Some(req.name.clone()),
            namespace: Some(project.namespace.clone()),
            labels: Some(BTreeMap::from([
                ("lattice.dev/tenant".into(), project.tenant_id.to_string()),
                ("lattice.dev/project".into(), project.name.clone()),
                ("lattice.dev/managed-by".into(), "lattice-cloud".into()),
            ])),
            ..Default::default()
        },
        spec: LatticeModelSpec {
            model_source: Some(ModelSourceSpec {
                uri: req.model_uri.clone(),
                cache_uri: Some("hostpath:///mnt/models".into()),
                cache_size: Some("100Gi".into()),
                ..Default::default()
            }),
            roles: BTreeMap::from([(
                "serve".into(),
                ModelRoleSpec {
                    replicas: Some(req.replicas),
                    entry_workload: WorkloadSpec {
                        containers: BTreeMap::from([(
                            "engine".into(),
                            ContainerSpec {
                                image: engine_image(req.inference_engine),
                                variables: req.env.clone(),
                                resources: Some(ResourceRequirements {
                                    requests: Some(ResourceQuantity {
                                        cpu: Some("4".into()),
                                        memory: Some("16Gi".into()),
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]),
                        resources: BTreeMap::from([(
                            "gpu".into(),
                            ResourceSpec {
                                type_: ResourceType::Gpu,
                                params: ResourceParams::Gpu(GpuParams {
                                    count: req.gpu_count,
                                    model: Some(req.gpu_model.clone()),
                                    memory: req.gpu_memory.clone(),
                                    compute: req.gpu_compute,
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                    autoscaling: req.max_replicas.map(|max| ModelAutoscalingSpec {
                        max,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            routing: Some(ModelRoutingSpec {
                inference_engine: req.inference_engine.into(),
                model: model_name_from_uri(&req.model_uri),
                port: Some(8000),
                ..Default::default()
            }),
            ..Default::default()
        },
        status: None,
    }
}
```

4. Applies to cluster using existing `kube::Client` (same client the operator uses)
5. Inserts endpoint record into PostgreSQL
6. Returns product-level response

### Deploy a GPU container

```
POST /api/v1/endpoints
{
    "project_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "name": "my-inference",
    "type": "service",
    "image": "myregistry/my-model:v2",
    "port": 8080,
    "gpu_model": "L4",
    "gpu_count": 1,
    "gpu_memory": "20Gi",
    "gpu_compute": 50,
    "replicas": 2,
    "env": { "MODEL_PATH": "/models/v2" }
}

Response 201:
{
    "id": "ep_abc456",
    "name": "my-inference",
    "type": "service",
    "status": "creating",
    "gpu_model": "L4",
    "gpu_count": 1,
    "gpu_memory": "20Gi",
    "gpu_compute": 50,
    "replicas": 2,
    "hourly_rate_cents": 81,
    "created_at": "2026-03-27T10:05:00Z"
}
```

Internally builds a `LatticeService` CRD with Hami vGPU params (`memory`, `compute`).

### Submit a training job

```
POST /api/v1/jobs
{
    "project_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
    "name": "fine-tune-llama",
    "framework": "pytorch",
    "image": "myregistry/trainer:latest",
    "command": ["python", "train.py", "--epochs", "50"],
    "gpu_model": "H100-SXM",
    "gpu_count": 8,
    "worker_count": 4,
    "env": { "WANDB_PROJECT": "my-project" }
}

Response 201:
{
    "id": "job_def456",
    "name": "fine-tune-llama",
    "status": "queued",
    "gpu_model": "H100-SXM",
    "gpu_count": 8,
    "worker_count": 4,
    "estimated_hourly_cost_cents": 11200,
    "created_at": "2026-03-27T10:10:00Z"
}
```

Internally builds a `LatticeJob` CRD with Volcano `training` config.

### Check GPU availability

```
GET /api/v1/gpus

Response 200:
{
    "regions": [
        {
            "name": "us-east-1",
            "display_name": "US East",
            "status": "available",
            "pools": [
                {
                    "gpu_model": "H100-SXM",
                    "available": 24,
                    "total": 64,
                    "rate_cents_per_hour": 350,
                    "hami_enabled": true
                },
                {
                    "gpu_model": "L4",
                    "available": 48,
                    "total": 48,
                    "rate_cents_per_hour": 81,
                    "hami_enabled": true
                }
            ]
        }
    ]
}
```

---

## CRD Mapping Reference

The `crd_builder.rs` module translates product requests into Lattice CRDs. Since the Rust API has direct access to all CRD types from `lattice-common`, this is type-safe — no JSON template construction.

### Endpoint (type: model) → LatticeModel

| API Field | CRD Field |
|-----------|-----------|
| `name` | `metadata.name` |
| `model_uri` | `spec.model_source.uri` |
| `inference_engine` | `spec.routing.inference_engine` |
| `gpu_model` | `spec.roles.serve.entry_workload.resources.gpu.params.model` |
| `gpu_count` | `spec.roles.serve.entry_workload.resources.gpu.params.count` |
| `gpu_memory` | `spec.roles.serve.entry_workload.resources.gpu.params.memory` |
| `gpu_compute` | `spec.roles.serve.entry_workload.resources.gpu.params.compute` |
| `replicas` | `spec.roles.serve.replicas` |
| `max_replicas` | `spec.roles.serve.autoscaling.max` |
| `env` | `spec.roles.serve.entry_workload.containers.engine.variables` |

Status sync (CRD → Postgres):

| CRD Status | Endpoint Status |
|------------|-----------------|
| `Pending` | `creating` |
| `Loading` | `loading` |
| `Serving` | `running` |
| `Failed` | `failed` |

### Endpoint (type: service) → LatticeService

| API Field | CRD Field |
|-----------|-----------|
| `name` | `metadata.name` |
| `image` | `spec.workload.containers.main.image` |
| `command` | `spec.workload.containers.main.command` |
| `port` | `spec.workload.service.ports.http.port` |
| `gpu_model` | `spec.workload.resources.gpu.params.model` |
| `gpu_count` | `spec.workload.resources.gpu.params.count` |
| `gpu_memory` | `spec.workload.resources.gpu.params.memory` |
| `gpu_compute` | `spec.workload.resources.gpu.params.compute` |
| `replicas` | `spec.replicas` |
| `max_replicas` | `spec.autoscaling.max` |
| `env` | `spec.workload.containers.main.variables` |

Status sync:

| CRD Status | Endpoint Status |
|------------|-----------------|
| `Pending` | `creating` |
| `Compiling` | `creating` |
| `Ready` | `running` |
| `Failed` | `failed` |

### Job → LatticeJob

| API Field | CRD Field |
|-----------|-----------|
| `name` | `metadata.name` (suffixed with short ID for uniqueness) |
| `image` | `spec.tasks.worker.workload.containers.main.image` |
| `command` | `spec.tasks.worker.workload.containers.main.command` |
| `gpu_model` | `spec.tasks.worker.workload.resources.gpu.params.model` |
| `gpu_count` | `spec.tasks.worker.workload.resources.gpu.params.count` |
| `gpu_memory` | `spec.tasks.worker.workload.resources.gpu.params.memory` |
| `gpu_compute` | `spec.tasks.worker.workload.resources.gpu.params.compute` |
| `worker_count` | `spec.tasks.worker.replicas` |
| `framework` | `spec.training.framework` |
| `env` | `spec.tasks.worker.workload.containers.main.variables` |

Status sync:

| CRD Status | Job Status |
|------------|------------|
| `Pending` | `queued` |
| `Running` | `running` |
| `Succeeded` | `succeeded` |
| `Failed` | `failed` |

---

## Background Tasks

Tokio tasks spawned at API server startup. No external job queue needed — these are lightweight polling loops.

### 1. Status Syncer

Polls CRD status from clusters and updates Postgres endpoint/job records.

```rust
// Runs every 5 seconds
async fn status_sync_loop(pool: PgPool, kube_clients: Arc<ClusterClients>) {
    loop {
        // For each active project (from Postgres):
        //   1. List LatticeModels + LatticeServices in project namespace
        //   2. Match to endpoint records by name
        //   3. Update status, current_replicas, url, error
        //   4. Broadcast changes via SSE channel

        // For each active job:
        //   1. List LatticeJobs by label lattice.dev/job-id
        //   2. Update status, started_at, completed_at, error

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
```

### 2. Usage Meter

Records GPU-seconds consumed for billing. Runs every 60 seconds.

```rust
async fn usage_meter_loop(pool: PgPool) {
    loop {
        // For each endpoint with status = 'running':
        //   Record 60 seconds × gpu_count at current gpu_model rate
        //   Insert UsageRecord, increment invoice subtotal

        // For each job with status = 'running':
        //   Record 60 seconds × worker_count × gpu_count
        //   Update job.gpu_seconds and job.cost_cents

        // Spending limit enforcement:
        //   If tenant's month total >= spending_limit_cents:
        //     Scale all endpoints to 0, set tenant to 'suspended'

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
```

### 3. GPU Pool Syncer

Syncs available GPU capacity from LatticeCluster status into Postgres.

```rust
async fn gpu_pool_sync_loop(pool: PgPool, kube_clients: Arc<ClusterClients>) {
    loop {
        // For each GpuRegion:
        //   Read LatticeCluster status.pool_resources
        //   Update gpu_pools: total_gpus, available_gpus
        //   If all pools full: set region status to 'full'

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
```

### 4. Invoice Finalizer

Monthly cron-like task for Stripe invoice generation.

```rust
async fn invoice_finalizer_loop(pool: PgPool, stripe: StripeClient) {
    loop {
        // Check if it's past the 1st of the month at 00:05 UTC
        // If so, for each active tenant:
        //   Finalize previous month's draft invoice
        //   Create Stripe invoice
        //   Create new draft for current month

        tokio::time::sleep(Duration::from_secs(3600)).await; // check hourly
    }
}
```

---

## Authentication

### API Key Auth (primary for API/CLI)

```rust
// Middleware: extract and validate API key
async fn api_key_auth(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<TenantContext, ApiError> {
    let key = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let hash = argon2_hash(key);
    let api_key = sqlx::query_as!(ApiKey,
        "SELECT * FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
        hash
    ).fetch_optional(&pool).await?
     .ok_or(ApiError::Unauthorized)?;

    if let Some(expires) = api_key.expires_at {
        if expires < Utc::now() { return Err(ApiError::Unauthorized); }
    }

    // Update last_used_at (fire-and-forget)
    let _ = sqlx::query!("UPDATE api_keys SET last_used_at = now() WHERE id = $1", api_key.id)
        .execute(&pool).await;

    let project = load_project(&pool, api_key.project_id).await?;
    let tenant = load_tenant(&pool, project.tenant_id).await?;

    if tenant.status != "active" { return Err(ApiError::TenantSuspended); }

    Ok(TenantContext { tenant, project, api_key })
}
```

### OIDC Auth (for dashboard)

Use the existing OIDC validator already in `lattice-api`. Map OIDC subject to tenant via email lookup.

### Lattice API proxy auth for CRD operations

The product API server runs in the same process as the Lattice operator (or has direct access to cluster kubeconfigs). CRD operations use the internal `kube::Client` — no proxy hop needed for server-side operations.

---

## Tenant Isolation

Each tenant's workloads are isolated at multiple layers:

```
Layer 1: Namespace
  Each project → unique K8s namespace ("t-{tenant_short}-{project}")
  Rust API scopes all CRD operations to tenant's namespace

Layer 2: Network (Lattice mesh — automatic)
  Istio ambient mesh enforces mTLS between all pods
  Default-deny AuthorizationPolicy per namespace
  Tenants cannot reach other tenants' pods

Layer 3: GPU (Hami)
  Hami device plugin manages GPU sharing
  Memory and compute limits enforced at device level
  No GPU memory leak between tenants

Layer 4: Secrets (Cedar — automatic)
  Cedar default-deny for secret access
  Tenants can only access secrets in their namespace

Layer 5: API
  API key scoped to project → namespace
  Cannot list/modify other tenants' resources
```

---

## React Dashboard

### Tech Stack

```
React 19 + TypeScript
Vite (build tool)
React Router (client-side routing)
TanStack Query (data fetching + caching)
Recharts (GPU utilization, spend charts)
Tailwind CSS (styling)
```

### Pages

#### Dashboard (`/`)
- Spend ticker: current month, projected, limit bar
- Endpoint cards: name, status badge, GPU utilization %, request rate, cost/hr
- Active jobs: name, progress, ETA, cost
- GPU availability by region
- Real-time via SSE (`/api/v1/events`)

#### Deploy (`/deploy`)
- Type selector: Model | Container
- Model: URI input, engine selector (vLLM/SGLang)
- Container: image, command, port
- GPU picker: model dropdown (filtered by availability), count, Hami toggle (memory/compute sliders)
- Replicas + autoscaling toggle
- Region selector
- Env var key-value editor
- Live cost preview (computed client-side from `/api/v1/gpus/pricing`)
- Submit → redirect to endpoint detail

#### Endpoint Detail (`/endpoints/:id`)
- Status badge, URL with copy button
- GPU utilization chart (real-time via SSE)
- Request rate + latency charts
- Cost: today, week, month
- Log viewer (SSE stream from `/api/v1/endpoints/:id/logs`)
- Scale slider, stop/start buttons
- Env var editor (PATCH triggers rolling update)
- Delete with confirmation

#### Jobs (`/jobs`)
- Job list with status filters (queued, running, succeeded, failed)
- Job detail: logs, GPU usage, cost, artifact downloads

#### Billing (`/billing`)
- Usage breakdown by endpoint, by GPU model
- Daily GPU-hours chart
- Invoice history table
- Payment method (Stripe Elements)
- Spending limit config

#### Settings (`/settings`)
- API keys (create, list, revoke)
- Projects (create, archive)

### Serving

Axum serves the built React app as static files:

```rust
use tower_http::services::ServeDir;

let app = Router::new()
    .nest("/api/v1", api_routes)
    // Serve React SPA — fallback to index.html for client-side routing
    .fallback_service(ServeDir::new("frontend/dist").fallback(ServeFile::new("frontend/dist/index.html")));
```

---

## CLI Design

The CLI talks to `/api/v1/*`. Can be a Rust binary (reuses existing `lattice-cli` patterns) or a standalone tool.

```bash
# Auth
lattice cloud login                        # Browser OIDC flow
lattice cloud login --api-key lk_abc123    # API key

# Deploy
lattice cloud deploy --gpu h100 --model hf://meta-llama/Llama-3-70B
lattice cloud deploy --gpu l4 --image myregistry/app:latest --port 8080
lattice cloud deploy --gpu h100 --gpu-memory 40Gi --gpu-compute 50 --model hf://...

# Manage
lattice cloud endpoints                    # list
lattice cloud endpoints llama-70b          # status
lattice cloud scale llama-70b --replicas 4
lattice cloud stop llama-70b
lattice cloud start llama-70b
lattice cloud destroy llama-70b
lattice cloud logs llama-70b               # stream

# Jobs
lattice cloud run --gpu h100x8 --workers 4 -- python train.py
lattice cloud jobs                         # list
lattice cloud logs fine-tune-llama         # stream
lattice cloud cancel fine-tune-llama

# Info
lattice cloud gpus                         # availability + pricing
lattice cloud billing                      # current spend
```

CLI commands are `lattice cloud <verb>` to avoid collision with operator commands.

---

## Implementation Order

### Phase 1: API Foundation
1. Add SQLx + PostgreSQL to `lattice-api` (or create `lattice-cloud` crate)
2. Database migrations (all tables)
3. Tenant + Project CRUD handlers
4. API key auth middleware
5. `GET /api/v1/gpus` (read from `gpu_regions` + `gpu_pools` tables)

### Phase 2: Core Deploy Flow
6. `crd_builder.rs` — build LatticeModel from product request
7. `POST /api/v1/endpoints` (model type) — validate, build CRD, apply, store
8. `crd_builder.rs` — build LatticeService from product request
9. `POST /api/v1/endpoints` (service type)
10. Status syncer background task
11. `GET /PATCH/DELETE /api/v1/endpoints/*`
12. SSE endpoint for real-time status

### Phase 3: Jobs
13. `crd_builder.rs` — build LatticeJob from product request
14. `POST /api/v1/jobs` — validate, build CRD, apply, store
15. Job status syncer
16. `GET /api/v1/jobs/:id/logs` (SSE, proxied from cluster)

### Phase 4: Billing
17. GPU pool syncer background task
18. Usage meter background task
19. Invoice + UsageRecord models
20. `GET /api/v1/billing/*` handlers
21. Stripe integration (async-stripe): customer creation, invoice sync
22. Spending limit enforcement in usage meter
23. Stripe webhook handler

### Phase 5: React Dashboard
24. Vite + React project setup in `frontend/`
25. Auth flow (OIDC login page, API key storage)
26. Dashboard page (endpoint cards, spend ticker)
27. Deploy form
28. Endpoint detail page (logs, metrics, controls)
29. Jobs page
30. Billing page
31. Settings page
32. Axum static file serving + SPA fallback

### Phase 6: CLI
33. `lattice cloud` subcommand in existing `lattice-cli`
34. Auth commands (login, api-key)
35. Deploy/scale/stop/destroy commands
36. Job submit/cancel/logs commands
37. GPU availability + billing commands

---

## Lattice CRD Field Reference (Quick Reference)

These are the exact fields the `crd_builder.rs` module needs. Full type definitions are in `crates/lattice-common/src/crd/`.

### LatticeModel (model endpoints)

```
spec.model_source.uri                                          String    "hf://meta-llama/Llama-3-70B"
spec.model_source.cache_uri                                    String?   "hostpath:///mnt/models"
spec.model_source.cache_size                                   String?   "100Gi"
spec.model_source.egress                                       Vec       ["huggingface.co"]
spec.roles.{name}.replicas                                     u32       1
spec.roles.{name}.entry_workload.containers.{name}.image       String    "vllm/vllm-openai:latest"
spec.roles.{name}.entry_workload.containers.{name}.variables   Map       env vars
spec.roles.{name}.entry_workload.containers.{name}.resources   Resources cpu/memory requests
spec.roles.{name}.entry_workload.resources.gpu.params.count    u32       2
spec.roles.{name}.entry_workload.resources.gpu.params.model    String?   "H100-SXM"
spec.roles.{name}.entry_workload.resources.gpu.params.memory   String?   "20Gi" (Hami)
spec.roles.{name}.entry_workload.resources.gpu.params.compute  u32?      50 (Hami)
spec.roles.{name}.autoscaling.max                              u32       4
spec.routing.inference_engine                                  Enum      VLlm | SGLang
spec.routing.model                                             String    "meta-llama/Llama-3-70B"
spec.routing.port                                              u16?      8000
status.phase                                                   Enum      Pending|Loading|Serving|Failed
status.cost.hourly_cost                                        String    "7.0000"
```

### LatticeService (container endpoints)

```
spec.replicas                                                  u32       2
spec.workload.containers.{name}.image                          String    "myregistry/app:latest"
spec.workload.containers.{name}.command                        Vec?      ["python", "serve.py"]
spec.workload.containers.{name}.variables                      Map       env vars
spec.workload.containers.{name}.resources                      Resources cpu/memory
spec.workload.resources.gpu.params.count                       u32       1
spec.workload.resources.gpu.params.model                       String?   "L4"
spec.workload.resources.gpu.params.memory                      String?   "20Gi" (Hami)
spec.workload.resources.gpu.params.compute                     u32?      50 (Hami)
spec.workload.service.ports.{name}.port                        u16       8080
spec.autoscaling.max                                           u32       10
status.phase                                                   Enum      Pending|Compiling|Ready|Failed
status.cost.hourly_cost                                        String    "0.8100"
```

### LatticeJob (training jobs)

```
spec.tasks.{name}.replicas                                     u32?      4
spec.tasks.{name}.workload.containers.{name}.image             String    "trainer:latest"
spec.tasks.{name}.workload.containers.{name}.command           Vec       ["python", "train.py"]
spec.tasks.{name}.workload.containers.{name}.variables         Map       env vars
spec.tasks.{name}.workload.containers.{name}.resources         Resources cpu/memory
spec.tasks.{name}.workload.resources.gpu.params.count          u32       8
spec.tasks.{name}.workload.resources.gpu.params.model          String?   "H100-SXM"
spec.tasks.{name}.workload.resources.gpu.params.memory         String?   (Hami)
spec.tasks.{name}.workload.resources.gpu.params.compute        u32?      (Hami)
spec.training.framework                                        Enum      PyTorch|DeepSpeed|Jax
spec.training.coordinator_task                                 String    "worker"
status.phase                                                   Enum      Pending|Running|Succeeded|Failed
status.cost.hourly_cost                                        String    "112.0000"
```
