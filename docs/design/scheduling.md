# Lattice Scheduling Design

## Overview

Platform engineers define **capacity pools** (regions with budgets) and **placement policies**. Services declare **requirements** including node selectors and tolerations. Lattice automatically provisions clusters with appropriate **worker pools** and places workloads on the right nodes. Clusters are an implementation detail - users never create them directly.

## Design Principles

1. **Clusters are invisible** - Platform engineers think in regions, budgets, and policies
2. **Declarative constraints** - Define what you need, not where to put it
3. **Hierarchical knowledge** - Parents see children, placement quality improves with scope
4. **Same binary everywhere** - Scheduler is integrated into the operator, not separate
5. **Worker pools for heterogeneity** - Different node types within a cluster via worker pools

## CRD Hierarchy

```
LatticePool (capacity + budget per region)
    │
    └── LatticePlacementPolicy (global rules)
            │
            └── LatticeService (workload + requirements)
                    │
                    └── [Auto-created: LatticeCluster]
                            │
                            └── Worker Pools (general, gpu, highmem, etc.)
```

---

## Core CRDs

### LatticePool

Defines available capacity in a region. Platform engineers create these.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticePool
metadata:
  name: us-east
spec:
  # Provider configuration for this pool
  provider:
    type: aws
    region: us-east-1
    credentials:
      secretRef: aws-creds

  # Capacity constraints
  capacity:
    maxNodes: 100
    maxCores: 2000
    maxMemoryGi: 8000

  # Budget constraints
  budget:
    maxMonthlyCost: 10000
    currency: USD
    alertThreshold: 0.8  # Alert at 80%

  # Default worker pool templates for auto-created clusters
  # These define what worker pools are available in this region
  workerPoolTemplates:
    general:
      nodeClass: t3.large      # Provider-specific instance type
      maxNodes: 50
      labels:
        workload-type: general
    compute:
      nodeClass: c5.2xlarge
      maxNodes: 30
      labels:
        workload-type: compute
    gpu:
      nodeClass: p3.2xlarge
      maxNodes: 10
      labels:
        workload-type: gpu
        nvidia.com/gpu: "true"
      taints:
        - key: nvidia.com/gpu
          effect: NoSchedule

  # Labels for placement matching
  labels:
    compliance: [soc2, hipaa]
    tier: production
    network: low-latency
```

### LatticePlacementPolicy

Global rules for placement decisions.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticePlacementPolicy
metadata:
  name: production-policy
spec:
  # Selector for which services this applies to
  selector:
    matchLabels:
      env: production

  # Hard requirements (must satisfy)
  requirements:
    # Minimum replicas across regions for HA
    minRegions: 2

    # Compliance requirements
    compliance:
      - soc2

    # Anti-affinity at region level
    spreadConstraint:
      topologyKey: region
      maxSkew: 1

  # Soft preferences (try to satisfy)
  preferences:
    # Prefer cheaper regions
    - weight: 50
      preference:
        sortBy: cost
        order: ascending

    # Prefer regions with existing capacity
    - weight: 30
      preference:
        sortBy: availableCapacity
        order: descending

  # Cluster sizing rules
  clusterPolicy:
    # Min/max nodes per auto-created cluster (total across all pools)
    minNodes: 3
    maxNodes: 50

    # When to create new cluster vs expand existing
    binPackingThreshold: 0.8  # Create new at 80% full

    # Cluster consolidation
    consolidation:
      enabled: true
      minUtilization: 0.3  # Consolidate if under 30%
```

### LatticeService (updated)

Services declare requirements including node placement preferences.

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: ml-inference
  labels:
    env: production
spec:
  containers:
    main:
      image: ml-inference:v1.2.3
      resources:
        requests:
          nvidia.com/gpu: 1

  # Placement requirements
  placement:
    # Where it CAN run (pool selector)
    pools:
      matchLabels:
        tier: production

    # Where it MUST run (at least one replica)
    requiredRegions:
      - us-east
      - eu-west

    # Node selection within cluster (maps to worker pool selection)
    nodeSelector:
      workload-type: gpu

    # Tolerations for tainted nodes
    tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule

    # Resource requirements (for bin packing)
    resources:
      cores: 4
      memoryGi: 16
      gpu: 1

    # Latency requirements to dependencies
    latency:
      model-store:
        maxMs: 5
        # Implies: place in same cluster as model-store

  # Service dependencies
  resources:
    model-store:
      type: Service
      direction: outbound

  replicas:
    min: 2
    max: 8
```

---

## Scheduling Algorithm

### Phase 1: Pool Selection

```
Input: LatticeService with placement requirements
Output: Set of eligible LatticePool resources

1. Filter pools by label selector (pools.matchLabels)
2. Filter by compliance requirements
3. Filter by worker pool availability:
   - Service requires nodeSelector: workload-type=gpu
   - Pool must have workerPoolTemplate with matching labels
4. Filter by capacity (can fit resources)
5. Filter by budget (won't exceed)
6. Result: Candidate pools
```

### Phase 2: Cluster Selection/Creation

```
Input: Target pool, service requirements
Output: Cluster to deploy to

1. List existing clusters in pool
2. For each cluster:
   a. Check if required worker pool exists
   b. Check available capacity in that pool
   c. Score by utilization (prefer bin packing)

3. If suitable cluster exists:
   - Return cluster
   - Scale up worker pool if needed

4. If no suitable cluster:
   a. Create new LatticeCluster with required worker pools
   b. Worker pools derived from:
      - Service nodeSelector -> matching pool template
      - Dependencies in same cluster -> their pool requirements
   c. Cluster auto-pivots and self-manages

5. Result: Target cluster with appropriate worker pools
```

### Phase 3: Worker Pool Matching

```
Input: Cluster, service nodeSelector/tolerations
Output: Target worker pool within cluster

1. For each worker pool in cluster:
   a. Check labels match nodeSelector
   b. Check tolerations satisfy taints

2. If matching pool exists:
   - Return pool name

3. If no matching pool:
   a. Check if pool template exists in LatticePool
   b. Add new worker pool to cluster spec
   c. Wait for nodes to be ready
   d. Return new pool name

4. Result: Worker pool for pod scheduling
```

### Phase 4: Deployment

```
Input: Target cluster, worker pool, LatticeService
Output: Running workload

1. Generate Deployment with:
   - nodeSelector from worker pool labels
   - tolerations from worker pool taints
2. Deploy to cluster
3. Update service status with placement info
4. Create/update bilateral agreements for cross-cluster deps
5. Done
```

---

## Cluster Auto-Configuration

When the scheduler creates a cluster, it configures worker pools based on service requirements:

```yaml
# Scheduler creates this LatticeCluster automatically
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: us-east-prod-7a3b
spec:
  provider:
    kubernetes:
      version: "1.32.0"
    config:
      aws:
        region: us-east-1
  nodes:
    controlPlane: 3
    workerPools:
      # Created because ml-inference service needs GPU nodes
      gpu:
        replicas: 2
        nodeClass: p3.2xlarge
        labels:
          workload-type: gpu
          nvidia.com/gpu: "true"
        taints:
          - key: nvidia.com/gpu
            effect: NoSchedule

      # Created for api-gateway service (no special requirements)
      general:
        replicas: 5
        nodeClass: t3.large
        labels:
          workload-type: general
```

### Worker Pool Scaling

The scheduler adjusts worker pool replicas based on demand:

```rust
fn calculate_pool_size(pool: &str, services: &[Service]) -> u32 {
    let pool_services: Vec<_> = services
        .iter()
        .filter(|s| s.targets_pool(pool))
        .collect();

    let total_cores: u32 = pool_services.iter().map(|s| s.cores()).sum();
    let total_memory: u32 = pool_services.iter().map(|s| s.memory()).sum();

    let node_class = get_node_class(pool);
    let nodes_for_cores = (total_cores + node_class.cores - 1) / node_class.cores;
    let nodes_for_memory = (total_memory + node_class.memory - 1) / node_class.memory;

    // Add headroom for scheduling flexibility
    let base_nodes = nodes_for_cores.max(nodes_for_memory);
    (base_nodes as f32 * 1.2).ceil() as u32
}
```

---

## Status and Observability

### LatticeService Status

```yaml
status:
  phase: Running
  placements:
    - pool: us-east
      cluster: us-east-prod-7a3b
      workerPool: gpu
      replicas: 2
      nodeClass: p3.2xlarge
      cost:
        hourly: 6.12

    - pool: eu-west
      cluster: eu-west-prod-2c1d
      workerPool: gpu
      replicas: 1
      nodeClass: p3.2xlarge
      cost:
        hourly: 3.06

  totalCost:
    hourly: 9.18
    projected30Day: 6609.60

  health:
    available: 3
    ready: 3

  lastScheduled: "2024-01-15T10:30:00Z"
  schedulerDecision:
    reason: "Placed on gpu worker pools per nodeSelector requirement"
    workerPoolSelection:
      required: "workload-type=gpu"
      matched: ["us-east-prod-7a3b/gpu", "eu-west-prod-2c1d/gpu"]
```

### LatticeCluster Status (with Worker Pools)

```yaml
status:
  phase: Ready
  readyWorkers: 7
  workerPools:
    general:
      desiredReplicas: 5
      currentReplicas: 5
      readyReplicas: 5
    gpu:
      desiredReplicas: 2
      currentReplicas: 2
      readyReplicas: 2
  endpoint: "https://k8s-api.us-east.example.com:6443"
```

### LatticePool Status

```yaml
status:
  phase: Ready
  capacity:
    allocatedNodes: 45
    allocatedCores: 720
    allocatedMemoryGi: 2880

  utilization:
    nodes: 0.45
    cores: 0.36
    memory: 0.36

  budget:
    currentMonthCost: 4523.50
    projectedMonthCost: 8200.00
    utilizationPercent: 0.82

  workerPoolUsage:
    general:
      totalNodes: 30
      totalCores: 120
    compute:
      totalNodes: 10
      totalCores: 80
    gpu:
      totalNodes: 5
      totalCores: 40
      totalGpus: 5

  clusters:
    - name: us-east-prod-7a3b
      workerPools: [general, gpu]
      nodes: 15
      services: 23
    - name: us-east-prod-9x2y
      workerPools: [general, compute]
      nodes: 12
      services: 18
```

---

## Migration and Rebalancing

### Triggers

1. **Budget exceeded** - Migrate to cheaper pool
2. **Capacity exhausted** - Migrate to pool with room
3. **Worker pool exhausted** - Scale pool or create new cluster
4. **Consolidation** - Merge underutilized clusters
5. **Compliance change** - Pool loses compliance label
6. **Manual** - Platform engineer requests rebalance

### Migration Flow

```
1. Scheduler detects trigger
2. Find new placement for affected services
3. For each service:
   a. Ensure target cluster has required worker pool
   b. Scale up worker pool if needed
   c. Scale up service in new location
   d. Wait for healthy
   e. Update bilateral agreements
   f. Drain from old location
4. If source worker pool empty, scale to 0
5. If source cluster empty, delete it
```

### Worker Pool Consolidation

```
When pool utilization < 30% for extended period:
1. Identify services on underutilized pool
2. Check if another pool in same cluster can absorb
3. If same-cluster migration possible:
   a. Reschedule pods to other pool
   b. Scale down underutilized pool
4. If cross-cluster migration needed:
   a. Follow standard migration flow
   b. Scale down/delete pool after drain
```

---

## Examples

### GPU Workload Placement

```yaml
# Service requiring GPU
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: image-classifier
spec:
  containers:
    main:
      image: classifier:v2
      resources:
        requests:
          nvidia.com/gpu: 1
  placement:
    nodeSelector:
      workload-type: gpu
    tolerations:
      - key: nvidia.com/gpu
        operator: Exists
```

Scheduler flow:
1. Find pools with `gpu` worker pool template
2. Select pool with capacity and budget
3. Find/create cluster with `gpu` worker pool
4. Deploy with `nodeSelector: workload-type=gpu`
5. Kubernetes schedules to GPU nodes

### Mixed Workload Cluster

```yaml
# Cluster auto-created with multiple pools
nodes:
  controlPlane: 3
  workerPools:
    general:
      replicas: 10
      nodeClass: t3.large
      labels:
        workload-type: general
    compute:
      replicas: 5
      nodeClass: c5.2xlarge
      labels:
        workload-type: compute
    gpu:
      replicas: 2
      nodeClass: p3.2xlarge
      labels:
        workload-type: gpu
        nvidia.com/gpu: "true"
      taints:
        - key: nvidia.com/gpu
          effect: NoSchedule
```

Services scheduled to appropriate pools:
- `api-gateway` -> general pool (no nodeSelector)
- `data-processor` -> compute pool (nodeSelector: workload-type=compute)
- `ml-inference` -> gpu pool (nodeSelector + toleration)

---

## Future Considerations

### Not in v0

- Spot/preemptible instance support in worker pools
- Per-pool autoscaling (min/max in schema, not implemented)
- Network topology awareness (zone-level pool placement)
- Cost prediction ML
- Pod-level GPU sharing

### v0 Scope

- LatticePool CRD with worker pool templates
- LatticePlacementPolicy with nodeSelector support
- Automatic cluster creation with required worker pools
- Worker pool scaling based on service demand
- Service status with worker pool placement info
- Basic bin packing (first fit by pool)
