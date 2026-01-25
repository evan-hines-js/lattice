# Cluster Autoscaler Integration

## Overview

Integrate the Kubernetes Cluster Autoscaler with CAPI provider into Lattice's self-managing clusters. Because clusters own their own CAPI resources post-pivot, both kubeconfigs point to the same cluster ("Unified Cluster" topology - the simplest).

## Design

### Opt-in via Existing Fields

The `WorkerPoolSpec` already has `min` and `max` fields. When both are set, autoscaling is enabled:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
spec:
  nodes:
    worker_pools:
      general:
        replicas: 3      # Initial count (ignored when autoscaling enabled)
        min: 1           # Enables autoscaling when set with max
        max: 10          # Required if min is set
```

**Behavior Matrix:**

| min | max | replicas | Behavior |
|-----|-----|----------|----------|
| unset | unset | 3 | Static scaling. Operator reconciles to exactly 3. |
| 1 | 10 | 3 | Autoscaling enabled. Operator hands-off, autoscaler manages. |
| 1 | 10 | 0 | Autoscaling enabled. Initial replicas = min (avoids 0-replica trap). |

### Implementation (Complete)

1. **`WorkerPoolSpec`** (`types.rs`)
   - `is_autoscaling_enabled()` - returns true when both min and max are set
   - `initial_replicas()` - returns min when autoscaling enabled and replicas < min
   - `validate()` - ensures min <= max, min >= 1, both or neither set

2. **Manifest Generation** (`provider/mod.rs`)
   - Adds CAPI autoscaler annotations to MachineDeployment when min/max set:
     - `cluster.x-k8s.io/cluster-api-autoscaler-node-group-min-size`
     - `cluster.x-k8s.io/cluster-api-autoscaler-node-group-max-size`

3. **Reconciliation** (`controller.rs`)
   - When autoscaling enabled: `continue` (hands-off, trust autoscaler)
   - When static: reconcile replicas to match spec (existing behavior)
   - Emits warning when replicas is outside [min, max] bounds

4. **Status** (`cluster.rs`)
   - `WorkerPoolStatus.autoscaling_enabled` - reflects current autoscaling state
   - `desired_replicas` always reflects MachineDeployment reality, not spec

### Autoscaler Deployment

Deploy in `lattice-system` namespace:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: lattice-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    spec:
      serviceAccountName: cluster-autoscaler
      priorityClassName: system-cluster-critical
      containers:
      - name: cluster-autoscaler
        image: registry.k8s.io/autoscaling/cluster-autoscaler:v1.31.0
        command:
        - /cluster-autoscaler
        - --cloud-provider=clusterapi
        - --node-group-auto-discovery=clusterapi:namespace=capi-system
        - --scale-down-delay-after-add=5m
        - --scale-down-unneeded-time=5m
        - --skip-nodes-with-local-storage=false
        resources:
          requests:
            cpu: 100m
            memory: 300Mi
          limits:
            memory: 600Mi
```

No kubeconfig files needed - uses in-cluster service account for both CAPI and workload APIs.

### RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-autoscaler
rules:
- apiGroups: [cluster.x-k8s.io]
  resources: [machinedeployments, machinedeployments/scale, machinesets, machinesets/scale, machinepools, machinepools/scale]
  verbs: [get, list, watch, patch, update]
- apiGroups: [cluster.x-k8s.io]
  resources: [machines]
  verbs: [get, list, watch, delete]
- apiGroups: [""]
  resources: [nodes, pods, services, replicationcontrollers, persistentvolumeclaims, persistentvolumes, namespaces]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [nodes]
  verbs: [delete, patch, update]
- apiGroups: [apps]
  resources: [daemonsets, replicasets, statefulsets]
  verbs: [get, list, watch]
- apiGroups: [policy]
  resources: [poddisruptionbudgets]
  verbs: [get, list, watch]
- apiGroups: [""]
  resources: [events]
  verbs: [create, patch]
- apiGroups: [coordination.k8s.io]
  resources: [leases]
  verbs: [get, create, update]
```

## Security

The autoscaler has delete permissions on Nodes and Machines. Mitigations:
- Restricted to `lattice-system` namespace
- Minimum required RBAC permissions
- No secrets access needed
- Audit logging captures node deletions

Post-pivot, the cluster manages its own infrastructure - no cross-cluster credentials.

## Non-Goals

- **Scale-from-zero**: Requires capacity annotations. min must be >= 1.
- **Per-pool autoscaler profiles**: All pools use same scale-down timing.

## Migration

Existing clusters with only `replicas` continue unchanged. Autoscaling is opt-in via `min`/`max`.
