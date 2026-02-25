# Multi-Cluster Service Mesh Design

## Problem Statement

Today, Lattice's bilateral agreement model operates within a single cluster. Service A declares `outbound: [service-b]`, Service B declares `inbound: [service-a]`, the `ServiceCompiler` sees both sides, and the `PolicyCompiler` generates CiliumNetworkPolicy + AuthorizationPolicy to enforce the agreement.

When Service A lives on Cluster A and Service B lives on Cluster B, no single compiler sees both sides. We need a mechanism to:

- **Discover** remote services across the cluster hierarchy
- **Distribute** remote service metadata so local compilers can resolve dependencies
- **Generate** the right infrastructure (ServiceEntry + Gateway API) for cross-cluster traffic
- **Preserve** location transparency so services don't need to know where their dependencies run

## Design Constraints

- **Self-contained clusters**: A cluster must be able to resolve cross-cluster dependencies from local state alone. The parent being offline cannot block compilation of new dependencies against known remote services.
- **No etcd pressure**: Cross-cluster state must not scale as O(N * S) CRDs. The cost should be memory, not etcd objects.
- **Outbound-only**: No new inbound connections on workload clusters. The parent gRPC stream remains the only coordination channel.
- **Location transparency**: Services declare dependencies by name. Whether the target is local or remote is a compilation detail, not a user concern.

## Architecture Overview

```
                    Root Cluster
                   (Full Registry)
                   /            \
            Cluster A          Cluster B
          ┌──────────┐      ┌──────────┐
          │ service-a │      │ service-b │
          │  (local)  │      │  (local)  │
          │           │      │           │
          │ [catalog] │      │ [catalog] │
          │ service-b │      │ service-a │
          │ @ clust-b │      │ @ clust-a │
          └──────────┘      └──────────┘

  service-a declares outbound: [service-b]
  service-b declares inbound: [service-a]

  Compiler on Cluster A checks local graph → no match
    → checks in-memory catalog → finds service-b on cluster-b → compiles as external
  Compiler on Cluster B checks local graph → no match
    → checks in-memory catalog → finds service-a on cluster-a → compiles as external
```

**Key principles:**
- The parent cluster acts as service registry and distributes a lightweight **service catalog** to all children
- The catalog lives **in-memory** in the operator, persisted as **sharded ConfigMaps** for crash recovery
- The compiler resolves dependencies against the local ServiceGraph first, then the catalog
- Actual data-plane traffic flows directly between clusters — the parent never proxies runtime traffic

## Service Catalog

### What It Is

The service catalog is an in-memory lookup table of all remote services in the tree. Each entry contains just enough information for the local compiler to resolve a dependency and generate the right infrastructure:

```rust
pub struct RemoteService {
    pub cluster: String,           // originating cluster
    pub namespace: String,         // originating namespace
    pub name: String,              // service name
    pub allowed_callers: Vec<CallerRef>,  // who can call this (bilateral inbound)
    pub ports: Vec<PortInfo>,      // exposed ports
    pub gateway_address: String,   // cluster's ingress gateway LB IP
    pub gateway_port: u16,         // mTLS passthrough port
}
```

~200-300 bytes per entry. 10,000 remote services = ~3MB. Trivial in memory.

### Why Not CRDs

Storing remote services as CRDs (e.g., external LatticeMeshMembers) creates O(N * S) etcd objects across the tree:

| Tree Size | Clusters | Services/Cluster | External CRDs per Cluster | Total CRDs |
|-----------|----------|-------------------|---------------------------|------------|
| Medium | 50 | 100 | 4,900 | 245,000 |
| Large | 200 | 200 | 39,800 | ~8 million |

Each CRD also triggers policy generation (ServiceEntry + AuthorizationPolicy + CiliumNetworkPolicy), multiplying the etcd pressure ~4x. This doesn't scale.

The catalog approach: **zero additional CRDs**. The compiler reads from memory and generates only the policies it actually needs for resolved dependencies.

### Why Not Demand-Based

An alternative is demand-based distribution: only push remote service info when a local service declares a dependency. This minimizes fan-out but **breaks the self-contained property** — you can't add a new cross-cluster dependency unless the parent is online to resolve it.

The catalog approach gives every cluster the full picture locally. Adding `outbound: [service-b]` resolves immediately from the local catalog, no parent round-trip needed.

### Persistence: Sharded ConfigMaps

The in-memory catalog is persisted as ConfigMaps for crash recovery. One ConfigMap per source cluster:

```
lattice-system/remote-catalog-cluster-b   # all services from cluster-b
lattice-system/remote-catalog-cluster-c   # all services from cluster-c
...
```

**Why per-cluster sharding:**
- ConfigMaps have a 1MiB size limit. Per-cluster shards stay well under (~200 bytes * 200 services = ~40KB)
- Updates are scoped — a service change on cluster-b touches one ConfigMap
- Garbage collection is natural — cluster leaves the tree, delete one ConfigMap
- Delta sync maps directly — parent sends update for one cluster, agent overwrites one ConfigMap

100 clusters in a tree = 100 ConfigMaps in `lattice-system`. Negligible etcd pressure.

**Startup recovery:** Operator lists `remote-catalog-*` ConfigMaps, rebuilds in-memory catalog. No parent connection needed to resume compilation with the last-known catalog state.

### Catalog Sync Protocol

The catalog is distributed via the existing gRPC stream, extending the `SubtreeState` message:

```protobuf
message SubtreeState {
  bool is_full_sync = 1;
  repeated ClusterInfo clusters = 2;
  repeated ServiceInfo services = 3;        // NEW
  repeated ServiceInfo removed_services = 4; // NEW (delta updates)
}

message ServiceInfo {
  string cluster_name = 1;
  string namespace = 2;
  string name = 3;
  repeated CallerRef allowed_callers = 4;
  repeated ServiceRef dependencies = 5;
  repeated PortInfo ports = 6;
  string gateway_address = 7;
  uint32 gateway_port = 8;
}
```

**Sync flow:**
- On agent connect: parent sends full catalog as `is_full_sync = true`
- On service changes: parent sends delta with added/removed services
- Agent updates in-memory catalog + writes affected ConfigMap shard
- Agent triggers recompilation for any local services whose dependencies may be affected

### Registry Bubbling

Each cluster reports its local services to its parent via the gRPC stream. In a multi-level hierarchy, the registry bubbles to the root — the root holds a complete service map. The root then pushes the full catalog back down to all descendants.

The registry boundary is **per-tree**. Multiple roots (a forest) naturally scopes service discovery and blast radius. A service in Tree A is not discoverable from Tree B.

## Dependency Resolution

### User-Facing API

Users write `LatticeService` specs. Dependencies are declared by name in `spec.resources`:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: service-a
spec:
  resources:
    service-b:
      direction: outbound          # unqualified — resolved at compile time
    cluster-x:service-c:
      direction: outbound          # qualified — pinned to cluster-x
```

Users never write LatticeMeshMembers or interact with the catalog directly.

### Resolution Algorithm

The compiler resolves dependencies in two phases:

```
resolve(dep_name) -> Result<ResolvedDep, Error>:
  if ":" in dep_name:
    // Qualified: cluster:service — skip local lookup
    cluster, service = dep_name.split(":")
    match catalog.get(cluster, service):
      Some(entry) → return ResolvedDep::External(entry)
      None → error("service {service} not found on cluster {cluster}")
  else:
    // Unqualified: check local first, then catalog
    local = graph.find(dep_name)
    remote = catalog.find_all(dep_name)  // may return multiple
    candidates = local.into_iter().chain(remote).collect()
    match candidates.len():
      0 → error("unknown dependency: {dep_name}")
      1 → return candidates[0]  // Local or External
      _ → error("ambiguous: {dep_name} exists on {list_clusters}")
```

### Name Collision Behavior

A name collision (same service name on multiple clusters, or local + remote) is a **hard conflict** for that specific dependency. Compilation fails with an actionable error:

```
error: ambiguous dependency "service-b"
  → exists on: cluster-a (local), cluster-b (remote)
  help: use "cluster-a:service-b" or "cluster-b:service-b" to disambiguate
```

Other dependencies on the same LatticeService compile normally — only the ambiguous one fails.

### Qualified Names

The `cluster:service` form:
- Skips local lookup entirely — goes straight to catalog
- Used when there's a name collision, or the user intentionally pins to a cluster
- Also works for inbound declarations: `allowed_callers: [{name: "cluster-a:service-a"}]`

## Compilation Output

The compiler produces different infrastructure based on whether the resolved dependency is local or external.

### Local Dependency (Same as Today)

```
service-a (outbound: service-b) → resolved as local
  Generates:
    - LatticeMeshMember (compiled by MeshMember controller)
    - CiliumNetworkPolicy (L4 eBPF, HBONE allow)
    - AuthorizationPolicy (L7 SPIFFE identity)
    - PeerAuthentication (mTLS mode)
```

### External Dependency (New)

On the **consumer side** (Cluster A, where service-a lives):

```
service-a (outbound: service-b) → resolved as external (cluster-b)
  Generates:
    - ServiceEntry (registers service-b's gateway endpoint in local mesh)
    - AuthorizationPolicy (allows service-a to reach the ServiceEntry)
    - CiliumNetworkPolicy (allows egress to cluster-b's gateway IP)
```

On the **provider side** (Cluster B, where service-b lives):

```
service-b (inbound: service-a) → service-a resolved as external (cluster-a) from catalog
  Generates:
    - Gateway listener (accepts cross-cluster mTLS traffic)
    - AuthorizationPolicy on Gateway (allows service-a's cross-cluster SPIFFE principal)
    - TCPRoute/HTTPRoute on Gateway (routes to local service-b)
```

No intermediate CRD. The compiler goes directly from catalog entry to ServiceEntry + Gateway route.

## Cross-Cluster Traffic Path

Traffic flows directly between clusters. The parent is never in the data path.

```
Cluster A                                          Cluster B
┌────────────────────┐                    ┌────────────────────┐
│ service-a pod      │                    │ service-b pod      │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ ztunnel (ambient)  │                    │ ztunnel (ambient)  │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ ServiceEntry       │                    │ Gateway (istio)    │
│ (service-b.ext)    │                    │ (mTLS passthrough) │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ Egress             │ ──── mTLS ────▶   │ Ingress Gateway    │
└────────────────────┘                    └────────────────────┘
```

From service-a's perspective, this is standard north/south traffic: pod → mesh → ServiceEntry → remote Gateway → pod.

## Gateway Configuration

### Per-Cluster Mesh Gateway

Each cluster that hosts services consumed cross-cluster gets a mesh ingress gateway, provisioned once during bootstrap or on first cross-cluster dependency:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: lattice-mesh-gateway
  namespace: lattice-system
spec:
  gatewayClassName: istio
  listeners:
    - name: mesh-mtls
      port: 15443
      protocol: TLS
      tls:
        mode: Passthrough   # mTLS passthrough, ztunnel handles termination
```

The gateway's LoadBalancer IP is reported to the parent as part of `ServiceInfo.gateway_address`.

### Per-Service Routes (Provider Side)

For each service consumed cross-cluster, a route is attached to the mesh gateway:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: service-b-mesh-route
  namespace: default
spec:
  parentRefs:
    - name: lattice-mesh-gateway
      namespace: lattice-system
      sectionName: mesh-mtls
  rules:
    - backendRefs:
        - name: service-b
          port: 8080
```

### ServiceEntry (Consumer Side)

On Cluster A, the external dependency generates:

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: service-b-cluster-b
  namespace: default
spec:
  hosts:
    - service-b.cluster-b.mesh.lattice.dev   # synthetic DNS name
  ports:
    - number: 8080
      name: http
      protocol: HTTP
  location: MESH_EXTERNAL
  resolution: STATIC
  endpoints:
    - address: 10.0.1.50       # Cluster B's gateway LB IP
      ports:
        http: 15443             # Gateway mTLS passthrough port
```

## Identity and mTLS

### Cross-Cluster Trust

Each Lattice cluster has its own Istio trust domain: `lattice.{cluster_name}.local`. For cross-cluster mTLS, clusters need to trust each other's CA.

**Approach: Shared root CA.** All clusters in the same tree share a root CA distributed during pivot. Each cluster's Istio uses an intermediate CA signed by the shared root. Cross-cluster mTLS works automatically because both sides trust the root.

This aligns with the existing certificate distribution flow — the agent already receives certs from the parent during bootstrap.

### SPIFFE Identity Across Clusters

When service-a on Cluster A calls service-b on Cluster B, the AuthorizationPolicy on Cluster B's Gateway allows:

```
principal: lattice.cluster-a.local/ns/default/sa/service-a
```

This works with the existing `trust_domain::principal()` helper — the catalog entry carries the source cluster name, so the policy compiler generates the correct cross-cluster principal.

### Identity Continuity on Migration

If service-b moves from Cluster B to Cluster A:
- Its SPIFFE identity changes from `lattice.cluster-b.local/.../service-b` to `lattice.cluster-a.local/.../service-b`
- Consumers using unqualified names don't change their LatticeService spec
- Policies are recompiled automatically because the catalog updates
- No consumer manifest changes required

## Agent-Side Service Reporting

The agent watches local `LatticeMeshMember` CRDs and reports them to the parent as `ServiceInfo` entries in the `SubtreeState`:

```rust
// In subtree.rs, extend the watcher to include services
fn build_subtree_state(&self) -> SubtreeState {
    let clusters = self.get_local_clusters();
    let services = self.get_local_services();  // Watch LMMs, exclude catalog-derived
    SubtreeState {
        is_full_sync: true,
        clusters,
        services,
        removed_services: vec![],
    }
}
```

The agent filters out any services that were generated from the catalog itself (to avoid echo loops).

## Cell-Side Registry

The cell's `SubtreeRegistry` is extended to track services:

```rust
pub struct SubtreeRegistry {
    clusters: DashMap<String, ClusterInfo>,
    services: DashMap<ServiceKey, ServiceInfo>,  // NEW
}

#[derive(Hash, Eq, PartialEq)]
pub struct ServiceKey {
    pub cluster: String,
    pub namespace: String,
    pub name: String,
}
```

When the registry changes, the cell:
- Computes the updated catalog for each child (all services except the child's own)
- Sends delta `SubtreeState` to affected children
- Bubbles changes up to its own parent (so the root stays current)

## Migration Story

Service-b moves from Cluster B to Cluster A:

- User deploys `LatticeService` for service-b on Cluster A
- Cluster A's agent reports service-b to the parent
- Parent updates catalog: service-b now exists on both cluster-a and cluster-b
- Parent pushes updated catalog to all children
- On any cluster, `outbound: [service-b]` → **ambiguous error** (exists on cluster-a and cluster-b)
- Qualified `cluster-a:service-b` or `cluster-b:service-b` → works
- User removes `LatticeService` for service-b from Cluster B
- Parent updates catalog: service-b only on cluster-a
- Unqualified `outbound: [service-b]` → resolves again

The ambiguity during transition forces explicit routing, preventing split-brain.

## Independence Guarantees

**Parent goes down:**
- Catalog is in-memory + persisted in ConfigMaps → compilations continue
- Existing ServiceEntries + Gateway routes are materialized in etcd → traffic flows
- New remote services can't be discovered (catalog is stale) → acceptable
- New local dependencies against known remote services → works (catalog is local)

**Operator restarts:**
- Reads `remote-catalog-*` ConfigMaps → rebuilds in-memory catalog
- Reconnects to parent → receives full sync → updates catalog
- Between restart and reconnect, catalog is last-known state → safe for compilation

**Node death (all replicas):**
- ConfigMaps survive in etcd → new pods read them on startup
- Catalog is restored without parent connection

## Scalability

### Per-Tree Limits

| Dimension | Comfortable Limit | Bottleneck |
|-----------|-------------------|------------|
| Clusters per tree | ~100 | gRPC fan-out for catalog updates |
| Services per cluster | ~200 | None (local only) |
| Total services per tree | ~10,000 | Catalog size in memory (~3MB) |
| Cross-cluster dependencies | ~1,000 | Compiled policy count |
| ConfigMap shards | ~100 | One per source cluster, ~40KB each |

### At 1,000 Trees (Global Control Plane)

- 1,000 trees * ~50 clusters = ~50,000 clusters
- 1,000 trees * ~5,000 services = ~5 million services globally
- Cross-tree is not supported by design — each tree is independent
- Global control plane manages tree metadata and root provisioning only
- Each tree's root handles its own registry independently

The 1,000-tree limit is about the global control plane's capacity to manage root clusters, not service mesh complexity.

### Scaling Levers

- **Forest topology**: Keep trees small (~20-50 clusters) with multiple roots
- **Catalog filtering**: If needed, the parent could filter the catalog to only include services that declare cross-cluster availability (opt-in via annotation), reducing catalog size for trees where most services are cluster-internal

## Implementation Phases

### Phase 1: Catalog Infrastructure

- Define `RemoteService` struct and in-memory `ServiceCatalog`
- ConfigMap shard read/write (serialize/deserialize per-cluster)
- Catalog startup recovery from ConfigMaps

### Phase 2: Protocol Extension

- Extend `SubtreeState` protobuf with `ServiceInfo` and `removed_services`
- Agent watches local LMMs and reports to parent
- Cell aggregates services in `SubtreeRegistry`
- Cell pushes catalog to children, bubbles up to parent

### Phase 3: Compiler Changes

- Dependency resolution: local graph → in-memory catalog fallback
- Qualified name parsing (`cluster:service`)
- Ambiguity detection and error messages
- External dependency compilation: ServiceEntry + CiliumNetworkPolicy egress rule

### Phase 4: Cross-Cluster Gateway

- Per-cluster mesh ingress gateway provisioning
- Per-service TCPRoute/HTTPRoute generation on provider side
- Gateway LB IP reporting in `ServiceInfo`
- AuthorizationPolicy on gateway for cross-cluster SPIFFE principals

### Phase 5: Trust Federation

- Shared root CA distribution during bootstrap/pivot
- Cross-cluster SPIFFE identity resolution in `trust_domain::principal()`
- AuthorizationPolicy generation with remote trust domain principals

### Phase 6: Testing

- Unit tests: dependency resolution (unqualified, qualified, ambiguous, missing)
- Unit tests: catalog sync, ConfigMap shard persistence, startup recovery
- Unit tests: external dependency compilation output (ServiceEntry, Gateway, AuthzPolicy)
- Integration tests: two-cluster cross-cluster bilateral enforcement
- E2E test: cross-cluster service dependency with live traffic verification
- E2E test: service migration between clusters (ambiguity → resolution)
- E2E test: parent failure with existing cross-cluster traffic (independence)
- E2E test: operator restart with catalog recovery from ConfigMaps
