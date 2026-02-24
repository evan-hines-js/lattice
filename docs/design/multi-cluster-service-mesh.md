# Multi-Cluster Service Mesh Design

## Problem Statement

Today, Lattice's bilateral agreement model operates within a single cluster. Service A declares `outbound: [service-b]`, Service B declares `inbound: [service-a]`, the `ServiceCompiler` sees both sides, and the `PolicyCompiler` generates CiliumNetworkPolicy + AuthorizationPolicy to enforce the agreement.

When Service A lives on Cluster A and Service B lives on Cluster B, no single compiler sees both sides. We need a mechanism to:

1. **Discover** remote services across the cluster hierarchy
2. **Distribute** remote service metadata so local compilers can resolve dependencies
3. **Generate** the right infrastructure (ServiceEntry + Gateway API) for cross-cluster traffic
4. **Preserve** location transparency so services don't need to know where their dependencies run

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
          │ service-b │      │ service-a │
          │(external  │      │(external  │
          │   LMM)    │      │   LMM)    │
          └──────────┘      └──────────┘

  service-a declares outbound: [service-b]
  service-b declares inbound: [service-a]

  Compiler on Cluster A sees local service-a + external LMM for service-b → match
  Compiler on Cluster B sees local service-b + external LMM for service-a → match
```

**Key principle**: The parent cluster acts as service registry and config broker. Actual data-plane traffic flows directly between clusters (north/south). The parent never proxies runtime traffic.

## Service Registry

### Parent as Registry

Each cluster reports its local services to its parent via the existing gRPC stream. The parent aggregates a global service registry across all children. In a multi-level hierarchy, the registry bubbles all the way to the root — the root holds a complete service map.

This is the only viable coordination point because:
- The parent already has outbound connections from all children (via the agent gRPC stream)
- Peer-to-peer would require full mesh and inbound access (violates outbound-only architecture)
- The parent is already the coordination point for provisioning and pivot

### Registry Scope

The registry boundary is per-tree. Multiple roots (a forest) naturally scopes service discovery and blast radius. A service on a cluster in Tree A is not discoverable from Tree B.

### Independence Guarantee

When the parent goes down:
- Existing ServiceEntries + Gateway routes are already materialized on each cluster
- Cross-cluster traffic continues to flow
- **New** service registrations or dependency changes cannot be resolved until the parent recovers

This is an acceptable architectural requirement. There must always be an external registry to handle cross-cluster additions. The parent is that registry.

## External LatticeMeshMember Distribution

When the parent learns about a service from one child, it creates an **external** `LatticeMeshMember` on all other children to represent that remote service as a targetable dependency.

### Why This Works

- **Same bilateral model**: The local `ServiceCompiler` doesn't need a "cross-cluster" codepath. It sees a local LMM and resolves against it like any other dependency.
- **Bilateral enforcement comes for free**: The external LMM carries the inbound declarations from the original service, so the local compiler validates the agreement using existing logic.
- **Location transparency**: Consumers declare `outbound: [service-b]` — the compiler determines whether the resolved LMM is local or external and generates the appropriate infrastructure.

### External LMM Shape

The external LMM is structurally a `LatticeMeshMember` with additional fields to indicate its remote origin:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: service-b
  namespace: lattice-mesh       # dedicated namespace for external LMMs
  labels:
    lattice.dev/external: "true"
    lattice.dev/source-cluster: "cluster-b"
  annotations:
    lattice.dev/managed-by: "parent-registry"
spec:
  # Identity from the original service
  source_cluster: cluster-b
  source_namespace: default
  source_name: service-b

  # Bilateral agreement metadata (copied from origin)
  allowed_callers:
    - name: service-a
    # callers from the original service's inbound declarations

  # Gateway endpoint for traffic routing
  gateway_endpoint:
    address: 10.0.1.50          # Cluster B's ingress gateway LB IP
    port: 15443                 # mTLS passthrough port
```

### What the Parent Pushes

When the parent sees a new or updated service on Cluster B:

1. Extracts the service identity, bilateral declarations, and gateway endpoint
2. Constructs an external LMM
3. Pushes it to **all other children** via `ApplyManifestsCommand` on the gRPC stream
4. On deletion or update, the parent removes/updates the external LMM accordingly

## Dependency Resolution

### Unqualified Names (Common Case)

```yaml
# User writes in LatticeService:
resources:
  service-b:
    direction: outbound
```

The compiler resolves `service-b` by searching:
1. Local LMMs in the same namespace
2. External LMMs in the external mesh namespace

**Resolution rules:**
- Exactly one match → use it (local or external)
- Zero matches → unknown dependency error
- Multiple matches → ambiguous dependency error (compilation fails for this specific dependency)

### Qualified Names (Disambiguation)

```yaml
# User writes in LatticeService:
resources:
  cluster-b:service-b:
    direction: outbound
```

The `cluster:service` form skips the registry lookup and resolves directly to the external LMM for `service-b` on `cluster-b`. This is used when:
- There's a name collision (same service name on multiple clusters)
- The user intentionally wants to pin to a specific cluster's instance

### Resolution Algorithm

```
resolve(dep_name) -> Result<LMM, Error>:
  if ":" in dep_name:
    cluster, service = dep_name.split(":")
    find external LMM where source_cluster == cluster AND source_name == service
    if not found → error("service {service} not found on cluster {cluster}")
    return lmm
  else:
    local_matches = local LMMs where name == dep_name
    external_matches = external LMMs where source_name == dep_name
    candidates = local_matches + external_matches
    match candidates.len():
      0 → error("unknown dependency: {dep_name}")
      1 → return candidates[0]
      _ → error("ambiguous dependency: {dep_name} exists on clusters: {list}")
```

### Name Collision Behavior

A name collision is a **hard conflict** for that specific dependency — compilation fails with an actionable error telling the user which clusters have the service. Other dependencies on the same service compile normally.

## Compilation Output

The compiler produces different infrastructure based on whether the resolved LMM is local or external:

### Local Dependency (Same as Today)

```
service-a (outbound: service-b) → local LMM for service-b
  Generates:
    - CiliumNetworkPolicy (L4 eBPF, HBONE allow)
    - AuthorizationPolicy (L7 SPIFFE identity)
    - PeerAuthentication (mTLS mode)
```

### External Dependency (New)

```
service-a (outbound: service-b) → external LMM for service-b
  Generates:
    - ServiceEntry (registers service-b's gateway endpoint in local mesh)
    - Gateway API HTTPRoute/TCPRoute (routes to remote gateway endpoint)
    - AuthorizationPolicy (allows service-a's SPIFFE identity to reach the ServiceEntry)
    - CiliumNetworkPolicy (allows egress to remote gateway IP)
```

On the **remote side** (Cluster B, where service-b lives):

```
service-b has external LMM for service-a in its allowed_callers
  Generates:
    - Gateway listener (accepts inbound traffic on mTLS passthrough port)
    - AuthorizationPolicy on Gateway (allows service-a's cross-cluster SPIFFE identity)
    - HTTPRoute/TCPRoute on Gateway (routes to local service-b)
```

## Cross-Cluster Traffic Path

Traffic flows directly between clusters. The parent is never in the data path.

```
Cluster A                                          Cluster B
┌────────────────────┐                    ┌────────────────────┐
│ service-a pod      │                    │ service-b pod      │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ ztunnel (sidecar)  │                    │ ztunnel (sidecar)  │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ ServiceEntry       │                    │ Gateway (istio)    │
│ (service-b.ext)    │                    │ (mTLS passthrough) │
│       │            │                    │       ▲            │
│       ▼            │                    │       │            │
│ Egress Gateway     │ ──── mTLS ────▶   │ Ingress Gateway    │
└────────────────────┘                    └────────────────────┘
```

From service-a's perspective, this is standard north/south traffic: pod → mesh → ServiceEntry → remote Gateway → pod.

## Identity and mTLS

### Cross-Cluster Trust

Each Lattice cluster has its own Istio trust domain: `lattice.{cluster_name}.local`. For cross-cluster mTLS to work, clusters need to trust each other's certificate authority.

**Options (in order of preference):**

1. **Shared root CA**: All clusters in the same tree share a root CA distributed during pivot. Each cluster's Istio uses an intermediate CA signed by the shared root. Cross-cluster mTLS works automatically because both sides trust the root.

2. **Trust bundle federation**: Each cluster's CA cert is distributed to peers via the parent registry. Istio is configured with additional trusted roots. More complex but allows independent CA rotation.

**Recommendation**: Shared root CA distributed during bootstrap/pivot. This aligns with the existing certificate distribution flow (the agent already receives certs from the parent).

### SPIFFE Identity Across Clusters

When service-a on Cluster A calls service-b on Cluster B, the AuthorizationPolicy on Cluster B's Gateway needs to allow:

```
principal: lattice.cluster-a.local/ns/default/sa/service-a
```

This works with the existing `trust_domain::principal()` helper — the external LMM carries the source cluster name, so the policy compiler can generate the correct cross-cluster principal.

### Identity Continuity on Migration

If service-b moves from Cluster B to Cluster A:
- Its SPIFFE identity changes from `lattice.cluster-b.local/.../service-b` to `lattice.cluster-a.local/.../service-b`
- Consumers using unqualified names don't need to change their LatticeService spec
- The **policies** are recompiled automatically because the external LMM is replaced with a local LMM
- No consumer manifest changes required

## Protocol Changes

### gRPC Stream Additions

The `SubtreeState` message already bubbles cluster hierarchy to the parent. We extend it to include service metadata:

```protobuf
message SubtreeState {
  bool is_full_sync = 1;
  repeated ClusterInfo clusters = 2;
  repeated ServiceInfo services = 3;       // NEW
  repeated ServiceInfo removed_services = 4; // NEW (for delta updates)
}

message ServiceInfo {
  string cluster_name = 1;
  string namespace = 2;
  string name = 3;
  repeated CallerRef allowed_callers = 4;  // Bilateral inbound declarations
  repeated ServiceRef dependencies = 5;    // Bilateral outbound declarations
  repeated PortInfo ports = 6;
  string gateway_address = 7;              // Cluster's ingress gateway LB IP
  uint32 gateway_port = 8;
}
```

### Cell-Side Registry

The cell's `SubtreeRegistry` is extended to track services:

```rust
pub struct SubtreeRegistry {
    clusters: DashMap<String, ClusterInfo>,
    services: DashMap<ServiceKey, ServiceInfo>,  // NEW
    // ...
}

#[derive(Hash, Eq, PartialEq)]
pub struct ServiceKey {
    pub cluster: String,
    pub namespace: String,
    pub name: String,
}
```

When the registry changes, the cell:
1. Computes the set of external LMMs needed on each child
2. Diffs against previously distributed LMMs
3. Pushes additions/updates/deletions via `ApplyManifestsCommand`

### Agent-Side Service Reporting

The agent watches local `LatticeMeshMember` CRDs (excluding external ones) and reports them to the parent as `ServiceInfo` entries in the `SubtreeState`:

```rust
// In subtree.rs, extend the watcher to include services
fn build_subtree_state(&self) -> SubtreeState {
    let clusters = self.get_local_clusters();
    let services = self.get_local_services();  // NEW: watch LMMs, filter external
    SubtreeState {
        is_full_sync: true,
        clusters,
        services,
        removed_services: vec![],
    }
}
```

## Migration Story

Service-b moves from Cluster B to Cluster A:

1. User deploys `LatticeService` for service-b on Cluster A
2. Cluster A's agent reports service-b to the parent
3. **Name collision**: service-b now exists on both Cluster A (local) and Cluster B (external LMM from parent)
4. Parent detects the collision and:
   - Removes external LMM for service-b from Cluster A (it's now local)
   - Updates external LMMs on all other clusters to point to Cluster A's gateway
5. User removes `LatticeService` for service-b from Cluster B
6. Cluster B's agent reports removal, parent cleans up

**During the transition** (service-b exists on both clusters):
- Unqualified `outbound: [service-b]` → compilation error (ambiguous)
- Qualified `outbound: [cluster-a:service-b]` or `outbound: [cluster-b:service-b]` → works
- This forces explicit routing during migration, preventing split-brain

## Gateway Configuration

### Per-Cluster Ingress Gateway

Each cluster that hosts services which are consumed cross-cluster needs an ingress gateway:

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

This gateway is provisioned once per cluster (during bootstrap or on first cross-cluster dependency) and its LoadBalancer IP is reported to the parent as part of the `ServiceInfo`.

### Per-Service Routes

For each service consumed cross-cluster, a route is attached to the gateway:

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

### ServiceEntry on Consumer Side

On Cluster A (where service-a lives), the external dependency generates:

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

## Implementation Phases

### Phase 1: Service Registry

- Extend `SubtreeState` protobuf with `ServiceInfo`
- Extend `SubtreeRegistry` to track services
- Agent watches local LMMs and reports to parent
- Parent aggregates global service map

### Phase 2: External LMM Distribution

- Parent computes external LMMs from registry
- Push external LMMs to children via `ApplyManifestsCommand`
- Handle additions, updates, and deletions
- Add `external` field to `LatticeMeshMemberSpec`

### Phase 3: Compiler Changes

- Dependency resolution: unqualified and qualified name lookup
- Detect local vs external LMM
- External path: generate ServiceEntry + Gateway route instead of local mesh policy
- Ambiguity detection and error messages

### Phase 4: Cross-Cluster Gateway

- Per-cluster mesh ingress gateway provisioning
- Per-service TCPRoute/HTTPRoute generation
- Gateway LB IP reporting in ServiceInfo
- AuthorizationPolicy on gateway for cross-cluster SPIFFE principals

### Phase 5: Trust Federation

- Shared root CA distribution during bootstrap
- Cross-cluster SPIFFE identity resolution
- AuthorizationPolicy generation with remote trust domain principals

### Phase 6: Testing

- Unit tests for dependency resolution (unqualified, qualified, ambiguous, missing)
- Unit tests for external LMM generation and distribution
- Integration tests for cross-cluster bilateral enforcement
- E2E test: two clusters, cross-cluster service dependency, verify traffic flows
- E2E test: service migration between clusters
- E2E test: parent failure with existing cross-cluster traffic (independence)
