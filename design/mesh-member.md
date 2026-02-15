# LatticeMeshMember Design

Policy-only mesh enrollment for existing in-cluster workloads. Generates Cilium and Istio policies without managing Deployments or Services.

## Use Cases

- **Monitoring infrastructure**: VMSingle/VMInsert/VMSelect need mTLS callers (vmagent, KEDA) with bilateral agreements
- **Webhook pods**: KEDA metrics-apiserver, VM operator webhook — permissive ports for kube-apiserver calls
- **Stateful workloads**: CloudNativePG clusters that need peer traffic between replicas
- **Third-party operators**: Any existing workload that needs mesh enrollment without a full LatticeService

## Non-goals

- **Core infrastructure** (CAPI, ESO, cert-manager, GPU, lattice-operator): excluded from default-deny via `system_namespaces`. These create chicken-and-egg deadlocks if enrolled via MeshMember because the operator must be running to reconcile them.

## CRD: `LatticeMeshMember`

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: vmsingle
  namespace: lattice-system     # owner namespace (where the CRD lives)
spec:
  target:
    # Option A: pod label selector (within owner namespace)
    selector:
      app.kubernetes.io/name: vmsingle
      app.kubernetes.io/instance: vm-stack
    # Option B: all pods in a namespace (requires Cedar authorization)
    # namespace: monitoring

  ports:
    - port: 8429
      name: http
      peerAuth: strict          # default — requires mTLS
    - port: 6443
      name: metrics-api
      peerAuth: permissive      # accepts plaintext (kube-apiserver, LBs)

  allowedCallers:               # inbound side of bilateral agreement
    - name: vmagent
      namespace: monitoring     # defaults to owner namespace if omitted
    - name: keda-operator
      namespace: keda
    # - name: "*"              # wildcard: allow all mesh identities

  dependencies:                 # outbound side — what this workload calls
    - name: some-service
      namespace: prod

  egress:                       # non-mesh egress (CIDR, FQDN, entities)
    - target:
        entity: kube-apiserver
    - target:
        cidr: 172.18.255.0/32
      ports: [8443, 50051]
    - target:
        fqdn: api.example.com
      ports: [443]

  allowPeerTraffic: false       # if true, pods with same identity can talk to each other
```

### Target types

| Target | Selector | Policy namespace | Cedar check |
|--------|----------|-----------------|-------------|
| `selector: {labels}` | Pod labels | Owner namespace | No |
| `namespace: monitoring` | None (all pods) | Target namespace | Yes — `TargetNamespace` action |

### Status

```yaml
status:
  phase: Ready          # Pending, Ready, Failed
  scope: Workload       # Workload or Namespace (derived from target)
  message: "policies applied"
  observedGeneration: 3
  conditions: [...]
```

## Resource naming: `derived_names`

All generated K8s resources use deterministic hash-based names to stay within the 63-character DNS label limit.

Format: `{prefix}{hash8}` where `hash8 = SHA-256(parts.join("/"))[0..8]` in hex.

```
allow-to-a1b2c3d4          # inbound AuthorizationPolicy
allow-webhook-e5f6g7h8     # permissive port AuthorizationPolicy
permissive-i9j0k1l2        # PeerAuthentication
cnp-mesh-m3n4o5p6          # CiliumNetworkPolicy
allow-ext-q7r8s9t0         # external access AuthorizationPolicy
```

Source name stored in `lattice.dev/source-name` label for discoverability.

Lives in `lattice-common/src/crd/mod.rs` — same crate as the CRD, uses `aws_lc_rs::digest::SHA256` (FIPS).

## Policy compilation

### Istio (ztunnel-enforced, no waypoint)

**Inbound AuthorizationPolicy** (`compile_mesh_member_inbound_policy`):
- Selector: mesh member's pod labels (or none for namespace-scoped)
- ALLOW with SPIFFE principals from bilateral agreements
- Ports: all declared ports (target_port = service_port for mesh members)
- Only generated if there are inbound edges

**Permissive PeerAuthentication** (`compile_permissive_policies_for_member`):
- One PeerAuthentication per mesh member with permissive ports
- PERMISSIVE mode, scoped to the member's selector
- Paired with an open ALLOW AuthorizationPolicy (empty `from:[]`) restricted to the permissive ports only

**Peer traffic AuthorizationPolicy**:
- If `allowPeerTraffic: true`, add the member's own SPIFFE principal to the inbound policy

### Cilium (L4 eBPF)

**CiliumNetworkPolicy** (`compile_mesh_member_cilium_policy`):
- Endpoint selector: mesh member's pod labels
- Ingress: HBONE (port 15008) for strict-port callers, direct TCP (endpoint + world) for permissive ports
- Egress: DNS to kube-dns, HBONE for outbound deps, entity/CIDR/FQDN rules from `spec.egress`

### Compilation flow

```
PolicyCompiler::compile(name, namespace)
  └─ if ServiceType::MeshMember → compile_mesh_member()
       ├─ compile_mesh_member_inbound_policy()     → AuthorizationPolicy
       ├─ compile_mesh_member_cilium_policy()       → CiliumNetworkPolicy
       └─ (permissive policies added by controller, not compiler)
```

Permissive policies are generated by the controller calling `compile_permissive_policies_for_member()` directly, because peerAuth mode is not stored in the ServiceGraph — it's spec-level detail.

## Cedar authorization

Namespace-scoped members (targeting pods in a different namespace) require Cedar authorization:

```
permit(
    principal,
    action == Lattice::Action::"TargetNamespace",
    resource
) when {
    principal.namespace == "lattice-system"
};
```

Entities:
- `Lattice::MeshMember::"namespace/name"` (principal)
- `Lattice::Namespace::"target-namespace"` (resource)

Installed at operator startup as a CedarPolicy CRD.

## Controller: `mesh_member_controller.rs`

```
reconcile(member, ctx):
  1. Validate spec
  2. Cedar namespace scope check (if namespace-scoped)
  3. ctx.graph.put_mesh_member(namespace, name, spec)
  4. compiler.compile(name, namespace) → policies
  5. spec.permissive_policies(name, target_namespace) → peer_auths, auth_policies
  6. Merge permissive policies into compiled output
  7. Apply all policies via SSA (apply_mesh_member_policies)
  8. Update status (phase, scope, observedGeneration)
  9. Requeue 60s
```

The controller MUST actually apply the policies — compile-and-log-only is a bug.

## Graph integration

`ServiceNode` additions:
- `selector: Option<BTreeMap<String, String>>` — custom pod labels for policy targeting
- `target_namespace: Option<String>` — for namespace-scoped members
- `allow_peer_traffic: bool` — self-to-self communication
- `egress_rules: Vec<EgressRule>` — non-mesh egress

`ServiceGraph::put_mesh_member()` creates a `ServiceNode` with `type_: ServiceType::MeshMember`.

Bilateral agreement resolution works the same as services — `callee.allows(caller_ns, caller_name)` checks `allowed_callers`.

## What NOT to do

- Don't add `ResourceType::MeshMember` to the service resource model — MeshMember is a separate CRD, not a resource within LatticeService
- Don't create stub methods that return empty vecs — either implement or don't add
- Don't use `format!("prefix-{}", name)` for resource names — use `derived_names` with hash
- Don't leave hand-crafted policy functions as dead code when MeshMembers replace them
- Don't dogfood core infrastructure (CAPI, operator, ESO, cert-manager) — system namespace exclusions exist for a reason

## File layout

```
lattice-common/src/crd/mesh_member.rs     # CRD types, validation, helpers
lattice-common/src/crd/mod.rs             # derived_names module, re-exports
lattice-common/src/graph/mod.rs           # put_mesh_member, ServiceNode additions
lattice-common/src/policy/cilium.rs       # from_entities on CiliumIngressRule
lattice-cedar/src/mesh_member_auth.rs     # MeshMemberAuthzRequest
lattice-cedar/src/entities.rs             # MeshMember + Namespace entities
lattice-service/src/mesh_member_controller.rs  # reconcile loop
lattice-service/src/policy/cilium.rs      # compile_mesh_member_cilium_policy
lattice-service/src/policy/istio_ambient.rs  # compile_mesh_member_inbound_policy, permissive
lattice-service/src/policy/mod.rs         # compile_mesh_member dispatch, tests
lattice-service/src/controller.rs         # apply_mesh_member_policies
lattice-operator/src/controller_runner.rs # register controller
lattice-operator/src/startup/crds.rs      # CRD install + Cedar policy
```
