# basis-controller — BGP Route Reflector & Address Pool Allocator

Status: design
Scope: the basis-controller-side work that pairs with the BGP-based LB advertisement design already landed in lattice-rust. This document is the companion: it specifies the daemon, CRDs, allocator, and status surface that the lattice-rust changes assume on the other end of the wire.

Lattice (this repo) is done. Everything described here is implemented in the basis-controller (and lightly in basis-capi-provider).

## Goals

- Be the BGP peer every node in every cluster in the cell talks to. Reflect routes between clusters so cluster A's nodes know how to reach cluster B's LB IP without going through any Lattice control-plane hop.
- Re-originate `public`-scope prefixes upstream as eBGP to the customer router; keep `cell`-scope prefixes inside the cell.
- Own address-pool allocation. Lattice clusters reference pools by name; basis carves slices and reports allocations on the `BasisCluster` status. Single source of truth for who has which IPs.
- Single Rust binary. No sidecar BGP daemon, no FFI, no `vtysh` shellouts.
- Session security via kernel source-IP ACLs on the cell's isolated management network. No TCP-MD5 (FIPS-illegal). TCP-AO is a future upgrade gated on kernel + daemon support.

## Non-Goals

- IPv6.
- Multi-cell topology. A future cell-of-cells design will need basis controllers to peer with each other; out of scope here.
- A user-facing BGP API. Pools are the user-facing primitive. ASNs and route reflection are internal.
- Replacing Cilium IPAM in clusters. Cilium still allocates LB IPs from the per-cluster `CiliumLoadBalancerIPPool`s; basis only carves the *blocks* those pools draw from.

## Architecture

```
                 ┌─────────────────────┐
                 │  customer upstream  │
                 │  router (eBGP)      │
                 └─────────────────────┘
                         ▲
            eBGP, public-scope /32s only
                         │
              ┌──────────┴──────────────┐
              │   basis-controller      │
              │   (Rust, single binary) │
              │                         │
              │   ┌─────────────────┐   │
              │   │ holo BGP embed  │   │
              │   │ - RR for cell   │   │
              │   │ - eBGP upstream │   │
              │   └─────────────────┘   │
              │   ┌─────────────────┐   │
              │   │ AddressPool     │   │
              │   │ allocator       │   │
              │   └─────────────────┘   │
              │   ┌─────────────────┐   │
              │   │ K8s controllers │   │
              │   │ - AddressPool   │   │
              │   │ - PodCidrPool   │   │
              │   │ - BasisCluster  │   │
              │   │   reconciler    │   │
              │   └─────────────────┘   │
              │   ┌─────────────────┐   │
              │   │ source-IP ACL   │   │
              │   │ (nftables)      │   │
              │   └─────────────────┘   │
              └─────────────────────────┘
                  ▲     ▲     ▲     ▲
        iBGP      │     │     │     │
                  │     │     │     │
       ┌──────────┘     │     │     └──────────┐
       │                │     │                │
   ┌───┴────┐      ┌────┴───┐ │            ┌───┴────┐
   │ cluster│      │ cluster│ │            │ cluster│
   │ A node │      │ A node │ │            │ B node │
   │ (Cilium│      │ (Cilium│ │            │ (Cilium│
   │  +kvip)│      │  +kvip)│ │            │  +kvip)│
   └────────┘      └────────┘ │            └────────┘
                              │
                          (every node
                          peers with the
                          basis controller)
```

Every BGP speaker in the cell has exactly one peer: basis-controller. There are no node-to-node sessions and no full mesh. basis-controller is the route reflector.

## BGP Daemon Choice

**holo, embedded.** Pure-Rust routing suite (https://github.com/holo-routing/holo). Single binary, no FFI, MPL-licensed.

Required features (all present): iBGP route reflection, eBGP, route policy with community matching, BGP communities (standard + large), graceful restart. BFD is nice-to-have.

Fallback if a holo gap surfaces: gobgp as a sidecar process consumed via its gRPC API from Rust. We do not embed FRR — keeping a C daemon in the basis-controller pod for capabilities we don't use isn't worth the lifecycle complexity.

## ASN Model

Single cell ASN. Every node in every Lattice-managed cluster runs iBGP at the cell ASN. basis-controller advertises its own router-id at the same ASN. There are no per-cluster ASNs.

Per-cluster identity is carried in BGP communities, not ASNs:

- `cluster:<id>` — large community, set by basis-controller as routes ingress from a cluster's nodes (so other clusters can filter on it if needed).
- `pool:<name>` — large community marking which address pool a /32 belongs to. Set on ingress, used by upstream-redistribution filter.
- `scope:cell` / `scope:public` — derived from the pool's `scope` field. The eBGP-to-upstream filter matches `scope:public` and rejects everything else.

This avoids private-ASN exhaustion (1023 addresses in 64512–65534), removes the need for confederation config, and makes route policy expressible in plain `community match` rules.

## CRDs

All cluster-scoped, group `basis.lattice.dev/v1alpha1`.

### `AddressPool`

User-facing. Cell admin creates one of these per pool the cell offers.

```yaml
apiVersion: basis.lattice.dev/v1alpha1
kind: AddressPool
metadata:
  name: cell-public
spec:
  cidr: 10.0.0.0/24
  scope: public            # cell | public
  sliceSize: 28            # default /28 per cluster, configurable
  upstream:                # required iff scope=public
    asn: 64500
    peer: 10.0.0.1
status:
  allocated:
    - { cluster: e2e-mgmt,    cidr: 10.0.0.176/28 }
    - { cluster: e2e-other,   cidr: 10.0.0.192/28 }
  free: 13                 # number of unallocated /28 slices
```

`scope: cell` pools are reflected within the cell only. `scope: public` pools are additionally re-originated as eBGP to the configured upstream peer (one peer per public pool; multiple public pools allowed).

`sliceSize` is per-pool because pool sizing varies — public pools fed from a customer's /24 are tight, internal pools fed from RFC1918 space are not. `/28` is the default; the root cluster's public allocation typically wants `/27` or `/26`.

### `PodCidrPool`

Same shape as `AddressPool`, but slices are per-node, not per-cluster. basis allocates a `/24` to each node when it's provisioned and stores the allocation on the `BasisMachine` status. Lattice's Cilium IPAM (kubernetes-mode) reads the per-node CIDR off the K8s node object that basis populates.

```yaml
apiVersion: basis.lattice.dev/v1alpha1
kind: PodCidrPool
metadata:
  name: pod-cidrs
spec:
  cidr: 10.244.0.0/16
  sliceSize: 24            # /24 per node
status:
  allocated:
    - { cluster: e2e-mgmt,  node: cp-0,     cidr: 10.244.0.0/24 }
    - { cluster: e2e-mgmt,  node: worker-0, cidr: 10.244.1.0/24 }
  free: 254
```

PodCidrPools are always cell-scope. PodCIDRs are not advertised upstream.

### `BasisCluster` spec additions

Lattice already writes these fields. basis-capi-provider reads them.

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: BasisCluster
spec:
  credentialsRef: { ... }
  apiserverVipPool: cell-public      # which pool to draw the apiserver VIP from
  podCidrPool: pod-cidrs
status:
  controlPlaneEndpoint: 10.0.0.176   # written by basis after VIP allocation
  addressPoolAllocations:
    - { pool: cell-internal, cidr: 10.255.4.16/28 }
    - { pool: cell-public,   cidr: 10.0.0.176/28 }
  bgpSessions:
    - { node: cp-0,     state: Established, advertised: 3 }
    - { node: worker-0, state: Established, advertised: 2 }
```

Lattice's CRD schema already requires `bgpPeer`, `addressPools`, `apiserverVipPool`, `podCidrPool`. basis-capi-provider's job is to:

1. On `BasisCluster` create, allocate slices from each named `AddressPool` (one per cluster) and the `PodCidrPool` (one per node, tracked separately). Write allocations to `status`.
2. On `BasisMachine` create, allocate a node-PodCIDR slice and write it to `status.podCidr`. The `lattice-node` cloud-init reads it and sets the kubelet `--node-ip` + Cilium IPAM accordingly.
3. After Basis allocates the apiserver VIP from `apiserverVipPool`, write the IP to `BasisCluster.spec.controlPlaneEndpoint` so Lattice's reconciler can SSA the KubeadmControlPlane on its next pass.

### `Bgp` daemon resource (optional)

Internal. Records the basis-controller's own BGP runtime state (peer up/down, RIB size, last reload time) for ops debugging. Exposed by the daemon, not user-edited.

## Allocator

In-process, transactional, persisted to etcd via the K8s API.

**Atomicity.** Allocation goes through a `Lease`-style optimistic concurrency loop on `AddressPool.status.allocated`: read current state, compute the next free slice, attempt `update` with the prior `resourceVersion`. If the update conflicts, re-read and retry. Bounded retries → fail → CR conditions surface the error.

**Slicing.** First-fit by lowest free address. No coalescing required; pool reclaim is whole-slice on `BasisCluster` deletion.

**Reclaim.** Garbage-collect on `BasisCluster` deletion via owner references on the `AddressPool` allocation entries. PodCIDR allocations garbage-collect on `BasisMachine` deletion. No explicit "release" RPC.

**Validation.** Reject `AddressPool` updates that would orphan an existing allocation (CIDR shrink, sliceSize change with allocations outstanding). Allow only safe widenings.

## Route Distribution

`holo` is configured with one address-family (IPv4 unicast) and one peer template per cluster. On `BasisCluster` create:

1. Allocator carves slices from each subscribed pool.
2. basis-controller adds a peer-config entry for every node in that cluster (peer IPs come from the `BasisMachine` underlay-IP allocations basis already does for VM provisioning).
3. The peer-config carries an import policy: tag every prefix received from a node with `cluster:<id>`, `pool:<name>` (looked up by longest-prefix match into the pool's slice), `scope:<cell|public>`.
4. Reflect to all other peers in the cell (RR client config).
5. For peers in the eBGP upstream group, apply an export policy: `match community scope:public; permit; default deny`.

On `BasisCluster` delete: drop the cluster's peers from holo, free its address-pool slices, the cell's RIB stops reflecting the prefixes naturally.

## Session Security

The cell's management network is isolated by physical / L2 fabric design — node IPs are basis-allocated and basis-known. The basis-controller's nftables (or equivalent) inputs:

- `tcp dport 179 ip saddr <every-known-node-IP> accept`
- `tcp dport 179 drop`

The ACL is rebuilt by the controller every time the set of provisioned nodes changes (debounced). This is stronger than a shared MD5 secret on a flat L2 — there is no preshared-key leak path because there is no preshared key. TCP-AO will replace this when the kernel + holo support land; until then, the network-layer control is the security boundary.

CLAUDE.md's "no MD5" rule is not bypassable; this design has no MD5 path to reach for if you're tempted.

## Status Surface

basis-controller's `Bgp` resource exposes per-peer state. Lattice's cluster reconciler reads `BasisCluster.status.bgpSessions` and surfaces a condition on `LatticeCluster.status.conditions`:

```yaml
conditions:
  - type: BgpSessionsReady
    status: "True"
    reason: AllPeersEstablished
    message: 3/3 nodes established with cell controller
```

Failing peers surface with `status: False` and a `reason: PeerDown` so users debugging "my LB IP isn't reachable" don't have to read the basis-controller logs.

## Phased Implementation

Land in this order. Each phase is independently shippable.

1. **holo embed.** Wire holo into basis-controller as a library. Empty BGP config, no peers. Verify the daemon starts, RIB is empty, holo's gRPC mgmt surface is reachable from in-process Rust.

2. **Allocator + AddressPool/PodCidrPool CRDs + reconciler.** No BGP yet. `BasisCluster` create → allocations written to status. `BasisCluster` delete → reclaim. Unit + integration tests on the allocator.

3. **Per-cluster peer config drive.** When `BasisCluster.status.addressPoolAllocations` is populated and `BasisMachine`s exist, generate holo peer entries. Verify nodes establish iBGP sessions in an integration test against a real Cilium-on-kind cluster.

4. **Route reflection + community policy.** Import/export policies for `cluster:` / `pool:` / `scope:` communities. Reflect within cell. Verify cluster-A nodes learn cluster-B's LB /32s via packet captures in an integration test.

5. **eBGP upstream re-origination.** Per-public-pool upstream peer entries. Filter to scope:public only. Integration test with a containerized FRR as the upstream peer; verify only public /32s leak.

6. **Source-IP ACL controller.** nftables (or equivalent) reconciler driven by `BasisMachine` underlay-IP set. Integration test: spoof from an unknown source, verify the BGP TCP SYN never reaches holo.

7. **Status surface.** Per-peer `bgpSessions` on `BasisCluster.status`. Lattice condition wiring follows automatically since lattice-rust already reads that field.

## Test Plan

- Unit: allocator (concurrent allocate, reclaim, CIDR-shrink rejection, fragmentation cases).
- Unit: community policy match/transform rules.
- Integration: real Cilium-on-kind cluster speaks iBGP to basis-controller, verifies LB /32s and PodCIDRs propagate.
- Integration: two-cluster cell, verify cluster-A reaches cluster-B's `cell-internal` LB IP without any basis-controller hairpin.
- Integration: containerized FRR upstream, verify only `scope:public` prefixes leak; `scope:cell` does not.
- Chaos: kill a node, verify holo drops the session within holdtime and prefixes are withdrawn from the RIB; restart the node, verify reconvergence.

## Open Questions

- **TCP-AO timeline.** Defer until kernel + holo support is mature. Source-IP ACL is the v1 boundary.
- **BFD.** Sub-second failure detection. Layer on once the basics work; not a blocker.
- **Multi-cell.** Cell-to-cell eBGP between basis-controllers comes with the multi-cell design. Not v1.
- **PodCIDR pool scope.** v1 keeps PodCidrPool as a single global pool per cell. If clusters need isolated pod ranges (per-tenant) this becomes per-cluster pool selection, mirroring `addressPools`.
