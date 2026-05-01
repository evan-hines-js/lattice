# Cilium BGP on basis-provider clusters

Status: design
Scope: switch the Cilium load-balancer datapath from L2-announce + SNAT to BGP-announced + DSR for clusters running on the **basis** provider. Other providers (Proxmox, Docker/kind) keep the L2-announce path unchanged.

The basis-controller side already runs an iBGP route reflector (holod, embedded), peers with every basis hypervisor, and reflects per-host advertised cluster_vips. The remaining work — adding K8s nodes as additional iBGP clients of the same reflector, flipping the Lattice Cilium install to peer with it, and tightening the import policy — is what this doc plans.

## Goals

- Basis-provider clusters announce LB IPs via BGP instead of L2 ARP. The leaf failure mode that motivated this — `loadBalancer.mode=dsr` + `l2announcements.enabled=true` leaving the announcing node ARPing for the VIP without IP-claiming it on `lo`, producing an ICMP-redirect loop between the carrier and cluster gateway — disappears entirely under BGP.
- DSR becomes free. With the LB IP reachable as a route rather than an L2 claim, there's nothing to install on `lo`; the holder receives the packet via plain routing, eBPF DNATs to backend, no SNAT mode dance, no source-IP loss.
- Set up the path for eventual removal of the basis LAN-VIP owner election + proxy-ARP. **Not removed in this change.** proxy-ARP + GARP + `elect_lan_vip_owner` remain the L2-stub for any LAN segment whose router doesn't speak BGP — without them, a non-BGP-aware LAN client (laptop, phone, anything that ARPs for an IP in its `/24`) can't reach a cluster VIP at all. They become vestigial only once the deployment also runs eBGP-upstream peering between basis-controller and the customer's edge router (the "scope: public" path in the existing basis-controller BGP design); that's listed under "Implementation plan" step 5 here. For the current shape of any non-eBGP-upstream cell (homelab, plus any production environment whose customer router doesn't peer with the cell), the L2-stub is still the only path for LAN clients.
- **Don't leak basis-internal concepts into Lattice.** Lattice keeps naming pools (`externalIpPool: cell-public`); basis keeps allocating IPs and reporting them on `BasisCluster.status`. No `AddressPool`, `PodCidrPool`, BGP community, or scope concept appears in any Lattice CRD.

## Non-goals

- IPv6.
- Multi-cell topology.
- Replacing L2-announce on Proxmox / Docker / kind providers. Those clusters don't have a BGP fabric to peer with and the L2-announce + SNAT path that was just stabilised is the right shape for them.
- Migrating live clusters in place. The flip is per-cluster at provision time; existing clusters re-create on upgrade.

## Current state

The transport is real and reflecting agent-advertised cluster_vips end-to-end inside the cell. The gap is on the policy side (no scope/community filtering yet) and on the K8s side (Cilium doesn't peer at all). The DSR-blocker is the latter. Audit:

| Design item | Implemented | Source |
|---|---|---|
| holod-driven cell route reflector on basis-controller | ✅ | `crates/basis-controller/src/bgp.rs` |
| Single cell ASN, all sessions iBGP | ✅ | `BgpConfig::asn` in `config.rs` |
| `peer_reconciler` mirrors `hosts` table into holod neighbors | ✅ | `bgp.rs:237` |
| nftables source-IP ACL on tcp/179 via `acl_reconciler` | ✅ | `bgp.rs:198` |
| `RegisterHostResponse` carries `bgp_asn` + `bgp_reflector_address` | ✅ | `server.rs:1946` |
| Agent-side `Speaker` peers with RR, advertises cluster_vips | ✅ | `basis-agent/src/bgp.rs` |
| AddressPool / PodCidrPool CRDs | ❌ | Pool config lives in the controller's static config today |
| Community tagging on import (`cluster:<id>`, `pool:<name>`, `scope:<cell\|public>`) | ❌ | No community policy in `bgp.rs` |
| eBGP re-origination of `public`-scope prefixes upstream | ❌ | No upstream peer group |
| Cilium-on-node peering with the RR | ❌ | `bgpControlPlane.enabled=false` in `lattice-cilium/build.rs` |
| Per-node /24 PodCIDR slice allocation | ❌ | basis-agent allocates pod CIDRs differently today |

## Architecture

### Peering model

```
                ┌──────────────────────────┐
                │   basis-controller       │
                │   holod (route reflector)│
                │   ASN: <cell>            │
                └──────────────┬───────────┘
                               │ iBGP, source-IP ACL
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
   ┌───┴────┐              ┌───┴────┐              ┌───┴────┐
   │ host A │              │ host B │              │ host C │
   │ holod  │              │ holod  │              │ holod  │
   │ (basis │              │        │              │        │
   │  speak)│              │        │              │        │
   └────────┘              └────────┘              └────────┘
       │                                                │
       │   k8s node VMs (provisioned by basis)          │
       │                                                │
   ┌───┴──────┐         ┌──────────┐         ┌─────────┴┐
   │ k8s node │         │ k8s node │         │ k8s node │
   │ Cilium   │─iBGP───▶│ Cilium   │─iBGP───▶│ Cilium   │
   │ BGP      │         │ BGP      │         │ BGP      │
   └──────────┘         └──────────┘         └──────────┘
```

Every speaker — basis hypervisor, k8s node — is an iBGP client of the cell RR at the same cell ASN. There are no node-to-node sessions. K8s nodes announce LB-pool /32s; the RR reflects them to all other speakers in the cell, including the carrier hypervisors that bridge LAN traffic in.

The k8s node's BGP source IP is its node IP on the cluster overlay (the same IP basis already allocated and seeded into cloud-init). basis-controller already knows this IP (it's on `BasisMachine.status.address`); the only change is feeding it to `peer_reconciler` as a peer.

### Lattice surface (unchanged)

User-facing YAML stays the same:

```yaml
spec:
  provider:
    config:
      basis:
        externalIpPool: cell-public
```

What changes is downstream of `basis-capi-provider`:

1. CAPI provider asks basis-controller for the cluster's allocations (already does this) and additionally for the cell's BGP reflector address + ASN (already exposed via `bgp_asn`/`bgp_reflector_address` on RegisterHostResponse — needs a small RPC at the cluster level too).
2. CAPI provider generates the Cilium install for the cluster. For provider=basis, it renders the BGP variant; for provider=proxmox or docker or kind, the L2 variant.

The cluster's `CiliumLoadBalancerIPPool` is unchanged in either path — Cilium IPAM still allocates from the pool block basis carved. What differs is what announces the resulting /32: under BGP it's a `CiliumBGPAdvertisement` selecting that pool; under L2 it's a `CiliumL2AnnouncementPolicy`. Same Service spec, same allocation, different advertisement.

### What basis hides

Everything below the pool name. Lattice never sees:

- BGP communities (`cluster:<id>`, `pool:<name>`, `scope:<cell|public>` are policy that lives in basis-controller's import filters)
- The RR's ASN (basis-capi-provider reads it once and renders it into the Cilium BGP config; it never appears in Lattice's CRD types)
- Per-node /24 PodCIDR slicing (basis-agent allocates pod CIDRs in cloud-init; Cilium IPAM is told via kubernetes-mode and reads the node's `Spec.PodCIDR`)
- The carrier hypervisor's role (which host advertises which VIP, the proxy-ARP fallback for non-BGP-aware LAN segments, etc.)

If a Lattice CRD field starts to mention BGP, ASN, route reflector, or community — it's leaking and should move to basis.

## Implementation plan

Ordered so each step is independently shippable.

### 1. lattice-cilium: split L2 vs BGP helm value sets

Today `crates/lattice-cilium/build.rs` renders one `cilium.yaml` at build time with a single set of `--set` flags. Split into two outputs:

- `cilium-l2.yaml`: existing flags, `loadBalancer.mode=snat`, `l2announcements.enabled=true`, `bgpControlPlane.enabled=false`. Default for non-basis providers.
- `cilium-bgp.yaml`: `loadBalancer.mode=dsr`, `loadBalancer.dsrDispatch=geneve`, `l2announcements.enabled=false`, `bgpControlPlane.enabled=true`. Selected by provider=basis.

Both go in `OUT_DIR`; the runtime selector picks one. Costs one extra helm render at build time; no runtime overhead.

### 2. basis-capi-provider: generate per-cluster BGP CRDs

When provider=basis, after the Cilium install is applied, also apply:

- `CiliumBGPClusterConfig` — peer group pointing at basis-controller's reflector address. Single peer (the RR), iBGP at the cell ASN, source-IP from each node's overlay address.
- `CiliumBGPAdvertisement` — select the LB pool by label, announce its /32s.
- `CiliumBGPPeerConfig` — graceful restart, MD5 if/when basis turns it on (today: nftables source-IP ACL, no MD5 — see existing design doc).

The reflector address + ASN come from a new field on the cluster-level RPC, not from leaking RegisterHostResponse to the Lattice operator. Add `BgpReflectorEndpoint` (or similar) to the create-cluster response in basis-proto; basis-capi-provider reads it once and renders into the CRDs.

### 3. basis-controller: extend peer_reconciler to include k8s node VMs

Today `peer_reconciler` reads from the `hosts` table — hypervisors only. K8s nodes are `BasisMachine` rows, not `hosts`. Either:

- (a) Extend the reconciler to also enumerate `BasisMachine` rows and add their overlay IPs as additional peers, or
- (b) Add a separate `node_peer_reconciler` so the hypervisor and node peering paths stay independent.

(b) is cleaner — different lifecycle (hypervisors are static, nodes churn with cluster scaling), different ACL granularity.

The nftables ACL (`acl_reconciler`) needs the same extension: tcp/179 from k8s node IPs has to be permitted, otherwise sessions never come up.

### 4. basis-controller: community tagging + scope policy

The existing design specifies tagging on import:

- `cluster:<id>` — large community, attached to every prefix ingressing from a node in that cluster
- `pool:<name>` — looked up by longest-prefix match into the announcing pool
- `scope:<cell|public>` — derived from the pool

Plus the export filter to upstream eBGP: `match community scope:public; permit; default deny`.

Without this, every cluster's LB /32s reflect to every other cluster (which is mostly fine for cell-internal pools but actively wrong for inter-cluster isolation). Implementation lives entirely in basis-controller's holod policy config — no Lattice surface.

### 5. (Future) eBGP upstream re-origination

Out of scope for the first cut. Once `scope:public` exists, basis-controller adds an eBGP upstream peer group (one per public pool) and re-originates only `scope:public`-tagged routes. This is what makes a `cell-public` pool actually globally reachable instead of just LAN-reachable via proxy-ARP from an elected owner.

## Provider-conditional behavior

| Provider | LB advertisement | Datapath mode | basis LAN-VIP owner election |
|---|---|---|---|
| basis | BGP via cell RR | DSR (geneve dispatch) | Disabled for BGP-announced pools |
| proxmox | L2-announce | SNAT | N/A |
| docker / kind | L2-announce | SNAT | N/A |

The selector lives in `lattice-capi/src/provider/mod.rs` (or wherever provider dispatch happens). The Cilium install path branches once on provider; everything downstream — CRDs, datapath mode, peer config — is determined by that branch.

## Migration

- New basis clusters: ship in BGP mode from day one once steps 1–3 land.
- Existing basis clusters running L2-announce: stay on L2-announce until the next `lattice apply` that re-creates them. No live migration. This is a reasonable choice because the L2-announce + SNAT path works (we just fixed the DSR-incompatibility bug), so there's no urgency.
- Non-basis clusters: no change at any point.

## Open questions

1. **Cilium BGP peer source-IP under per-tree VRF.** basis enslaves cluster bridges to per-tree VRFs. The k8s node's BGP TCP session to the RR has to traverse the cluster VRF on the node side and arrive on the RR-host side. Today's `tcp_l3mdev_accept=1` sysctl (added in `basis-prereqs`) handles VRF-bound sockets reaching the default VRF for node-side originated traffic; verify the same path works for incoming BGP on the RR host.
2. **Failure-mode of the RR.** If basis-controller's holod restarts, every k8s node's Cilium loses its BGP session and graceful-restart timers kick in (default 120s). Verify this is the same blast radius as the existing basis-agent RR-loss case (cluster_vip routes flap on the same boundary).
3. **MD5 / TCP-AO.** Existing design says MD5 is FIPS-illegal so the security boundary is the source-IP ACL. K8s node sessions inherit the same model — no MD5 by default. Worth confirming the ACL granularity is acceptable: a k8s node can announce arbitrary /32s; a compromised node could blackhole a sibling cluster's VIP. Per-cluster import policy filtering by allowed-source-prefix mitigates but doesn't eliminate.
4. **Static pool config vs CRDs.** Pool config is static in basis-controller today. A future CRD-driven `AddressPool` is independent of this work and can land later — the Cilium-side flip only needs the *current* (static-config) pools to be BGP-reachable.

## Out of scope (explicitly)

- Per-cluster ASNs. The existing design rules them out and this stays.
- BGP-aware Lattice CRDs. Anything BGP-shaped that surfaces in `LatticeCluster` or `BasisCluster` user-edited fields is a leak.
- BGP between basis-controller and basis-controller (cell-of-cells).
