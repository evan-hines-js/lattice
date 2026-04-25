# cilium-kube-proxy-replacement — DSR data path with install-time API server templating

Status: design
Scope: switch the Cilium install from `kubeProxyReplacement=false` (kube-proxy + iptables SNAT) to `kubeProxyReplacement=true` with `loadBalancer.mode=dsr`, resolving the bootstrap chicken-and-egg by templating `k8sServiceHost`/`k8sServicePort` at install time using the same `__PLACEHOLDER__` mechanism `lattice-istio` already uses for cluster name and trust domain.

## Goals

- Eliminate kube-proxy entirely. Cilium's eBPF datapath handles all Service / NodePort / LoadBalancer traffic.
- Run the LB data path in DSR mode so backend pods reply directly to clients, preserving client source IPs and skipping the return hop through the LB-selected node. This composes naturally with the iBGP /32 advertisement model basis already provides — every node can be the ingress node for any LB VIP, and the return path doesn't have to retrace the ingress hop.
- Resolve the API server endpoint that Cilium agents need at startup *without* runtime discovery. The actor doing the install (operator or CLI) already knows the endpoint; it just needs to stamp it into the manifests before apply.

## Non-Goals

- Migrating existing live clusters. Per `feedback_no_backcompat`: this is a fix-forward change. Clusters provisioned before this lands keep running kube-proxy; new clusters get DSR. No in-place flip.
- UDP DSR. Pure DSR over UDP loses connection-tracked flows on rehash. We use `loadBalancer.mode=dsr` for TCP and accept that any UDP service falls back to SNAT via `hybrid` if we discover a need; default is `dsr` and we revisit if a UDP workload appears.
- XDP acceleration in this round. `loadBalancer.acceleration=native` requires NIC-driver support we haven't audited across Proxmox / Basis / Docker. Default `disabled`; revisit per-provider.
- Replacing the Istio ambient L7 path. Cilium handles L4 LB; ztunnel still handles mTLS + L7 policy. Defense-in-depth (per `feedback_defense_in_depth`) is unchanged.

## Why this is worth doing

Today every Service connection takes an extra hop through kube-proxy iptables, gets SNAT'd to a node IP, and the reply traces the same path back. Three concrete costs:

- **Lost client identity.** Backends see the LB node's IP, not the actual client. Anything that wants source-IP-aware policy (rate limiting, audit logs, geo-routing) is blind.
- **Asymmetric-path waste.** With basis advertising LB /32s from every node via iBGP, the underlay can already deliver client traffic to whichever node is closest. But the SNAT'd reply is forced back through that same node, undoing the win.
- **iptables scale.** kube-proxy's iptables chains are O(services × endpoints) and a known cliff at a few thousand services. The eBPF map lookup is O(1).

DSR fixes all three at once, and the iBGP underlay we already built for basis is exactly the topology DSR needs.

## The chicken-and-egg, restated

Cilium with `kubeProxyReplacement=true` needs to know the API server's host:port before it starts, because the agent itself uses that endpoint to talk to kube — and there's no kube-proxy to translate the `kubernetes.default` ClusterIP for it. Helm values `k8sServiceHost` and `k8sServicePort` carry the answer.

The naive read is: "the operator has to look up the API server, but the operator already needs to talk to the API server to do anything, so how would it find it?" The dissolve: the operator never *discovers* the endpoint — it (or its parent in the provisioning chain) *chose* the endpoint. By the time CiliumInstall reconciles, the value has already been written to a stable location we can read.

## Resolution paths, ordered by preference

For an operator running inside a kubeadm-provisioned cluster (the common case post-bootstrap):

1. **`kube-system/kubeadm-config` ConfigMap, `ClusterConfiguration.controlPlaneEndpoint`.** Canonical record of what kubeadm was told to advertise. Always present on a kubeadm cluster, written before any CNI is installed, readable with any authenticated kube client. This is the value to use.

2. **Fallback: operator pod env vars `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`.** Injected by kubelet into every pod. Points at the `kubernetes` Service ClusterIP. Works for non-kubeadm clusters where path 1 is absent. Note: this is the ClusterIP, which on a kubeProxyReplacement cluster is itself programmed by Cilium — fine for the *operator's* connection (it was running before this reconcile fires), but using it as Cilium's `k8sServiceHost` is a bootstrap hazard if Cilium ever restarts before the eBPF entry is rehydrated. Acceptable as fallback; not the primary path.

3. **Bootstrap cluster (kind / docker, before any operator exists).** `lattice-cli` is the actor — it's the thing *writing* the kubeadm `controlPlaneEndpoint` in the first place. The CLI knows the value by construction and renders the Cilium manifests before applying. Same template, different caller.

4. **Explicit override on `CiliumInstallSpec`.** Optional `api_server_endpoint: Option<HostPort>` field. Air-gapped or non-kubeadm setups can pin the value declaratively instead of relying on the discovery chain. When set, skips paths 1 and 2.

The operator never has to "find" the API server in the discovery sense — every entry in the chain reads from a place that the previous step (kubeadm, CAPI, or the CLI) already wrote.

## Build-time changes

`crates/lattice-cilium/build.rs` — adjust the `helm template` invocation:

- Drop `kubeProxyReplacement=false`; add `kubeProxyReplacement=true`.
- Drop `bpf.hostLegacyRouting=true`.
- Add `bpf.masquerade=true` (BPF masquerading is the kube-proxy-replacement default and cleaner than host iptables).
- Add `loadBalancer.mode=dsr`.
- Add `loadBalancer.acceleration=disabled` for now (revisit XDP per provider).
- Add `k8sServiceHost=__LATTICE_API_SERVER_HOST__` and `k8sServicePort=__LATTICE_API_SERVER_PORT__`.

Output filename stays `cilium.yaml`, but the file now contains placeholders and is treated as a template, not a finished manifest set.

## Runtime changes

`crates/lattice-cilium/src/install/manifests.rs` — mirror `lattice-istio`:

```rust
static CILIUM_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/cilium.yaml"));

pub fn render_cilium_manifests(api_server_host: &str, api_server_port: u16) -> Vec<String> {
    let yaml = CILIUM_TEMPLATE
        .replace("__LATTICE_API_SERVER_HOST__", api_server_host)
        .replace("__LATTICE_API_SERVER_PORT__", &api_server_port.to_string());
    split_yaml_documents(&yaml)
}
```

Delete `generate_cilium_manifests()` and the `CILIUM_MANIFESTS` `LazyLock` — there is no longer a meaningful "unrendered" form to expose, and per `CLAUDE.md` ("Delete code as you move it"), the compiler errors will drive the integration.

`crates/lattice-cilium/src/install/controller.rs` — resolve the endpoint before rendering:

```rust
let endpoint = match install.spec.api_server_endpoint.as_ref() {
    Some(ep) => ep.clone(),
    None => resolve_api_server_endpoint(&ctx.client).await?,
};
let mut manifests = manifests::render_cilium_manifests(&endpoint.host, endpoint.port);
```

`resolve_api_server_endpoint` lives in `lattice-common` (not `lattice-cilium`, since istiod and ztunnel could plausibly want the same lookup later — though they don't today, so build it inline first and lift only when a second caller appears, per `feedback_aggregator_at_consumer`):

- Read `kube-system/kubeadm-config`, parse the `ClusterConfiguration` YAML out of the `ClusterConfiguration` key, extract `controlPlaneEndpoint`, split `host:port`.
- On `NotFound` or parse error, fall back to `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` env vars.
- Surface a typed error (`ApiServerEndpointError::NotFound`) if both fail. The reconciler turns this into a `Status::Failed` so the user sees a clear message instead of Cilium pods crashlooping silently.

`crates/lattice-crd/src/crd/installs.rs` (or wherever `CiliumInstallSpec` lives) — add the override:

```rust
pub struct CiliumInstallSpec {
    pub base: InstallSpecBase,
    /// Optional override for the API server endpoint Cilium agents use at
    /// startup. If unset, resolved from the kubeadm-config ConfigMap, then
    /// from the operator pod's environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server_endpoint: Option<HostPort>,
}
```

`HostPort` belongs in `lattice-crd::crd::types` next to other shared CRD types.

## Bootstrap path (`lattice-cli`)

`crates/lattice-cli/src/commands/install.rs` (or wherever the bootstrap kubeadm-init flow renders Cilium) — when the CLI bootstraps a cluster, it knows the `controlPlaneEndpoint` it just wrote into the kubeadm config. Pass that value into `render_cilium_manifests` directly; do not go through the operator path. The CLI's apply step uses the rendered manifest set.

This means there are two callers of `render_cilium_manifests`: the controller and the CLI. That's the correct shape — the function is the single rendering primitive, and both bootstrap (CLI) and steady-state (controller) use it.

## kube-proxy must not run

`kubeProxyReplacement=true` requires the kube-proxy DaemonSet to be absent. Two options for the bootstrap flow:

- **Skip at init**: `kubeadm init --skip-phases=addon/kube-proxy`. Cleanest; kube-proxy never exists on the cluster. Requires the bootstrap flow to wire that flag through.
- **Delete after init**: kubeadm installs kube-proxy as part of the `addon` phase; we delete the `kube-system/kube-proxy` DaemonSet immediately after init and before applying Cilium.

Skip-at-init is the right answer — deleting an addon kubeadm thinks it owns invites future upgrade pain. The bootstrap flow needs to thread the skip flag through wherever it shells out to kubeadm; `crates/lattice-cell/src/bootstrap` is the place to look.

## Underlay assumptions for DSR

DSR sends backend replies directly to the client, bypassing the LB-selected node. Two things must hold for this to work:

- **No reverse-path filtering drops.** Many Linux defaults (and many switches) will RPF-drop a packet that arrives on an interface that wouldn't be the route back to the source. Cilium's DSR uses an IPv4 option (or, optionally, Geneve encap) to carry the original VIP through to the backend; the backend then sources its reply from the VIP. If anything between backend and client checks "did this source IP arrive on the expected interface," the reply gets dropped. The basis iBGP setup advertises LB /32s from every node, so every node already legitimately sources VIP traffic — but anywhere with strict RPF (notably some Proxmox bridge configs) needs verification.
- **MTU headroom for the DSR option.** The IPv4-option DSR encoding adds 8 bytes; the Geneve variant adds more. We need to ensure pod MTU is sized accordingly, or fragmentation will silently degrade large flows. Cilium can be told to use Geneve DSR if IPv4-option is unsafe in a given underlay.

These are real concerns for a default flip, not blockers for the design. The plan: enable DSR by default, document the underlay requirements, and provide a per-cluster override (`loadBalancer.mode` exposed as a `CiliumInstallSpec` field) so a provider that can't meet them can fall back to `hybrid` or `snat` without forking the manifests.

## Test plan

Unit:
- `render_cilium_manifests("api.example.com", 6443)` produces a manifest string with no `__LATTICE_*__` placeholders remaining and the expected `k8sServiceHost: api.example.com` / `k8sServicePort: "6443"` in the cilium-config ConfigMap.
- `resolve_api_server_endpoint` reads kubeadm-config when present, falls back to env vars, returns `NotFound` when both are absent.

E2E (per `CLAUDE.md`, all E2E tests build fresh):
- `unified_e2e` — full lifecycle. Verify `kubectl -n kube-system get ds kube-proxy` returns NotFound; verify `cilium status` reports `KubeProxyReplacement: True`; verify `loadBalancer.mode` reports `dsr`.
- Mesh tests — existing bilateral-agreement coverage runs unchanged. If anything regresses, it's an honest signal that the L4 path changed shape.
- Source-IP preservation — add a single integration test that hits a Service with `externalTrafficPolicy=Cluster` from a known client IP and asserts the backend pod sees that client IP. This is the user-visible win and deserves an explicit assertion.

## Rollout

This is a default flip for new clusters; existing clusters are not touched. No feature flag — per `feedback_no_backcompat`, we fix forward. The override field on `CiliumInstallSpec` is the escape hatch if a specific provider can't meet the underlay requirements.

## Open questions

- Should `resolve_api_server_endpoint` live in `lattice-common` from day one, or inline in the cilium controller until a second caller appears? Default: inline, lift later. (Per `feedback_aggregator_at_consumer`.)
- Do we need to expose `loadBalancer.mode` on `CiliumInstallSpec` immediately, or wait for the first provider that needs `hybrid`/`snat`? Default: wait. The override exists conceptually; we add the field when something concrete drives it.
- XDP acceleration: worth a follow-up design once we know which providers' NICs support it. Out of scope here.
