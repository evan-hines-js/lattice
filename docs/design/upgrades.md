# Safe Dependency Upgrades — Design

Status: draft
Scope: the Helm-rendered infrastructure dependencies that ship burned into every Lattice release (Istio, Cilium, cert-manager, ESO, Volcano, Tetragon) and the Lattice operator itself.

## Goals

- Upgrade managed dependencies safely and automatically on every Lattice release, with no operator-hands interaction for the common case.
- Each dependency gets a **dedicated CRD + controller** that owns its full lifecycle (install, upgrade, drift, health). No shared upgrade orchestrator, no generic `ComponentUpgrader` trait.
- Component-specific upgrade protocols (Istio ambient revisions, Cilium agent rolling, cert-manager webhook availability gate, etc.) live entirely inside the owning controller.
- **Auto-rollback within a single upgrade attempt** on health-gate breach. Primary signal: ztunnel denied-rate from the existing mesh probe harness.
- Atomic releases: a Lattice binary bundles one known-good set of dependency versions. The user does not pin component versions.

## Non-Goals

- **Kubernetes / kubelet upgrades.** CAPI owns node replacement via `MachineDeployment` rolling updates. Out of scope for this design.
- **CAPI provider upgrades.** Different install pathway (`lattice-capi`), different cadence, can be tackled later.
- **Cross-release downgrade.** No dual-version bundles, no forward-compat shims on CRDs. Fix forward. In-flight rollback within a single upgrade attempt is the only reverse motion supported.
- **Fleet / cohort orchestration.** Single cluster scope. A parent cell coordinating child cluster upgrades is a follow-up.
- **User-facing scheduler/policy/security CRDs** like `LatticeJob`, `LatticeService`, `CertIssuer`, `CedarPolicy`. Those are already compiled-at-runtime abstractions owned by their existing crates and are unrelated to installing the underlying dependency.

## Current State (summary)

- All dependency charts are pre-rendered with `helm template` at build time (`crates/lattice-infra/build.rs`) using versions from `versions.toml`. Rendered YAML is embedded into the operator binary via `include_str!`.
- `crates/lattice-infra/src/bootstrap/{component}.rs` owns manifest generation per component. Dynamic values (cluster name, trust domain) are placeholder-substituted at runtime.
- `crates/lattice-infra/src/bootstrap/mod.rs::generate_phases()` returns an ordered list of `InfraPhase { components: Vec<InfraComponent>, ... }` and `apply_phase()` does a server-side apply plus a deployment-readiness gate per phase.
- `crates/lattice-operator/src/startup/infrastructure.rs` calls this **once at operator startup** — not a reconciler. Cert-manager + ESO synchronously (`apply_prereqs_phase`), rest via background task (`spawn_general_infrastructure`).
- Status is reported via `LatticeClusterStatus.infrastructure: Vec<InfraComponentStatus>` (name + desired/current version + phase: `UpToDate` | `Upgrading` | `Degraded`) — written once on install, not continuously reconciled.
- No component-specific upgrade protocols. No health gates beyond "namespace deployments ready." No rollback. Upgrade today is "apply the new manifests and hope."

## Target Architecture

### One CRD per dependency

Each dependency gets a cluster-scoped CRD describing desired state and reporting observed state:

```yaml
apiVersion: lattice.dev/v1
kind: IstioInstall        # or CiliumInstall, CertManagerInstall, etc.
metadata:
  name: default            # singleton per cluster
spec:
  version: "1.29.1"        # bundled default, patched by orchestrator on Lattice upgrade
  values: {}               # component-specific overrides (usually empty)
  upgradePolicy:
    autoRollback: true
    healthGate:
      # component-specific; see per-component sections
status:
  phase: Installing | Ready | Upgrading | RollingBack | Failed
  observedVersion: "1.29.0"
  targetVersion:   "1.29.1"
  conditions: []           # standard k8s condition set
  lastUpgrade:
    startedAt, completedAt, outcome, failureReason
  lastKnownGood:           # snapshot for in-attempt rollback
    version, revisionHash, rollbackManifestRef
  revisionHistory: []      # bounded: last 5
  componentHealth: {}      # component-specific probe results
```

No shared trait. `IstioInstallSpec` and `CiliumInstallSpec` are unrelated types — each controller's logic is concrete, not polymorphic.

### One controller per dependency, in a dedicated crate

Mapping from dependency to crate:

| Dependency   | Crate                    | Notes                                                                 |
|--------------|--------------------------|-----------------------------------------------------------------------|
| cert-manager | `lattice-cert-manager` *(new)* | Distinct from `lattice-cert-issuer`, which compiles user `CertIssuer` objects. |
| Cilium       | `lattice-cilium` *(new)* |                                                                       |
| Istio        | `lattice-istio` *(new)*  | Owns istiod + istio-cni + ztunnel + east-west gateway + trust-domain resolution |
| ESO          | `lattice-eso` *(new)*    | Distinct from `lattice-secret-provider` (user-facing providers)       |
| Volcano      | `lattice-volcano` *(extended)* | Existing crate is a compiler for `LatticeJob`. Add `install/` module. |
| Tetragon     | `lattice-tetragon` *(extended)* | Same pattern — existing compiler, add `install/` module.              |

Each controller owns: manifest rendering (moved from `lattice-infra/bootstrap/`), install, upgrade protocol, health probing, rollback, status reporting. `lattice-infra` shrinks to shared primitives (mTLS, PKI, trust-domain resolution helpers).

### LatticeCluster becomes a thin orchestrator

The existing LatticeCluster reconciler gains a new responsibility: **ensure dependency Install CRs exist in dependency order, with `spec.version` matching what the running Lattice binary bundles**.

Ordering is enforced by readiness gating, not by applying in sequence and hoping:

```
LatticeCluster reconciler loop:
  1. Ensure CertManagerInstall exists, spec.version = bundled.
     If not Ready → requeue, do not proceed.
  2. Ensure CiliumInstall exists, spec.version = bundled.
     If not Ready → requeue.
  3. Ensure IstioInstall exists, spec.version = bundled.
     (IstioInstall itself waits for lattice-ca Secret; see Istio section.)
     If not Ready → requeue.
  4. Ensure ESOInstall, VolcanoInstall, TetragonInstall (concurrent — no inter-dep).
  5. Aggregate status from child Install CRs → LatticeClusterStatus.infrastructure.
  6. Update status.phase based on child phases.
```

**Version cascade.** The orchestrator reads the bundled version from the binary (e.g. `env!("ISTIO_VERSION")`). If `spec.version` on a child Install CR is drifted from the bundled version, it patches to the bundled version. That patch triggers the child controller's upgrade protocol. This is how a new Lattice release propagates to dependencies.

User pinning is not supported. Users upgrade Lattice; dependencies follow.

### Status aggregation

`LatticeClusterStatus.infrastructure: Vec<InfraComponentStatus>` is retained as a **denormalized cache** for visibility. It is written by the orchestrator based on child Install CR status, not by direct install code. `kubectl get latticecluster -o yaml` continues to show per-component state at a glance, and per-component detail is available via `kubectl get istioinstall -o yaml` etc.

### Manifest rendering stays at build time

`versions.toml` + `build.rs` pattern unchanged. Each component crate owns its slice of rendering (moved from the current `lattice-infra/bootstrap/*.rs`). The Lattice binary still ships one atomic set of rendered manifests — the architectural change is in how they're *applied and progressed*, not how they're built.

## State Machine (generic)

Same shape for every Install controller, even though the work inside each phase is component-specific:

```
      [CR created]
           ↓
      PreFlight ─── fail ──→ Failed (blocks further work)
           ↓ pass
     [first install?] ── yes ──→ Installing ───→ Verifying ───→ Ready
           ↓ no
 [spec.version changed?] ── no ──→ Ready (periodic drift check)
           ↓ yes
      Upgrading ─── health breach ──→ RollingBack ──→ Ready (old version)
           ↓ success
      Verifying ───→ Ready
```

- **PreFlight**: component-specific preconditions (CRD diffs non-destructive, dependencies ready, cluster capacity, etc.).
- **Installing** / **Upgrading** / **RollingBack**: the work, component-specific.
- **Verifying**: component-specific health probe must pass for a stabilization window.
- **Ready**: periodic (every 5m) drift check; re-enter Upgrading on spec change.
- **Failed**: terminal, requires spec change to retry.

All phases commit to `status.phase` atomically — a controller crash resumes from `status.phase` on restart.

## Rollback Model

Within-attempt only. Cross-release rollback is not supported.

On entry to `Upgrading`, controller snapshots the pre-change state into `status.lastKnownGood`:
- Current version
- Hash of currently applied manifests
- Reference to a `Secret` or `ConfigMap` holding the pre-change manifests for rapid restore

On health-gate breach or timeout in `Verifying`:
1. Enter `RollingBack`.
2. Server-side apply the `lastKnownGood` manifests.
3. Run the component health probe.
4. On success → `Ready` (on the old version). Set `status.lastUpgrade.outcome: RolledBack`.
5. On failure of the rollback itself → `Failed` and stop. Human intervention required.

Phase-4-style "forward-only" concerns (from the earlier K8s-upgrade design) do not apply here — all dependency upgrades are manifest-level, so all are reversible until a post-rollback health check passes.

## Per-Component Design

### cert-manager

**Why it's first:** every other component with a validating/mutating webhook (including its own upgrade flow) depends on cert-manager being available. Bringing cert-manager down brings new cert issuance down, which can cascade.

**Upgrade protocol:**
1. PreFlight: CRD diff check (refuse destructive changes — no removed fields, no narrowed types).
2. Apply CRDs (server-side, `--force-conflicts`).
3. Rolling upgrade the `cert-manager-cainjector` Deployment.
4. Rolling upgrade the `cert-manager-webhook` Deployment. Maintain ≥1 webhook replica throughout (requires HA default in rendered manifest).
5. Rolling upgrade the `cert-manager` controller Deployment.
6. Verify.

**Health signal:** issue a short-lived self-signed `Certificate` in `lattice-system` via an internal Issuer and measure end-to-end latency. Failure to issue within 60s → breach.

**Rollback:** revert Deployments to `lastKnownGood` image tags. CRD downgrade is not supported; destructive CRD changes are refused at preflight.

### Cilium

**Risk:** agent DS restart disrupts node pod networking briefly. With default-deny Cilium policies, any L3/L4 denial during upgrade shows as a hard failure.

**Upgrade protocol:**
1. PreFlight: CRD diff check. Node readiness, no concurrent CNI plugin changes.
2. Apply CRDs.
3. Rolling upgrade `cilium-operator` (2 replicas → rolling).
4. Rolling upgrade `cilium` agent DaemonSet with `maxUnavailable: 1`. Drain one node's worth of mesh probing between steps.
5. Verify.

**Health signal:**
- Pod-to-pod reachability probe across nodes (existing mesh probe harness — lightweight cross-node ping).
- Cilium agent pod `Ready` count across the fleet.
- **Primary:** Cilium drop counter delta stays under 0.5% of baseline during rollout.

**Rollback:** revert DaemonSet + operator images. CNI is node-local; rollback fully re-applies the old agent DS manifests.

### Istio (ambient)

The hardest. Upgrade sub-protocol by subcomponent (per Istio's own ambient upgrade guidance):

1. **PreFlight**:
   - `lattice-ca` Secret exists (trust domain derivable).
   - CRD diff check.
   - Version skew: new ztunnel/cni must be within 1 minor of current istiod.
   - Baseline ztunnel denied-rate is below threshold for 5m before starting.

2. **istiod revision canary:**
   - Render `istiod-$newRev` alongside existing `istiod`. Server-side apply.
   - Wait for `istiod-$newRev` Deployment Ready.
   - No traffic shifted yet.

3. **Waypoints:**
   - Shift waypoint revision tags to `$newRev`.
   - Health-gate: denied-rate < threshold for stabilization window (default 5m).

4. **ztunnel (DaemonSet):**
   - Rolling update with `maxUnavailable: 1`. Per Istio docs, this disrupts per-node mesh traffic briefly; unavoidable in ambient.
   - Between each node: wait for new ztunnel pod Ready + denied-rate gate.

5. **istio-cni (DaemonSet):**
   - No canary possible. In-place rolling update with `maxUnavailable: 1`.
   - Denied-rate gate between each node.

6. **Verify:** denied-rate stays under threshold for 10m. East-west gateway reachable from sibling clusters (if any).

7. **GC:** once no namespace labels, Gateways, or Deployments reference `$oldRev` for 15m, remove `istiod-$oldRev`. Until then, old istiod stays up.

**Health signal:**
- **Primary:** ztunnel `tcp.rbac.denied` rate from logs/metrics. Threshold: < 0.01 (1%) of baseline.
- Secondary: istiod `pilot_xds_push_errors_total` rate.
- Tertiary: envoy 5xx from waypoints.

**Rollback** — phase-specific:
- Steps 2–3: reversible (relabel back, delete `istiod-$newRev`).
- Steps 4–5: partial rollback. Revert DS manifest, rolling-update back to `$oldRev` images. New nodes already on `$newRev` bounce back.

Trust-domain resolution (existing `resolve_istio_ca` in `lattice-infra`) moves into `lattice-istio`. IstioInstall sits in `PreFlight` until `lattice-ca` exists.

### ESO (External Secrets Operator)

**Risk:** webhook downtime blocks `ExternalSecret` admission; existing secrets continue flowing via controller reconcile.

**Upgrade protocol:**
1. PreFlight: CRD diff.
2. Apply CRDs.
3. Rolling upgrade `external-secrets-webhook` (maintain ≥1 replica).
4. Rolling upgrade `external-secrets-cert-controller`.
5. Rolling upgrade `external-secrets` controller.
6. Verify.

**Health signal:** create a probe `ExternalSecret` backed by the local webhook secret store, measure reconcile latency. > 30s to sync → breach.

**Rollback:** revert Deployment images.

### Volcano

**Risk:** scheduler is stateful (in-flight `PodGroup`/`Job` bookkeeping). Replacing it mid-flight can drop pending jobs from consideration for a reconcile cycle. Webhook downtime blocks new job admission. vGPU device plugin DS interacts with HAMi on GPU nodes.

**Upgrade protocol:**
1. PreFlight: CRD diff. GPU node headroom (vGPU allocations can be rescheduled).
2. Apply CRDs.
3. Rolling upgrade `volcano-admission` (webhook).
4. Rolling upgrade `volcano-controllers`.
5. Rolling upgrade `volcano-scheduler` (stateful — single replica rolling). Brief scheduling pause expected.
6. Rolling upgrade `volcano-vgpu-device-plugin` DaemonSet (GPU nodes only, `maxUnavailable: 1`).
7. Verify.

**Health signal:**
- Webhook admission latency < 5s.
- Scheduler pending-pod count does not grow beyond 2× baseline for 10m.
- No `PodGroup` stuck in `PodGroupNotReady` beyond 10m that wasn't already so.

**Rollback:** Deployment image revert for #3–5; DS revert for #6.

### Tetragon

**Risk:** eBPF detach/reattach on agent DS restart = brief gap in `TracingPolicy` enforcement per node. Policies are recreated on reattach.

**Upgrade protocol:**
1. PreFlight: CRD diff. Tetragon operator Ready.
2. Apply CRDs.
3. Rolling upgrade `tetragon-operator`.
4. Rolling upgrade `tetragon` agent DS with `maxUnavailable: 1`.
5. Verify.

**Health signal:**
- Agent DS pod Ready count == node count after rollout.
- No `TracingPolicy` in `Error` status for 5m post-upgrade.

**Rollback:** DS image revert.

### Lattice operator self-upgrade

This is the trigger for all the above.

1. User (or parent cell cascade) patches `LatticeCluster.spec.latticeImage`.
2. Existing ready reconciler patches the `lattice-system/lattice-operator` Deployment image.
3. New operator starts. First action in its reconcile: check `LatticeClusterStatus.upgrade.phase` — if non-terminal, resume.
4. New operator reads bundled dependency versions from `env!()` vars, patches child Install CR `spec.version`s accordingly. Each child controller runs its upgrade protocol per the sections above.

The operator Deployment upgrade is a standard k8s rolling update. Because only the operator pod is affected (not the dataplane), no custom orchestration needed beyond the existing self-patch code.

## Bootstrap vs Upgrade

The same controllers handle both. Bootstrap is just "upgrade from nothing to bundled version":

- On first reconcile with no observed state, controller enters `Installing` (instead of `Upgrading`).
- Same state machine, different labels on the phases.

This replaces the current one-shot `startup/infrastructure.rs` flow. The LatticeCluster reconciler creates the child Install CRs; each controller self-drives through `Installing → Verifying → Ready` on first cluster boot, then sits in `Ready` until a version change or 5m drift-check requeue.

## Migration Plan (multi-week)

Each phase leaves the tree green and deployable. No Big Bang.

### Phase 1 — Scaffold (week 1–2)

Goal: per-dependency CRDs + controllers exist and behave **identically** to today's bootstrap path. No upgrade logic yet, no health gates beyond current deployment-readiness.

- Add `CertManagerInstall`, `CiliumInstall`, `IstioInstall`, `ESOInstall`, `VolcanoInstall`, `TetragonInstall` CRDs to `lattice-crd`.
- Create `lattice-cert-manager`, `lattice-cilium`, `lattice-istio`, `lattice-eso` crates. Extend `lattice-volcano` and `lattice-tetragon` with `install/` modules.
- Move manifest generation from `lattice-infra/bootstrap/{component}.rs` into the respective crate.
- Each controller: reconcile `(spec.version, spec.values) → render → server-side apply → readiness gate → set status.phase = Ready`. Install only — no version-change path.
- LatticeCluster reconciler: create Install CRs in dep order, wait for each to be Ready before creating the next.
- **Cutover:** delete `startup/infrastructure.rs::spawn_general_infrastructure` and `apply_prereqs_phase`. Delete `lattice-infra/bootstrap/mod.rs::generate_phases` and `apply_all_phases`.
- Keep `LatticeClusterStatus.infrastructure` populated (aggregated from child Install CR statuses) for backward-visible output.

At the end of Phase 1, a cluster bootstraps identically to today. Nothing can upgrade yet.

### Phase 2 — Upgrade protocols (week 3–5)

Implement the version-change path per controller, starting easiest → hardest:

1. Tetragon (simplest — just DS + operator rolling).
2. ESO (webhook + controller rolling, simple health signal).
3. cert-manager (webhook availability is the gate, but straightforward).
4. Volcano (stateful scheduler, vGPU plugin care).
5. Cilium (dataplane substrate, maxUnavailable DS rolling).
6. Istio (revision canary + waypoint tag shift + ztunnel DS + cni). **Hardest, last.**

Each component's upgrade logic is a standalone PR with its own E2E test.

### Phase 3 — Health gates & auto-rollback (week 6)

- Deploy `lattice-upgrade-probe` DaemonSet on-demand during upgrades. Generates mesh probe cycles; controllers read ztunnel denied-rate from its metrics.
- Wire `lastKnownGood` snapshot + restore in each controller.
- Add forced-failure e2e tests (inject a policy break, assert auto-rollback fires within `rollback.timeoutMinutes`).

### Phase 4 — Cleanup (week 7)

- Remove `LatticeClusterStatus.infrastructure` if no consumer remains (or keep as cache — decide based on tooling/UX).
- Remove dead bootstrap helpers from `lattice-infra`.
- Shrink `lattice-infra` to mTLS/PKI helpers only.
- Remove `InfraComponent` / `InfraPhase` types from `lattice-crd`.
- Update `upgrade_e2e.rs`: keep K8s-upgrade tests, add one full-stack dependency upgrade test per component.

## Open Questions

1. **`LatticeClusterStatus.infrastructure` survival.** Keep the denormalized cache for `kubectl get latticecluster` UX, or remove and direct people to `kubectl get istioinstall` etc.? Leaning keep.
2. **CRD diff validation.** Library-level — is there an existing Rust crate that diffs OpenAPI v3 schemas for destructive changes, or do we write a minimal one?
3. **Health probe DaemonSet location.** Lives in the Istio controller's namespace? Or a shared `lattice-upgrade-system` namespace? Leaning istio-system because ztunnel metrics are scoped there.
4. **Per-component probe budget during simultaneous upgrades.** Phase 1 gates with deployment-readiness only, but once upgrade protocols land, multiple controllers may attempt upgrades concurrently on a new Lattice release. Do we serialize via a cluster-wide mutex, or trust dependency ordering (cert-manager → Cilium → Istio serial; then ESO+Volcano+Tetragon concurrent)? Leaning on dependency ordering — it's already topological.
5. **Operator resume after mid-upgrade crash.** New operator reads `status.phase` and resumes. If the crash happened during `Verifying`, do we re-enter `Verifying` with a fresh stabilization window, or check the time remaining? Fresh window is simpler and the cost is one extra `healthGate.stabilizationWindow` of delay.
