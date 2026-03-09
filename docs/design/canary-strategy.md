# Canary Deployment Strategy for LatticeServices

## Status: Draft

## Problem

The `DeployStrategy::Canary` variant and `CanarySpec` fields (`interval`, `threshold`, `maxWeight`, `stepWeight`) are declared in the CRD and documented in `service-deployment.md`, but no implementation exists. Today, selecting `strategy: canary` only changes the Deployment's RollingUpdate parameters (0% maxUnavailable, 100% maxSurge) — no traffic shifting, metric analysis, or automated rollback occurs.

## Current State

**What exists:**
- `DeploySpec` / `CanarySpec` types in `crates/lattice-common/src/crd/workload/deploy.rs`
- `CompilerPhase` trait designed to emit arbitrary `DynamicResource` entries
- `VMServiceScrapePhase` as a working reference implementation of a compiler phase
- Istio Ambient mode (ztunnel L4 + waypoint L7) — no sidecars
- Gateway API (HTTPRoute, GRPCRoute, TCPRoute) for ingress
- Weighted routing already implemented in the model-serving subsystem (LatticeModel → Volcano ModelRoute)
- VictoriaMetrics for metrics collection

**What's missing:**
- Traffic splitting between canary and stable pod sets
- Metric-driven progression / automated rollback
- A controller or external tool that orchestrates the rollout

## Requirements

- Progressive traffic shifting from 0% → `maxWeight` in `stepWeight` increments
- Automatic rollback when error rate exceeds `threshold` within an `interval`
- Works with Istio Ambient mode (no sidecar injection)
- Integrates with existing bilateral mesh agreements (AuthorizationPolicy + CiliumNetworkPolicy)
- Observable: canary status visible on the LatticeService status subresource
- No new inbound connections on workload clusters (outbound-only architecture)

---

## Option A: Flagger

[Flagger](https://flagger.app/) is a CNCF project that automates canary, A/B, and blue-green deployments.

### How It Works

Flagger watches a target Deployment. On spec change, it scales up a canary Deployment, creates/updates routing resources with weighted backends, queries metrics at each interval, and either promotes or rolls back.

### Why It Doesn't Fit

**Istio Ambient mode is broken.** [Flagger issue #1822](https://github.com/fluxcd/flagger/issues/1822) documents that when Flagger splits traffic at the ingress HTTPRoute to the canary Service, that traffic bypasses the Service-bound HTTPRoute at the canary's waypoint. Headers aren't injected, downstream routing breaks. Flagger was designed around sidecar-based Istio — it doesn't understand waypoint proxies.

Additionally:
- Flagger renames Services (`my-service` → `my-service-primary`), which conflicts with our AuthorizationPolicy and LatticeMeshMember generation
- Service renaming means the mesh-member controller needs special-case logic for Flagger's naming convention
- We'd depend on upstream fixing Ambient support on their timeline, not ours
- Another operator to deploy and maintain per cluster

---

## Option B: Argo Rollouts

[Argo Rollouts](https://argoproj.github.io/rollouts/) is a Kubernetes controller for progressive delivery that replaces Deployment with a `Rollout` CRD.

### How It Works

Manages ReplicaSets directly and integrates with traffic routers for weighted splitting. Supports explicit step sequences (setWeight, pause, analysis).

### Why It Doesn't Fit

**Istio Ambient support is not implemented.** [Discussion #3897](https://github.com/argoproj/argo-rollouts/discussions/3897) asks for HTTPRoute support with Istio Ambient — no resolution. The existing Istio integration is built entirely on VirtualService and DestinationRule, which don't exist in Ambient mode. The Gateway API plugin exists but targets generic Gateway API implementations, not Istio Ambient's waypoint-specific routing model.

Additionally:
- Replaces Deployment with Rollout CRD — invasive change that breaks KEDA ScaledObject, PDBs, and monitoring integrations
- Requires deploying controller + separate Gateway API plugin per cluster
- Step-based config doesn't map cleanly from our `stepWeight`/`maxWeight` model
- Heavier operational footprint: controller + plugin + AnalysisTemplate CRDs

---

## Option C: Build It Ourselves (Recommended)

Implement canary orchestration as a native Lattice controller using Gateway API HTTPRoute for traffic splitting.

### Why This Is the Right Choice

Neither Flagger nor Argo Rollouts has working Istio Ambient support. Both tools were designed for sidecar-based Istio (VirtualService/DestinationRule) or generic ingress controllers. Istio Ambient's waypoint proxy model is fundamentally different — traffic management happens via Service-attached HTTPRoutes evaluated by waypoint proxies, not sidecar-injected VirtualServices. We'd be waiting on upstream projects to support our exact stack, with no timeline.

Meanwhile, we already have the building blocks:
- Waypoint-aware HTTPRoute generation in the mesh-member controller
- VictoriaMetrics for metrics
- The `CompilerPhase` architecture for extending compilation
- Deep understanding of our bilateral mesh agreement model

### How It Works

A `CanaryController` watches LatticeServices with `strategy: canary`. The service reconciler detects spec changes (via the existing `lattice.dev/config-hash` annotation) and delegates to the canary controller for progressive rollout.

#### Rollout Lifecycle

```
User updates LatticeService spec (image, env, config)
    │
    ▼
ServiceReconciler detects spec drift (config-hash changed)
    │
    ├── strategy: rolling → normal Deployment update (existing behavior)
    │
    └── strategy: canary → CanaryController takes over
        │
        ▼
    ┌─────────────────────────────────────────────────────┐
    │  Phase: Initializing                                │
    │  - Create <name>-canary Deployment (new spec)       │
    │  - Create <name>-canary Service                     │
    │  - Wait for canary pods Ready                       │
    └──────────────────────┬──────────────────────────────┘
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │  Phase: Progressing                                 │
    │  - Create/update HTTPRoute with weighted backendRefs│
    │  - Wait interval                                    │
    │  - Query VictoriaMetrics for canary error rate      │
    │  - If error rate < threshold → increment weight     │
    │  - If error rate >= threshold → goto Rollback       │
    │  - If weight >= maxWeight → goto Promoting          │
    │  - Loop                                             │
    └──────────┬───────────────────────┬──────────────────┘
               ▼                       ▼
    ┌────────────────────┐  ┌────────────────────────────┐
    │  Phase: Promoting  │  │  Phase: RollingBack        │
    │  - Update primary  │  │  - Delete canary Deployment│
    │    Deployment spec  │  │  - Delete canary Service   │
    │  - Shift weight to │  │  - Delete HTTPRoute        │
    │    100% primary     │  │  - Update status           │
    │  - Delete canary   │  │    (rollback reason)       │
    │  - Delete HTTPRoute│  └────────────────────────────┘
    │  - Update status   │
    └────────────────────┘
```

#### Traffic Splitting via Gateway API + Waypoint

Istio Ambient's waypoint proxy natively evaluates Gateway API HTTPRoute weights for east-west (service-to-service) traffic. This is the key architectural advantage — we use the same mechanism the mesh already provides:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-service-canary-route
  namespace: prod
spec:
  parentRefs:
    - group: ""
      kind: Service
      name: my-service        # Attach to the original Service
      port: 8080
  rules:
    - backendRefs:
        - name: my-service           # Stable pods
          port: 8080
          weight: 90
        - name: my-service-canary    # Canary pods
          port: 8080
          weight: 10
```

When any service in the mesh calls `my-service:8080`, the waypoint evaluates this HTTPRoute and splits traffic accordingly. No VirtualService, no DestinationRule, no sidecar — just Gateway API resources that waypoints already understand.

#### Mesh Policy Integration

This is where building our own pays off. The canary controller is mesh-aware from the start:

**L4 (CiliumNetworkPolicy):** Both primary and canary pods share the same `app: my-service` label. Existing CiliumNetworkPolicy selectors match both pod sets automatically. No policy changes needed during canary rollout.

**L7 (AuthorizationPolicy):** The LatticeMeshMember controller already generates AuthorizationPolicies based on bilateral agreements. Since the canary Service targets the same workload identity (same ServiceAccount), ztunnel and waypoint RBAC decisions are identical for primary and canary pods. The SPIFFE identity `spiffe://lattice.cluster.local/ns/prod/sa/my-service` covers both.

**Bilateral agreements:** No changes. A canary rollout doesn't alter the service's dependency graph — it's still the same service, just with two pod sets.

#### Metrics Analysis

Query VictoriaMetrics (Prometheus-compatible) for canary health:

```promql
# Success rate for canary pods (via Istio standard metrics)
sum(rate(istio_requests_total{
  destination_service_name="my-service-canary",
  response_code!~"5.*"
}[1m]))
/
sum(rate(istio_requests_total{
  destination_service_name="my-service-canary"
}[1m]))
```

Istio Ambient emits `istio_requests_total` from waypoint proxies, with `destination_service_name` distinguishing primary from canary. This gives us per-pod-set error rates without any custom instrumentation.

The analysis loop runs every `interval` (from `CanarySpec`). If the success rate drops below `(100 - threshold)%` for any check, the canary is rolled back. If it passes for enough iterations to reach `maxWeight`, promotion begins.

### CRD Changes

Add canary status to `LatticeServiceStatus`:

```rust
/// Canary rollout status
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanaryStatus {
    /// Current canary phase
    pub phase: CanaryPhase,
    /// Current traffic weight on canary (0-100)
    pub weight: u32,
    /// Last analysis timestamp
    pub last_analysis: Option<String>,
    /// Last measured success rate (0.0-1.0)
    pub last_success_rate: Option<f64>,
    /// Message (promotion reason, rollback reason, etc.)
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CanaryPhase {
    Initializing,
    Progressing,
    Promoting,
    Completed,
    RollingBack,
    RolledBack,
    Failed,
}
```

### Controller Implementation

The `CanaryController` is a standard kube-rs controller:

```rust
struct CanaryController {
    client: Client,
    metrics_url: String,  // VictoriaMetrics endpoint
}

async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<CanaryController>,
) -> Result<Action> {
    let spec = &service.spec;
    if spec.deploy.strategy != DeployStrategy::Canary {
        return Ok(Action::await_change());
    }

    let canary_config = spec.deploy.canary.as_ref()
        .ok_or(CanaryError::MissingConfig)?;

    let status = service.status.as_ref()
        .and_then(|s| s.canary.as_ref());

    match status.map(|s| &s.phase) {
        None | Some(CanaryPhase::Completed) | Some(CanaryPhase::RolledBack) => {
            // Check for spec drift → start new rollout
            if detect_spec_drift(&service, &ctx.client).await? {
                initialize_canary(&service, canary_config, &ctx).await?;
            }
            Ok(Action::requeue(Duration::from_secs(30)))
        }
        Some(CanaryPhase::Initializing) => {
            // Wait for canary pods ready, then start progressing
            if canary_pods_ready(&service, &ctx.client).await? {
                update_phase(&service, CanaryPhase::Progressing, &ctx).await?;
                set_canary_weight(&service, canary_config.step_weight.unwrap_or(10), &ctx).await?;
            }
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Some(CanaryPhase::Progressing) => {
            let current_weight = status.unwrap().weight;
            let success_rate = query_canary_metrics(&service, &ctx).await?;

            if success_rate < (100 - canary_config.threshold.unwrap_or(5)) as f64 / 100.0 {
                rollback_canary(&service, &ctx).await?;
            } else {
                let step = canary_config.step_weight.unwrap_or(10);
                let max = canary_config.max_weight.unwrap_or(50);
                let new_weight = (current_weight + step).min(100);
                if new_weight >= max {
                    promote_canary(&service, &ctx).await?;
                } else {
                    set_canary_weight(&service, new_weight, &ctx).await?;
                }
            }
            let interval = parse_duration(&canary_config.interval.clone()
                .unwrap_or_else(|| "60s".to_string()))?;
            Ok(Action::requeue(interval))
        }
        Some(CanaryPhase::Promoting) => {
            finalize_promotion(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Some(CanaryPhase::RollingBack) => {
            finalize_rollback(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Some(CanaryPhase::Failed) => {
            Ok(Action::await_change())  // Manual intervention needed
        }
    }
}
```

### Crash Recovery

The controller is idempotent. If it crashes mid-rollout:
- On restart, it reads the `CanaryStatus` from the LatticeService status subresource
- The phase tells it exactly where to resume
- Each phase's operations are idempotent (create-or-update Deployment, create-or-update HTTPRoute)
- No in-memory state — everything is persisted in Kubernetes resources

### What We Build

| Component | Estimated Size | Crate |
|---|---|---|
| `CanaryController` reconcile loop | ~400 lines | `lattice-service` |
| `CanaryStatus` / `CanaryPhase` types | ~60 lines | `lattice-common` |
| HTTPRoute generation for weighted split | ~100 lines | `lattice-service` |
| Canary Deployment/Service creation | ~150 lines | `lattice-service` |
| VictoriaMetrics query client | ~100 lines | `lattice-service` |
| Spec drift detection | ~50 lines | `lattice-service` |
| Unit tests | ~400 lines | `lattice-service` |
| Integration test (canary lifecycle) | ~300 lines | e2e tests |
| **Total** | **~1,560 lines** | |

### Edge Cases to Handle

- **No traffic during analysis:** If VictoriaMetrics returns no data (service has no callers), skip the analysis step and progress on weight alone. Log a warning.
- **Canary pods never become ready:** Timeout after 5 minutes (configurable), rollback automatically.
- **Spec changes during active rollout:** Restart the rollout with the newest spec. Don't layer canaries.
- **Service has no waypoint:** L4-only services (no L7 policies) can't do weighted traffic splitting. Reject `strategy: canary` at compilation time with a clear error if the service doesn't have a waypoint.
- **Multiple ports:** The HTTPRoute targets the primary Service port. If the service exposes multiple ports, apply weighted routing to all of them.

---

## Comparison Matrix

| Criteria | Flagger | Argo Rollouts | Build Ourselves |
|---|---|---|---|
| **Istio Ambient support** | Broken ([#1822](https://github.com/fluxcd/flagger/issues/1822)) | Not implemented ([#3897](https://github.com/argoproj/argo-rollouts/discussions/3897)) | Native (Gateway API HTTPRoute) |
| **Mesh policy compat** | Poor (Service renaming) | Medium (replaces Deployment) | Best (same labels, same SA) |
| **Integration effort** | Low (~200 lines) but blocked | High (replace Deployment) | Medium (~1,560 lines) |
| **Operational overhead** | +1 operator | +1 operator + plugin | None |
| **Customization** | Limited | High | Full |
| **CRD coupling** | Flagger CRD versions | Rollout CRD versions | Our own types |
| **Time to MVP** | Blocked on upstream | Blocked on upstream | ~4-6 weeks |
| **Maintenance burden** | Depends on upstream fixes | Depends on upstream fixes | On us, but scoped |

## Decision: Build Our Own (Option C)

Neither OSS tool supports Istio Ambient mode today. Flagger has a known bug with waypoint routing. Argo Rollouts' Istio integration is built on VirtualService/DestinationRule which don't exist in Ambient. We'd be adopting a tool and immediately fighting its assumptions.

Building our own gives us:
- **Working Ambient support from day one** — Gateway API HTTPRoute with weighted `backendRefs` is the native traffic management primitive for waypoint proxies
- **Deep mesh integration** — bilateral agreements, AuthorizationPolicy, CiliumNetworkPolicy all work without special-casing
- **No external dependencies** — no additional operators, no CRD version coupling, no upstream blocking issues
- **Status on LatticeService** — canary state is a first-class field, not scraped from a separate CR

The scope is manageable (~1,560 lines including tests) because we're not building a generic progressive delivery framework. We're building canary support for LatticeServices specifically, using primitives we already have.

## Implementation Plan

**Phase 1: Core Controller**
- Add `CanaryStatus` / `CanaryPhase` to `lattice-common` CRD types
- Implement `CanaryController` with the reconcile state machine
- Canary Deployment + Service creation and cleanup
- HTTPRoute generation with weighted `backendRefs`
- Unit tests for state transitions and HTTPRoute generation

**Phase 2: Metrics Analysis**
- VictoriaMetrics query client for `istio_requests_total`
- Success rate computation with canary pod filtering
- Threshold-based progression and rollback logic
- Unit tests with mock metrics responses

**Phase 3: Integration with ServiceReconciler**
- Spec drift detection via `lattice.dev/config-hash`
- Wire `CanaryController` into the existing reconcile loop
- Validate `strategy: canary` requires waypoint (compile-time check)

**Phase 4: Testing**
- Integration test: deploy a canary, verify HTTPRoute weights shift, verify rollback on injected errors
- E2E test: full canary lifecycle with mesh traffic and bilateral agreement verification
- Chaos test: controller restart mid-rollout, verify recovery
