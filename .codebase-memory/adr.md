# Lattice — Architecture Decision Record

## Context
Lattice is a Kubernetes operator for multi-cluster lifecycle management,
designed to provision clusters via CAPI and make each cluster
**fully self-managing** through a pivoting architecture. It is the
foundation for a GPU cloud platform (Fly.io for GPUs), with primary
target use case: convert Proxmox clusters into a zero-trust mesh.

## Workspace Shape
- **53 crates**, ~189k LOC Rust (~155k non-test).
- Top-heavy crates: `lattice-cli` (e2e harness), `lattice-crd`
  (CRDs/types, ~21k LOC), `lattice-cell` (parent gRPC server / pivot
  orchestrator, ~14k LOC), `lattice-common` (shared kube/install/policy
  utilities, ~11k LOC), `lattice-capi` (CAPI providers + installer),
  `lattice-cluster` (LatticeCluster reconciler).
- Workload axis: `lattice-service`, `lattice-workload`, `lattice-job`,
  `lattice-model`, `lattice-mesh-member`, `lattice-render`,
  `lattice-graph`.
- Auth/security axis: `lattice-cedar`, `lattice-auth`, `lattice-api`
  (Cedar-gated K8s proxy), `lattice-webhook`.
- Provider axes: `lattice-cloud-provider`, `lattice-image-provider`,
  `lattice-secret-provider`, `lattice-dns-provider`,
  `lattice-cert-issuer`.

## Per-Dependency Install Pattern (load-bearing)
13 managed-infra crates (cilium, istio, cert-manager, eso, gpu-operator,
keda, kthena, metrics-server, rook, tetragon, velero, victoria-metrics,
volcano) each have their own `*Install` CRD + bespoke controller. Each
crate has the same `install/{mod,controller,ensure,manifests}.rs`
layout, but reconcile logic lives in
`lattice_common::install::run_simple_install_reconcile` with
per-dependency `SimpleInstallConfig` + `ReadinessCheck` enum
(Deployment / Deployments / DaemonSet / ResourceStatus). The shared
helper handles SSA, status skip-if-unchanged, manifest-hash
short-circuit, `spec.requires` cross-subsystem upgrade gating
(`UpgradeBlocked` condition), and `UpgradeAttempt` audit.
**This is intentional — bespoke controllers with shared mechanical
plumbing, not a shared trait.** The architecture honors the project
rule that managed infra never goes through a `LatticePackage` or shared
reconciler skeleton.

## Cluster / Pivot Architecture
- Parent cell creates `LatticeCluster` CRDs.
- CAPI provisions infra; agent established outbound gRPC to parent.
- `PivotCommand` over the stream moves CAPI ownership to the child
  cluster (distributed move protocol — `lattice-move`).
- All workload-cluster traffic is **outbound-only**; inbound is never
  required for self-management.
- gRPC stream multiplexes coordination + K8s API proxy +
  `KubernetesRequest` for parent visibility, but children operate
  100% independently of the parent.

## Defense-in-Depth (immutable)
- Service mesh bilateral agreement: caller `outbound` + callee
  `inbound` → both **Cilium CNP** (L4 eBPF) and **Istio
  AuthorizationPolicy** (L7 SPIFFE) generated. Both layers required.
- Default-deny via `CiliumClusterwideNetworkPolicy` + empty
  `AuthorizationPolicy` in non-system namespaces.
- Cedar policy authorization for secret access (default-deny, principal =
  `Lattice::Service::"namespace/name"`).
- ESO routes secret material through 5 paths (env/mixed/file/imagePull/
  dataFrom), backed by Vault or local webhook.
- All crypto: rustls + aws-lc-rs (FIPS).

## Hygiene Indicators
- **Zero `#[allow(dead_code)]` or `#[allow(unused)]`** anywhere in
  `crates/*/src`.
- **Zero non-test `.unwrap()` outside `k8s_forwarder/tests.rs`.**
- **2 TODO comments** total across the workspace.
- **2 `#[allow(clippy::too_many_arguments)]`** — both candidates for
  refactor per project rule.

## Notable Cross-Cutting Modules
- `lattice-common::kube_utils` — manifest apply, SSA helpers, status
  patch, dynamic client wrappers, deployment/DS waiters.
- `lattice-common::policy` — Cilium CNP, Istio AuthorizationPolicy,
  ServiceEntry, Tetragon policy generators.
- `lattice-common::install` — install reconcile runner +
  `spec.requires` semver gating.
- `lattice-common::credentials` — provider credential plumbing
  (Proxmox, AWS, Basis).
- `lattice-common::leader_election` — controller leader election.
- `lattice-cedar` — sub-engines per resource (mesh, secret, image,
  external endpoint, security, volume).

## Key Decisions
1. Outbound-only network model for child clusters (firewall-friendly,
   no attack surface).
2. Per-dependency Install controllers, never a shared trait or
   LatticePackage skeleton.
3. Cross-release backwards compatibility is **not** maintained
   (pre-release; fix forward only).
4. Cross-crate aggregation lives at the consumer; foundational
   crates have no dependents.
5. `cosign` is invoked as a subprocess; `sigstore-rs` is blocked by a
   `ring`/FIPS conflict.
6. Defense-in-depth (Cilium L4 + Istio L7) is correct and load-bearing;
   not duplication.
7. `LatticeService` is Score-shaped and intentionally simple at the
   user API; operator-internal complexity is hidden behind it.

## Open Refactor Candidates (Pre-release)
- `agent::commands::CommandContext::new` — 10 args, replace with
  struct-literal init.
- `workload::compiler::collect_compiled_files` — 10 args, fold the
  `&mut Vec<...>` accumulators into a single `&mut Accumulators`
  struct.
- `cell::server::process_agent_message` (533 lines) — split per
  message variant.
- `operator::main::run` (530 lines) — split into
  `bootstrap_runtime`, `start_controllers`, `start_servers`.
- `model::controller::reconcile` (402 lines) — extract per-phase
  helpers.
- `service::controller::compile_and_apply` (238 lines) — pipeline
  stages.
- `cluster::phases::ready` (1239 lines) — split sub-reconcilers
  into per-aspect modules.
- `is_local_resource` is `!is_inherited_resource` — collapse one of
  the two.
