# Tetragon Runtime Enforcement via ServiceCompiler

## Overview

Add Tetragon TracingPolicy generation to the existing `ServiceCompiler::compile()` pipeline. No new CRDs — runtime enforcement policies are derived from the same `LatticeServiceSpec` that already produces CiliumNetworkPolicy and AuthorizationPolicy. Users declare *what* their service needs; Lattice computes *what to enforce* at the kernel level.

## Design Principle

The LatticeService spec already captures security-relevant intent:

| Spec Field | What Lattice Knows | What Tetragon Can Enforce |
|---|---|---|
| `containers.*.image` | Expected binary | Block unexpected `execve` syscalls |
| `containers.*.security.capabilities` | Requested caps | Kill processes using unrequested capabilities |
| `containers.*.security.privileged` | Privilege level | Enforce no-privilege if not requested |
| `containers.*.security.read_only_root_filesystem` | FS intent | Block writes to `/` if declared read-only |
| `containers.*.files` | Expected file mounts | Block reads of sensitive paths not in mount list |
| `containers.*.volumes` | Expected volumes | Restrict file access to declared paths |
| `workload.resources` (type: secret) | Secret access | Block reads of secret file paths by non-entitled containers |
| `runtime.sysctls` | Requested sysctls | Baseline: block sysctl writes not in list |
| No `hostNetwork` declared | No host access needed | Block `connect`/`bind` on host network namespaces |

The key insight: **if a service didn't ask for a capability, it shouldn't be able to use it at runtime**. The SecurityContext prevents the *container runtime* from granting it; Tetragon prevents the *kernel* from honoring it even if the runtime is bypassed.

## Architecture

```
LatticeServiceSpec
  │
  ├─→ CiliumNetworkPolicy    (L4 — who can connect)
  ├─→ AuthorizationPolicy    (L7 — who is authenticated)
  ├─→ TracingPolicy           (runtime — what processes/syscalls are allowed)
  │
  └─→ All three derived from the same spec. No additional user config.
```

### Policy Tiers

TracingPolicies compile into three tiers, each progressively more restrictive:

**Tier 1: Baseline (all services, no opt-in)**
- Block `execve` of shells (`/bin/sh`, `/bin/bash`, `/bin/dash`) in non-debug containers, **unless the container's liveness, readiness, or startup probes use `exec` commands** (the compiler inspects probe specs and excludes shell paths that appear in probe commands)
- Block writes to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`
- Block `ptrace` (anti-debugging/container-escape)
- Block loading kernel modules (`init_module`, `finit_module`)
- Block `mount`/`umount` syscalls
- Kill processes that call `unshare` or `setns` (namespace escape)

Services that legitimately need to escape Tier 1 restrictions (e.g., build containers that must exec shells) can be exempted via Cedar policy: `Lattice::Action::"ExemptBaselineEnforcement"` on `Lattice::Service::"namespace/name"`. The compiler checks for this permit before emitting baseline kprobes for the service.

**Tier 2: Spec-derived (automatic from LatticeServiceSpec) — enforced via Sigkill**
- If `read_only_root_filesystem: true` → block `open(..., O_WRONLY|O_RDWR)` on `/` tree (excluding tmpfs mounts)
- If `capabilities` is empty → block `capset` syscall entirely
- If specific capabilities listed → block `capset` for capabilities NOT in the list
- If `files` declared → restrict `open` to declared paths + standard library/runtime paths
- If no `hostNetwork` → block `connect`/`bind` on host-namespace sockets

Tier 2 enforces with Sigkill, not audit. These policies derive from the service author's own declared intent — if a service declared `readOnlyRootFilesystem: true` and something writes to root, that is a violation of the author's spec and should be killed.

**Tier 3: Cedar-authorized hardening (opt-in via Cedar policy) — audit by default during rollout**
- `Lattice::Action::"EnforceAllowlist"` → only allow `execve` for explicitly listed binaries
- `Lattice::Action::"EnforceFileIntegrity"` → block writes to application directories (immutable container)

Tier 3 defaults to audit mode (`Post` action with event logging) since these are operator-imposed policies beyond what the service author declared. Switch to Sigkill per-service via `Lattice::Action::"EnforceStrict"`.

## Implementation

### 1. TracingPolicy Types

Add Tetragon CRD types to `lattice-common` using `kube::CustomResource` or `DynamicObject`:

```
crates/lattice-common/src/policy/tetragon.rs
```

```rust
use kube::api::DynamicObject;

/// Build a TracingPolicyNamespaced as a DynamicObject.
///
/// We use DynamicObject rather than hand-rolling CRD structs to avoid
/// serialization mismatches with upstream Tetragon API types.
pub fn build_tracing_policy(
    name: &str,
    namespace: &str,
    spec: TracingPolicySpec,
) -> DynamicObject {
    // Construct via DynamicObject with apiVersion/kind set to
    // "cilium.io/v1alpha1" / "TracingPolicyNamespaced"
    todo!()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracingPolicySpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracepoints: Vec<TracepointSpec>,
    pub selectors: Vec<Selector>,
}

/// Use tracepoints (arch-independent) instead of kprobes.
/// `sys_enter_execve` works on both x86_64 and aarch64, unlike
/// `__x64_sys_execve` / `__arm64_sys_execve`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracepointSpec {
    pub subsystem: String,               // e.g., "syscalls"
    pub event: String,                   // e.g., "sys_enter_execve"
    pub args: Vec<TracepointArg>,
    pub selectors: Vec<Selector>,
    pub action: TracingAction,           // Sigkill, Post, etc.
}
```

### 2. Runtime Policy Compiler

New sub-module alongside `cilium.rs` and `istio_ambient.rs`:

```
crates/lattice-service/src/policy/tetragon.rs
```

```rust
impl PolicyCompiler<'_> {
    pub fn compile_tracing_policies(
        &self,
        service_name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> Vec<DynamicObject> {
        let mut policies = vec![];

        // Check Cedar exemption before emitting baseline
        if !self.has_cedar_permit(namespace, service_name, "ExemptBaselineEnforcement") {
            policies.push(self.compile_baseline_policy(service_name, namespace, spec));
        }

        // Tier 2: spec-derived
        policies.extend(self.compile_spec_derived_policies(service_name, namespace, spec));

        policies
    }

    fn compile_baseline_policy(
        &self,
        service_name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> DynamicObject {
        // Collect shell paths used by exec probes so we don't block them
        let probe_shell_paths = Self::extract_probe_shell_paths(spec);
        let blocked_shells: Vec<&str> = ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh"]
            .into_iter()
            .filter(|s| !probe_shell_paths.contains(&s.to_string()))
            .collect();

        // Emit tracepoints (NOT kprobes) for arch independence
        // e.g., tracepoint: syscalls/sys_enter_execve
        todo!()
    }
}
```

The compiler reads `ContainerSecuritySpec` fields and emits corresponding tracepoint rules. Each TracingPolicy is scoped to the service's pods via `matchLabels: { "lattice.dev/name": "{service}" }`.

All tracepoint hooks use the `syscalls` subsystem (e.g., `sys_enter_execve`, `sys_enter_openat`, `sys_enter_ptrace`) which are architecture-independent. This ensures identical enforcement on x86_64 and aarch64 nodes without arch-detection logic.

### 3. Integration into PolicyCompiler

Extend `GeneratedPolicies`:

```rust
pub struct GeneratedPolicies {
    pub authorization_policies: Vec<AuthorizationPolicy>,
    pub cilium_policies: Vec<CiliumNetworkPolicy>,
    pub service_entries: Vec<ServiceEntry>,
    pub tracing_policies: Vec<DynamicObject>,  // NEW
}
```

Add to `PolicyCompiler::compile()`:

```rust
// Generate TracingPolicies (runtime enforcement)
output.tracing_policies = self.compile_tracing_policies(name, namespace, spec);
```

This requires threading `&LatticeServiceSpec` into `PolicyCompiler::compile()` — currently it only uses the `ServiceGraph`. The spec is needed because runtime policies depend on container-level fields (security context, files, volumes) that the graph doesn't capture.

### 4. Controller Changes

The service controller already applies `CompiledService.policies`. Extend it to apply `tracing_policies` alongside the existing policy types. Same ownership model — TracingPolicies are owned by the LatticeService and garbage-collected on deletion.

### 5. Default-Deny Baseline

Add a cluster-wide TracingPolicy during bootstrap (alongside the existing CiliumClusterwideNetworkPolicy and mesh-default-deny AuthorizationPolicy):

```
crates/lattice-infra/src/bootstrap/tetragon.rs
```

This installs the Tier 1 baseline for all non-system namespaces, using the same namespace exclusion pattern as the Cilium default-deny:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: baseline-runtime-deny
spec:
  tracepoints:
    - subsystem: "syscalls"
      event: "sys_enter_execve"
      args:
        - index: 0
          type: string
      selectors:
        - matchArgs:
            - index: 0
              operator: In
              values: ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh"]
          matchNamespaces:
            - namespace: !kube-system
              operator: NotIn
      action: Sigkill
    # ... ptrace, module loading, etc.
```

Per-service TracingPolicies from Tier 2 layer on top of this baseline. Per-service policies use `TracingPolicyNamespaced` so they are namespace-scoped and owned by the LatticeService.

## Compilation Examples

### Example 1: Minimal service (Tier 1 only)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  workload:
    containers:
      main:
        image: api:latest
```

**Produces:** Baseline TracingPolicy only (block shells, ptrace, module loading). No additional runtime restrictions since no security context is specified.

### Example 2: Hardened service (Tier 1 + Tier 2)

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  workload:
    containers:
      main:
        image: api:latest
        security:
          readOnlyRootFilesystem: true
          capabilities: []
          runAsNonRoot: true
```

**Produces:**
- Baseline TracingPolicy (Tier 1)
- Block `open(O_WRONLY|O_RDWR)` on non-tmpfs paths (from `readOnlyRootFilesystem`)
- Block `capset` entirely (from empty `capabilities`)
- Block `setuid`/`setgid` syscalls (from `runAsNonRoot`)

### Example 3: Service needing specific capability

```yaml
spec:
  workload:
    containers:
      main:
        image: proxy:latest
        security:
          capabilities: [NET_BIND_SERVICE]
```

**Produces:**
- Baseline TracingPolicy (Tier 1)
- Allow `NET_BIND_SERVICE` via `capset`, block all others

### Example 4: Service with shell-based health check

```yaml
spec:
  workload:
    containers:
      main:
        image: legacy-app:latest
        livenessProbe:
          exec:
            command: ["/bin/sh", "-c", "curl -f http://localhost:8080/health"]
```

**Produces:**
- Baseline TracingPolicy (Tier 1) with `/bin/sh` **excluded** from the blocked shells list (detected from probe spec)
- `/bin/bash`, `/bin/dash`, `/usr/bin/sh` still blocked

### Example 5: Build container exempt from baseline

```yaml
# Cedar policy:
# permit(
#   principal == Lattice::Service::"ci/build-runner",
#   action == Lattice::Action::"ExemptBaselineEnforcement",
#   resource
# );
```

**Produces:** No Tier 1 baseline policy for this service. Tier 2 policies still apply if security context fields are set.

## Deployment Prerequisites

- Tetragon >= v1.0 (required for `TracingPolicyNamespaced`)
- Tetragon DaemonSet installed per cluster (add to cluster bootstrap, alongside Cilium and Istio)
- Kernel >= 5.3 for full tracepoint support (verify in CAPI node image)
- Tetragon CRDs registered (TracingPolicy, TracingPolicyNamespaced)

### Bootstrap Integration

Add Tetragon installation to the cluster provisioning pipeline in `lattice-infra`:

```rust
// In bootstrap sequence, after Cilium and Istio:
install_tetragon(client).await?;
apply_baseline_tracing_policy(client).await?;
```

## FIPS Considerations

Tetragon's enforcement path is entirely in-kernel eBPF — no cryptographic operations. The only FIPS-relevant surface is Tetragon's gRPC export endpoint (metrics/events). Options:

1. **Don't expose gRPC export** — use Tetragon's JSON log output instead, collected by existing log pipeline
2. **If gRPC needed** — front it with an Envoy sidecar using FIPS-validated TLS (same pattern as other internal services)

Recommendation: option 1. Tetragon events go to stdout, collected by the cluster's log aggregator. No new TLS surface.

## Testing Strategy

### Unit Tests

- `compile_baseline_policy()` produces expected tracepoint specs
- `compile_spec_derived_policies()` with various `ContainerSecuritySpec` combinations
- Empty capabilities → blocks `capset`
- `readOnlyRootFilesystem: true` → blocks write syscalls
- Privileged container → no write-blocking policies (would conflict)
- Shell-based exec probe → excluded from baseline shell block list
- Cedar `ExemptBaselineEnforcement` → no baseline policy emitted

### Integration Tests

New test module `integration/runtime.rs`:

1. Deploy a LatticeService with `readOnlyRootFilesystem: true`
2. `kubectl exec` into the pod and attempt `touch /tmp-not-tmpfs/file`
3. Verify process is killed by Tetragon (exit code 137 / SIGKILL)
4. Verify writes to declared tmpfs mounts succeed
5. Deploy a LatticeService **without** `readOnlyRootFilesystem` and confirm writes to `/` succeed (no false enforcement)
6. Deploy a service with a shell-based liveness probe and confirm the probe runs successfully (shell not blocked)

### E2E Tests

Add runtime enforcement verification to `unified_e2e.rs` post-mesh-validation phase:
- Deploy hardened service
- Verify TracingPolicy exists and matches expected spec
- Attempt blocked operation, confirm enforcement

## File Changes Summary

| File | Change |
|---|---|
| `crates/lattice-common/src/policy/mod.rs` | Add `pub mod tetragon;` |
| `crates/lattice-common/src/policy/tetragon.rs` | **New** — TracingPolicySpec types + DynamicObject builder |
| `crates/lattice-service/src/policy/mod.rs` | Add `mod tetragon;`, extend `GeneratedPolicies`, thread `&LatticeServiceSpec` into `compile()` |
| `crates/lattice-service/src/policy/tetragon.rs` | **New** — runtime policy compilation + tests for all tiers |
| `crates/lattice-service/src/controller.rs` | Apply TracingPolicies alongside other policies |
| `crates/lattice-infra/src/bootstrap/mod.rs` | Add `pub mod tetragon;` |
| `crates/lattice-infra/src/bootstrap/tetragon.rs` | **New** — baseline TracingPolicy + Tetragon install |
