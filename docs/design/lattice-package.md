# LatticePackage Design

## Problem

Teams need to install third-party Helm charts (Redis, Postgres, Kafka, etc.) into
Lattice-managed clusters with the same secret injection, Cedar authorization, and
mesh integration that LatticeService provides. Today, infrastructure charts are
pre-rendered at build time and embedded in the operator binary. There is no
user-facing mechanism for declarative Helm chart lifecycle management.

## Goals

- Declarative Helm chart installation via a CRD
- Reuse the existing `${secret.name.key}` templating and ESO pipeline for values
- Cedar-authorized secret access (default-deny, same as LatticeService)
- Mesh integration via LatticeMeshMember generation
- Quota-aware (packages consume cluster resources)
- Upgrade, rollback, and drift detection

## Non-Goals

- Replacing the build-time infrastructure chart pipeline (Cilium, Istio, ESO, etc.)
- Arbitrary Kubernetes manifest management (use LatticeService for workloads)
- Multi-chart dependency resolution (one LatticePackage = one chart)

---

## CRD: LatticePackage

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticePackage
metadata:
  name: redis-prod
  namespace: payments
spec:
  chart:
    repository: oci://registry.example.com/charts
    name: redis
    version: 18.6.1

  # Secret resources — same as LatticeService. Both modes use this.
  resources:
    redis-creds:
      type: secret
      id: payments/redis/prod
      params:
        provider: vault-prod
        keys: [password, username]
    redis-tls:
      type: secret
      id: payments/redis/tls
      params:
        provider: vault-prod
        keys: [cert, private_key]

  # Helm values with secret injection support.
  values:
    architecture: replication
    auth:
      # Mode 1 — $secret directive: maps resource keys to chart-expected
      # keys, creates a K8s Secret, replaces this object with the name.
      # The chart sees: existingSecret: "redis-prod-auth-existingsecret"
      existingSecret:
        $secret:
          redis-password: "${redis-creds.password}"
          redis-username: "${redis-creds.username}"
    master:
      resources:
        requests:
          cpu: "500m"
          memory: 1Gi
    tls:
      enabled: true
      existingSecret:
        $secret:
          tls.crt: "${redis-tls.cert}"
          tls.key: "${redis-tls.private_key}"

  # Optional: mesh integration for chart workloads.
  # Generates LatticeMeshMember so chart pods participate in
  # bilateral agreements and get Cilium/Istio policies.
  mesh:
    # Label selector for pods created by this chart that should
    # be part of the mesh. Applied to the generated MeshMember's target.
    selector:
      matchLabels:
        app.kubernetes.io/instance: redis-prod
    ports:
      - name: redis
        port: 6379
        protocol: TCP
    # Services allowed to connect (inbound side of bilateral agreement)
    allowedCallers:
      - name: checkout-service
      - name: cart-service

  # Namespace to render the chart into. Defaults to metadata.namespace.
  targetNamespace: payments

  # Helm-specific options
  createNamespace: false
  skipCRDs: false
  timeout: 10m
```

---

## Architecture

```
LatticePackage CRD
       |
       v
PackageController (reconcile)
       |
       +---> 1. Walk values tree
       |       - Extract $secret directives (Mode 1)
       |       - Extract ${secret.X.Y} references (Mode 2, if resources block present)
       |       - Collect (provider, remote_key) pairs for Cedar
       |
       +---> 2. Cedar authorization (authorize_secrets — reused)
       |         Default-deny: package must have Cedar permit for each secret
       |
       +---> 3. Generate + apply ExternalSecrets
       |       - Mode 1: one ExternalSecret per $secret directive (with key mapping)
       |       - Mode 2: via SecretsCompiler (same as LatticeService)
       |
       +---> 4. Wait for synced K8s Secrets to exist
       |
       +---> 5. Rewrite values tree
       |       - Mode 1: replace $secret objects with Secret name strings
       |       - Mode 2: replace ${secret.X.Y} with actual values from Secret .data
       |         (in memory only — resolved values are never persisted)
       |
       +---> 6. Helm template + server-side apply
       |         helm template → YAML manifests → kubectl apply (SSA)
       |         No Helm release state (no Tiller, no release secrets)
       |
       +---> 7. Apply LatticeMeshMember (if spec.mesh is set)
       |
       +---> 8. Update status (phase, conditions, applied version)
       |
       +---> 9. Drift detection on requeue
                Compare applied manifests hash vs current
```

### Why "helm template + apply" instead of "helm install"

Lattice already uses this pattern for all infrastructure charts. Benefits:

- No Helm release state to manage (no release secrets, no rollback state)
- Server-side apply gives proper field ownership and conflict detection
- Same apply mechanism as LatticeService (ApplyBatch, field manager)
- Drift detection via content hash comparison
- No Tiller/Helm SDK dependency at runtime — just the template engine

The chart is pulled at reconcile time (not build time like infra charts) and
cached locally. `helm template` is invoked as a subprocess, same as `cosign`
(see feedback_cosign_subprocess memory — subprocess is preferred over library
bindings when the library has FIPS/dependency conflicts).

---

## Secret Injection: Two Modes

### Mode 1: `$secret` Directive (Preferred)

A `$secret` object anywhere in the values tree tells the controller to:

1. Create an ESO ExternalSecret with the specified key mapping
2. Replace that object with the name of the resulting K8s Secret (a string)

The rule: **`$secret` replaces its parent value with a string.** Put it
wherever the chart expects a string that should be a K8s Secret name. The
controller walks the deserialized `serde_json::Value` tree, finds any
`Value::Object` containing a `$secret` key, creates the ExternalSecret,
and swaps the entire object for `Value::String(secret_name)`. No YAML
parsing — Kubernetes already deserializes the CRD to JSON.

#### Replacement semantics

```rust
// Pseudocode: recursive tree walk over the already-deserialized values
fn extract_secret_directives(value: &mut Value, path: &str, pkg: &str) -> Vec<SecretDirective> {
    match value {
        Value::Object(map) if map.contains_key("$secret") => {
            let directive = parse_directive(map.remove("$secret").unwrap(), path, pkg);
            *value = Value::String(directive.secret_name.clone());
            vec![directive]
        }
        Value::Object(map) => {
            map.values_mut().flat_map(|v| extract_secret_directives(v, ...)).collect()
        }
        Value::Array(arr) => { /* recurse */ }
        _ => vec![],
    }
}
```

The generated Secret name is deterministic: `{package_name}-{path_hash}`
where `path_hash` is derived from the values path (e.g., `auth.existingSecret`).

#### Examples: different chart conventions

Charts accept secret references in many different shapes. The `$secret`
directive works with all of them because it replaces any single value node:

**Bitnami Redis** — `existingSecret` at top level:

```yaml
values:
  auth:
    existingSecret:                        # chart expects a string here
      $secret:
        id: payments/redis/prod
        provider: vault-prod
        keys:
          redis-password: password         # K8s Secret key: source key
```

Helm sees: `auth.existingSecret: "redis-prod-a1b2c3"`

**PostgreSQL** — nested under `secret.name`:

```yaml
values:
  global:
    postgresql:
      auth:
        existingSecret:
          $secret:
            id: payments/pg/prod
            provider: vault-prod
            keys:
              postgres-password: password
              replication-password: repl_password
```

Helm sees: `global.postgresql.auth.existingSecret: "redis-prod-d4e5f6"`

**Grafana** — admin credentials in a separate field:

```yaml
values:
  admin:
    existingSecret:
      $secret:
        id: monitoring/grafana
        provider: vault-prod
        keys:
          admin-user: username
          admin-password: password
```

Helm sees: `admin.existingSecret: "redis-prod-g7h8i9"`

**Generic chart** — `secretName` nested deeply:

```yaml
values:
  ingress:
    tls:
      - hosts: [app.example.com]
        secretName:
          $secret:
            id: infra/tls/wildcard
            provider: vault-prod
            keys:
              tls.crt: cert
              tls.key: key
```

Helm sees: `ingress.tls[0].secretName: "redis-prod-j0k1l2"`

#### Key mapping (`keys` field)

The `keys` map bridges the naming gap between what the chart reads from
the K8s Secret and what the source store has:

```
keys:
  redis-password: password
  ^                ^
  |                └── key in the source store (Vault, etc.)
  └── key in the K8s Secret (what the chart reads)
```

The generated ExternalSecret maps these via ESO's `data` field:

```yaml
# Generated ExternalSecret
spec:
  secretStoreRef:
    name: vault-prod
    kind: ClusterSecretStore
  target:
    name: redis-prod-a1b2c3
  data:
    - secretKey: redis-password         # key in the K8s Secret
      remoteRef:
        key: payments/redis/prod        # remote path
        property: password              # key in the store
```

If `keys` is omitted, all keys from the source are synced with their
original names (passthrough, same as ESO `dataFrom.extract`).

#### Multiple directives

Each `$secret` in the tree produces its own ExternalSecret. A single
LatticePackage can have as many as the chart needs:

```yaml
values:
  auth:
    existingSecret:
      $secret:
        id: payments/redis/prod
        provider: vault-prod
        keys: { redis-password: password }
  tls:
    existingSecret:
      $secret:
        id: payments/redis/tls
        provider: vault-prod
        keys: { tls.crt: cert, tls.key: private_key }
  metrics:
    existingSecret:
      $secret:
        id: payments/redis/metrics
        provider: vault-prod
```

### Mode 2: Inline Secret Values

For charts that accept secret values directly in their values (no
`existingSecret` option), the controller resolves `${secret.X.Y}` in
the values tree before templating.

```yaml
spec:
  values:
    auth:
      password: "${secret.redis-creds.password}"
  resources:
    redis-creds:
      type: secret
      id: payments/redis/prod
      params:
        provider: vault-prod
        keys:
          - password
```

Flow:
1. ESO syncs the secret into a K8s Secret
2. Controller reads the synced K8s Secret's `.data`
3. Controller walks the values tree, replacing `${secret.X.Y}` with the
   actual base64-decoded value
4. Resolved values are passed to `helm template`
5. Resolved values are **never persisted** — they exist only in memory
   during template rendering

This reuses `extract_secret_refs()` from `lattice-common::template::renderer`
to find all secret references, and the existing `SecretsCompiler` to generate
the ExternalSecrets.

---

## Reused Components

| Component | Used by | Source | Reuse |
|-----------|---------|--------|-------|
| ESO types and builders | Mode 1 + 2 | `lattice-secret-provider::eso` | `build_external_secret()` |
| Cedar authorization | Mode 1 + 2 | `lattice-cedar::secret_auth` | `authorize_secrets()` |
| Secret wait polling | Mode 1 + 2 | `lattice-service::controller` | `wait_for_image_pull_secrets` pattern |
| `${secret.X.Y}` parsing | Mode 2 only | `lattice-common::template::renderer` | `parse_secret_ref()`, `extract_secret_refs()` |
| Secret resource declaration | Mode 2 only | `lattice-common::crd::workload::resources` | `ResourceSpec`, `SecretParams` |
| ExternalSecret generation | Mode 2 only | `lattice-workload::pipeline::secrets` | `SecretsCompiler::compile()` |
| Mesh member generation | mesh config | `lattice-service::compiler` | `LatticeMeshMember` spec construction |
| Quota enforcement | optional | `lattice-quota` | `QuotaBudget::check()` |
| Apply batch | always | `lattice-common::kube_utils` | `ApplyBatch`, server-side apply |

Mode 1 (`$secret` directives) generates ExternalSecrets directly from the
tree walk — it doesn't go through `SecretsCompiler` because there's no
`resources` block involved. The directive IS the declaration.

Mode 2 (`${secret.X.Y}` inline) reuses `SecretsCompiler` and the full
workload secret pipeline. The `authorize_secrets` function currently takes
a `WorkloadSpec` as input; to reuse it for Mode 2, extract the
secret-relevant subset (`resources` map) into a shared trait or standalone
function that both `WorkloadSpec` and `LatticePackageSpec` can provide.

Both modes feed into the same Cedar authorization: each `$secret` directive
or `${secret.X.Y}` reference produces a `(provider, remote_key)` pair that
Cedar evaluates against `Lattice::Action::"AccessSecret"`.

---

## Status

```yaml
status:
  phase: Ready          # Pending | Rendering | Applying | Ready | Failed
  chartVersion: 18.6.1
  appliedHash: "sha256:abc..."   # Hash of rendered manifests for drift detection
  observedGeneration: 3
  conditions:
    - type: SecretsReady
      status: "True"
      lastTransitionTime: "2026-04-08T..."
    - type: ChartRendered
      status: "True"
    - type: ManifestsApplied
      status: "True"
    - type: MeshReady
      status: "True"
  message: "redis 18.6.1 applied (12 resources)"
```

### Phase Transitions

```
Pending ──> Rendering ──> Applying ──> Ready
   │            │             │          │
   └──> Failed  └──> Failed   └─> Failed │
                                         │
                              (drift) <──┘
```

- **Pending**: Waiting for ExternalSecrets to sync (secrets not yet available)
- **Rendering**: Secrets resolved, running `helm template`
- **Applying**: Server-side applying rendered manifests
- **Ready**: All manifests applied, mesh member ready (if configured)
- **Failed**: Cedar denied, secret sync failed, template error, apply error

---

## Upgrade Flow

When `spec.chart.version` changes:

1. Pull new chart version
2. Re-resolve secrets (same ExternalSecrets, values may reference new keys)
3. Re-render with `helm template`
4. Diff rendered manifests against `status.appliedHash`
5. If changed: server-side apply (SSA handles field ownership transitions)
6. Update status with new version and hash

Secret rotation (ESO refreshes a value) triggers re-render via the same
content-hash mechanism used by LatticeService. The controller watches the
synced K8s Secrets and requeues when their content changes.

---

## Drift Detection

On periodic requeue (60s when Ready):

1. Re-render chart with current values + secrets
2. Compare manifest hash against `status.appliedHash`
3. If different: re-apply (covers both value changes and external drift)

This is the same pattern LatticeService uses with `eso_content_hash` to
detect secret rotation and trigger rollouts.

---

## Security Model

### Cedar Authorization

Packages use the same Cedar entity model as services:

- **Principal**: `Lattice::Package::"namespace/name"`
- **Action**: `Lattice::Action::"AccessSecret"`
- **Resource**: `Lattice::SecretPath::"vault-prod:payments/redis/prod"`

```cedar
permit(
    principal == Lattice::Package::"payments/redis-prod",
    action == Lattice::Action::"AccessSecret",
    resource == Lattice::SecretPath::"vault-prod:payments/redis/prod"
);
```

### Secret Handling by Mode

**Mode 1 (`$secret` directives)**: Secret values never enter the Helm values
pipeline at all. The directive is replaced with a K8s Secret *name* (a
non-sensitive string). The chart reads the actual secret values from the K8s
Secret at runtime. This is the safest path.

**Mode 2 (`${secret.X.Y}` inline)**: Resolved secret values exist only in
memory during `helm template`. They are never written to any K8s resource,
ConfigMap, or status field. The rendered manifests may contain secrets (e.g.,
a chart that puts passwords in a ConfigMap), but that is the chart's
responsibility, not Lattice's.

### Mesh Integration

When `spec.mesh` is set, the controller generates a `LatticeMeshMember` with:
- Target selector matching chart pods
- Declared ports
- Allowed callers (inbound bilateral agreements)

This gives chart workloads the same Cilium + Istio policy enforcement as
LatticeService workloads. Without `spec.mesh`, chart pods get the cluster's
default-deny baseline but no explicit allow rules.

---

## Unified Secret Templating Crate: `lattice-secret-template`

### Motivation

Secret reference handling is currently scattered:

| What | Where | Does |
|------|-------|------|
| `parse_secret_ref()` | `lattice-common::template::renderer` | Parse `${secret.X.Y}` as pure ref |
| `extract_secret_refs()` | `lattice-common::template::renderer` | Replace `${secret.X.Y}` with ESO Go templates in strings |
| `FileSecretRef`, `SecretVariableRef` | `lattice-common::template::renderer` | Types, mixed with rendering types |
| `SecretsCompiler::compile()` | `lattice-workload::pipeline::secrets` | Generate ExternalSecrets from resources block |
| ESO templated env vars | `lattice-workload::pipeline::eso_templated` | Mixed-content string → ESO ExternalSecret |
| `resolve_single_store()` | `lattice-workload::pipeline::secrets` | Validate all refs use same store |
| `resolve_eso_data()` | `lattice-workload::pipeline::secrets` | Convert FileSecretRef → ExternalSecretData |

This is all string-level. Neither the workload compiler nor the package
controller should be doing tree walking — that's a shared concern.

### Design

A new `lattice-secret-template` crate that operates on `serde_json::Value`
trees. It handles both expansion modes in a single recursive walk:

```rust
/// Result of processing a Value tree for secret references.
pub struct SecretExpansionResult {
    /// $secret directives found (Mode 1).
    /// Each generates an ExternalSecret; the directive node was replaced
    /// with Value::String(secret_name).
    pub directives: Vec<SecretDirective>,

    /// ${secret.X.Y} string references found (Mode 2).
    /// Grouped by containing string for ESO template generation.
    pub inline_refs: Vec<InlineSecretRef>,
}

/// A $secret directive extracted from the tree.
pub struct SecretDirective {
    /// Deterministic name for the generated K8s Secret
    pub secret_name: String,
    /// Path in the values tree where this directive was found
    pub values_path: String,
    /// Remote key in the secret store
    pub id: String,
    /// ClusterSecretStore name
    pub provider: String,
    /// Key mapping: K8s Secret key → source store key.
    /// If empty, all keys pass through.
    pub keys: BTreeMap<String, String>,
}

/// A ${secret.X.Y} reference found in a string value.
pub struct InlineSecretRef {
    /// Path in the values tree
    pub values_path: String,
    /// Resource name (the X in ${secret.X.Y})
    pub resource_name: String,
    /// Key (the Y in ${secret.X.Y})
    pub key: String,
    /// ESO-safe data key for Go template references
    pub eso_data_key: String,
}

/// Walk a Value tree, expanding all secret references in place.
///
/// - `$secret` objects are replaced with `Value::String(secret_name)`
/// - `${secret.X.Y}` in strings are replaced with ESO Go template syntax
///   OR with resolved values (depending on the mode)
/// - Returns all references found for Cedar authorization and ESO generation
pub fn expand_secrets(
    value: &mut Value,
    name_prefix: &str,
) -> Result<SecretExpansionResult, SecretTemplateError> {
    // recursive tree walk
}
```

### How each consumer uses it

**LatticeService (workload compiler):**

Today the renderer processes each env var and file as an individual string.
Instead, the workload compiler could run `expand_secrets()` on the entire
rendered container spec as a `Value` tree. This replaces `parse_secret_ref`,
`extract_secret_refs`, and the per-string routing logic in `env.rs` and
`files.rs` with a single tree walk.

The workload compiler gets back `SecretExpansionResult` and:
- `directives` → should be empty (workloads don't use `$secret`)
- `inline_refs` → generates ExternalSecrets via existing ESO builders,
  routes to secretKeyRef (pure refs) or ESO templates (mixed-content)

**LatticePackage (package controller):**

Runs `expand_secrets()` on the values tree. Gets back:
- `directives` → generates ExternalSecrets with key mapping, values tree
  already has the secret names substituted in
- `inline_refs` → resolves from synced K8s Secret `.data`, replaces in
  the values tree before `helm template`

Both call `expand_secrets()` and then feed the results into the same
Cedar authorization and ESO builders.

### What moves where

```
FROM lattice-common::template::renderer:
  parse_secret_ref()        → lattice-secret-template
  parse_secret_ref_inner()  → lattice-secret-template
  extract_secret_refs()     → lattice-secret-template (absorbed into tree walk)
  FileSecretRef             → lattice-secret-template::InlineSecretRef
  SecretVariableRef         → lattice-secret-template::InlineSecretRef
  EsoTemplatedEnvVar        → removed (tree walk handles this)

FROM lattice-workload::pipeline::secrets:
  resolve_single_store()    → lattice-secret-template
  resolve_eso_data()        → lattice-secret-template

STAYS in lattice-workload:
  SecretsCompiler           → still generates ExternalSecrets from resources block
                              but delegates ref parsing to lattice-secret-template

STAYS in lattice-common::template:
  TemplateEngine            → Score ${metadata.*}/${resources.*} rendering
  TemplateRenderer          → orchestrates Score rendering (calls expand_secrets after)
  TemplateContext            → Score template context building
  filters, types, etc.      → unchanged
```

The Score template engine (`${metadata.name}`, `${resources.db.host}`) stays
in `lattice-common::template` — it's specific to the Score spec and
LatticeService. The `$secret` / `${secret.*}` expansion is the piece that
generalizes to any Value tree and belongs in its own crate.

### Crate dependencies

```
lattice-secret-template
  ├── serde_json          (Value tree)
  ├── lattice-secret-provider  (ESO types, build_external_secret)
  └── thiserror           (errors)

lattice-workload
  ├── lattice-secret-template  (expand_secrets, InlineSecretRef)
  ├── lattice-common           (Score templates, CRD types)
  └── ...

lattice-package
  ├── lattice-secret-template  (expand_secrets, SecretDirective)
  ├── lattice-common           (CRD types)
  └── ...
```

---

## Crate Structure

```
crates/
  lattice-secret-template/
    src/
      lib.rs              # expand_secrets(), types
      directive.rs        # $secret directive parsing
      inline.rs           # ${secret.X.Y} string ref parsing
      eso.rs              # resolve_single_store, resolve_eso_data, ESO generation
      error.rs
    Cargo.toml

  lattice-package/
    src/
      lib.rs
      controller.rs       # Reconcile loop, phase transitions
      compiler.rs          # Values resolution, helm template invocation
      helm.rs              # Helm subprocess (pull, template)
      error.rs
    Cargo.toml

  lattice-common/src/crd/
    package.rs             # LatticePackageSpec, LatticePackageStatus CRD
```

The package controller is registered in `lattice-operator/src/main.rs`
alongside the existing service, job, model, and cluster controllers.

---

## Open Questions

1. **Chart caching**: Should charts be cached on a PVC or re-pulled each reconcile?
   Re-pulling is simpler and avoids stale cache bugs. OCI registries are fast.
   Start with re-pull, add caching if it becomes a bottleneck.

2. **CRD installation**: Some charts install CRDs. Should `skipCRDs` default to
   true (safer) or false (more convenient)? Recommend false with a warning in
   status when CRDs are installed.

3. **Resource ownership**: Server-side apply with a field manager gives clean
   ownership semantics. But charts that create cluster-scoped resources (CRDs,
   ClusterRoles) need careful handling on deletion. Recommend tracking created
   resources in status for cleanup.

4. **Quota enforcement**: Packages don't declare explicit resource requests like
   LatticeService. Options: skip quota (packages are admin-controlled), or parse
   rendered Deployment specs to compute demand. Recommend skip for v1, add later.

5. **valuesFrom**: Should we support pulling values from ConfigMaps or Secrets
   directly (like FluxCD's `valuesFrom`)? The `${secret.X.Y}` mechanism already
   covers the secret case. ConfigMap values can be added later if needed.

6. **Migration**: The workload compiler currently works. Migrating it to use
   `lattice-secret-template` can happen incrementally — start by having
   `lattice-package` use the new crate, then refactor `lattice-workload` to
   use it in a follow-up. The old string-level functions can be thin wrappers
   that delegate to the tree walker until fully migrated.
