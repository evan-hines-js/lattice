# Design: LatticeService workloadRef Patch Mode

> **Status:** Future work - implement after hardening current Score-like implementation

## Summary

Add an **optional** `workloadRef` field to LatticeService. When present, the same Score-like spec is interpreted as a strategic merge patch on an existing Deployment rather than creating a new one.

## Dual Mode Behavior

```yaml
# Mode 1: Ownership (current) - LatticeService creates Deployment
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  containers:
    main:
      image: nginx:latest
      variables:
        REDIS_HOST: "${service.config.redis.host}"
  resources:
    auth-service:
      direction: outbound
```

```yaml
# Mode 2: Patch (future) - LatticeService patches existing Deployment
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api-gateway
spec:
  workloadRef:
    kind: Deployment
    name: existing-nginx
    namespace: default

  # Same spec, interpreted as strategic merge patch
  containers:
    main:
      variables:
        REDIS_HOST: "${service.config.redis.host}"
  resources:
    auth-service:
      direction: outbound
```

**Key insight:** Same spec shape, different interpretation. No separate "patch" field.

## WorkloadRef Type

```rust
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadRef {
    /// Kind of workload (only "Deployment" supported in v1)
    pub kind: String,
    /// Name of the workload
    pub name: String,
    /// Namespace of the workload
    pub namespace: String,
}
```

## Implementation Components

### 1. Mutating Webhook

When workloadRef is set, a mutating admission webhook intercepts Deployment create/update:

1. Webhook receives Deployment admission
2. Finds matching LatticeService by workloadRef (kind + name + namespace)
3. Converts ContainerSpec to JSON Patch operations
4. Resolves template variables (`${service.config.x}`)
5. Applies patch to Deployment
6. Adds `lattice.dev/service` label

### 2. Controller Changes

```rust
async fn reconcile_service(service: Arc<LatticeService>, ctx: Arc<Context>) -> Result<Action> {
    if service.spec.is_patch_mode() {
        // Patch mode: webhook handles workload, controller only does policies
        reconcile_patch_mode(&service, &ctx).await
    } else {
        // Ownership mode: controller creates/manages the workload
        reconcile_ownership_mode(&service, &ctx).await
    }
}
```

### 3. Files to Create

| File | Purpose |
|------|---------|
| `src/webhook/mod.rs` | Module root |
| `src/webhook/handler.rs` | AdmissionReview handler |
| `src/webhook/patch.rs` | Strategic merge patch logic |
| `src/infra/webhook.rs` | MutatingWebhookConfiguration generator |

### 4. Files to Modify

| File | Changes |
|------|---------|
| `src/crd/service.rs` | Add `WorkloadRef`, add `workload_ref` to spec |
| `src/controller/service.rs` | Branch on `is_patch_mode()` |
| `src/bootstrap/mod.rs` | Add `/mutate/deployments` route |
| `src/lib.rs` | Add `pub mod webhook;` |

## Validation Rules

**When workloadRef is set:**
- `workloadRef.kind` must be "Deployment" (v1)
- `workloadRef.name` required
- `workloadRef.namespace` required
- Referenced Deployment must exist
- `containers` field is optional (patch only what's specified)

**When workloadRef is NOT set:**
- `containers` must have at least one container
- At least one container must have `image` set

## Status Reporting

```yaml
status:
  phase: Ready
  mode: Patch  # or "Ownership"
  workloadRef:
    resolved: true
    name: existing-nginx
    namespace: default
```

## Benefits

- Works with existing Helm charts, Kustomize, GitOps
- Same familiar Score-like spec
- One resource, two modes
- Template variable injection still works
- No awkward separate "patch" field
