# Sidecars and Security Context Design

## Executive Summary

This document describes the design for sidecars and security context in LatticeService. The goal is to support advanced use cases (VPN killswitch, privileged containers, init containers) while keeping the happy path API clean and uncluttered.

**Design Principles:**
1. Happy path stays clean - 99% of services never touch security settings
2. Sidecars are just containers - same schema, different section
3. Advanced features are nested and optional - hidden until needed
4. Pod-level settings (sysctls) are separate from container settings

---

## API Overview

### Happy Path (Most Services)

Most services only need containers, resources, and service ports:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
  namespace: prod
spec:
  containers:
    main:
      image: myapp:latest
      variables:
        PORT: "8080"
      volumes:
        /data:
          source: ${resources.data}
  service:
    ports:
      http:
        port: 8080
  resources:
    data:
      type: volume
      params:
        size: 10Gi
```

No sidecars, no security context, no sysctls. Clean and simple.

---

### Advanced: Sidecars

Sidecars use the **same schema as containers**. They're just in a separate section to indicate "infrastructure" vs "application" containers.

```yaml
spec:
  containers:
    main:
      image: myapp:latest

  sidecars:
    logging:
      image: fluent-bit:latest
      volumes:
        /var/log:
          source: ${resources.logs}
```

Sidecars support everything containers support:
- `image`, `command`, `args`
- `variables`
- `volumes`
- `resources` (CPU/memory)
- `readinessProbe`, `livenessProbe`, `startupProbe`

Plus sidecar-specific options:
- `init: true` - Run as init container (runs once before main containers)
- `security` - Security context (see below)

---

### Advanced: Security Context

Security settings are nested under an optional `security` block. This keeps them hidden from users who don't need them.

```yaml
spec:
  containers:
    main:
      image: myapp:latest
      security:                        # Optional, rarely needed
        capabilities: [NET_BIND_SERVICE]
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
```

**Available security settings:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `capabilities` | `[string]` | `[]` | Linux capabilities to add |
| `dropCapabilities` | `[string]` | `[ALL]` | Capabilities to drop (secure default) |
| `privileged` | `bool` | `false` | Run privileged (discouraged) |
| `readOnlyRootFilesystem` | `bool` | `false` | Mount root filesystem read-only |
| `runAsNonRoot` | `bool` | `false` | Require non-root user |
| `runAsUser` | `int` | - | UID to run as |
| `runAsGroup` | `int` | - | GID to run as |
| `allowPrivilegeEscalation` | `bool` | `false` | Allow setuid binaries |

---

### Advanced: Pod-Level Settings

Some settings apply to the entire pod, not individual containers. These go at the spec level:

```yaml
spec:
  # Pod-level settings
  sysctls:
    net.ipv4.conf.all.src_valid_mark: "1"
    net.core.somaxconn: "65535"

  hostNetwork: false      # Use host network namespace
  shareProcessNamespace: false  # Share PID namespace between containers

  containers:
    main:
      image: myapp:latest
```

---

## Complete Example: VPN Killswitch

Here's how nzbget with a wireguard VPN killswitch would look:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: nzbget
  namespace: media
spec:
  # Pod-level: required for wireguard
  sysctls:
    net.ipv4.conf.all.src_valid_mark: "1"

  containers:
    main:
      image: linuxserver/nzbget:latest
      variables:
        PUID: "1000"
        PGID: "1000"
      volumes:
        /config:
          source: ${resources.config}
        /downloads:
          source: ${resources.media-storage}
          path: downloads

  sidecars:
    vpn:
      image: linuxserver/wireguard:latest
      variables:
        PUID: "1000"
        PGID: "1000"
      volumes:
        /config:
          source: ${resources.wg-config}
      security:
        capabilities: [NET_ADMIN, SYS_MODULE]

  service:
    ports:
      http:
        port: 6789

  resources:
    config:
      type: volume
      params:
        size: 1Gi
    media-storage:
      type: volume
      id: media-storage
    wg-config:
      type: volume
      params:
        size: 100Mi
```

**What the compiler generates:**

1. **Pod spec** with:
   - `securityContext.sysctls` from spec.sysctls
   - Main container from `containers.main`
   - Sidecar container from `sidecars.vpn` with security context

2. **Wireguard container** security context:
   ```yaml
   securityContext:
     capabilities:
       add: [NET_ADMIN, SYS_MODULE]
       drop: [ALL]
   ```

3. The killswitch logic is handled by the wireguard image's entrypoint - we just provide the capabilities it needs.

---

## Complete Example: Init Container

Init containers run once before the main containers start:

```yaml
spec:
  containers:
    main:
      image: myapp:latest
      volumes:
        /data:
          source: ${resources.data}

  sidecars:
    setup-permissions:
      image: busybox:latest
      init: true                    # Makes this an init container
      command: ["sh", "-c"]
      args: ["chown -R 1000:1000 /data"]
      volumes:
        /data:
          source: ${resources.data}
      security:
        runAsUser: 0                # Run as root to fix permissions
```

---

## Schema Definition

### LatticeServiceSpec (updated)

```rust
pub struct LatticeServiceSpec {
    // Existing fields
    pub containers: BTreeMap<String, ContainerSpec>,
    pub resources: BTreeMap<String, ResourceSpec>,
    pub service: Option<ServicePortsSpec>,
    pub replicas: ReplicaSpec,
    pub deploy: DeploySpec,
    pub ingress: Option<IngressSpec>,

    // New fields
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sidecars: BTreeMap<String, SidecarSpec>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctls: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,
}
```

### SidecarSpec

Sidecars extend ContainerSpec with sidecar-specific options:

```rust
/// Sidecar container specification
///
/// Identical to ContainerSpec but with additional sidecar-specific options.
/// Sidecars are infrastructure containers (VPN, logging, metrics) that support
/// the main application containers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarSpec {
    // All ContainerSpec fields
    pub image: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, VariableValue>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ContainerResources>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,

    // Sidecar-specific fields

    /// Run as init container (runs once before main containers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Security context for the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityContext>,
}
```

### SecurityContext

```rust
/// Container security context
///
/// Controls Linux security settings for a container. All fields are optional
/// with secure defaults. Most services never need to set these.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContext {
    /// Linux capabilities to add (e.g., NET_ADMIN, SYS_MODULE)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Capabilities to drop (default: [ALL] for security)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_capabilities: Option<Vec<String>>,

    /// Run container in privileged mode (strongly discouraged)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Mount root filesystem as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,

    /// Require the container to run as a non-root user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,

    /// UID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,

    /// GID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,

    /// Allow privilege escalation (setuid binaries)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
}
```

---

## Compilation

### Container Security Context

The compiler generates Kubernetes security context from our schema:

```rust
fn compile_security_context(security: &SecurityContext) -> k8s::SecurityContext {
    let mut ctx = k8s::SecurityContext::default();

    // Capabilities
    if !security.capabilities.is_empty() || security.drop_capabilities.is_some() {
        let mut caps = k8s::Capabilities::default();

        if !security.capabilities.is_empty() {
            caps.add = Some(security.capabilities.clone());
        }

        // Default: drop ALL capabilities for security
        caps.drop = Some(
            security.drop_capabilities
                .clone()
                .unwrap_or_else(|| vec!["ALL".to_string()])
        );

        ctx.capabilities = Some(caps);
    }

    ctx.privileged = security.privileged;
    ctx.read_only_root_filesystem = security.read_only_root_filesystem;
    ctx.run_as_non_root = security.run_as_non_root;
    ctx.run_as_user = security.run_as_user;
    ctx.run_as_group = security.run_as_group;
    ctx.allow_privilege_escalation = security.allow_privilege_escalation;

    ctx
}
```

### Pod Security Context

Pod-level settings go in the pod's security context:

```rust
fn compile_pod_security_context(spec: &LatticeServiceSpec) -> k8s::PodSecurityContext {
    let mut ctx = k8s::PodSecurityContext::default();

    // Sysctls
    if !spec.sysctls.is_empty() {
        ctx.sysctls = Some(
            spec.sysctls
                .iter()
                .map(|(name, value)| k8s::Sysctl {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect()
        );
    }

    ctx
}
```

### Init vs Sidecar Containers

```rust
fn compile_containers(spec: &LatticeServiceSpec) -> (Vec<Container>, Vec<Container>) {
    let mut init_containers = Vec::new();
    let mut sidecar_containers = Vec::new();

    for (name, sidecar) in &spec.sidecars {
        let container = compile_container(name, sidecar);

        if sidecar.init.unwrap_or(false) {
            init_containers.push(container);
        } else {
            sidecar_containers.push(container);
        }
    }

    (init_containers, sidecar_containers)
}
```

---

## Security Considerations

### Default Security Posture

By default, all containers:
- Drop ALL capabilities (secure default)
- Don't run privileged
- Allow privilege escalation is false
- No special sysctls

### Capability Restrictions

Some capabilities are sensitive and may require additional validation:
- `SYS_ADMIN` - Almost equivalent to root
- `NET_RAW` - Can craft arbitrary packets
- `SYS_PTRACE` - Can trace other processes

Consider adding validation that warns or requires explicit approval for sensitive capabilities.

### Privileged Mode

Privileged mode (`privileged: true`) should be strongly discouraged. It:
- Gives full access to host devices
- Bypasses all security mechanisms
- Should almost never be needed

Consider adding a cluster-level policy that can block privileged containers.

### Sysctl Restrictions

Not all sysctls are safe. Kubernetes divides them into:
- **Safe sysctls**: Can be set without restrictions
- **Unsafe sysctls**: Require explicit cluster-level allowlisting

The compiler should validate sysctls against the cluster's allowed list.

---

## Testing Strategy

### Unit Tests

1. **Schema parsing**: Verify YAML parses correctly with all optional fields
2. **Security context compilation**: Verify K8s security context is generated correctly
3. **Init container detection**: Verify `init: true` creates init containers
4. **Default values**: Verify secure defaults are applied

### Integration Tests

1. **Sidecar ordering**: Verify sidecars start alongside main containers
2. **Init container ordering**: Verify init containers complete before main
3. **Capability enforcement**: Verify capabilities are actually applied
4. **Sysctl application**: Verify sysctls are set in the pod

### E2E Tests

1. **VPN killswitch**: Deploy nzbget with wireguard, verify traffic routing
2. **Init container permissions**: Verify init container can modify volumes
3. **Security restrictions**: Verify containers can't exceed their security context

---

## Migration Path

### Phase 1: Add Schema (Non-Breaking)

Add new optional fields to LatticeServiceSpec:
- `sidecars`
- `sysctls`
- `host_network`
- `share_process_namespace`

Add `security` field to ContainerSpec (also used by SidecarSpec).

Existing services continue to work unchanged.

### Phase 2: Compiler Support

Update the compiler to:
- Generate init containers from sidecars with `init: true`
- Generate sidecar containers alongside main containers
- Apply security context to containers
- Apply pod-level settings

### Phase 3: Validation

Add validation for:
- Sensitive capabilities (warn or require approval)
- Privileged mode (warn strongly)
- Unsafe sysctls (check cluster allowlist)

---

## Files to Modify

| File | Action | Description |
|------|--------|-------------|
| `crates/lattice-common/src/crd/service.rs` | Modify | Add SidecarSpec, SecurityContext, pod-level fields |
| `crates/lattice-service/src/workload/mod.rs` | Modify | Compile sidecars and security context |
| `crates/lattice-service/src/workload/container.rs` | Modify | Add security context compilation |
| `crates/lattice-service/src/compiler/mod.rs` | Modify | Include sidecars in compiled output |
| `examples/media-server/nzbget.yaml` | Modify | Add VPN sidecar example |

---

## Appendix: Common Sidecar Patterns

### VPN/Wireguard

```yaml
sidecars:
  vpn:
    image: linuxserver/wireguard:latest
    volumes:
      /config:
        source: ${resources.wg-config}
    security:
      capabilities: [NET_ADMIN, SYS_MODULE]
```

Required pod-level: `sysctls: { net.ipv4.conf.all.src_valid_mark: "1" }`

### Cloudflared Tunnel

```yaml
sidecars:
  tunnel:
    image: cloudflare/cloudflared:latest
    args: ["tunnel", "--no-autoupdate", "run"]
    variables:
      TUNNEL_TOKEN: ${secrets.cloudflare-token}
```

### Fluent Bit Logging

```yaml
sidecars:
  logging:
    image: fluent/fluent-bit:latest
    volumes:
      /var/log:
        source: ${resources.app-logs}
        readOnly: true
      /fluent-bit/etc:
        source: ${resources.fluent-config}
```

### OAuth2 Proxy

```yaml
sidecars:
  auth:
    image: quay.io/oauth2-proxy/oauth2-proxy:latest
    args:
      - --http-address=0.0.0.0:4180
      - --upstream=http://localhost:8080
    variables:
      OAUTH2_PROXY_CLIENT_ID: ${secrets.oauth-client-id}
      OAUTH2_PROXY_CLIENT_SECRET: ${secrets.oauth-client-secret}
```

### Permissions Init Container

```yaml
sidecars:
  fix-permissions:
    image: busybox:latest
    init: true
    command: ["sh", "-c", "chown -R 1000:1000 /data && chmod -R 755 /data"]
    volumes:
      /data:
        source: ${resources.data}
    security:
      runAsUser: 0
```
