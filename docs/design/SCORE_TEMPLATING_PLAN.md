# Score-Compatible Templating Implementation Plan

## Overview

Implement Score-compatible `${...}` placeholder syntax using minijinja's custom syntax configuration. This enables Lattice to accept Score-native workload definitions while providing Lattice-specific extensions.

## Key Design Decisions

### 1. Syntax: Score's `${...}` via minijinja custom_syntax

```rust
use minijinja::syntax::SyntaxConfig;

let syntax = SyntaxConfig::builder()
    .variable_delimiters("${", "}")
    .block_delimiters("{%", "%}")      // Keep for Lattice extensions (conditionals, loops)
    .comment_delimiters("{#", "#}")
    .build()
    .unwrap();

let mut env = Environment::new();
env.set_syntax(syntax);
```

**Why this approach:**
- Direct Score compatibility: `${resources.db.host}` works as-is
- Superset capability: `{% if %}` blocks for advanced use cases Score doesn't support
- Single parser handles both Score-native and Lattice-extended templates

### 2. Shell Escaping (Addressing Design Doc Concern)

The original design doc rejected `${}` due to shell conflicts. Our solution:

```yaml
# In Score/Lattice YAML (not in shell) - works fine
variables:
  DB_HOST: "${resources.postgres.host}"

# In shell heredocs - use single quotes to prevent expansion
cat <<'EOF'
host: ${resources.postgres.host}
EOF

# Or escape the dollar sign
cat <<EOF
host: \${resources.postgres.host}
EOF
```

**Documentation will emphasize:** Score files are YAML, not shell scripts. Shell conflicts only matter when embedding in shell heredocs, which is rare.

## Namespace Mapping: Score → Lattice

| Score Placeholder | Lattice Resolution |
|-------------------|-------------------|
| `${metadata.name}` | `LatticeService.metadata.name` |
| `${metadata.annotations.KEY}` | `LatticeService.metadata.annotations[KEY]` |
| `${resources.NAME.FIELD}` | Resolved from `ResourceSpec` + provisioner outputs |
| `${resources.NAME}` | Resource identifier (for cross-workload sharing) |

### Resource Output Resolution

```rust
pub struct ResourceOutputs {
    /// Provisioner-provided outputs (from status or external)
    outputs: HashMap<String, Value>,
}

// Example: PostgreSQL resource
// Declared: resources.postgres.type = "postgres"
// Resolved outputs:
//   ${resources.postgres.host} → "postgres-xyz.svc.cluster.local"
//   ${resources.postgres.port} → 5432
//   ${resources.postgres.connection_string} → "postgres://..."
//   ${resources.postgres.username} → from secret ref
```

## Implementation Phases

### Phase 1: Core Template Engine (Week 1)

**Files to create:**
```
src/template/
├── mod.rs           # Public API
├── engine.rs        # TemplateEngine with Score syntax
├── context.rs       # TemplateContext builder
├── error.rs         # TemplateError types
└── types.rs         # TemplateString, StaticString
```

**Core implementation:**

```rust
// src/template/engine.rs
use minijinja::{Environment, syntax::SyntaxConfig};

pub struct TemplateEngine {
    env: Environment<'static>,
}

impl TemplateEngine {
    pub fn new() -> Self {
        let syntax = SyntaxConfig::builder()
            .variable_delimiters("${", "}")
            .block_delimiters("{%", "%}")
            .comment_delimiters("{#", "#}")
            .build()
            .expect("valid syntax config");

        let mut env = Environment::new();
        env.set_syntax(syntax);
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);

        // Register filters
        env.add_filter("default", filters::default_filter);
        env.add_filter("base64_encode", filters::base64_encode);
        env.add_filter("base64_decode", filters::base64_decode);
        env.add_filter("required", filters::required);

        Self { env }
    }

    pub fn render(&self, template: &str, ctx: &TemplateContext) -> Result<String, TemplateError> {
        self.env
            .render_str(template, ctx.to_minijinja_value())
            .map_err(TemplateError::from)
    }
}
```

**Context structure (Score-compatible):**

```rust
// src/template/context.rs
use minijinja::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TemplateContext {
    /// Score: ${metadata.name}, ${metadata.annotations.KEY}
    pub metadata: MetadataContext,

    /// Score: ${resources.NAME.FIELD}
    /// Lattice resolves from ResourceSpec + provisioner outputs
    pub resources: HashMap<String, ResourceOutputs>,

    /// Lattice extension: ${cluster.name}, ${cluster.environment}
    pub cluster: HashMap<String, Value>,

    /// Lattice extension: ${env.KEY} from LatticeEnvironment.spec.config
    pub env: HashMap<String, Value>,

    /// Lattice extension: ${config.KEY} from LatticeServiceConfig
    pub config: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct MetadataContext {
    pub name: String,
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ResourceOutputs {
    /// Standard outputs based on resource type
    pub host: Option<String>,
    pub port: Option<u16>,
    pub url: Option<String>,
    pub connection_string: Option<String>,

    /// Additional outputs from provisioner
    pub extra: HashMap<String, Value>,
}
```

### Phase 2: CRD Integration (Week 2)

**Update `LatticeServiceSpec` to use template types:**

```rust
// src/crd/service.rs changes

/// String that may contain ${...} placeholders
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TemplateString(String);

/// String that rejects ${...} placeholders (for names, keys)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String")]
pub struct StaticString(String);

pub struct ContainerSpec {
    // name stays StaticString - no templating in identifiers
    pub name: StaticString,

    // image supports templating
    pub image: TemplateString,

    // env values support templating
    pub variables: BTreeMap<StaticString, TemplateString>,

    // ... etc
}
```

### Phase 3: Resource Provisioner Interface (Week 3)

**Define how resources provide outputs:**

```rust
// src/template/provisioner.rs

/// Trait for resource types that can provide template outputs
pub trait ResourceProvisioner: Send + Sync {
    /// Resource type this provisioner handles
    fn resource_type(&self) -> &str;

    /// Resolve outputs for a resource
    async fn resolve_outputs(
        &self,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, ProvisionerError>;
}

/// Built-in provisioner for "service" type (other LatticeServices)
pub struct ServiceProvisioner;

impl ResourceProvisioner for ServiceProvisioner {
    fn resource_type(&self) -> &str { "service" }

    async fn resolve_outputs(
        &self,
        resource: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, ProvisionerError> {
        // Resolve from service graph
        let service_name = resource.id.as_ref()
            .ok_or(ProvisionerError::MissingId)?;

        let endpoint = ctx.service_graph
            .get_endpoint(service_name)
            .ok_or(ProvisionerError::ServiceNotFound(service_name.clone()))?;

        Ok(ResourceOutputs {
            host: Some(endpoint.host),
            port: Some(endpoint.port),
            url: Some(endpoint.url),
            ..Default::default()
        })
    }
}

/// Built-in provisioner for "external-service" type
pub struct ExternalServiceProvisioner;

/// Future: Crossplane provisioner for postgres, redis, etc.
pub struct CrossplaneProvisioner;
```

### Phase 4: Workload Compiler Integration (Week 4)

**Render templates during workload generation:**

```rust
// src/workload/mod.rs changes

impl WorkloadCompiler {
    pub async fn compile(
        &self,
        service: &LatticeService,
        ctx: &CompilerContext,
    ) -> Result<GeneratedWorkloads, CompilerError> {
        // 1. Build template context
        let template_ctx = self.build_template_context(service, ctx).await?;

        // 2. Validate all templates before rendering
        let validation = self.validate_templates(service, &template_ctx)?;
        if !validation.errors.is_empty() {
            return Err(CompilerError::TemplateValidation(validation.errors));
        }

        // 3. Render templates
        let rendered = self.render_service(service, &template_ctx)?;

        // 4. Generate K8s resources from rendered spec
        self.generate_resources(&rendered, ctx)
    }

    async fn build_template_context(
        &self,
        service: &LatticeService,
        ctx: &CompilerContext,
    ) -> Result<TemplateContext, CompilerError> {
        let mut resources = HashMap::new();

        // Resolve outputs for each declared resource
        for (name, spec) in &service.spec.resources {
            let provisioner = self.get_provisioner(&spec.type_)?;
            let outputs = provisioner.resolve_outputs(spec, &ctx.provisioner_ctx).await?;
            resources.insert(name.clone(), outputs);
        }

        Ok(TemplateContext {
            metadata: MetadataContext {
                name: service.name_any(),
                annotations: service.annotations().clone(),
            },
            resources,
            cluster: ctx.cluster_context.clone(),
            env: ctx.environment_config.clone(),
            config: ctx.service_config.clone(),
        })
    }
}
```

## Cargo.toml Change

```toml
# Update minijinja to enable custom syntax
minijinja = { version = "2", features = ["custom_syntax"] }
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_variable_syntax() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext {
            metadata: MetadataContext {
                name: "my-service".into(),
                annotations: HashMap::new(),
            },
            resources: [(
                "db".into(),
                ResourceOutputs {
                    host: Some("postgres.svc".into()),
                    port: Some(5432),
                    ..Default::default()
                },
            )].into(),
            ..Default::default()
        };

        // Score-style variable
        assert_eq!(
            engine.render("${metadata.name}", &ctx).unwrap(),
            "my-service"
        );

        // Score-style resource reference
        assert_eq!(
            engine.render("${resources.db.host}:${resources.db.port}", &ctx).unwrap(),
            "postgres.svc:5432"
        );
    }

    #[test]
    fn test_lattice_extension_blocks() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext {
            config: [("debug".into(), Value::from(true))].into(),
            ..Default::default()
        };

        // Lattice extension: conditionals
        let template = r#"{% if config.debug %}--debug{% endif %}"#;
        assert_eq!(engine.render(template, &ctx).unwrap(), "--debug");
    }

    #[test]
    fn test_undefined_variable_strict() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::default();

        let result = engine.render("${undefined.var}", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_static_string_rejects_templates() {
        let result: Result<StaticString, _> = "my-${name}".to_string().try_into();
        assert!(result.is_err());

        let result: Result<StaticString, _> = "my-service".to_string().try_into();
        assert!(result.is_ok());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_service_rendering() {
    let service = LatticeService {
        metadata: ObjectMeta {
            name: Some("api".into()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers: [(
                "main".into(),
                ContainerSpec {
                    image: TemplateString("${cluster.registry}/api:${config.version}".into()),
                    variables: [
                        ("DB_HOST".into(), TemplateString("${resources.postgres.host}".into())),
                        ("DB_PORT".into(), TemplateString("${resources.postgres.port}".into())),
                    ].into(),
                    ..Default::default()
                },
            )].into(),
            resources: [(
                "postgres".into(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: Some("postgres".into()),
                    ..Default::default()
                },
            )].into(),
            ..Default::default()
        },
        ..Default::default()
    };

    let compiler = WorkloadCompiler::new(/* ... */);
    let ctx = CompilerContext {
        cluster_context: [("registry".into(), "gcr.io/my-project".into())].into(),
        service_config: [("version".into(), "1.2.3".into())].into(),
        // postgres service exists in service graph
        ..Default::default()
    };

    let result = compiler.compile(&service, &ctx).await.unwrap();

    // Verify rendered container
    let deployment = result.deployment;
    let container = &deployment.spec.template.spec.containers[0];
    assert_eq!(container.image, "gcr.io/my-project/api:1.2.3");
    assert_eq!(
        container.env.iter().find(|e| e.name == "DB_HOST").unwrap().value,
        Some("postgres.svc.cluster.local".into())
    );
}
```

## Score Compatibility Matrix

| Score Feature | Lattice Support | Notes |
|---------------|-----------------|-------|
| `${metadata.name}` | ✅ Full | Direct mapping |
| `${metadata.annotations.KEY}` | ✅ Full | Direct mapping |
| `${resources.NAME.FIELD}` | ✅ Full | Via ResourceProvisioner |
| `${resources.NAME}` (ID only) | ✅ Full | Returns resource identifier |
| `$${...}` escaping | ✅ Full | Minijinja handles |
| Nested properties | ✅ Full | `${resources.db.config.pool_size}` |

## Lattice Extensions (Superset)

| Feature | Syntax | Description |
|---------|--------|-------------|
| Cluster context | `${cluster.name}`, `${cluster.environment}` | Cluster metadata |
| Environment config | `${env.log_level}` | From LatticeEnvironment |
| Service config | `${config.version}` | From LatticeServiceConfig |
| Conditionals | `{% if config.debug %}...{% endif %}` | Advanced templating |
| Loops | `{% for item in config.items %}...{% endfor %}` | List iteration |
| Filters | `${value \| default("fallback")}` | Value transformation |

## Migration Notes

The existing bootstrap script in `src/provider/mod.rs` uses `{{ }}` syntax. Options:
1. **Keep separate**: Bootstrap uses `{{ }}`, Score templates use `${}`
2. **Migrate**: Update bootstrap to use `${}` for consistency

**Recommendation:** Keep separate. Bootstrap scripts are internal implementation detail, not user-facing. No migration needed.

## Files to Modify

1. `Cargo.toml` - Add `custom_syntax` feature to minijinja
2. `src/lib.rs` - Export template module
3. `src/crd/service.rs` - Add TemplateString/StaticString types
4. `src/workload/mod.rs` - Integrate template rendering

## Files to Create

1. `src/template/mod.rs` - Module exports
2. `src/template/engine.rs` - TemplateEngine implementation
3. `src/template/context.rs` - TemplateContext and builders
4. `src/template/error.rs` - Error types
5. `src/template/types.rs` - TemplateString, StaticString
6. `src/template/filters.rs` - Custom filters
7. `src/template/provisioner.rs` - ResourceProvisioner trait

## Success Criteria

1. Score YAML with `${...}` placeholders parses and renders correctly
2. Undefined variables produce clear errors with field context
3. Static fields (names, keys) reject template syntax at parse time
4. Resource outputs resolve from service graph and provisioners
5. All existing tests pass
6. New template tests achieve 90%+ coverage
