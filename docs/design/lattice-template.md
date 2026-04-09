# lattice-template Design

## Problem

Template expansion is scattered across three locations with an unnecessary
minijinja dependency:

- `lattice-common::template` — Score `${...}` rendering via minijinja,
  secret ref parsing, ESO Go template generation, types
- `lattice-workload::pipeline::secrets` — ExternalSecret generation,
  `resolve_single_store`, `resolve_eso_data`, `SecretRef`
- `lattice-workload::pipeline::eso_templated` — mixed-content env var
  ESO templating

minijinja brings a full Jinja2 engine (`{% if %}`, `{% for %}`, filters)
but nothing in the codebase uses it outside tests. All real usage is
`${dotted.path}` lookups and `${secret.X.Y}` references. The engine is
overkill and the real operations — tree walking, secret directive handling,
context-based substitution — are what should be first-class.

## Goals

- One crate (`lattice-template`) that operates on `serde_json::Value` trees
- Drop minijinja — implement `${dotted.path}` resolution directly
- Unify `${secret.X.Y}` inline refs and `$secret` directives in a single tree walk
- Reusable by both LatticeService (workload compilation) and LatticePackage (helm values)
- Generate ESO ExternalSecrets from collected secret references
- Cedar authorization input from collected secret references

## Non-Goals

- Full Jinja2 compatibility (conditionals, loops, filters)
- YAML parsing (input is already `serde_json::Value`)

---

## Core API

### Tree expansion

```rust
/// Walk a Value tree, expanding all template expressions in place.
///
/// In a single recursive pass:
/// - String values containing `${...}` are resolved from the context
/// - `${secret.X.Y}` references are collected (not resolved — caller decides)
/// - Objects with a `$secret` key are replaced with Value::String(secret_name)
///   and collected as directives
/// - `$${...}` escape syntax produces literal `${...}`
pub fn expand(
    value: &mut Value,
    ctx: &TemplateContext,
    opts: &ExpandOptions,
) -> Result<Expansion, TemplateError>;
```

### Context

The context is a flat map of dotted paths to values. No nested HashMap
gymnastics — just string lookups:

```rust
/// Template context for ${...} resolution.
///
/// Stores values as dotted paths: "metadata.name" → "my-service",
/// "resources.db.host" → "postgres.svc", "cluster.name" → "prod".
pub struct TemplateContext {
    values: BTreeMap<String, String>,
}

impl TemplateContext {
    pub fn builder() -> TemplateContextBuilder { ... }

    /// Resolve a dotted path like "metadata.name" or "resources.db.host"
    pub fn resolve(&self, path: &str) -> Option<&str> {
        self.values.get(path).map(|s| s.as_str())
    }
}

impl TemplateContextBuilder {
    /// Add a single value: ctx.set("metadata.name", "my-service")
    pub fn set(mut self, path: &str, value: &str) -> Self { ... }

    /// Add a group: ctx.group("cluster", [("name", "prod"), ("env", "production")])
    /// Stores as "cluster.name" → "prod", "cluster.env" → "production"
    pub fn group(mut self, prefix: &str, pairs: impl IntoIterator<Item = (&str, &str)>) -> Self { ... }

    /// Add resource outputs: ctx.resource("db", [("host", "pg.svc"), ("port", "5432")])
    /// Stores as "resources.db.host" → "pg.svc", "resources.db.port" → "5432"
    pub fn resource(mut self, name: &str, outputs: impl IntoIterator<Item = (&str, &str)>) -> Self { ... }
}
```

### Expansion result

```rust
/// Result of expanding a Value tree.
pub struct Expansion {
    /// $secret directives found and replaced with secret names.
    pub directives: Vec<SecretDirective>,

    /// ${secret.X.Y} references found in string values.
    /// Grouped by the string they appeared in.
    pub inline_refs: Vec<InlineSecretRef>,
}

/// A $secret directive extracted from the tree.
pub struct SecretDirective {
    /// Deterministic name for the generated K8s Secret
    pub secret_name: String,
    /// Dotted path in the tree where this was found (e.g., "auth.existingSecret")
    pub path: String,
    /// Remote key in the secret store (the `id` field)
    pub id: String,
    /// ClusterSecretStore name
    pub provider: String,
    /// Key mapping: target key (K8s Secret) → source key (store).
    /// Empty = passthrough all keys.
    pub keys: BTreeMap<String, String>,
}

/// A ${secret.X.Y} reference found in a string value.
pub struct InlineSecretRef {
    /// Dotted path in the tree (e.g., "containers.main.env.DB_URL")
    pub path: String,
    /// Resource name (X in ${secret.X.Y})
    pub resource_name: String,
    /// Key (Y in ${secret.X.Y})
    pub key: String,
    /// ESO-safe data key for Go template references
    pub eso_data_key: String,
}
```

### Options

```rust
pub struct ExpandOptions {
    /// How to handle ${secret.X.Y} in strings.
    pub secret_mode: SecretMode,
    /// Prefix for generated secret names from $secret directives.
    /// Typically the resource name (e.g., "redis-prod").
    pub name_prefix: String,
}

pub enum SecretMode {
    /// Collect refs but leave ${secret.X.Y} in the string as-is.
    /// Caller will resolve them later (e.g., read from K8s Secret .data).
    Collect,
    /// Replace ${secret.X.Y} with ESO Go template syntax: {{ .X_Y }}
    /// For generating ESO ExternalSecret templates.
    EsoTemplate,
    /// Replace ${secret.X.Y} with actual values from a provided map.
    /// For resolving secrets in-memory before helm template.
    Resolve(BTreeMap<String, BTreeMap<String, String>>),
    // key: resource_name, value: key→value map
}
```

---

## String expansion algorithm

For each string value in the tree:

```
Input:  "postgres://${secret.db.user}:${secret.db.pass}@${resources.db.host}"
                     ^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^      ^^^^^^^^^^^^^^^^^^^^
                     secret ref       secret ref          context lookup

1. Scan for ${...} patterns
2. For each match:
   a. Starts with "secret." → secret ref, handle per SecretMode
   b. Otherwise → look up in TemplateContext, substitute
   c. $${...} → emit literal ${...} (escape)
3. Unresolved non-secret paths → error (strict mode)
```

No regex. Single-pass left-to-right scan, same as the current
`extract_secret_refs` but generalized to also resolve context lookups.

```rust
fn expand_string(
    s: &str,
    ctx: &TemplateContext,
    secret_mode: &SecretMode,
    path: &str,
    refs: &mut Vec<InlineSecretRef>,
) -> Result<String, TemplateError> {
    let mut result = String::with_capacity(s.len());
    let mut remaining = s;

    while let Some(start) = remaining.find("${") {
        // Check for escape: $${
        if start > 0 && remaining.as_bytes()[start - 1] == b'$' {
            result.push_str(&remaining[..start - 1]); // everything before the $$
            // Find closing } and emit literal ${...}
            if let Some(end) = remaining[start + 2..].find('}') {
                result.push_str(&remaining[start..start + 2 + end + 1]);
                remaining = &remaining[start + 2 + end + 1..];
            } else {
                result.push_str(&remaining[start..]);
                remaining = "";
            }
            continue;
        }

        result.push_str(&remaining[..start]);

        let after = &remaining[start + 2..];
        let end = after.find('}').ok_or_else(|| {
            TemplateError::syntax(format!("unclosed ${{}} at path '{}'", path))
        })?;
        let expr = &after[..end];
        remaining = &after[end + 1..];

        if let Some(inner) = expr.strip_prefix("secret.") {
            // Secret reference
            let (resource, key, eso_key) = parse_secret_inner(inner)?;
            refs.push(InlineSecretRef { path: path.into(), resource_name: resource.clone(), key: key.clone(), eso_data_key: eso_key.clone() });

            match secret_mode {
                SecretMode::Collect => {
                    // Leave as-is for caller to resolve
                    result.push_str(&format!("${{secret.{}}}", inner));
                }
                SecretMode::EsoTemplate => {
                    result.push_str(&format!("{{{{ .{} }}}}", eso_key));
                }
                SecretMode::Resolve(secrets) => {
                    let val = secrets.get(&resource)
                        .and_then(|m| m.get(&key))
                        .ok_or_else(|| TemplateError::unresolved_secret(&resource, &key, path))?;
                    result.push_str(val);
                }
            }
        } else {
            // Context lookup
            let value = ctx.resolve(expr).ok_or_else(|| {
                TemplateError::unresolved(expr, path)
            })?;
            result.push_str(value);
        }
    }

    result.push_str(remaining);
    Ok(result)
}
```

---

## Tree walk algorithm

```rust
fn walk(
    value: &mut Value,
    ctx: &TemplateContext,
    opts: &ExpandOptions,
    path: &str,
    result: &mut Expansion,
) -> Result<(), TemplateError> {
    match value {
        Value::String(s) => {
            if !s.contains("${") {
                return Ok(()); // fast path: no templates
            }
            let expanded = expand_string(s, ctx, &opts.secret_mode, path, &mut result.inline_refs)?;
            *s = expanded;
        }

        Value::Object(map) => {
            // Check for $secret directive
            if map.contains_key("$secret") {
                let directive = parse_secret_directive(map, path, &opts.name_prefix)?;
                *value = Value::String(directive.secret_name.clone());
                result.directives.push(directive);
                return Ok(());
            }

            // Recurse into children
            let keys: Vec<_> = map.keys().cloned().collect();
            for key in keys {
                let child_path = if path.is_empty() { key.clone() } else { format!("{}.{}", path, key) };
                if let Some(child) = map.get_mut(&key) {
                    walk(child, ctx, opts, &child_path, result)?;
                }
            }
        }

        Value::Array(arr) => {
            for (i, child) in arr.iter_mut().enumerate() {
                let child_path = format!("{}[{}]", path, i);
                walk(child, ctx, opts, &child_path, result)?;
            }
        }

        _ => {} // numbers, bools, null — leave as-is
    }
    Ok(())
}
```

---

## ESO generation helpers

These move from `lattice-workload::pipeline::secrets` into `lattice-template`:

```rust
/// Validate all inline refs in a group come from the same ClusterSecretStore.
pub fn resolve_single_store(
    refs: &[InlineSecretRef],
    secret_refs: &BTreeMap<String, SecretRef>,
    context: &str,
) -> Result<String, TemplateError>;

/// Convert InlineSecretRefs into ESO ExternalSecretData entries.
pub fn resolve_eso_data(
    refs: &[InlineSecretRef],
    secret_refs: &BTreeMap<String, SecretRef>,
    context: &str,
) -> Result<Vec<ExternalSecretData>, TemplateError>;

/// Generate an ExternalSecret from a $secret directive.
pub fn directive_to_external_secret(
    directive: &SecretDirective,
    namespace: &str,
) -> ExternalSecret;

/// Existing SecretRef type — reference to a synced K8s Secret.
pub struct SecretRef {
    pub secret_name: String,
    pub remote_key: String,
    pub keys: Option<Vec<String>>,
    pub store_name: String,
}
```

---

## How each consumer uses it

### LatticeService (workload compiler)

Today the workload compiler calls `TemplateRenderer::render_containers()`
which uses minijinja per-string, then separately handles secret refs.
After migration:

```rust
// 1. Build context (same data, simpler API)
let ctx = TemplateContext::builder()
    .set("metadata.name", &service.name)
    .group("cluster", [("name", &cluster_name), ("environment", &env)])
    .resource("db", [("host", "pg.svc"), ("port", "5432")])
    .build();

// 2. Serialize the workload spec containers to a Value tree
let mut tree = serde_json::to_value(&spec.containers)?;

// 3. Expand everything in one pass
let expansion = lattice_template::expand(&mut tree, &ctx, &ExpandOptions {
    secret_mode: SecretMode::EsoTemplate,  // replace ${secret.*} with {{ .key }}
    name_prefix: service_name.into(),
})?;

// 4. Deserialize back to typed containers
let containers: BTreeMap<String, ContainerSpec> = serde_json::from_value(tree)?;

// 5. Use expansion.inline_refs to generate ExternalSecrets
// 6. Use expansion.directives (should be empty for services)
```

The per-string routing (pure ref vs mixed-content vs no-secret) is now
determined by examining the expanded string: if it was fully resolved by
context, it's a plain value. If it has `{{ .key }}` syntax, it needs an
ESO ExternalSecret. If the original was exactly `${secret.X.Y}` (nothing
else), it's a pure secretKeyRef. This logic stays in `lattice-workload`
but the parsing is done by `lattice-template`.

### LatticePackage (helm values)

```rust
// 1. Context is simpler — packages don't have Score resources
let ctx = TemplateContext::builder()
    .set("metadata.name", &package.name)
    .group("cluster", [("name", &cluster_name)])
    .build();

// 2. The values tree is already a Value (from the CRD)
let mut values = package.spec.values.clone();

// 3. Expand — $secret directives get replaced with names,
//    ${secret.X.Y} get resolved from synced secrets
let expansion = lattice_template::expand(&mut values, &ctx, &ExpandOptions {
    secret_mode: SecretMode::Resolve(resolved_secrets),
    name_prefix: package_name.into(),
})?;

// 4. expansion.directives → generate ExternalSecrets with key mapping
// 5. values tree is now fully resolved → pass to helm template
```

---

## What moves where

```
lattice-common::template::renderer
  parse_secret_ref()           → lattice-template (absorbed into expand_string)
  parse_secret_ref_inner()     → lattice-template::parse_secret_inner()
  extract_secret_refs()        → lattice-template (absorbed into tree walk)
  FileSecretRef                → lattice-template::InlineSecretRef
  SecretVariableRef            → lattice-template::InlineSecretRef
  EsoTemplatedEnvVar           → removed (tree walk handles this)
  RenderedContainer, etc.      → stays in lattice-workload (workload-specific types)
  TemplateRenderer             → removed (tree walk replaces it)

lattice-common::template::engine
  TemplateEngine (minijinja)   → removed
  has_template_syntax()        → lattice-template (trivial: contains("${"))

lattice-common::template::context
  TemplateContext              → lattice-template::TemplateContext (simplified)
  TemplateContextBuilder       → lattice-template::TemplateContextBuilder

lattice-common::template::types
  TemplateString               → lattice-template
  StaticString                 → lattice-template

lattice-common::template::filters
  all filters                  → removed (unused in production)

lattice-common::template::provisioner
  ProvisionerRegistry          → stays in lattice-common (workload-specific)
  ResourceProvisioner trait    → stays in lattice-common
  (provisioners build TemplateContext, then call lattice-template)

lattice-workload::pipeline::secrets
  SecretsCompiler              → stays (generates ExternalSecrets from resources block)
  resolve_single_store()       → lattice-template
  resolve_eso_data()           → lattice-template
  SecretRef                    → lattice-template

lattice-workload::pipeline::eso_templated
  compile_eso_templated_env_vars → stays but uses lattice-template types
```

## Crate dependencies

```
lattice-template
  ├── serde_json               (Value tree)
  ├── lattice-secret-provider  (ESO types for directive_to_external_secret)
  └── thiserror

lattice-common
  ├── lattice-template         (TemplateContext, TemplateString, StaticString)
  └── ... (no more minijinja)

lattice-workload
  ├── lattice-template         (expand, InlineSecretRef, SecretRef, ESO helpers)
  └── lattice-common

lattice-package (future)
  ├── lattice-template
  └── lattice-common
```

## Migration plan

1. Create `lattice-template` crate with the `expand()` API, context,
   types, and ESO helpers. Include comprehensive tests.

2. Have `lattice-workload` depend on `lattice-template`. Migrate
   `resolve_single_store`, `resolve_eso_data`, `SecretRef` first (these
   are pure moves). Wire `eso_templated.rs` and `files.rs` to use the
   new types.

3. Replace the `TemplateRenderer` in `lattice-workload::compiler` with
   `lattice_template::expand()`. The per-container rendering becomes:
   serialize to Value → expand → deserialize back.

4. Remove `lattice-common::template::engine` (minijinja) and
   `lattice-common::template::filters`. Move remaining types
   (`TemplateString`, `StaticString`) to `lattice-template`.

5. Drop the `minijinja` dependency from the workspace.

Each step is independently shippable and testable.
