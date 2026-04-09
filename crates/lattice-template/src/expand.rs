//! Tree-walking template expansion
//!
//! Single recursive pass over a `serde_json::Value` tree that handles:
//! - `${dotted.path}` context lookups
//! - `${secret.X.Y}` inline secret references
//! - `$secret` directives (object → string replacement)
//! - `$${...}` escape syntax

use std::collections::BTreeMap;

use serde_json::Value;

use crate::context::TemplateContext;
use crate::directive::{self, SecretDirective};
use crate::error::TemplateError;
use crate::inline::{self, InlineSecretRef};

/// How to handle `${secret.X.Y}` references in string values.
#[derive(Clone, Debug)]
pub enum SecretMode {
    /// Collect refs but leave `${secret.X.Y}` in the string unchanged.
    /// Caller resolves them later.
    Collect,

    /// Replace `${secret.X.Y}` with ESO Go template syntax: `{{ .X_Y }}`.
    /// Also escapes existing `{{`/`}}` in user content to prevent injection.
    EsoTemplate,

    /// Replace `${secret.X.Y}` with actual values from a provided map.
    /// Key: resource name, value: key→value map.
    Resolve(BTreeMap<String, BTreeMap<String, String>>),
}

/// Options for `expand()`.
pub struct ExpandOptions {
    /// How to handle `${secret.X.Y}` in strings.
    pub secret_mode: SecretMode,
    /// Prefix for generated secret names from `$secret` directives.
    /// Typically the resource name (e.g., `"redis-prod"`).
    pub name_prefix: String,
}

/// Result of expanding a value tree.
#[derive(Clone, Debug, Default)]
pub struct Expansion {
    /// `$secret` directives found and replaced with secret names.
    pub directives: Vec<SecretDirective>,
    /// `${secret.X.Y}` references found in string values.
    pub inline_refs: Vec<InlineSecretRef>,
}

/// Walk a `Value` tree, expanding all template expressions in place.
///
/// In a single recursive pass:
/// - String values containing `${...}` are resolved from the context
/// - `${secret.X.Y}` references are handled per `SecretMode`
/// - Objects with a `$secret` key are replaced with `Value::String(secret_name)`
/// - `$${...}` produces literal `${...}`
pub fn expand(
    value: &mut Value,
    ctx: &TemplateContext,
    opts: &ExpandOptions,
) -> Result<Expansion, TemplateError> {
    let mut result = Expansion::default();
    walk(value, ctx, opts, "", &mut result)?;
    Ok(result)
}

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
                return Ok(()); // fast path
            }
            let expanded =
                expand_string(s, ctx, &opts.secret_mode, path, &mut result.inline_refs)?;
            *s = expanded;
        }

        Value::Object(map) => {
            // Check for $secret directive
            if map.contains_key("$secret") {
                let directive_val = map
                    .get("$secret")
                    .expect("just checked contains_key");
                let d = directive::parse_directive(directive_val, path, &opts.name_prefix)?;
                *value = Value::String(d.secret_name.clone());
                result.directives.push(d);
                return Ok(());
            }

            // Recurse into children
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
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

/// Expand a single string value. Single-pass left-to-right scan.
fn expand_string(
    s: &str,
    ctx: &TemplateContext,
    secret_mode: &SecretMode,
    path: &str,
    refs: &mut Vec<InlineSecretRef>,
) -> Result<String, TemplateError> {
    let mut result = String::with_capacity(s.len());
    let mut remaining = s;

    while let Some(pos) = remaining.find("${") {
        // Check for escape: $${ → emit literal "${" and continue scanning
        // the content after it. Inner refs like ${config.port} are still
        // expanded, so $${PORT:-${config.port}} → ${PORT:-8080}.
        if pos > 0 && remaining.as_bytes()[pos - 1] == b'$' {
            result.push_str(&remaining[..pos - 1]);
            result.push_str("${");
            remaining = &remaining[pos + 2..];
            continue;
        }

        // Emit everything before ${
        result.push_str(&remaining[..pos]);

        let after = &remaining[pos + 2..];
        let end = after.find('}').ok_or_else(|| TemplateError::UnclosedPlaceholder {
            path: path.to_string(),
        })?;
        let expr = &after[..end];
        remaining = &after[end + 1..];

        if let Some(inner) = expr.strip_prefix("secret.") {
            // Secret reference
            let (resource, key, eso_key) =
                inline::parse_secret_inner(inner).ok_or_else(|| TemplateError::InvalidSecretRef {
                    inner: inner.to_string(),
                    path: path.to_string(),
                })?;

            refs.push(InlineSecretRef {
                path: path.to_string(),
                resource_name: resource.clone(),
                key: key.clone(),
                eso_data_key: eso_key.clone(),
            });

            match secret_mode {
                SecretMode::Collect => {
                    // Re-emit the original placeholder
                    result.push_str("${secret.");
                    result.push_str(inner);
                    result.push('}');
                }
                SecretMode::EsoTemplate => {
                    // Escape any existing Go template delimiters that have been
                    // emitted so far (in the literal parts before this ref).
                    // We do this lazily: only the final result needs escaping,
                    // but it's simpler to emit the Go ref directly here and
                    // do a full escape pass if needed.
                    result.push_str("{{ .");
                    result.push_str(&eso_key);
                    result.push_str(" }}");
                }
                SecretMode::Resolve(secrets) => {
                    let val = secrets
                        .get(&resource)
                        .and_then(|m| m.get(&key))
                        .ok_or_else(|| TemplateError::UnresolvedSecret {
                            resource: resource.clone(),
                            key: key.clone(),
                            path: path.to_string(),
                        })?;
                    result.push_str(val);
                }
            }
        } else {
            // Context lookup — normalize hyphens in resource names
            let normalized = normalize_expr(expr);
            let lookup = if normalized != expr {
                normalized.as_str()
            } else {
                expr
            };
            let value = ctx.resolve(lookup).ok_or_else(|| TemplateError::Unresolved {
                expr: expr.to_string(),
                path: path.to_string(),
            })?;
            result.push_str(value);
        }
    }

    result.push_str(remaining);

    // In EsoTemplate mode, escape Go template delimiters in the literal parts.
    // The {{ .key }} refs we emitted are unescaped; user content with {{ or }}
    // must be escaped to prevent injection into ESO's Go template engine.
    if matches!(secret_mode, SecretMode::EsoTemplate) && !refs.is_empty() {
        result = escape_go_templates_preserving_refs(&result);
    }

    Ok(result)
}

/// Normalize hyphens in resource name paths so `${resources.my-db.host}`
/// matches the context key `resources.my_db.host`.
fn normalize_expr(expr: &str) -> String {
    if !expr.starts_with("resources.") || !expr.contains('-') {
        return expr.to_string();
    }
    // Only normalize the resource name part (second segment)
    let parts: Vec<&str> = expr.splitn(3, '.').collect();
    if parts.len() == 3 {
        format!("{}.{}.{}", parts[0], parts[1].replace('-', "_"), parts[2])
    } else {
        expr.to_string()
    }
}

/// Escape `{{` and `}}` in user content while preserving `{{ .key }}` refs
/// generated by EsoTemplate mode.
///
/// Strategy: temporarily replace our refs with placeholders, escape everything,
/// then restore refs.
fn escape_go_templates_preserving_refs(s: &str) -> String {
    // Find all {{ .identifier }} patterns (our generated refs)
    let mut segments: Vec<Segment> = Vec::new();
    let mut remaining = s;
    let mut offset = 0;

    while let Some(start) = remaining.find("{{ .") {
        if let Some(end) = remaining[start..].find(" }}") {
            segments.push(Segment {
                start: offset + start,
                end: offset + start + end + 3,
            });
            remaining = &remaining[start + end + 3..];
            offset += start + end + 3;
        } else {
            break;
        }
    }

    if segments.is_empty() {
        // No refs to preserve — escape everything
        return s.replace("{{", "{{`{{`}}").replace("}}", "{{`}}`}}");
    }

    // Build result: escape literal parts, preserve ref parts
    let mut result = String::with_capacity(s.len());
    let mut pos = 0;
    for seg in &segments {
        // Escape the literal part before this ref
        let literal = &s[pos..seg.start];
        result.push_str(&literal.replace("{{", "{{`{{`}}").replace("}}", "{{`}}`}}"));
        // Preserve the ref as-is
        result.push_str(&s[seg.start..seg.end]);
        pos = seg.end;
    }
    // Escape trailing literal
    let trailing = &s[pos..];
    result.push_str(&trailing.replace("{{", "{{`{{`}}").replace("}}", "{{`}}`}}"));

    result
}

struct Segment {
    start: usize,
    end: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn empty_ctx() -> TemplateContext {
        TemplateContext::new()
    }

    fn collect_opts() -> ExpandOptions {
        ExpandOptions {
            secret_mode: SecretMode::Collect,
            name_prefix: "test".into(),
        }
    }

    fn eso_opts() -> ExpandOptions {
        ExpandOptions {
            secret_mode: SecretMode::EsoTemplate,
            name_prefix: "test".into(),
        }
    }

    // =========================================================================
    // Context resolution
    // =========================================================================

    #[test]
    fn resolve_simple_path() {
        let ctx = TemplateContext::builder()
            .set("metadata.name", "my-svc")
            .build();
        let mut val = json!("name: ${metadata.name}");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("name: my-svc"));
    }

    #[test]
    fn resolve_multiple_paths() {
        let ctx = TemplateContext::builder()
            .resource("db", [("host", "pg.svc"), ("port", "5432")])
            .build();
        let mut val = json!("postgres://${resources.db.host}:${resources.db.port}/mydb");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("postgres://pg.svc:5432/mydb"));
    }

    #[test]
    fn resolve_hyphenated_resource() {
        let ctx = TemplateContext::builder()
            .resource("my-db", [("host", "pg.svc")])
            .build();
        let mut val = json!("${resources.my-db.host}");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("pg.svc"));
    }

    #[test]
    fn unresolved_variable_errors() {
        let ctx = empty_ctx();
        let mut val = json!("${missing.var}");
        let err = expand(&mut val, &ctx, &collect_opts()).unwrap_err();
        assert!(err.to_string().contains("unresolved variable"));
    }

    #[test]
    fn unclosed_placeholder_errors() {
        let ctx = empty_ctx();
        let mut val = json!("${unclosed");
        let err = expand(&mut val, &ctx, &collect_opts()).unwrap_err();
        assert!(err.to_string().contains("unclosed"));
    }

    // =========================================================================
    // Escape syntax
    // =========================================================================

    #[test]
    fn escape_produces_literal() {
        let ctx = empty_ctx();
        let mut val = json!("$${literal}");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("${literal}"));
    }

    #[test]
    fn escape_mixed_with_real() {
        let ctx = TemplateContext::builder()
            .set("config.port", "8080")
            .build();
        let mut val = json!("PORT=$${PORT:-${config.port}}");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("PORT=${PORT:-8080}"));
    }

    // =========================================================================
    // Secret refs — Collect mode
    // =========================================================================

    #[test]
    fn collect_leaves_secret_refs_in_place() {
        let ctx = empty_ctx();
        let mut val = json!("pass: ${secret.db.password}");
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("pass: ${secret.db.password}"));
        assert_eq!(exp.inline_refs.len(), 1);
        assert_eq!(exp.inline_refs[0].resource_name, "db");
        assert_eq!(exp.inline_refs[0].key, "password");
    }

    // =========================================================================
    // Secret refs — EsoTemplate mode
    // =========================================================================

    #[test]
    fn eso_template_replaces_refs() {
        let ctx = empty_ctx();
        let mut val = json!("postgres://${secret.db.user}:${secret.db.pass}@host");
        let exp = expand(&mut val, &ctx, &eso_opts()).unwrap();
        assert_eq!(
            val,
            json!("postgres://{{ .db_user }}:{{ .db_pass }}@host")
        );
        assert_eq!(exp.inline_refs.len(), 2);
    }

    #[test]
    fn eso_template_escapes_user_go_templates() {
        let ctx = empty_ctx();
        let mut val = json!("{{ user_content }} ${secret.db.pass}");
        let exp = expand(&mut val, &ctx, &eso_opts()).unwrap();
        let s = val.as_str().unwrap();
        // User {{ should be escaped, our ref should not
        assert!(s.contains("{{`{{`}}"));
        assert!(s.contains("{{ .db_pass }}"));
        assert_eq!(exp.inline_refs.len(), 1);
    }

    // =========================================================================
    // Secret refs — Resolve mode
    // =========================================================================

    #[test]
    fn resolve_substitutes_values() {
        let ctx = empty_ctx();
        let mut secrets = BTreeMap::new();
        let mut db = BTreeMap::new();
        db.insert("password".to_string(), "s3cret".to_string());
        secrets.insert("db".to_string(), db);

        let opts = ExpandOptions {
            secret_mode: SecretMode::Resolve(secrets),
            name_prefix: "test".into(),
        };
        let mut val = json!("pass=${secret.db.password}");
        expand(&mut val, &ctx, &opts).unwrap();
        assert_eq!(val, json!("pass=s3cret"));
    }

    #[test]
    fn resolve_missing_secret_errors() {
        let ctx = empty_ctx();
        let opts = ExpandOptions {
            secret_mode: SecretMode::Resolve(BTreeMap::new()),
            name_prefix: "test".into(),
        };
        let mut val = json!("${secret.db.password}");
        let err = expand(&mut val, &ctx, &opts).unwrap_err();
        assert!(err.to_string().contains("unresolved secret"));
    }

    // =========================================================================
    // $secret directives
    // =========================================================================

    #[test]
    fn directive_replaced_with_name() {
        let ctx = empty_ctx();
        let mut val = json!({
            "auth": {
                "existingSecret": {
                    "$secret": {
                        "id": "payments/redis/prod",
                        "provider": "vault-prod",
                        "keys": { "redis-password": "password" }
                    }
                }
            }
        });
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(
            val["auth"]["existingSecret"],
            json!("test-auth-existingsecret")
        );
        assert_eq!(exp.directives.len(), 1);
        assert_eq!(exp.directives[0].id, "payments/redis/prod");
        assert_eq!(
            exp.directives[0].keys.get("redis-password"),
            Some(&"password".to_string())
        );
    }

    #[test]
    fn directive_deeply_nested() {
        let ctx = empty_ctx();
        let mut val = json!({
            "global": {
                "postgresql": {
                    "auth": {
                        "existingSecret": {
                            "$secret": {
                                "id": "db/prod",
                                "provider": "vault"
                            }
                        }
                    }
                }
            }
        });
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert!(val["global"]["postgresql"]["auth"]["existingSecret"]
            .as_str()
            .unwrap()
            .starts_with("test-"));
        assert_eq!(exp.directives.len(), 1);
    }

    #[test]
    fn directive_in_array() {
        let ctx = empty_ctx();
        let mut val = json!({
            "tls": [{
                "hosts": ["app.example.com"],
                "secretName": {
                    "$secret": {
                        "id": "tls/wildcard",
                        "provider": "vault"
                    }
                }
            }]
        });
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert!(val["tls"][0]["secretName"].is_string());
        assert_eq!(exp.directives.len(), 1);
    }

    // =========================================================================
    // Tree walk — mixed content
    // =========================================================================

    #[test]
    fn tree_walk_expands_all_types() {
        let ctx = TemplateContext::builder()
            .set("metadata.name", "redis-prod")
            .set("config.replicas", "3")
            .build();
        let mut val = json!({
            "name": "${metadata.name}",
            "replicas": "${config.replicas}",
            "auth": {
                "existingSecret": {
                    "$secret": {
                        "id": "redis/prod",
                        "provider": "vault"
                    }
                }
            },
            "env": {
                "REDIS_URL": "redis://${metadata.name}.svc:6379"
            },
            "unchanged": 42,
            "also_unchanged": true,
            "null_field": null
        });
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();

        assert_eq!(val["name"], json!("redis-prod"));
        assert_eq!(val["replicas"], json!("3"));
        assert!(val["auth"]["existingSecret"].is_string());
        assert_eq!(val["env"]["REDIS_URL"], json!("redis://redis-prod.svc:6379"));
        assert_eq!(val["unchanged"], json!(42));
        assert_eq!(val["also_unchanged"], json!(true));
        assert!(val["null_field"].is_null());
        assert_eq!(exp.directives.len(), 1);
    }

    #[test]
    fn no_templates_is_noop() {
        let ctx = empty_ctx();
        let original = json!({
            "plain": "string",
            "number": 42,
            "nested": { "key": "value" }
        });
        let mut val = original.clone();
        let exp = expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, original);
        assert!(exp.directives.is_empty());
        assert!(exp.inline_refs.is_empty());
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn string_with_only_literal_dollar() {
        let ctx = empty_ctx();
        let mut val = json!("cost: $100");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!("cost: $100"));
    }

    #[test]
    fn empty_string_untouched() {
        let ctx = empty_ctx();
        let mut val = json!("");
        expand(&mut val, &ctx, &collect_opts()).unwrap();
        assert_eq!(val, json!(""));
    }

    #[test]
    fn invalid_secret_ref_errors() {
        let ctx = empty_ctx();
        let mut val = json!("${secret.nodot}");
        let err = expand(&mut val, &ctx, &collect_opts()).unwrap_err();
        assert!(err.to_string().contains("invalid secret reference"));
    }
}
