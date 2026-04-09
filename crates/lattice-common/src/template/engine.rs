//! Template engine — thin wrapper over lattice-template for string-level rendering
//!
//! Converts the legacy `TemplateContext` (with nested maps) into
//! `lattice_template::TemplateContext` (flat dotted paths) and calls the
//! string expander. No minijinja, no Jinja2, no filters.

use super::context::TemplateContext;
use super::error::TemplateError;

/// Template engine for Score-compatible placeholder resolution
///
/// Wraps `lattice_template::expand` for per-string rendering, bridging
/// the legacy `TemplateContext` (nested maps) to the new flat context.
pub struct TemplateEngine;

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateEngine {
    /// Create a new template engine.
    pub fn new() -> Self {
        Self
    }

    /// Render a template string with the given context.
    ///
    /// Resolves `${dotted.path}` placeholders from the context.
    /// `$${...}` escape syntax produces literal `${...}`.
    /// `${secret.*}` references pass through unchanged (handled later by the pipeline).
    pub fn render(&self, template: &str, ctx: &TemplateContext) -> Result<String, TemplateError> {
        if !template.contains("${") {
            return Ok(template.to_string());
        }

        let flat_ctx = ctx.to_flat_context();
        let mut value = serde_json::Value::String(template.to_string());
        let opts = lattice_template::ExpandOptions {
            secret_mode: lattice_template::SecretMode::Collect,
            name_prefix: String::new(),
        };
        lattice_template::expand(&mut value, &flat_ctx, &opts)
            .map_err(|e| TemplateError::Render(e.to_string()))?;
        match value {
            serde_json::Value::String(s) => Ok(s),
            _ => unreachable!("expand on a string always returns a string"),
        }
    }

    /// Check if a string contains any template syntax.
    pub fn has_template_syntax(s: &str) -> bool {
        lattice_template::has_template_syntax(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::context::ResourceOutputs;
    use std::collections::HashMap;

    fn basic_context() -> TemplateContext {
        TemplateContext::builder()
            .metadata("test-service", HashMap::new())
            .build()
    }

    #[test]
    fn test_simple_variable() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("${metadata.name}", &ctx).unwrap();
        assert_eq!(result, "test-service");
    }

    #[test]
    fn test_variable_in_text() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("Hello ${metadata.name}!", &ctx).unwrap();
        assert_eq!(result, "Hello test-service!");
    }

    #[test]
    fn test_multiple_variables() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("version", "1.0")
            .config("env", "prod")
            .build();
        let result = engine
            .render("${metadata.name}-${config.version}-${config.env}", &ctx)
            .unwrap();
        assert_eq!(result, "api-1.0-prod");
    }

    #[test]
    fn test_resource_access() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "postgres",
                ResourceOutputs::builder()
                    .output("host", "pg.svc.cluster.local")
                    .output("port", "5432")
                    .build(),
            )
            .build();
        let result = engine
            .render(
                "${resources.postgres.host}:${resources.postgres.port}",
                &ctx,
            )
            .unwrap();
        assert_eq!(result, "pg.svc.cluster.local:5432");
    }

    #[test]
    fn test_undefined_strict() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        assert!(engine.render("${undefined_var}", &ctx).is_err());
    }

    #[test]
    fn test_nested_undefined_strict() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        assert!(engine.render("${resources.missing.host}", &ctx).is_err());
    }

    #[test]
    fn test_literal_dollar() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("$PATH is set", &ctx).unwrap();
        assert_eq!(result, "$PATH is set");
    }

    #[test]
    fn test_score_escape_double_dollar() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("$${literal}", &ctx).unwrap();
        assert_eq!(result, "${literal}");
    }

    #[test]
    fn test_score_escape_in_context() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("name", "myapp")
            .build();
        let result = engine
            .render("echo $${VAR}; app=${config.name}", &ctx)
            .unwrap();
        assert_eq!(result, "echo ${VAR}; app=myapp");
    }

    #[test]
    fn test_score_escape_multiple() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("$${FOO} and $${BAR}", &ctx).unwrap();
        assert_eq!(result, "${FOO} and ${BAR}");
    }

    #[test]
    fn test_has_template_syntax() {
        assert!(TemplateEngine::has_template_syntax("${foo}"));
        assert!(!TemplateEngine::has_template_syntax("plain text"));
        assert!(!TemplateEngine::has_template_syntax("$foo"));
    }

    #[test]
    fn test_annotations() {
        let engine = TemplateEngine::new();
        let mut annotations = HashMap::new();
        annotations.insert("team".to_string(), "platform".to_string());
        let ctx = TemplateContext::builder()
            .metadata("api", annotations)
            .build();
        let result = engine
            .render("${metadata.annotations.team}", &ctx)
            .unwrap();
        assert_eq!(result, "platform");
    }

    #[test]
    fn test_static_string_no_rendering() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine.render("plain-text-no-placeholders", &ctx).unwrap();
        assert_eq!(result, "plain-text-no-placeholders");
    }

    #[test]
    fn test_hyphenated_resource_renders_correctly() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "my-db",
                ResourceOutputs::builder()
                    .output("host", "db.svc")
                    .output("port", "5432")
                    .build(),
            )
            .build();
        let result = engine
            .render("${resources.my-db.host}:${resources.my-db.port}", &ctx)
            .unwrap();
        assert_eq!(result, "db.svc:5432");
    }

    #[test]
    fn secret_refs_pass_through() {
        let engine = TemplateEngine::new();
        let ctx = basic_context();
        let result = engine
            .render("pass=${secret.db.password}", &ctx)
            .unwrap();
        assert_eq!(result, "pass=${secret.db.password}");
    }
}
