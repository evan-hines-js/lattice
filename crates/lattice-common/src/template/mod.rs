//! Score-compatible templating for Lattice
//!
//! This module implements Score-compatible `${...}` placeholder syntax using
//! minijinja's custom syntax configuration. It enables Lattice to accept
//! Score-native workload definitions while providing Lattice-specific extensions.
//!
//! # Score Compatibility
//!
//! The following Score placeholders are supported:
//! - `${metadata.name}` - Service name from LatticeService
//! - `${metadata.annotations.KEY}` - Annotation values
//! - `${resources.NAME.FIELD}` - Resource outputs (host, port, url, etc.)
//!
//! # Lattice Extensions
//!
//! - `${cluster.name}`, `${cluster.environment}` - Cluster metadata
//! - `${env.KEY}` - Environment config from LatticeEnvironment
//! - `${config.KEY}` - Service config from LatticeServiceConfig
//! - `{% if %}...{% endif %}` - Conditionals
//! - `{% for %}...{% endfor %}` - Loops
//! - Filters: `${value | default("fallback")}`, `${value | base64_encode}`

mod context;
mod engine;
mod error;
mod output;
mod provisioner;
mod renderer;
mod types;

pub use context::{MetadataContext, ResourceOutputs, TemplateContext};
pub use engine::TemplateEngine;
pub use error::TemplateError;
pub use output::ProvisionOutput;
pub use provisioner::{
    ExternalServiceProvisioner, ProvisionerContext, ProvisionerRegistry, ResourceProvisioner,
    ServiceProvisioner, VolumeProvisioner,
};
pub use renderer::{
    extract_secret_refs, parse_secret_ref, parse_secret_ref_inner, EsoTemplatedEnvVar,
    FileSecretRef, RenderConfig, RenderedContainer, RenderedFile, RenderedVariable, RenderedVolume,
    SecretVariableRef, TemplateRenderer,
};
pub use types::{StaticString, TemplateString};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_score_metadata_name() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("my-service", HashMap::new())
            .build();
        assert_eq!(engine.render("${metadata.name}", &ctx).unwrap(), "my-service");
    }

    #[test]
    fn test_score_metadata_annotations() {
        let engine = TemplateEngine::new();
        let mut annotations = HashMap::new();
        annotations.insert("version".to_string(), "1.2.3".to_string());
        let ctx = TemplateContext::builder()
            .metadata("my-service", annotations)
            .build();
        assert_eq!(
            engine.render("${metadata.annotations.version}", &ctx).unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn test_score_resource_outputs() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "db",
                ResourceOutputs::builder()
                    .output("host", "postgres.svc")
                    .output("port", "5432")
                    .build(),
            )
            .build();
        assert_eq!(
            engine.render("${resources.db.host}:${resources.db.port}", &ctx).unwrap(),
            "postgres.svc:5432"
        );
    }

    // =========================================================================
    // Story: Lattice Extensions
    // =========================================================================

    #[test]
    fn test_lattice_cluster_context() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .cluster("name", "prod-cluster")
            .cluster("environment", "production")
            .build();

        assert_eq!(
            engine
                .render("${cluster.name}", &ctx)
                .expect("cluster.name should render successfully"),
            "prod-cluster"
        );
        assert_eq!(
            engine
                .render("${cluster.environment}", &ctx)
                .expect("cluster.environment should render successfully"),
            "production"
        );
    }

    #[test]
    fn test_lattice_env_config() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .env("log_level", "debug")
            .build();

        assert_eq!(
            engine
                .render("${env.log_level}", &ctx)
                .expect("env.log_level should render successfully"),
            "debug"
        );
    }

    #[test]
    fn test_lattice_service_config() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("version", "2.0.0")
            .config("replicas", "3")
            .build();

        assert_eq!(
            engine
                .render("${config.version}", &ctx)
                .expect("config.version should render successfully"),
            "2.0.0"
        );
    }

    #[test]
    fn test_undefined_variable_errors() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();
        assert!(engine.render("${undefined.var}", &ctx).is_err());
    }

    #[test]
    fn test_undefined_resource_errors() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();
        assert!(engine.render("${resources.missing.host}", &ctx).is_err());
    }

    #[test]
    fn test_static_string_accepts_plain_text() {
        let result: Result<StaticString, _> = "my-service".to_string().try_into();
        assert_eq!(result.unwrap().as_str(), "my-service");
    }

    #[test]
    fn test_static_string_rejects_dollar_brace() {
        let result: Result<StaticString, _> = "my-${name}".to_string().try_into();
        assert!(result.is_err());
    }

    // =========================================================================
    // Story: TemplateString Allows Templates
    // =========================================================================

    #[test]
    fn test_template_string_allows_placeholders() {
        let ts = TemplateString::new("${metadata.name}-svc");
        assert!(ts.has_placeholders());
    }

    #[test]
    fn test_template_string_detects_static() {
        let ts = TemplateString::new("static-value");
        assert!(!ts.has_placeholders());
    }

    // =========================================================================
    // Story: ResourceOutputs Builder
    // =========================================================================

    #[test]
    fn test_resource_outputs_builder() {
        let outputs = ResourceOutputs::builder()
            .output("host", "db.svc.cluster.local")
            .output("port", "5432")
            .output("url", "postgres://db.svc.cluster.local:5432")
            .sensitive(
                "connection_string",
                "postgres://user:pass@db.svc.cluster.local:5432/mydb",
            )
            .output("pool_size", "10")
            .build();

        assert_eq!(
            outputs.outputs.get("host"),
            Some(&"db.svc.cluster.local".to_string())
        );
        assert_eq!(outputs.outputs.get("port"), Some(&"5432".to_string()));
        assert_eq!(
            outputs.outputs.get("url"),
            Some(&"postgres://db.svc.cluster.local:5432".to_string())
        );
        // connection_string is in sensitive, not outputs
        assert!(outputs.sensitive.contains_key("connection_string"));
    }

    // =========================================================================
    // Story: Complex Template Rendering
    // =========================================================================

    #[test]
    fn test_complex_template_with_multiple_resources() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "postgres",
                ResourceOutputs::builder()
                    .output("host", "pg.svc")
                    .output("port", "5432")
                    .build(),
            )
            .resource(
                "redis",
                ResourceOutputs::builder()
                    .output("host", "redis.svc")
                    .output("port", "6379")
                    .build(),
            )
            .cluster("registry", "gcr.io/myproject")
            .config("version", "1.0.0")
            .build();

        let template = "${cluster.registry}/api:${config.version}";
        assert_eq!(
            engine
                .render(template, &ctx)
                .expect("cluster registry template should render successfully"),
            "gcr.io/myproject/api:1.0.0"
        );

        let conn_template = "postgres://${resources.postgres.host}:${resources.postgres.port}/mydb";
        assert_eq!(
            engine
                .render(conn_template, &ctx)
                .expect("connection template should render successfully"),
            "postgres://pg.svc:5432/mydb"
        );
    }

    // =========================================================================
    // Story: Score Escape Syntax ($${...})
    // =========================================================================

    #[test]
    fn test_score_escape_produces_literal() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        // Score spec: $${...} renders as literal ${...}
        assert_eq!(
            engine
                .render("$${literal}", &ctx)
                .expect("escape syntax should render successfully"),
            "${literal}"
        );
    }

    #[test]
    fn test_score_escape_mixed_with_variables() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("port", "8080")
            .build();

        // Mix escaped and real variables
        assert_eq!(
            engine
                .render("PORT=$${PORT:-${config.port}}", &ctx)
                .expect("mixed escape and variables should render successfully"),
            "PORT=${PORT:-8080}"
        );
    }

    #[test]
    fn test_literal_dollar_without_brace() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();

        // Plain $ without { passes through unchanged
        assert_eq!(
            engine
                .render("$PATH", &ctx)
                .expect("dollar without brace should pass through"),
            "$PATH"
        );
        assert_eq!(
            engine
                .render("cost: $100", &ctx)
                .expect("literal dollar should pass through"),
            "cost: $100"
        );
    }

}
