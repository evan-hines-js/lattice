//! Score-compatible templating for Lattice
//!
//! Uses `lattice-template` for `${...}` placeholder expansion. This module
//! provides the workload-specific rendering pipeline: provisioners resolve
//! resource outputs, the renderer expands templates in container specs.
//!
//! # Score Compatibility
//!
//! - `${metadata.name}` - Service name
//! - `${metadata.annotations.KEY}` - Annotation values
//! - `${resources.NAME.FIELD}` - Resource outputs (host, port, url, etc.)
//! - `${cluster.name}`, `${cluster.environment}` - Cluster metadata
//! - `${env.KEY}` - Environment config
//! - `${config.KEY}` - Service config
//! - `$${...}` - Escape syntax (produces literal `${...}`)

mod context;
mod error;
mod output;
mod provisioner;
mod renderer;
mod types;

pub use context::{MetadataContext, ResourceOutputs, TemplateContext};
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
    use renderer::render_template;
    use std::collections::HashMap;

    #[test]
    fn score_metadata_name() {
        let ctx = TemplateContext::builder()
            .metadata("my-service", HashMap::new())
            .build();
        assert_eq!(
            render_template("${metadata.name}", &ctx).unwrap(),
            "my-service"
        );
    }

    #[test]
    fn score_metadata_annotations() {
        let mut annotations = HashMap::new();
        annotations.insert("version".to_string(), "1.2.3".to_string());
        let ctx = TemplateContext::builder()
            .metadata("my-service", annotations)
            .build();
        assert_eq!(
            render_template("${metadata.annotations.version}", &ctx).unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn score_resource_outputs() {
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
            render_template("${resources.db.host}:${resources.db.port}", &ctx).unwrap(),
            "postgres.svc:5432"
        );
    }

    #[test]
    fn cluster_and_config_context() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .cluster("name", "prod-cluster")
            .env("log_level", "debug")
            .config("version", "2.0.0")
            .build();
        assert_eq!(
            render_template("${cluster.name}", &ctx).unwrap(),
            "prod-cluster"
        );
        assert_eq!(render_template("${env.log_level}", &ctx).unwrap(), "debug");
        assert_eq!(render_template("${config.version}", &ctx).unwrap(), "2.0.0");
    }

    #[test]
    fn undefined_variable_errors() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();
        assert!(render_template("${undefined.var}", &ctx).is_err());
        assert!(render_template("${resources.missing.host}", &ctx).is_err());
    }

    #[test]
    fn escape_syntax() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .config("port", "8080")
            .build();
        assert_eq!(render_template("$${literal}", &ctx).unwrap(), "${literal}");
        assert_eq!(
            render_template("PORT=$${PORT:-${config.port}}", &ctx).unwrap(),
            "PORT=${PORT:-8080}"
        );
    }

    #[test]
    fn literal_dollar_passthrough() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();
        assert_eq!(render_template("$PATH", &ctx).unwrap(), "$PATH");
        assert_eq!(render_template("cost: $100", &ctx).unwrap(), "cost: $100");
    }

    #[test]
    fn hyphenated_resource() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource(
                "my-db",
                ResourceOutputs::builder().output("host", "db.svc").build(),
            )
            .build();
        assert_eq!(
            render_template("${resources.my-db.host}", &ctx).unwrap(),
            "db.svc"
        );
    }

    #[test]
    fn secret_refs_pass_through() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .build();
        assert_eq!(
            render_template("pass=${secret.db.password}", &ctx).unwrap(),
            "pass=${secret.db.password}"
        );
    }
}
