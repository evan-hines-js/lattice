//! Template Renderer
//!
//! High-level API for rendering Score templates in LatticeService specs.
//! Integrates the template engine, provisioners, and context building.

use std::collections::{BTreeMap, HashMap};

use crate::crd::{ContainerSpec, FileMount, LatticeService, LatticeServiceSpec, VolumeMount};
use crate::graph::ServiceGraph;

use super::context::{MetadataContext, ResourceOutputs, TemplateContext};
use super::engine::TemplateEngine;
use super::error::TemplateError;
use super::provisioner::{ProvisionerContext, ProvisionerRegistry};
use super::types::TemplateString;

/// Configuration for template rendering
pub struct RenderConfig<'a> {
    /// The service graph for resolving dependencies
    pub graph: &'a ServiceGraph,
    /// Environment name
    pub environment: &'a str,
    /// Namespace where service deploys
    pub namespace: &'a str,
    /// Cluster domain (e.g., "cluster.local")
    pub cluster_domain: &'a str,
    /// Additional cluster context values
    pub cluster_context: BTreeMap<String, String>,
    /// Environment config from LatticeEnvironment
    pub env_config: BTreeMap<String, String>,
    /// Service-specific config
    pub service_config: BTreeMap<String, String>,
}

impl<'a> RenderConfig<'a> {
    /// Create a new render config with defaults
    pub fn new(
        graph: &'a ServiceGraph,
        environment: &'a str,
        namespace: &'a str,
    ) -> Self {
        Self {
            graph,
            environment,
            namespace,
            cluster_domain: "cluster.local",
            cluster_context: BTreeMap::new(),
            env_config: BTreeMap::new(),
            service_config: BTreeMap::new(),
        }
    }

    /// Set custom cluster domain
    pub fn with_cluster_domain(mut self, domain: &'a str) -> Self {
        self.cluster_domain = domain;
        self
    }

    /// Add cluster context value
    pub fn with_cluster(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.cluster_context.insert(key.into(), value.into());
        self
    }

    /// Add environment config value
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_config.insert(key.into(), value.into());
        self
    }

    /// Add service config value
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.service_config.insert(key.into(), value.into());
        self
    }
}

/// Rendered container spec with all templates resolved
#[derive(Clone, Debug)]
pub struct RenderedContainer {
    /// Container name
    pub name: String,
    /// Rendered image
    pub image: String,
    /// Command (unchanged)
    pub command: Option<Vec<String>>,
    /// Args (unchanged)
    pub args: Option<Vec<String>>,
    /// Rendered environment variables
    pub variables: BTreeMap<String, String>,
    /// Rendered file mounts
    pub files: BTreeMap<String, RenderedFile>,
    /// Rendered volume mounts
    pub volumes: BTreeMap<String, RenderedVolume>,
}

/// Rendered file mount
#[derive(Clone, Debug)]
pub struct RenderedFile {
    /// Rendered content (if inline)
    pub content: Option<String>,
    /// Binary content (unchanged)
    pub binary_content: Option<String>,
    /// Rendered source path
    pub source: Option<String>,
    /// File mode
    pub mode: Option<String>,
}

/// Rendered volume mount
#[derive(Clone, Debug)]
pub struct RenderedVolume {
    /// Rendered source reference
    pub source: String,
    /// Sub path
    pub path: Option<String>,
    /// Read only flag
    pub read_only: Option<bool>,
}

/// Template renderer for LatticeService specs
pub struct TemplateRenderer {
    engine: TemplateEngine,
    registry: ProvisionerRegistry,
}

impl Default for TemplateRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateRenderer {
    /// Create a new template renderer
    pub fn new() -> Self {
        Self {
            engine: TemplateEngine::new(),
            registry: ProvisionerRegistry::new(),
        }
    }

    /// Build template context for a service
    pub fn build_context(
        &self,
        service: &LatticeService,
        config: &RenderConfig<'_>,
    ) -> Result<TemplateContext, TemplateError> {
        let name = service
            .metadata
            .name
            .as_deref()
            .unwrap_or("unknown");

        // Build metadata context (convert BTreeMap to HashMap)
        let annotations: HashMap<String, String> = service
            .metadata
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Resolve resource outputs via provisioners
        let prov_ctx = ProvisionerContext::new(
            config.graph,
            config.environment,
            config.namespace,
            config.cluster_domain,
        );
        let resources = self.registry.resolve_all(&service.spec, &prov_ctx)?;

        // Build the full context
        let mut builder = TemplateContext::builder()
            .metadata(name, annotations);

        // Add resources
        for (name, outputs) in resources {
            builder = builder.resource(name, outputs);
        }

        // Add cluster context
        for (k, v) in &config.cluster_context {
            builder = builder.cluster(k, v);
        }

        // Add env config
        for (k, v) in &config.env_config {
            builder = builder.env(k, v);
        }

        // Add service config
        for (k, v) in &config.service_config {
            builder = builder.config(k, v);
        }

        Ok(builder.build())
    }

    /// Render all templates in a container spec
    pub fn render_container(
        &self,
        name: &str,
        container: &ContainerSpec,
        ctx: &TemplateContext,
    ) -> Result<RenderedContainer, TemplateError> {
        // Render environment variables
        let mut variables = BTreeMap::new();
        for (k, v) in &container.variables {
            let rendered = self.engine.render(v.as_str(), ctx)?;
            variables.insert(k.clone(), rendered);
        }

        // Render files
        let mut files = BTreeMap::new();
        for (path, file) in &container.files {
            let rendered = self.render_file(file, ctx)?;
            files.insert(path.clone(), rendered);
        }

        // Render volumes
        let mut volumes = BTreeMap::new();
        for (path, vol) in &container.volumes {
            let rendered = self.render_volume(vol, ctx)?;
            volumes.insert(path.clone(), rendered);
        }

        Ok(RenderedContainer {
            name: name.to_string(),
            image: container.image.clone(), // Image not templated per Score spec
            command: container.command.clone(),
            args: container.args.clone(),
            variables,
            files,
            volumes,
        })
    }

    /// Render a file mount
    fn render_file(
        &self,
        file: &FileMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedFile, TemplateError> {
        // Check if expansion is disabled
        let no_expand = file.no_expand.unwrap_or(false);

        let content: Option<String> = if let Some(ref template) = file.content {
            let template: &TemplateString = template;
            if no_expand {
                Some(template.as_str().to_string())
            } else {
                Some(self.engine.render(template.as_str(), ctx)?)
            }
        } else {
            None
        };

        let source: Option<String> = if let Some(ref template) = file.source {
            let template: &TemplateString = template;
            if no_expand {
                Some(template.as_str().to_string())
            } else {
                Some(self.engine.render(template.as_str(), ctx)?)
            }
        } else {
            None
        };

        Ok(RenderedFile {
            content,
            binary_content: file.binary_content.clone(),
            source,
            mode: file.mode.clone(),
        })
    }

    /// Render a volume mount
    fn render_volume(
        &self,
        vol: &VolumeMount,
        ctx: &TemplateContext,
    ) -> Result<RenderedVolume, TemplateError> {
        let source = self.engine.render(vol.source.as_str(), ctx)?;

        Ok(RenderedVolume {
            source,
            path: vol.path.clone(),
            read_only: vol.read_only,
        })
    }

    /// Render all containers in a service spec
    pub fn render_all_containers(
        &self,
        spec: &LatticeServiceSpec,
        ctx: &TemplateContext,
    ) -> Result<BTreeMap<String, RenderedContainer>, TemplateError> {
        let mut rendered = BTreeMap::new();

        for (name, container) in &spec.containers {
            let rc = self.render_container(name, container, ctx)?;
            rendered.insert(name.clone(), rc);
        }

        Ok(rendered)
    }

    /// Render a single template string
    pub fn render_string(
        &self,
        template: &TemplateString,
        ctx: &TemplateContext,
    ) -> Result<String, TemplateError> {
        self.engine.render(template.as_str(), ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DependencyDirection, LatticeServiceSpec, PortSpec, ReplicaSpec,
        ResourceSpec, ResourceType, ServicePortsSpec,
    };
    use crate::template::TemplateString;
    use kube::api::ObjectMeta;

    fn make_graph_with_db(env: &str) -> ServiceGraph {
        let graph = ServiceGraph::new();

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "postgres:15".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "postgres".to_string(),
            PortSpec {
                port: 5432,
                target_port: None,
                protocol: None,
            },
        );

        let spec = LatticeServiceSpec {
            environment: env.to_string(),
            containers,
            resources: BTreeMap::new(),
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: crate::crd::DeploySpec::default(),
        };

        graph.put_service(env, "postgres", &spec);
        graph
    }

    fn make_service_with_templates() -> LatticeService {
        let mut variables = BTreeMap::new();
        variables.insert(
            "DB_HOST".to_string(),
            TemplateString::from("${resources.db.host}"),
        );
        variables.insert(
            "DB_PORT".to_string(),
            TemplateString::from("${resources.db.port}"),
        );
        variables.insert(
            "LOG_LEVEL".to_string(),
            TemplateString::from("${config.log_level}"),
        );

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            FileMount {
                content: Some(TemplateString::from(
                    "database:\n  host: ${resources.db.host}\n  port: ${resources.db.port}",
                )),
                binary_content: None,
                source: None,
                mode: Some("0644".to_string()),
                no_expand: None,
            },
        );

        // Note: volumes are left empty for this test since they reference
        // resources not in the graph. Volume rendering is tested separately.

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "myapp:latest".to_string(),
                command: None,
                args: None,
                variables,
                files,
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let mut resources = BTreeMap::new();
        resources.insert(
            "db".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: Some("postgres".to_string()),
                params: None,
                class: None,
            },
        );

        LatticeService {
            metadata: ObjectMeta {
                name: Some("my-api".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources,
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
            },
            status: None,
        }
    }

    // =========================================================================
    // Story: Full template rendering pipeline
    // =========================================================================

    #[test]
    fn test_render_container_variables() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("log_level", "debug");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        assert_eq!(
            rendered.variables.get("DB_HOST"),
            Some(&"postgres.prod-ns.svc.cluster.local".to_string())
        );
        assert_eq!(rendered.variables.get("DB_PORT"), Some(&"5432".to_string()));
        assert_eq!(
            rendered.variables.get("LOG_LEVEL"),
            Some(&"debug".to_string())
        );
    }

    #[test]
    fn test_render_file_content() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("log_level", "info"); // Required by the test fixture

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        let file = &rendered.files["/etc/app/config.yaml"];
        let content = file.content.as_ref().unwrap();

        assert!(content.contains("host: postgres.prod-ns.svc.cluster.local"));
        assert!(content.contains("port: 5432"));
    }

    #[test]
    fn test_no_expand_preserves_templates() {
        let graph = ServiceGraph::new();

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/script.sh".to_string(),
            FileMount {
                content: Some(TemplateString::from("echo ${VAR}")),
                binary_content: None,
                source: None,
                mode: None,
                no_expand: Some(true), // Disable expansion
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files,
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "test".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer.build_context(&service, &config).unwrap();

        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        // Should preserve the ${VAR} literally
        assert_eq!(
            rendered.files["/etc/script.sh"].content,
            Some("echo ${VAR}".to_string())
        );
    }

    #[test]
    fn test_render_all_containers() {
        let graph = make_graph_with_db("prod");
        let service = make_service_with_templates();

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_config("log_level", "info");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer.render_all_containers(&service.spec, &ctx).unwrap();

        assert!(rendered.contains_key("main"));
        assert_eq!(
            rendered["main"].variables.get("LOG_LEVEL"),
            Some(&"info".to_string())
        );
    }

    #[test]
    fn test_escaped_placeholders_preserved() {
        let graph = ServiceGraph::new();

        let mut variables = BTreeMap::new();
        variables.insert(
            "SHELL_VAR".to_string(),
            TemplateString::from("$${HOME}/app"), // Escaped
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "app:latest".to_string(),
                command: None,
                args: None,
                variables,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "test".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "test", "test-ns");
        let ctx = renderer.build_context(&service, &config).unwrap();

        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        // $${HOME} should become ${HOME}
        assert_eq!(
            rendered.variables.get("SHELL_VAR"),
            Some(&"${HOME}/app".to_string())
        );
    }

    #[test]
    fn test_cluster_and_env_context() {
        let graph = ServiceGraph::new();

        let mut variables = BTreeMap::new();
        variables.insert(
            "IMAGE".to_string(),
            TemplateString::from("${cluster.registry}/app:${env.version}"),
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "placeholder".to_string(),
                command: None,
                args: None,
                variables,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let service = LatticeService {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                environment: "prod".to_string(),
                containers,
                resources: BTreeMap::new(),
                service: None,
                replicas: ReplicaSpec::default(),
                deploy: crate::crd::DeploySpec::default(),
            },
            status: None,
        };

        let renderer = TemplateRenderer::new();
        let config = RenderConfig::new(&graph, "prod", "prod-ns")
            .with_cluster("registry", "gcr.io/myproject")
            .with_env("version", "1.2.3");

        let ctx = renderer.build_context(&service, &config).unwrap();
        let rendered = renderer
            .render_container("main", &service.spec.containers["main"], &ctx)
            .unwrap();

        assert_eq!(
            rendered.variables.get("IMAGE"),
            Some(&"gcr.io/myproject/app:1.2.3".to_string())
        );
    }
}
