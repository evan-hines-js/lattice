//! Template context for Score-compatible rendering
//!
//! Provides the context structure that maps Score placeholders to values:
//! - `${metadata.name}` - Service metadata
//! - `${resources.NAME.FIELD}` - Resource outputs
//! - `${cluster.*}` - Lattice cluster context
//! - `${env.*}` - Environment config
//! - `${config.*}` - Service config

use minijinja::Value;
use std::collections::HashMap;

/// Template context containing all values available for placeholder resolution
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    /// Score: `${metadata.name}`, `${metadata.annotations.KEY}`
    pub metadata: MetadataContext,

    /// Score: `${resources.NAME.FIELD}`
    /// Resolved from ResourceSpec + provisioner outputs
    pub resources: HashMap<String, ResourceOutputs>,

    /// Lattice extension: `${cluster.name}`, `${cluster.environment}`
    pub cluster: HashMap<String, String>,

    /// Lattice extension: `${env.KEY}` from LatticeEnvironment.spec.config
    pub env: HashMap<String, String>,

    /// Lattice extension: `${config.KEY}` from LatticeServiceConfig
    pub config: HashMap<String, String>,
}

impl TemplateContext {
    /// Create a new builder for TemplateContext
    pub fn builder() -> TemplateContextBuilder {
        TemplateContextBuilder::default()
    }

    /// Convert to minijinja Value for rendering
    pub fn to_value(&self) -> Value {
        let mut map = HashMap::new();

        // metadata
        let mut metadata_map = HashMap::new();
        metadata_map.insert("name".to_string(), Value::from(self.metadata.name.clone()));
        metadata_map.insert(
            "annotations".to_string(),
            Value::from_iter(self.metadata.annotations.clone()),
        );
        map.insert("metadata".to_string(), Value::from_iter(metadata_map));

        // resources
        let resources_map: HashMap<String, Value> = self
            .resources
            .iter()
            .map(|(name, outputs)| (name.clone(), outputs.to_value()))
            .collect();
        map.insert("resources".to_string(), Value::from_iter(resources_map));

        // cluster
        map.insert(
            "cluster".to_string(),
            Value::from_iter(self.cluster.clone()),
        );

        // env
        map.insert("env".to_string(), Value::from_iter(self.env.clone()));

        // config
        map.insert("config".to_string(), Value::from_iter(self.config.clone()));

        Value::from_iter(map)
    }
}

/// Builder for TemplateContext
#[derive(Debug, Default)]
pub struct TemplateContextBuilder {
    metadata: Option<MetadataContext>,
    resources: HashMap<String, ResourceOutputs>,
    cluster: HashMap<String, String>,
    env: HashMap<String, String>,
    config: HashMap<String, String>,
}

impl TemplateContextBuilder {
    /// Set the metadata context
    pub fn metadata(
        mut self,
        name: impl Into<String>,
        annotations: HashMap<String, String>,
    ) -> Self {
        self.metadata = Some(MetadataContext {
            name: name.into(),
            annotations,
        });
        self
    }

    /// Add a resource with its outputs
    pub fn resource(mut self, name: impl Into<String>, outputs: ResourceOutputs) -> Self {
        self.resources.insert(name.into(), outputs);
        self
    }

    /// Add a cluster context value
    pub fn cluster(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.cluster.insert(key.into(), value.into());
        self
    }

    /// Add an environment config value
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add a service config value
    pub fn config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Build the TemplateContext
    pub fn build(self) -> TemplateContext {
        TemplateContext {
            metadata: self.metadata.unwrap_or_default(),
            resources: self.resources,
            cluster: self.cluster,
            env: self.env,
            config: self.config,
        }
    }
}

/// Metadata context for Score's `${metadata.*}` placeholders
#[derive(Debug, Clone, Default)]
pub struct MetadataContext {
    /// Service name: `${metadata.name}`
    pub name: String,
    /// Annotations: `${metadata.annotations.KEY}`
    pub annotations: HashMap<String, String>,
}

/// Resource outputs resolved from provisioners
///
/// Standard fields based on resource type, plus arbitrary extras.
#[derive(Debug, Clone, Default)]
pub struct ResourceOutputs {
    /// Host/endpoint: `${resources.NAME.host}`
    pub host: Option<String>,
    /// Port: `${resources.NAME.port}`
    pub port: Option<u16>,
    /// Full URL: `${resources.NAME.url}`
    pub url: Option<String>,
    /// Connection string: `${resources.NAME.connection_string}`
    pub connection_string: Option<String>,
    /// Username: `${resources.NAME.username}`
    pub username: Option<String>,
    /// Password: `${resources.NAME.password}`
    pub password: Option<String>,
    /// Additional outputs from provisioner: `${resources.NAME.FIELD}`
    pub extra: HashMap<String, String>,
}

impl ResourceOutputs {
    /// Create a new builder
    pub fn builder() -> ResourceOutputsBuilder {
        ResourceOutputsBuilder::default()
    }

    /// Convert to minijinja Value
    pub fn to_value(&self) -> Value {
        let mut map: HashMap<String, Value> = HashMap::new();

        if let Some(ref host) = self.host {
            map.insert("host".to_string(), Value::from(host.clone()));
        }
        if let Some(port) = self.port {
            map.insert("port".to_string(), Value::from(port));
        }
        if let Some(ref url) = self.url {
            map.insert("url".to_string(), Value::from(url.clone()));
        }
        if let Some(ref cs) = self.connection_string {
            map.insert("connection_string".to_string(), Value::from(cs.clone()));
        }
        if let Some(ref username) = self.username {
            map.insert("username".to_string(), Value::from(username.clone()));
        }
        if let Some(ref password) = self.password {
            map.insert("password".to_string(), Value::from(password.clone()));
        }

        for (key, value) in &self.extra {
            map.insert(key.clone(), Value::from(value.clone()));
        }

        Value::from_iter(map)
    }
}

/// Builder for ResourceOutputs
#[derive(Debug, Default)]
pub struct ResourceOutputsBuilder {
    host: Option<String>,
    port: Option<u16>,
    url: Option<String>,
    connection_string: Option<String>,
    username: Option<String>,
    password: Option<String>,
    extra: HashMap<String, String>,
}

impl ResourceOutputsBuilder {
    /// Set the host
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the port
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the URL
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the connection string
    pub fn connection_string(mut self, cs: impl Into<String>) -> Self {
        self.connection_string = Some(cs.into());
        self
    }

    /// Set the username
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Add an extra field
    pub fn extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Build the ResourceOutputs
    pub fn build(self) -> ResourceOutputs {
        ResourceOutputs {
            host: self.host,
            port: self.port,
            url: self.url,
            connection_string: self.connection_string,
            username: self.username,
            password: self.password,
            extra: self.extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = TemplateContext::builder()
            .metadata("my-service", HashMap::new())
            .resource("db", ResourceOutputs::builder().host("db.svc").build())
            .cluster("name", "prod")
            .env("log_level", "info")
            .config("version", "1.0")
            .build();

        assert_eq!(ctx.metadata.name, "my-service");
        assert!(ctx.resources.contains_key("db"));
        assert_eq!(ctx.cluster.get("name"), Some(&"prod".to_string()));
        assert_eq!(ctx.env.get("log_level"), Some(&"info".to_string()));
        assert_eq!(ctx.config.get("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_resource_outputs_builder() {
        let outputs = ResourceOutputs::builder()
            .host("pg.svc")
            .port(5432)
            .url("postgres://pg.svc:5432")
            .username("admin")
            .extra("pool_size", "10")
            .build();

        assert_eq!(outputs.host, Some("pg.svc".to_string()));
        assert_eq!(outputs.port, Some(5432));
        assert_eq!(outputs.extra.get("pool_size"), Some(&"10".to_string()));
    }

    #[test]
    fn test_to_value() {
        let ctx = TemplateContext::builder()
            .metadata("api", HashMap::new())
            .resource("db", ResourceOutputs::builder().host("db.svc").port(5432).build())
            .build();

        let value = ctx.to_value();
        // Basic sanity check - it should be indexable as a map
        assert!(!value.is_undefined());
    }
}
