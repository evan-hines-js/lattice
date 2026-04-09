//! Template context — flat map of dotted paths to values.
//!
//! Stores values like `"metadata.name" → "my-service"` and
//! `"resources.db.host" → "postgres.svc"`. No nested maps — just string lookups.

use std::collections::BTreeMap;

/// Template context for `${...}` placeholder resolution.
///
/// Flat map of dotted paths to string values. Lookup is a single
/// `BTreeMap::get` — no nested map traversal.
#[derive(Clone, Debug, Default)]
pub struct TemplateContext {
    values: BTreeMap<String, String>,
}

impl TemplateContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder.
    pub fn builder() -> TemplateContextBuilder {
        TemplateContextBuilder::default()
    }

    /// Resolve a dotted path like `"metadata.name"` or `"resources.db.host"`.
    pub fn resolve(&self, path: &str) -> Option<&str> {
        self.values.get(path).map(|s| s.as_str())
    }

    /// Check if the context is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Builder for `TemplateContext`.
#[derive(Debug, Default)]
pub struct TemplateContextBuilder {
    values: BTreeMap<String, String>,
}

impl TemplateContextBuilder {
    /// Set a single dotted path to a value.
    ///
    /// ```
    /// # use lattice_template::TemplateContext;
    /// let ctx = TemplateContext::builder()
    ///     .set("metadata.name", "my-service")
    ///     .build();
    /// assert_eq!(ctx.resolve("metadata.name"), Some("my-service"));
    /// ```
    pub fn set(mut self, path: impl Into<String>, value: impl Into<String>) -> Self {
        self.values.insert(path.into(), value.into());
        self
    }

    /// Add a group of values under a common prefix.
    ///
    /// `group("cluster", [("name", "prod"), ("env", "production")])` stores
    /// `"cluster.name" → "prod"` and `"cluster.env" → "production"`.
    pub fn group(
        mut self,
        prefix: &str,
        pairs: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in pairs {
            self.values
                .insert(format!("{}.{}", prefix, k.into()), v.into());
        }
        self
    }

    /// Add resource outputs under `resources.{name}.{key}`.
    ///
    /// `resource("db", [("host", "pg.svc"), ("port", "5432")])` stores
    /// `"resources.db.host" → "pg.svc"` and `"resources.db.port" → "5432"`.
    ///
    /// Hyphens in the resource name are replaced with underscores so that
    /// `${resources.my-db.host}` resolves correctly (the expander normalizes
    /// hyphens in lookup paths too).
    pub fn resource(
        mut self,
        name: &str,
        outputs: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        let normalized = name.replace('-', "_");
        for (k, v) in outputs {
            self.values
                .insert(format!("resources.{}.{}", normalized, k.into()), v.into());
        }
        self
    }

    /// Build the context.
    pub fn build(self) -> TemplateContext {
        TemplateContext {
            values: self.values,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_resolve() {
        let ctx = TemplateContext::builder()
            .set("metadata.name", "api")
            .build();
        assert_eq!(ctx.resolve("metadata.name"), Some("api"));
        assert_eq!(ctx.resolve("metadata.namespace"), None);
    }

    #[test]
    fn group() {
        let ctx = TemplateContext::builder()
            .group("cluster", [("name", "prod"), ("region", "us-east-1")])
            .build();
        assert_eq!(ctx.resolve("cluster.name"), Some("prod"));
        assert_eq!(ctx.resolve("cluster.region"), Some("us-east-1"));
    }

    #[test]
    fn resource_normalizes_hyphens() {
        let ctx = TemplateContext::builder()
            .resource("my-db", [("host", "pg.svc")])
            .build();
        assert_eq!(ctx.resolve("resources.my_db.host"), Some("pg.svc"));
    }

    #[test]
    fn empty_context() {
        let ctx = TemplateContext::new();
        assert!(ctx.is_empty());
        assert_eq!(ctx.resolve("anything"), None);
    }
}
