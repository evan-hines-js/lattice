//! metrics-server manifest generation
//!
//! Embeds pre-rendered metrics-server manifests from build time.
//! metrics-server provides the Kubernetes metrics API (metrics.k8s.io)
//! required by HPA and KEDA CPU triggers.

use std::sync::LazyLock;

use super::split_yaml_documents;

static METRICS_SERVER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/metrics-server.yaml"
    )))
});

pub fn metrics_server_version() -> &'static str {
    env!("METRICS_SERVER_VERSION")
}

pub fn generate_metrics_server() -> &'static [String] {
    &METRICS_SERVER_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!metrics_server_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        assert!(!generate_metrics_server().is_empty());
    }
}
