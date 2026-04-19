//! metrics-server helm chart manifests.

use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;

static METRICS_SERVER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/metrics-server.yaml"
    )))
});

/// metrics-server chart version pinned at build time from `versions.toml`.
pub fn metrics_server_version() -> &'static str {
    env!("METRICS_SERVER_VERSION")
}

/// Pre-rendered metrics-server helm chart manifests.
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
