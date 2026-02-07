//! Prometheus Adapter manifest generation
//!
//! Embeds pre-rendered Prometheus Adapter manifests from build time.

use std::sync::LazyLock;

use super::prometheus::MONITORING_NAMESPACE;
use super::{namespace_yaml, split_yaml_documents};

/// Pre-rendered Prometheus Adapter manifests with namespace prepended.
static PROMETHEUS_ADAPTER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/prometheus-adapter.yaml"
    ))));
    manifests
});

/// Prometheus Adapter version (pinned at build time)
pub fn prometheus_adapter_version() -> &'static str {
    env!("PROMETHEUS_ADAPTER_VERSION")
}

/// Generate Prometheus Adapter manifests
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_prometheus_adapter() -> &'static [String] {
    &PROMETHEUS_ADAPTER_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = prometheus_adapter_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_prometheus_adapter();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
