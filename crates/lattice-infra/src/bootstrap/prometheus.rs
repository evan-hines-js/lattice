//! VictoriaMetrics K8s Stack manifest generation
//!
//! Embeds pre-rendered VictoriaMetrics manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Well-known service name for the VMCluster components.
/// Used as `fullnameOverride` so all downstream consumers (KEDA,
/// canary controller, KEDA, etc.) reference a stable integration point.
pub const VMCLUSTER_NAME: &str = "lattice-metrics";

/// Namespace for monitoring components.
pub const MONITORING_NAMESPACE: &str = "monitoring";

/// VMSelect query port (Prometheus-compatible read path, HA mode).
pub const VMSELECT_PORT: u16 = 8481;

/// VMSelect URL path prefix for Prometheus-compatible queries (HA mode).
pub const VMSELECT_PATH: &str = "/select/0/prometheus";

/// VMSingle query port (Prometheus-compatible read path, single-node mode).
pub const VMSINGLE_PORT: u16 = 8429;

/// VMSingle URL path prefix for Prometheus-compatible queries (single-node mode).
pub const VMSINGLE_PATH: &str = "/prometheus";

/// Build the VMSelect service URL from well-known constants (HA mode).
/// Returns e.g. `http://lattice-metrics-vmselect.monitoring.svc`
pub fn vmselect_url() -> String {
    format!(
        "http://{}-vmselect.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Build the VMSingle service URL from well-known constants (single-node mode).
/// Returns e.g. `http://lattice-metrics-vmsingle.monitoring.svc`
pub fn vmsingle_url() -> String {
    format!(
        "http://{}-vmsingle.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Return the Prometheus-compatible query port for the given HA mode.
pub fn query_port(ha: bool) -> u16 {
    if ha {
        VMSELECT_PORT
    } else {
        VMSINGLE_PORT
    }
}

/// Return the Prometheus-compatible query path for the given HA mode.
pub fn query_path(ha: bool) -> &'static str {
    if ha {
        VMSELECT_PATH
    } else {
        VMSINGLE_PATH
    }
}

/// Return the full Prometheus-compatible query base URL for the given HA mode.
pub fn query_url(ha: bool) -> String {
    if ha {
        vmselect_url()
    } else {
        vmsingle_url()
    }
}

/// Pre-rendered VictoriaMetrics HA manifests with namespace prepended.
static PROMETHEUS_HA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-ha.yaml"
    ))));
    manifests
});

/// Pre-rendered VictoriaMetrics single-node manifests with namespace prepended.
static PROMETHEUS_SINGLE_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-single.yaml"
    ))));
    manifests
});

/// VictoriaMetrics K8s Stack version (pinned at build time)
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Generate VictoriaMetrics K8s Stack manifests.
///
/// When `ha` is true, returns the HA VMCluster manifests (2 replicas each).
/// When `ha` is false, returns the single-node VMSingle manifests.
pub fn generate_prometheus(ha: bool) -> &'static [String] {
    if ha {
        &PROMETHEUS_HA_MANIFESTS
    } else {
        &PROMETHEUS_SINGLE_MANIFESTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = victoria_metrics_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
    }

    #[test]
    fn ha_manifests_are_embedded() {
        let manifests = generate_prometheus(true);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }

    #[test]
    fn single_manifests_are_embedded() {
        let manifests = generate_prometheus(false);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }

    #[test]
    fn query_helpers_return_correct_values() {
        assert_eq!(query_port(true), VMSELECT_PORT);
        assert_eq!(query_port(false), VMSINGLE_PORT);
        assert_eq!(query_path(true), VMSELECT_PATH);
        assert_eq!(query_path(false), VMSINGLE_PATH);
        assert!(query_url(true).contains("vmselect"));
        assert!(query_url(false).contains("vmsingle"));
    }
}
