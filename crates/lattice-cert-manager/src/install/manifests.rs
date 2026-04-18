//! cert-manager helm chart manifests.

use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::namespace_yaml;

static CERT_MANAGER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("cert-manager")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/cert-manager.yaml"
    ))));
    manifests
});

/// cert-manager chart version pinned at build time from `versions.toml`.
pub fn cert_manager_version() -> &'static str {
    env!("CERT_MANAGER_VERSION")
}

/// Pre-rendered cert-manager helm chart manifests, including the namespace.
pub fn generate_cert_manager() -> &'static [String] {
    &CERT_MANAGER_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!cert_manager_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_cert_manager();
        assert!(!m.is_empty());
        assert!(m[0].contains("kind: Namespace"));
    }

    #[test]
    fn webhook_deployment_present() {
        let m = generate_cert_manager();
        assert!(
            m.iter().any(|doc| doc.contains("kind: Deployment") && doc.contains("cert-manager-webhook")),
            "cert-manager-webhook Deployment must be present — it gates cert issuance cluster-wide"
        );
    }
}
