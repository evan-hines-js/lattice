//! Kthena Helm chart embedding for disaggregated model serving
//!
//! Provides pre-rendered Kthena manifests for model serving workloads.
//! Kthena is always installed as core infrastructure (required for LatticeModel).

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

static KTHENA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("kthena-system")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/kthena.yaml"
    ))));
    manifests
});

pub fn kthena_version() -> &'static str {
    env!("KTHENA_VERSION")
}

/// Pre-rendered Kthena Helm chart manifests
pub fn generate_kthena() -> &'static [String] {
    &KTHENA_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!kthena_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_kthena();
        assert!(!m.is_empty());
    }

    #[test]
    fn namespace_is_first_manifest() {
        let m = generate_kthena();
        assert!(
            m[0].contains("kthena-system"),
            "First manifest should create the kthena-system namespace"
        );
    }
}
