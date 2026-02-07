//! Velero manifest generation
//!
//! Embeds pre-rendered Velero manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Pre-rendered Velero manifests with namespace prepended.
static VELERO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("velero")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/velero.yaml"
    ))));
    manifests
});

/// Velero version (pinned at build time)
pub fn velero_version() -> &'static str {
    env!("VELERO_VERSION")
}

/// Generate Velero manifests
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_velero() -> &'static [String] {
    &VELERO_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = velero_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml("velero");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: velero"));
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_velero();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
