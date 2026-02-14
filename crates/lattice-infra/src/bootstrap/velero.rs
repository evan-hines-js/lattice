//! Velero manifest generation
//!
//! Embeds pre-rendered Velero manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

static VELERO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("velero")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/velero.yaml"
    ))));
    manifests
});

pub fn velero_version() -> &'static str {
    env!("VELERO_VERSION")
}

pub fn generate_velero() -> &'static [String] {
    &VELERO_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!velero_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_velero();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
