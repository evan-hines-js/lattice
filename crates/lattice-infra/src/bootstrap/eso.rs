//! External Secrets Operator (ESO) manifest generation
//!
//! Embeds pre-rendered ESO manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Pre-rendered ESO manifests with namespace prepended.
static ESO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("external-secrets")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/external-secrets.yaml"
    ))));
    manifests
});

/// ESO version (pinned at build time)
pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

/// Generate ESO manifests
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_eso() -> &'static [String] {
    &ESO_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = eso_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn namespace_is_correct() {
        let ns = namespace_yaml("external-secrets");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: external-secrets"));
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_eso();
        assert!(!manifests.is_empty());
        // First manifest should be the namespace
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
