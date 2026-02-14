//! External Secrets Operator (ESO) manifest generation
//!
//! Embeds pre-rendered ESO manifests from build time.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

static ESO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("external-secrets")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/external-secrets.yaml"
    ))));
    manifests
});

pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

pub fn generate_eso() -> &'static [String] {
    &ESO_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!eso_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_eso();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
    }
}
