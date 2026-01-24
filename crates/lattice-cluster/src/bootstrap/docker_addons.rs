//! Docker-specific addon manifests
//!
//! Generates local-path-provisioner for Docker/kind clusters.
//! These are included in the bootstrap manifests via `generate_all_manifests()`.

use minijinja::{context, Environment};

/// Local path provisioner version
const LOCAL_PATH_PROVISIONER_VERSION: &str = "v0.0.30";

/// Local path provisioner template loaded at compile time
const LOCAL_PATH_TEMPLATE: &str = include_str!("../../templates/local-path-provisioner.yaml");

fn render_template(template: &str, version: &str) -> String {
    let mut env = Environment::new();
    env.add_template("manifest", template)
        .expect("Invalid template");
    env.get_template("manifest")
        .expect("Template not found")
        .render(context! { version => version })
        .expect("Failed to render template")
}

/// Generate local-path-provisioner manifest YAML.
///
/// Provides a default StorageClass named "standard" for PVC provisioning.
fn generate_local_path_manifest() -> String {
    render_template(LOCAL_PATH_TEMPLATE, LOCAL_PATH_PROVISIONER_VERSION)
}

/// Generate all Docker addon manifests (local-path-provisioner) as raw YAML.
///
/// Returns a single YAML string with all resources separated by `---`.
/// Used by `generate_all_manifests()` to include Docker addons in bootstrap.
pub fn generate_docker_addon_manifests() -> String {
    generate_local_path_manifest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_path_manifest_contains_required_resources() {
        let manifest = generate_local_path_manifest();

        assert!(manifest.contains("kind: Namespace"));
        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: ClusterRole"));
        assert!(manifest.contains("kind: ClusterRoleBinding"));
        assert!(manifest.contains("kind: Deployment"));
        assert!(manifest.contains("kind: StorageClass"));
        assert!(manifest.contains("kind: ConfigMap"));
        assert!(manifest.contains("rancher/local-path-provisioner"));
        assert!(manifest.contains(LOCAL_PATH_PROVISIONER_VERSION));
    }

    #[test]
    fn storage_class_is_default() {
        let manifest = generate_local_path_manifest();

        assert!(manifest.contains("name: standard"));
        assert!(manifest.contains("storageclass.kubernetes.io/is-default-class: \"true\""));
    }

    #[test]
    fn provisioner_name_correct() {
        let manifest = generate_local_path_manifest();

        assert!(manifest.contains("provisioner: rancher.io/local-path"));
    }
}
