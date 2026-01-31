//! External Secrets Operator (ESO) manifest generation
//!
//! Generates ESO manifests for secret synchronization from external providers.

use tokio::process::Command;
use tracing::info;

use super::{charts_dir, namespace_yaml, split_yaml_documents};

/// ESO version (pinned at build time)
pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

/// Generate ESO manifests using helm template
pub async fn generate_eso() -> Result<Vec<String>, String> {
    let version = eso_version();
    let charts = charts_dir();
    let chart_path = format!("{}/external-secrets-{}.tgz", charts, version);

    info!(version, "Rendering ESO chart");

    let output = Command::new("helm")
        .args([
            "template",
            "external-secrets",
            &chart_path,
            "--namespace",
            "external-secrets",
            "--set",
            "installCRDs=true",
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run helm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("helm template external-secrets failed: {}", stderr));
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("external-secrets")];
    manifests.extend(split_yaml_documents(&yaml));

    info!(count = manifests.len(), "Rendered ESO manifests");
    Ok(manifests)
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
}
