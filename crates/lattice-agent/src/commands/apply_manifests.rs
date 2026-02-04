//! Apply manifests command handler.

use lattice_proto::ApplyManifestsCommand;
use tracing::{error, info};

use super::CommandContext;

/// Handle an apply manifests command from the cell.
pub async fn handle(cmd: &ApplyManifestsCommand, ctx: &CommandContext) {
    info!(
        manifests = cmd.manifests.len(),
        "Received apply manifests command"
    );

    if cmd.manifests.is_empty() {
        info!("No manifests to apply");
        return;
    }

    let Some(client) =
        crate::kube_client::create_client_logged(ctx.kube_provider.as_ref(), "apply manifests")
            .await
    else {
        return;
    };

    let manifests_count = cmd.manifests.len();
    let mut applied = 0;
    let mut errors = Vec::new();

    for (i, manifest) in cmd.manifests.iter().enumerate() {
        match String::from_utf8(manifest.clone()) {
            Ok(yaml) => {
                let (kind, name) = extract_manifest_info(&yaml);
                if let Err(e) = apply_manifest(&client, &yaml).await {
                    error!(
                        error = %e,
                        manifest_index = i,
                        kind = kind,
                        name = name,
                        "Failed to apply manifest"
                    );
                    errors.push(format!("{}/{}: {}", kind, name, e));
                } else {
                    applied += 1;
                }
            }
            Err(e) => {
                error!(error = %e, manifest_index = i, "Invalid UTF-8 in manifest");
                errors.push(format!("manifest {}: invalid UTF-8: {}", i, e));
            }
        }
    }

    info!(
        total = manifests_count,
        applied = applied,
        errors = errors.len(),
        "Manifests applied"
    );
}

/// Extract kind and name from a YAML/JSON manifest string for logging.
pub fn extract_manifest_info(yaml: &str) -> (String, String) {
    extract_manifest_info_from_value(lattice_common::yaml::parse_yaml(yaml).ok())
}

/// Extract kind and name from manifest bytes for logging.
pub fn extract_manifest_info_bytes(bytes: &[u8]) -> (String, String) {
    extract_manifest_info_from_value(serde_json::from_slice(bytes).ok())
}

/// Extract kind and name from a parsed JSON value.
fn extract_manifest_info_from_value(value: Option<serde_json::Value>) -> (String, String) {
    match value {
        Some(v) => {
            let kind = v["kind"].as_str().unwrap_or("unknown").to_string();
            let name = v["metadata"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            (kind, name)
        }
        None => ("invalid".to_string(), "invalid".to_string()),
    }
}

/// Apply a Kubernetes manifest using kube-rs server-side apply.
pub async fn apply_manifest(client: &kube::Client, yaml: &str) -> Result<(), std::io::Error> {
    use kube::api::{Api, Patch, PatchParams};
    use kube::core::DynamicObject;

    let value = lattice_common::yaml::parse_yaml(yaml)
        .map_err(|e| std::io::Error::other(format!("Invalid YAML: {}", e)))?;

    let api_version = value["apiVersion"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("Missing apiVersion"))?
        .to_string();
    let kind = value["kind"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("Missing kind"))?
        .to_string();
    let name = value["metadata"]["name"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("Missing metadata.name"))?
        .to_string();
    let namespace = value["metadata"]["namespace"]
        .as_str()
        .map(|s| s.to_string());

    tracing::debug!(
        api_version = %api_version,
        kind = %kind,
        name = %name,
        namespace = ?namespace,
        "Applying manifest via kube-rs"
    );

    let ar = lattice_common::kube_utils::build_api_resource(&api_version, &kind);

    let obj: DynamicObject = serde_json::from_value(value)
        .map_err(|e| std::io::Error::other(format!("Failed to parse manifest: {}", e)))?;

    let api: Api<DynamicObject> = if let Some(ns) = &namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else {
        Api::all_with(client.clone(), &ar)
    };

    api.patch(
        &name,
        &PatchParams::apply("lattice-agent").force(),
        &Patch::Apply(&obj),
    )
    .await
    .map_err(|e| std::io::Error::other(format!("Server-side apply failed: {}", e)))?;

    tracing::debug!(name = %name, kind = %kind, "Manifest applied successfully");
    Ok(())
}

/// Apply a list of manifests (bytes) using server-side apply.
pub async fn apply_manifests(client: &kube::Client, manifests: &[Vec<u8>]) -> Result<(), String> {
    for manifest_bytes in manifests {
        let yaml = String::from_utf8(manifest_bytes.clone())
            .map_err(|e| format!("Invalid UTF-8 in manifest: {}", e))?;
        apply_manifest(client, &yaml)
            .await
            .map_err(|e| format!("Failed to apply manifest: {}", e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_manifest_info() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: default
"#;
        let (kind, name) = extract_manifest_info(yaml);
        assert_eq!(kind, "ConfigMap");
        assert_eq!(name, "my-config");
    }

    #[test]
    fn test_extract_manifest_info_bytes() {
        let json = br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}"#;
        let (kind, name) = extract_manifest_info_bytes(json);
        assert_eq!(kind, "Pod");
        assert_eq!(name, "test-pod");
    }

    #[test]
    fn test_extract_manifest_info_invalid_json() {
        // For invalid JSON bytes, we get "invalid"
        let (kind, name) = extract_manifest_info_bytes(b"not valid json");
        assert_eq!(kind, "invalid");
        assert_eq!(name, "invalid");
    }

    #[test]
    fn test_extract_manifest_info_plain_string() {
        // Plain YAML string (not a map) parses successfully but has no kind/name
        let (kind, name) = extract_manifest_info("just a string");
        assert_eq!(kind, "unknown");
        assert_eq!(name, "unknown");
    }

    #[test]
    fn test_extract_manifest_info_missing_fields() {
        let yaml = "apiVersion: v1\n";
        let (kind, name) = extract_manifest_info(yaml);
        assert_eq!(kind, "unknown");
        assert_eq!(name, "unknown");
    }
}
