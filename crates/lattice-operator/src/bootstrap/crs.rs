//! ClusterResourceSet-based bootstrap for clusters reachable from parent
//!
//! When the parent cluster can reach the child cluster's API server,
//! CRS provides a simpler and more reliable bootstrap mechanism than webhooks.
//! The parent pushes manifests directly via ClusterResourceSet.

use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use serde_json::json;
use tracing::info;

use super::{generate_all_manifests, DefaultManifestGenerator, ManifestConfig};
use crate::crd::{LatticeCluster, ProviderType};
use crate::Error;

/// Create and apply ClusterResourceSet to bootstrap a child cluster
///
/// This creates ConfigMaps containing the bootstrap manifests and a CRS
/// that applies them to the target cluster. Used when the parent can reach
/// the child cluster's API server directly.
pub async fn apply_bootstrap_crs(
    client: &Client,
    cluster: &LatticeCluster,
    image: &str,
    registry_credentials: Option<&str>,
    capmox_credentials: Option<(&str, &str, &str)>,
) -> Result<(), Error> {
    let cluster_name = cluster
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| Error::validation("cluster must have a name"))?;

    let namespace = format!("capi-{}", cluster_name);
    let provider_str = cluster.spec.provider.provider_type().to_string();
    let bootstrap_str = cluster.spec.provider.kubernetes.bootstrap.to_string();

    // Generate manifests using shared generator
    let generator = DefaultManifestGenerator::new();
    let config = ManifestConfig {
        image,
        registry_credentials,
        networking: cluster.spec.networking.as_ref(),
        cluster_name: Some(cluster_name),
        provider: Some(&provider_str),
        bootstrap: Some(&bootstrap_str),
        parent_host: None, // CRS clusters don't need parent connection for bootstrap
        parent_grpc_port: crate::DEFAULT_GRPC_PORT,
        relax_fips: cluster
            .spec
            .provider
            .kubernetes
            .bootstrap
            .needs_fips_relax(),
    };

    let all_manifests = generate_all_manifests(&generator, &config);

    // Separate YAML manifests (Cilium) from JSON manifests (operator)
    let yaml_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("---") || m.starts_with("apiVersion:"))
        .map(|s| s.as_str())
        .collect();

    let operator_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("{"))
        .map(|s| s.as_str())
        .collect();

    // Create Cilium ConfigMap
    let cilium_yaml = yaml_manifests.join("\n---\n");
    let cilium_cm = create_configmap_manifest("cilium-cni", &namespace, "cilium.yaml", &cilium_yaml);

    // Create operator ConfigMap with numbered manifest files
    let operator_data = create_operator_configmap_data(&operator_manifests);
    let operator_cm = json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "lattice-operator",
            "namespace": namespace
        },
        "data": operator_data
    });

    // Build CRS resources list
    let mut crs_resources = vec![
        json!({"kind": "ConfigMap", "name": "cilium-cni"}),
        json!({"kind": "ConfigMap", "name": "lattice-operator"}),
    ];

    // Add CAPMOX credentials if Proxmox provider
    let capmox_secret = if cluster.spec.provider.provider_type() == ProviderType::Proxmox {
        if let Some((url, token, secret)) = capmox_credentials {
            crs_resources.push(json!({"kind": "Secret", "name": "capmox-credentials"}));

            let capmox_manifests = super::capmox_credentials_manifests(url, token, secret);
            Some(json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "capmox-credentials",
                    "namespace": namespace
                },
                "type": "addons.cluster.x-k8s.io/resource-set",
                "stringData": {
                    "capmox.yaml": capmox_manifests
                }
            }))
        } else {
            None
        }
    } else {
        None
    };

    // Create ClusterResourceSet
    let crs = json!({
        "apiVersion": "addons.cluster.x-k8s.io/v1beta2",
        "kind": "ClusterResourceSet",
        "metadata": {
            "name": format!("{}-bootstrap", cluster_name),
            "namespace": namespace
        },
        "spec": {
            "strategy": "ApplyOnce",
            "clusterSelector": {
                "matchLabels": {
                    "cluster.x-k8s.io/cluster-name": cluster_name
                }
            },
            "resources": crs_resources
        }
    });

    // Apply all resources to parent cluster
    info!(cluster = %cluster_name, namespace = %namespace, "applying CRS bootstrap resources");

    apply_json_resource(client, &cilium_cm).await?;
    apply_json_resource(client, &operator_cm).await?;
    if let Some(ref secret) = capmox_secret {
        apply_json_resource(client, secret).await?;
    }
    apply_json_resource(client, &crs).await?;

    info!(cluster = %cluster_name, "CRS bootstrap resources applied");
    Ok(())
}

fn create_configmap_manifest(name: &str, namespace: &str, key: &str, data: &str) -> serde_json::Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "data": {
            key: data
        }
    })
}

fn create_operator_configmap_data(manifests: &[&str]) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    for (i, manifest) in manifests.iter().enumerate() {
        let key = format!("{:02}-manifest.json", i + 1);
        data.insert(key, json!(manifest));
    }
    serde_json::Value::Object(data)
}

async fn apply_json_resource(client: &Client, resource: &serde_json::Value) -> Result<(), Error> {
    let api_version = resource["apiVersion"]
        .as_str()
        .ok_or_else(|| Error::validation("resource missing apiVersion"))?;
    let kind = resource["kind"]
        .as_str()
        .ok_or_else(|| Error::validation("resource missing kind"))?;
    let name = resource["metadata"]["name"]
        .as_str()
        .ok_or_else(|| Error::validation("resource missing metadata.name"))?;
    let namespace = resource["metadata"]["namespace"].as_str();

    // Use dynamic API for generic resource application
    let gvk = parse_gvk(api_version, kind)?;
    let api_resource = kube::discovery::ApiResource::from_gvk(&gvk);

    let api: Api<kube::api::DynamicObject> = if let Some(ns) = namespace {
        Api::namespaced_with(client.clone(), ns, &api_resource)
    } else {
        Api::all_with(client.clone(), &api_resource)
    };

    let patch_params = PatchParams::apply("lattice-crs").force();
    api.patch(name, &patch_params, &Patch::Apply(resource))
        .await
        .map_err(|e| Error::Bootstrap(e.to_string()))?;

    Ok(())
}

fn parse_gvk(api_version: &str, kind: &str) -> Result<kube::api::GroupVersionKind, Error> {
    let (group, version) = if api_version.contains('/') {
        let parts: Vec<&str> = api_version.splitn(2, '/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    };

    Ok(kube::api::GroupVersionKind {
        group,
        version,
        kind: kind.to_string(),
    })
}

/// Generate CRS YAML manifests for CLI usage
///
/// Returns a vector of YAML strings that can be applied via kubectl:
/// - ConfigMap for Cilium CNI
/// - ConfigMap for Lattice operator
/// - Secret for CAPMOX credentials (if Proxmox provider)
/// - ClusterResourceSet
///
/// This allows the CLI to share CRS generation logic with the operator.
pub fn generate_crs_yaml_manifests(
    cluster_name: &str,
    namespace: &str,
    all_manifests: &[String],
    capmox_credentials: Option<(&str, &str, &str)>,
) -> Vec<String> {
    let mut result = Vec::new();

    // Separate YAML manifests (Cilium) from JSON manifests (operator)
    let yaml_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("---") || m.starts_with("apiVersion:"))
        .map(|s| s.as_str())
        .collect();

    let operator_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("{"))
        .map(|s| s.as_str())
        .collect();

    // Cilium ConfigMap
    let cilium_yaml = yaml_manifests.join("\n---\n");
    let cilium_data_indented = cilium_yaml
        .lines()
        .map(|l| format!("    {}", l))
        .collect::<Vec<_>>()
        .join("\n");
    result.push(format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-cni
  namespace: {namespace}
data:
  cilium.yaml: |
{cilium_data}"#,
        namespace = namespace,
        cilium_data = cilium_data_indented
    ));

    // Operator ConfigMap with numbered manifest files
    let mut operator_data_keys = String::new();
    for (i, manifest) in operator_manifests.iter().enumerate() {
        let key_name = format!("{:02}-manifest.json", i + 1);
        let indented = manifest
            .lines()
            .map(|l| format!("    {}", l))
            .collect::<Vec<_>>()
            .join("\n");
        operator_data_keys.push_str(&format!("  {}: |\n{}\n", key_name, indented));
    }
    result.push(format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: lattice-operator
  namespace: {namespace}
data:
{operator_data}"#,
        namespace = namespace,
        operator_data = operator_data_keys.trim_end()
    ));

    // Build CRS resources list
    let mut crs_resources = String::from(
        r#"    - kind: ConfigMap
      name: cilium-cni
    - kind: ConfigMap
      name: lattice-operator"#,
    );

    // CAPMOX credentials secret if provided
    if let Some((url, token, secret)) = capmox_credentials {
        crs_resources.push_str(
            r#"
    - kind: Secret
      name: capmox-credentials"#,
        );

        let capmox_manifests = super::capmox_credentials_manifests(url, token, secret);
        let capmox_data_indented = capmox_manifests
            .lines()
            .map(|l| format!("    {}", l))
            .collect::<Vec<_>>()
            .join("\n");

        result.push(format!(
            r#"apiVersion: v1
kind: Secret
metadata:
  name: capmox-credentials
  namespace: {namespace}
type: addons.cluster.x-k8s.io/resource-set
stringData:
  capmox.yaml: |
{capmox_data}"#,
            namespace = namespace,
            capmox_data = capmox_data_indented
        ));
    }

    // ClusterResourceSet
    result.push(format!(
        r#"apiVersion: addons.cluster.x-k8s.io/v1beta2
kind: ClusterResourceSet
metadata:
  name: {cluster_name}-bootstrap
  namespace: {namespace}
spec:
  strategy: ApplyOnce
  clusterSelector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: {cluster_name}
  resources:
{crs_resources}"#,
        cluster_name = cluster_name,
        namespace = namespace,
        crs_resources = crs_resources
    ));

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_configmap_manifest() {
        let cm = create_configmap_manifest("test-cm", "test-ns", "config.yaml", "key: value");

        assert_eq!(cm["apiVersion"], "v1");
        assert_eq!(cm["kind"], "ConfigMap");
        assert_eq!(cm["metadata"]["name"], "test-cm");
        assert_eq!(cm["metadata"]["namespace"], "test-ns");
        assert_eq!(cm["data"]["config.yaml"], "key: value");
    }

    #[test]
    fn test_create_configmap_manifest_multiline_data() {
        let data = "line1\nline2\nline3";
        let cm = create_configmap_manifest("multi", "ns", "file.txt", data);

        assert_eq!(cm["data"]["file.txt"], data);
    }

    #[test]
    fn test_create_operator_configmap_data_empty() {
        let manifests: Vec<&str> = vec![];
        let data = create_operator_configmap_data(&manifests);

        assert!(data.is_object());
        assert!(data.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_create_operator_configmap_data_single_manifest() {
        let manifests = vec![r#"{"kind": "Deployment"}"#];
        let data = create_operator_configmap_data(&manifests);

        assert!(data.is_object());
        let obj = data.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("01-manifest.json"));
        assert_eq!(obj["01-manifest.json"], r#"{"kind": "Deployment"}"#);
    }

    #[test]
    fn test_create_operator_configmap_data_multiple_manifests() {
        let manifests = vec![
            r#"{"kind": "Namespace"}"#,
            r#"{"kind": "ServiceAccount"}"#,
            r#"{"kind": "Deployment"}"#,
        ];
        let data = create_operator_configmap_data(&manifests);

        let obj = data.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(obj["01-manifest.json"], r#"{"kind": "Namespace"}"#);
        assert_eq!(obj["02-manifest.json"], r#"{"kind": "ServiceAccount"}"#);
        assert_eq!(obj["03-manifest.json"], r#"{"kind": "Deployment"}"#);
    }

    #[test]
    fn test_create_operator_configmap_data_numbering_pads_zeros() {
        // Test that numbers are zero-padded for proper sorting
        let manifests: Vec<&str> = (0..12).map(|_| r#"{"kind": "ConfigMap"}"#).collect();
        let data = create_operator_configmap_data(&manifests);

        let obj = data.as_object().unwrap();
        assert_eq!(obj.len(), 12);
        // Check that keys are properly padded
        assert!(obj.contains_key("01-manifest.json"));
        assert!(obj.contains_key("09-manifest.json"));
        assert!(obj.contains_key("10-manifest.json"));
        assert!(obj.contains_key("12-manifest.json"));
    }

    #[test]
    fn test_parse_gvk_core_api() {
        let gvk = parse_gvk("v1", "ConfigMap").unwrap();

        assert_eq!(gvk.group, "");
        assert_eq!(gvk.version, "v1");
        assert_eq!(gvk.kind, "ConfigMap");
    }

    #[test]
    fn test_parse_gvk_with_group() {
        let gvk = parse_gvk("apps/v1", "Deployment").unwrap();

        assert_eq!(gvk.group, "apps");
        assert_eq!(gvk.version, "v1");
        assert_eq!(gvk.kind, "Deployment");
    }

    #[test]
    fn test_parse_gvk_capi_group() {
        let gvk = parse_gvk("addons.cluster.x-k8s.io/v1beta2", "ClusterResourceSet").unwrap();

        assert_eq!(gvk.group, "addons.cluster.x-k8s.io");
        assert_eq!(gvk.version, "v1beta2");
        assert_eq!(gvk.kind, "ClusterResourceSet");
    }

    #[test]
    fn test_parse_gvk_networking_group() {
        let gvk = parse_gvk("networking.k8s.io/v1", "NetworkPolicy").unwrap();

        assert_eq!(gvk.group, "networking.k8s.io");
        assert_eq!(gvk.version, "v1");
        assert_eq!(gvk.kind, "NetworkPolicy");
    }

    #[test]
    fn test_generate_crs_yaml_manifests_basic() {
        let all_manifests = vec![
            "---\napiVersion: v1\nkind: ConfigMap".to_string(),
            r#"{"kind": "Deployment"}"#.to_string(),
        ];

        let result = generate_crs_yaml_manifests("my-cluster", "capi-my-cluster", &all_manifests, None);

        assert_eq!(result.len(), 3); // cilium cm, operator cm, crs

        // Check cilium ConfigMap
        assert!(result[0].contains("kind: ConfigMap"));
        assert!(result[0].contains("name: cilium-cni"));
        assert!(result[0].contains("namespace: capi-my-cluster"));

        // Check operator ConfigMap
        assert!(result[1].contains("kind: ConfigMap"));
        assert!(result[1].contains("name: lattice-operator"));
        assert!(result[1].contains("01-manifest.json"));

        // Check ClusterResourceSet
        assert!(result[2].contains("kind: ClusterResourceSet"));
        assert!(result[2].contains("name: my-cluster-bootstrap"));
        assert!(result[2].contains("cluster.x-k8s.io/cluster-name: my-cluster"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_with_capmox() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests(
            "proxmox-cluster",
            "capi-proxmox-cluster",
            &all_manifests,
            Some(("https://proxmox.local:8006", "user@pve!token", "secret123")),
        );

        assert_eq!(result.len(), 4); // cilium cm, operator cm, capmox secret, crs

        // Check CAPMOX secret is present
        assert!(result[2].contains("kind: Secret"));
        assert!(result[2].contains("name: capmox-credentials"));
        assert!(result[2].contains("type: addons.cluster.x-k8s.io/resource-set"));

        // Check CRS references the secret
        assert!(result[3].contains("name: capmox-credentials"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_separates_yaml_and_json() {
        let all_manifests = vec![
            "---\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy".to_string(),
            "apiVersion: v1\nkind: Namespace".to_string(),
            r#"{"apiVersion": "v1", "kind": "ServiceAccount"}"#.to_string(),
            r#"{"apiVersion": "apps/v1", "kind": "Deployment"}"#.to_string(),
        ];

        let result = generate_crs_yaml_manifests("test", "capi-test", &all_manifests, None);

        // Cilium CM should have YAML manifests
        assert!(result[0].contains("CiliumNetworkPolicy"));
        assert!(result[0].contains("kind: Namespace"));

        // Operator CM should have JSON manifests
        assert!(result[1].contains("01-manifest.json"));
        assert!(result[1].contains("02-manifest.json"));
        assert!(result[1].contains("ServiceAccount"));
        assert!(result[1].contains("Deployment"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_crs_strategy() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests("cluster", "ns", &all_manifests, None);

        // Verify CRS uses ApplyOnce strategy
        assert!(result[2].contains("strategy: ApplyOnce"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_cluster_selector() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests("target-cluster", "capi-target", &all_manifests, None);

        // CRS should select the correct cluster
        let crs = &result[2];
        assert!(crs.contains("clusterSelector:"));
        assert!(crs.contains("matchLabels:"));
        assert!(crs.contains("cluster.x-k8s.io/cluster-name: target-cluster"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_empty_inputs() {
        let all_manifests: Vec<String> = vec![];

        let result = generate_crs_yaml_manifests("empty", "capi-empty", &all_manifests, None);

        // Should still generate valid structures even with no manifests
        assert_eq!(result.len(), 3);
        assert!(result[0].contains("name: cilium-cni"));
        assert!(result[1].contains("name: lattice-operator"));
        assert!(result[2].contains("kind: ClusterResourceSet"));
    }
}
