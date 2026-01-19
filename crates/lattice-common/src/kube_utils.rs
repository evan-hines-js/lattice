//! Shared Kubernetes utilities using kube-rs
//!
//! Provides kubectl-equivalent operations without shelling out to kubectl.
//! FIPS compliant - no external binaries needed.

use std::path::Path;
use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Node, Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::discovery::ApiResource;
use kube::{Client, Config};
use tracing::info;

use crate::Error;

/// Create a kube client from optional kubeconfig path
pub async fn create_client(kubeconfig: Option<&Path>) -> Result<Client, Error> {
    match kubeconfig {
        Some(path) => {
            let kubeconfig = Kubeconfig::read_from(path)
                .map_err(|e| Error::Internal(format!("failed to read kubeconfig: {}", e)))?;
            let config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                .await
                .map_err(|e| Error::Internal(format!("failed to load kubeconfig: {}", e)))?;
            Client::try_from(config)
                .map_err(|e| Error::Internal(format!("failed to create client: {}", e)))
        }
        None => Client::try_default()
            .await
            .map_err(|e| Error::Internal(format!("failed to create client: {}", e))),
    }
}

/// Wait for all nodes to be ready
pub async fn wait_for_nodes_ready(client: &Client, timeout: Duration) -> Result<(), Error> {
    let start = std::time::Instant::now();
    let nodes: Api<Node> = Api::all(client.clone());

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal("Timeout waiting for nodes to be ready".into()));
        }

        let node_list = nodes
            .list(&ListParams::default())
            .await
            .map_err(|e| Error::Internal(format!("Failed to list nodes: {}", e)))?;

        let all_ready = node_list.items.iter().all(|node| {
            node.status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Ready" && c.status == "True")
                })
                .unwrap_or(false)
        });

        if all_ready && !node_list.items.is_empty() {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Wait for a deployment to be available
pub async fn wait_for_deployment(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let start = std::time::Instant::now();
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal(format!(
                "Timeout waiting for deployment {} to be available",
                name
            )));
        }

        match deployments.get(name).await {
            Ok(deployment) => {
                let available = deployment
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .map(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Available" && c.status == "True")
                    })
                    .unwrap_or(false);

                if available {
                    return Ok(());
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                // Deployment doesn't exist yet, keep waiting
            }
            Err(e) => {
                return Err(Error::Internal(format!(
                    "Failed to get deployment {}: {}",
                    name, e
                )));
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Wait for all deployments in a namespace to be available
pub async fn wait_for_all_deployments(
    client: &Client,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let start = std::time::Instant::now();
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal(format!(
                "Timeout waiting for deployments in {} to be available",
                namespace
            )));
        }

        let deployment_list = deployments
            .list(&ListParams::default())
            .await
            .map_err(|e| Error::Internal(format!("Failed to list deployments: {}", e)))?;

        if deployment_list.items.is_empty() {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let all_available = deployment_list.items.iter().all(|deployment| {
            deployment
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Available" && c.status == "True")
                })
                .unwrap_or(false)
        });

        if all_available {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Check if a CRD exists
pub async fn crd_exists(client: &Client, crd_name: &str) -> Result<bool, Error> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    match crds.get(crd_name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::Internal(format!(
            "Failed to check CRD {}: {}",
            crd_name, e
        ))),
    }
}

/// Wait for a CRD to be available
pub async fn wait_for_crd(client: &Client, crd_name: &str, timeout: Duration) -> Result<(), Error> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal(format!(
                "Timeout waiting for CRD: {}",
                crd_name
            )));
        }

        if crd_exists(client, crd_name).await? {
            info!("CRD ready: {}", crd_name);
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Create a namespace (idempotent)
pub async fn create_namespace(client: &Client, name: &str) -> Result<(), Error> {
    let namespaces: Api<Namespace> = Api::all(client.clone());

    let ns = Namespace {
        metadata: kube::core::ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    match namespaces.create(&PostParams::default(), &ns).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(()), // Already exists
        Err(e) => Err(Error::Internal(format!(
            "Failed to create namespace {}: {}",
            name, e
        ))),
    }
}

/// Parsed manifest metadata for applying to Kubernetes
#[derive(Debug, Clone)]
pub struct ManifestMetadata {
    /// The parsed JSON value
    pub value: serde_json::Value,
    /// Resource name
    pub name: String,
    /// Optional namespace
    pub namespace: Option<String>,
    /// API resource definition
    pub api_resource: ApiResource,
}

/// Parse a manifest and extract its metadata
pub fn parse_manifest(manifest: &str) -> Result<ManifestMetadata, Error> {
    // Parse the manifest - try JSON first, then YAML
    let value: serde_json::Value = if manifest.trim().starts_with('{') {
        serde_json::from_str(manifest)
            .map_err(|e| Error::Internal(format!("Failed to parse manifest as JSON: {}", e)))?
    } else {
        serde_yaml::from_str(manifest)
            .map_err(|e| Error::Internal(format!("Failed to parse manifest as YAML: {}", e)))?
    };

    let api_version = value
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Internal("Manifest missing apiVersion".into()))?
        .to_string();

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Internal("Manifest missing kind".into()))?
        .to_string();

    let name = value
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Internal("Manifest missing metadata.name".into()))?
        .to_string();

    let namespace = value
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse apiVersion into group and version
    let (group, version) = parse_api_version(&api_version);

    // Build the plural form
    let plural = pluralize(&kind);

    let api_resource = ApiResource {
        group,
        version,
        kind,
        api_version,
        plural,
    };

    Ok(ManifestMetadata {
        value,
        name,
        namespace,
        api_resource,
    })
}

/// Parse apiVersion into (group, version)
fn parse_api_version(api_version: &str) -> (String, String) {
    if api_version.contains('/') {
        let parts: Vec<&str> = api_version.split('/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    }
}

/// Apply a manifest using server-side apply
pub async fn apply_manifest(client: &Client, manifest: &str) -> Result<(), Error> {
    let metadata = parse_manifest(manifest)?;
    let patch_params = PatchParams::apply("lattice").force();

    if let Some(ns) = &metadata.namespace {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &metadata.api_resource);
        api.patch(&metadata.name, &patch_params, &Patch::Apply(&metadata.value))
            .await
            .map_err(|e| Error::Internal(format!("Failed to apply {}/{}: {}", metadata.api_resource.kind, metadata.name, e)))?;
    } else {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &metadata.api_resource);
        api.patch(&metadata.name, &patch_params, &Patch::Apply(&metadata.value))
            .await
            .map_err(|e| Error::Internal(format!("Failed to apply {}/{}: {}", metadata.api_resource.kind, metadata.name, e)))?;
    }

    Ok(())
}

/// Apply a manifest with retry
pub async fn apply_manifest_with_retry(
    client: &Client,
    manifest: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let start = std::time::Instant::now();
    let mut last_error = String::new();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal(format!(
                "Timeout waiting for apply: {}",
                last_error
            )));
        }

        match apply_manifest(client, manifest).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_error = e.to_string();
                info!("Apply failed (retrying): {}", last_error);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Get a secret data value
pub async fn get_secret_data(
    client: &Client,
    name: &str,
    namespace: &str,
    key: &str,
) -> Result<Vec<u8>, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let secret = secrets
        .get(name)
        .await
        .map_err(|e| Error::Internal(format!("Failed to get secret {}/{}: {}", namespace, name, e)))?;

    let data = secret
        .data
        .as_ref()
        .and_then(|d| d.get(key))
        .ok_or_else(|| Error::Internal(format!("Secret {}/{} missing key {}", namespace, name, key)))?;

    Ok(data.0.clone())
}

/// Check if a secret exists
pub async fn secret_exists(client: &Client, name: &str, namespace: &str) -> Result<bool, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    match secrets.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::Internal(format!(
            "Failed to check secret {}/{}: {}",
            namespace, name, e
        ))),
    }
}

/// Wait for a secret to exist
pub async fn wait_for_secret(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Internal(format!(
                "Timeout waiting for secret {}/{}",
                namespace, name
            )));
        }

        if secret_exists(client, name, namespace).await? {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Get a dynamic resource field value
pub async fn get_dynamic_resource_status_field(
    client: &Client,
    ar: &ApiResource,
    name: &str,
    namespace: Option<&str>,
    field: &str,
) -> Result<Option<String>, Error> {
    let result = if let Some(ns) = namespace {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, ar);
        api.get(name).await
    } else {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
        api.get(name).await
    };

    match result {
        Ok(obj) => {
            let value = obj
                .data
                .get("status")
                .and_then(|s| s.get(field))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(value)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
        Err(e) => Err(Error::Internal(format!("Failed to get {}/{}: {}", ar.kind, name, e))),
    }
}

/// Get machine phases in a namespace
pub async fn get_machine_phases(client: &Client, namespace: &str) -> Result<Vec<String>, Error> {
    let ar = ApiResource {
        group: "cluster.x-k8s.io".to_string(),
        version: "v1beta1".to_string(),
        kind: "Machine".to_string(),
        api_version: "cluster.x-k8s.io/v1beta1".to_string(),
        plural: "machines".to_string(),
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let machines = api
        .list(&ListParams::default())
        .await
        .map_err(|e| Error::Internal(format!("Failed to list machines: {}", e)))?;

    let phases: Vec<String> = machines
        .items
        .iter()
        .filter_map(|m| {
            m.data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    Ok(phases)
}

/// Get count of ready worker nodes (excludes control-plane)
pub async fn get_ready_worker_count(client: &Client) -> Result<usize, Error> {
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| Error::Internal(format!("Failed to list nodes: {}", e)))?;

    let ready_workers = node_list.items.iter().filter(|node| {
        // Check if it's a worker (no control-plane label)
        let is_worker = node
            .metadata
            .labels
            .as_ref()
            .map(|labels| !labels.contains_key("node-role.kubernetes.io/control-plane"))
            .unwrap_or(true);

        // Check if Ready
        let is_ready = node
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .map(|conditions| {
                conditions
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
            .unwrap_or(false);

        is_worker && is_ready
    });

    Ok(ready_workers.count())
}

/// Simple pluralization for Kubernetes resource kinds
fn pluralize(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with("s") {
        format!("{}es", lower)
    } else if lower.ends_with("y") {
        format!("{}ies", lower[..lower.len() - 1].to_string())
    } else {
        format!("{}s", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pluralize() {
        assert_eq!(pluralize("Deployment"), "deployments");
        assert_eq!(pluralize("Pod"), "pods");
        assert_eq!(pluralize("Policy"), "policies");
        assert_eq!(pluralize("ClusterResourceSet"), "clusterresourcesets");
        assert_eq!(pluralize("Ingress"), "ingresses");
        assert_eq!(pluralize("Service"), "services");
        assert_eq!(pluralize("ConfigMap"), "configmaps");
        assert_eq!(pluralize("Secret"), "secrets");
        assert_eq!(pluralize("NetworkPolicy"), "networkpolicies");
    }

    #[test]
    fn test_parse_api_version_with_group() {
        let (group, version) = parse_api_version("apps/v1");
        assert_eq!(group, "apps");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_core() {
        let (group, version) = parse_api_version("v1");
        assert_eq!(group, "");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_crd() {
        let (group, version) = parse_api_version("lattice.io/v1alpha1");
        assert_eq!(group, "lattice.io");
        assert_eq!(version, "v1alpha1");
    }

    #[test]
    fn test_parse_manifest_yaml_deployment() {
        let manifest = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
"#;
        let meta = parse_manifest(manifest).unwrap();
        assert_eq!(meta.name, "my-app");
        assert_eq!(meta.namespace, Some("default".to_string()));
        assert_eq!(meta.api_resource.kind, "Deployment");
        assert_eq!(meta.api_resource.group, "apps");
        assert_eq!(meta.api_resource.version, "v1");
        assert_eq!(meta.api_resource.plural, "deployments");
    }

    #[test]
    fn test_parse_manifest_json() {
        let manifest = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-config"}}"#;
        let meta = parse_manifest(manifest).unwrap();
        assert_eq!(meta.name, "my-config");
        assert_eq!(meta.namespace, None);
        assert_eq!(meta.api_resource.kind, "ConfigMap");
        assert_eq!(meta.api_resource.group, "");
        assert_eq!(meta.api_resource.version, "v1");
    }

    #[test]
    fn test_parse_manifest_cluster_scoped() {
        let manifest = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
"#;
        let meta = parse_manifest(manifest).unwrap();
        assert_eq!(meta.name, "my-namespace");
        assert_eq!(meta.namespace, None);
        assert_eq!(meta.api_resource.kind, "Namespace");
    }

    #[test]
    fn test_parse_manifest_crd() {
        let manifest = r#"
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider: {}
"#;
        let meta = parse_manifest(manifest).unwrap();
        assert_eq!(meta.name, "my-cluster");
        assert_eq!(meta.api_resource.group, "lattice.io");
        assert_eq!(meta.api_resource.version, "v1alpha1");
        assert_eq!(meta.api_resource.plural, "latticeclusters");
    }

    #[test]
    fn test_parse_manifest_missing_api_version() {
        let manifest = r#"
kind: Deployment
metadata:
  name: test
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("apiVersion"));
    }

    #[test]
    fn test_parse_manifest_missing_kind() {
        let manifest = r#"
apiVersion: v1
metadata:
  name: test
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("kind"));
    }

    #[test]
    fn test_parse_manifest_missing_name() {
        let manifest = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: default
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name"));
    }

    #[test]
    fn test_parse_manifest_invalid_yaml() {
        let manifest = "not: valid: yaml: {{";
        let result = parse_manifest(manifest);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_manifest_invalid_json() {
        let manifest = "{not valid json";
        let result = parse_manifest(manifest);
        assert!(result.is_err());
    }
}
