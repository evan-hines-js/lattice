//! Manifest parsing and applying utilities.

use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{trace, warn};

use super::api_resource::{build_api_resource, parse_api_version};
use super::waiting::poll_until;
use crate::retry::{retry_with_backoff, RetryConfig};
use crate::Error;

/// Retry interval for apply operations
const APPLY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Parsed manifest metadata for applying to Kubernetes
#[derive(Debug, Clone)]
pub(crate) struct ManifestMetadata {
    /// The parsed JSON value
    pub(crate) value: serde_json::Value,
    /// Resource name
    pub(crate) name: String,
    /// Optional namespace
    pub(crate) namespace: Option<String>,
    /// API resource definition
    pub(crate) api_resource: ApiResource,
}

/// Parse a manifest and extract its metadata
pub(crate) fn parse_manifest(manifest: &str) -> Result<ManifestMetadata, Error> {
    // Parse the manifest - try JSON first, then YAML
    let value: serde_json::Value = if manifest.trim().starts_with('{') {
        serde_json::from_str(manifest).map_err(|e| {
            Error::internal_with_context(
                "parse_manifest",
                format!("Failed to parse manifest as JSON: {}", e),
            )
        })?
    } else {
        crate::yaml::parse_yaml(manifest).map_err(|e| {
            Error::internal_with_context(
                "parse_manifest",
                format!("Failed to parse manifest as YAML: {}", e),
            )
        })?
    };

    let api_version = value
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("parse_manifest", "Manifest missing apiVersion")
        })?
        .to_string();

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::internal_with_context("parse_manifest", "Manifest missing kind"))?
        .to_string();

    let name = value
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("parse_manifest", "Manifest missing metadata.name")
        })?
        .to_string();

    let namespace = value
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let api_resource = build_api_resource(&api_version, &kind);

    Ok(ManifestMetadata {
        value,
        name,
        namespace,
        api_resource,
    })
}

/// Apply a manifest using server-side apply
pub async fn apply_manifest(client: &Client, manifest: &str) -> Result<(), Error> {
    let metadata = parse_manifest(manifest)?;
    let patch_params = PatchParams::apply("lattice").force();

    let api: Api<DynamicObject> = match &metadata.namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &metadata.api_resource),
        None => Api::all_with(client.clone(), &metadata.api_resource),
    };

    api.patch(
        &metadata.name,
        &patch_params,
        &Patch::Apply(&metadata.value),
    )
    .await
    .map_err(|e| {
        Error::internal_with_context(
            "apply_manifest",
            format!(
                "Failed to apply {}/{}: {}",
                metadata.api_resource.kind, metadata.name, e
            ),
        )
    })?;

    Ok(())
}

/// Options for applying manifests with discovery
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Skip manifests for CRDs that aren't installed yet (default: false)
    pub skip_missing_crds: bool,
}

/// Apply a single manifest using API discovery
///
/// Uses Kubernetes API discovery to resolve the correct resource type,
/// supporting CRDs and custom resources. Server-side apply is used for
/// idempotency.
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `discovery` - Pre-built API discovery (reuse for efficiency)
/// * `manifest` - YAML or JSON manifest string
/// * `options` - Apply options (e.g., skip missing CRDs)
pub async fn apply_manifest_with_discovery(
    client: &Client,
    discovery: &kube::discovery::Discovery,
    manifest: &str,
    options: &ApplyOptions,
) -> Result<(), Error> {
    let obj: serde_json::Value = crate::yaml::parse_yaml(manifest).map_err(|e| {
        Error::internal_with_context(
            "apply_manifest_with_discovery",
            format!("invalid YAML: {}", e),
        )
    })?;

    let kind = obj.get("kind").and_then(|v| v.as_str()).ok_or_else(|| {
        Error::internal_with_context("apply_manifest_with_discovery", "missing kind")
    })?;
    let api_version = obj
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("apply_manifest_with_discovery", "missing apiVersion")
        })?;
    let name = obj
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("apply_manifest_with_discovery", "missing metadata.name")
        })?;
    let namespace = obj.pointer("/metadata/namespace").and_then(|v| v.as_str());

    // Parse apiVersion into group/version
    let (group, version) = parse_api_version(api_version);

    let gvk = kube::api::GroupVersionKind {
        group,
        version,
        kind: kind.to_string(),
    };

    let Some((api_resource, _)) = discovery.resolve_gvk(&gvk) else {
        if options.skip_missing_crds {
            trace!(kind = %kind, name = %name, "skipping manifest - CRD not available");
            return Ok(());
        }
        return Err(Error::internal_with_context(
            "apply_manifest_with_discovery",
            format!("unknown resource type: {}/{}", api_version, kind),
        ));
    };

    let params = PatchParams::apply("lattice").force();
    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
        None => Api::all_with(client.clone(), &api_resource),
    };

    api.patch(name, &params, &Patch::Apply(&obj))
        .await
        .map_err(|e| {
            Error::internal_with_context(
                "apply_manifest_with_discovery",
                format!("failed to apply {}/{}: {}", kind, name, e),
            )
        })?;

    trace!(kind = %kind, name = %name, namespace = ?namespace, "applied manifest");
    Ok(())
}

/// Get priority for a Kubernetes resource kind (lower = apply first)
///
/// Used to sort manifests for proper ordering during apply.
///
/// Security policies (PeerAuthentication, AuthorizationPolicy) MUST be applied
/// before workloads (Deployment, DaemonSet). Otherwise pods start with STRICT
/// mTLS before PERMISSIVE policies are in place, causing the kube-apiserver
/// (not in the mesh) to get EOF when reaching aggregated API services like
/// KEDA's metrics endpoint.
pub fn kind_priority(kind: &str) -> u8 {
    match kind {
        "Namespace" => 0,
        "CustomResourceDefinition" => 1,
        "ServiceAccount" => 2,
        "ClusterRole" | "Role" => 3,
        "ClusterRoleBinding" | "RoleBinding" => 4,
        "ConfigMap" | "Secret" => 5,
        // Network/security policies before workloads: PERMISSIVE mTLS, ALLOW policies,
        // and Cilium policies must be active before pods start, or aggregated API
        // services (e.g. KEDA metrics) break because kube-apiserver can't reach them.
        "PeerAuthentication"
        | "AuthorizationPolicy"
        | "CiliumNetworkPolicy"
        | "CiliumClusterwideNetworkPolicy" => 6,
        "Service" => 7,
        "Deployment" | "DaemonSet" | "StatefulSet" => 8,
        "ScaledObject" => 9,
        _ => 10,
    }
}

/// Extract kind from a YAML or JSON manifest (fast, no full parse)
///
/// Handles both YAML (`kind: Foo`) and pretty-printed JSON (`"kind": "Foo"`).
/// JSON support is needed because Istio/Cilium policies are serialized via
/// `serde_json::to_string_pretty` and must be ordered correctly during apply.
pub(crate) fn extract_kind(manifest: &str) -> &str {
    for line in manifest.lines() {
        let trimmed = line.trim();

        // YAML: `kind: Foo`
        if let Some(value) = trimmed.strip_prefix("kind:") {
            return value.trim();
        }

        // JSON (pretty-printed): `"kind": "Foo"` or `"kind": "Foo",`
        if let Some(rest) = trimmed.strip_prefix("\"kind\":") {
            let rest = rest.trim().trim_start_matches('"');
            if let Some(end) = rest.find('"') {
                return &rest[..end];
            }
        }
    }

    ""
}

/// Check if a JSON manifest is a Kubernetes Deployment
pub fn is_deployment_json(manifest: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest) {
        value.get("kind").and_then(|k| k.as_str()) == Some("Deployment")
    } else {
        false
    }
}

/// Run API discovery with retry.
///
/// Discovery can transiently fail when aggregated API endpoints (from recently
/// installed providers like CAPI or cert-manager) haven't registered yet.
/// Retries are bounded -- callers like the reconciler and operator startup
/// have their own retry/requeue logic for persistent failures.
///
/// Uses 1s initial backoff (not the default 100ms) because discovery is an
/// expensive operation that enumerates all API groups. With 100ms backoff,
/// 5 retries complete in ~3s which can overwhelm a stressed API server.
/// With 1s backoff the same 5 retries spread over ~31s.
pub(crate) async fn run_discovery(client: &Client) -> Result<kube::discovery::Discovery, Error> {
    use kube::discovery::Discovery;

    let config = RetryConfig {
        max_attempts: 5,
        initial_delay: Duration::from_secs(1),
        ..RetryConfig::default()
    };
    let client = client.clone();
    retry_with_backoff(&config, "api-discovery", || {
        let client = client.clone();
        async move {
            Discovery::new(client)
                .run()
                .await
                .map_err(|e| Error::internal_with_context("api-discovery", e.to_string()))
        }
    })
    .await
}

/// Apply multiple manifests with proper ordering and discovery
///
/// Applies in two phases:
/// 1. Namespaces and CRDs (foundational resources)
/// 2. Re-run discovery only if CRDs were applied (to learn new types)
/// 3. Everything else (sorted by kind priority)
///
/// Discovery is expensive (enumerates all API groups), so we minimize calls:
/// - Skip discovery entirely when no foundational resources exist (single call)
/// - Only re-run discovery after CRDs are applied (Namespaces don't register new types)
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `manifests` - Slice of manifest strings (YAML or JSON)
/// * `options` - Apply options
pub async fn apply_manifests_with_discovery(
    client: &Client,
    manifests: &[impl AsRef<str>],
    options: &ApplyOptions,
) -> Result<(), Error> {
    if manifests.is_empty() {
        return Ok(());
    }

    // Split into foundational (Namespace, CRD) and rest
    let (mut foundational, mut rest): (Vec<&str>, Vec<&str>) =
        manifests.iter().map(|m| m.as_ref()).partition(|m| {
            let kind = extract_kind(m);
            kind == "Namespace" || kind == "CustomResourceDefinition"
        });

    // Sort each group by priority
    foundational.sort_by_key(|m| kind_priority(extract_kind(m)));
    rest.sort_by_key(|m| kind_priority(extract_kind(m)));

    // Check if any foundational resources are CRDs (not just Namespaces).
    // Only CRDs register new API types that require re-discovery.
    let has_crds = foundational
        .iter()
        .any(|m| extract_kind(m) == "CustomResourceDefinition");

    // Phase 1: Apply foundational resources (Namespaces, CRDs) -- fail-fast.
    // These are prerequisites; if they fail, nothing else will work.
    if !foundational.is_empty() {
        let discovery = run_discovery(client).await?;

        for manifest in &foundational {
            apply_manifest_with_discovery(client, &discovery, manifest, options).await?;
        }

        // Phase 2: Apply remaining resources best-effort, continuing past failures.
        // Re-run discovery only if CRDs were applied (they register new API types).
        if !rest.is_empty() {
            let discovery = if has_crds {
                run_discovery(client).await?
            } else {
                discovery
            };

            apply_all_best_effort(client, &discovery, &rest, options).await?;
        }
    } else if !rest.is_empty() {
        let discovery = run_discovery(client).await?;
        apply_all_best_effort(client, &discovery, &rest, options).await?;
    }

    Ok(())
}

/// Apply manifests best-effort: try every manifest even if some fail.
/// Returns the first error after attempting all manifests.
/// This prevents a single webhook or transient failure from blocking
/// all subsequent manifests (e.g., LMMs that would unblock the webhook).
async fn apply_all_best_effort(
    client: &Client,
    discovery: &kube::discovery::Discovery,
    manifests: &[&str],
    options: &ApplyOptions,
) -> Result<(), Error> {
    let mut first_error: Option<Error> = None;
    let mut failed_count = 0usize;

    for manifest in manifests {
        if let Err(e) = apply_manifest_with_discovery(client, discovery, manifest, options).await {
            failed_count += 1;
            tracing::warn!(
                error = %e,
                kind = %extract_kind(manifest),
                "manifest apply failed, continuing with remaining manifests"
            );
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }

    match first_error {
        Some(e) => {
            tracing::warn!(
                failed = failed_count,
                total = manifests.len(),
                "some manifests failed to apply"
            );
            Err(e)
        }
        None => Ok(()),
    }
}

/// Apply a multi-document YAML manifest (documents separated by ---)
pub async fn apply_manifests(client: &Client, manifests: &str) -> Result<(), Error> {
    for doc in manifests.split("\n---") {
        let doc = doc.trim();
        // Skip non-manifest documents (empty, comments-only, etc.)
        if !doc.contains("apiVersion") {
            continue;
        }
        apply_manifest(client, doc).await?;
    }
    Ok(())
}

/// Apply a manifest with retry (supports multi-document YAML)
pub async fn apply_manifest_with_retry(
    client: &Client,
    manifest: &str,
    timeout: Duration,
) -> Result<(), Error> {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let client_clone = client.clone();
    let manifest_owned = manifest.to_string();
    let last_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let last_error_clone = last_error.clone();

    let result = poll_until(
        timeout,
        APPLY_RETRY_INTERVAL,
        "Timeout waiting for apply",
        || {
            let client = client_clone.clone();
            let manifest = manifest_owned.clone();
            let last_error = last_error_clone.clone();
            async move {
                match apply_manifests(&client, &manifest).await {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        let error_msg = e.to_string();
                        // Log at warn level so errors are visible during install
                        warn!("Apply failed (will retry): {}", error_msg);
                        *last_error.lock().await = Some(error_msg);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await;

    // If we timed out, include the last error in the message
    if result.is_err() {
        if let Some(err) = last_error.lock().await.take() {
            return Err(Error::internal_with_context(
                "apply_manifest_with_retry",
                format!("Timeout applying manifest. Last error: {}", err),
            ));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let meta =
            parse_manifest(manifest).expect("YAML deployment manifest should parse successfully");
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
        let meta = parse_manifest(manifest).expect("JSON manifest should parse successfully");
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
        let meta =
            parse_manifest(manifest).expect("cluster-scoped manifest should parse successfully");
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
        let meta = parse_manifest(manifest).expect("CRD manifest should parse successfully");
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
