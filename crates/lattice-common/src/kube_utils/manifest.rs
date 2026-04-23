//! Manifest parsing and applying utilities.

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{trace, warn};

use super::api_resource::build_api_resource;
use crate::retry::{retry_with_backoff, RetryConfig};
use crate::Error;

/// Options for applying manifests.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Skip manifests for resource types that aren't installed yet (default: false).
    /// A 404 from the API server (resource type not found) is treated as a skip.
    pub skip_missing_crds: bool,
}

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
        lattice_core::yaml::parse_yaml(manifest).map_err(|e| {
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

/// Apply manifests with proper ordering via server-side apply.
///
/// Each manifest's declared `apiVersion`/`kind` is used directly to construct
/// the ApiResource — no API discovery is needed. This avoids the problem where
/// a broken APIService (e.g. KEDA returning 503) poisons `Discovery::run()`
/// and blocks unrelated manifests.
///
/// Applies in two phases:
/// - Foundational resources (Namespaces, CRDs) — fail-fast
/// - Everything else sorted by kind priority — best-effort (continues past failures)
pub async fn apply_manifests(
    client: &Client,
    manifests: &[impl AsRef<str>],
    options: &ApplyOptions,
) -> Result<(), Error> {
    if manifests.is_empty() {
        // Callers with a legitimately empty bundle should early-return
        // before reaching here; a zero-length slice at this layer
        // usually means an upstream filter stripped everything.
        warn!("apply_manifests called with zero manifests — caller likely filtered them all out");
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

    // Phase 1: Foundational resources — fail-fast.
    for manifest in &foundational {
        apply_one(client, manifest, options).await?;
    }

    // Phase 2: Remaining resources — best-effort, continue past failures.
    let mut first_error: Option<Error> = None;
    let mut failed_count = 0usize;

    for manifest in &rest {
        if let Err(e) = apply_one(client, manifest, options).await {
            failed_count += 1;
            warn!(
                error = %e,
                kind = %extract_kind(manifest),
                "manifest apply failed, continuing with remaining manifests"
            );
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }

    if let Some(e) = first_error {
        warn!(
            failed = failed_count,
            total = rest.len(),
            "some manifests failed to apply"
        );
        return Err(e);
    }

    Ok(())
}

/// Apply manifests with retry on transient apiserver errors.
///
/// The install-time workhorse. Fresh clusters, pivots, and bootstrap
/// paths hit windows where the apiserver is briefly unreachable (pod
/// restart, leader election, kube-vip failover) — plain
/// [`apply_manifests`] surfaces a single `Connect` / `SendRequest` as
/// a terminal error, while this wrapper absorbs them via
/// [`retry_with_backoff`] and only fails if `retry_config`'s budget is
/// exhausted.
///
/// Use [`RetryConfig::install`] for the standard install-time profile.
///
/// For in-reconciler or RPC-handler code paths where the caller's
/// framework already retries (controller-runtime requeue, agent
/// command redispatch), use [`apply_manifests`] directly.
pub async fn apply_manifests_with_retry(
    client: &Client,
    manifests: &[impl AsRef<str>],
    options: &ApplyOptions,
    retry_config: &RetryConfig,
    label: &str,
) -> Result<(), Error> {
    // Own the inputs so the retry closure can be called repeatedly
    // without borrowing from the caller.
    let docs: Vec<String> = manifests.iter().map(|m| m.as_ref().to_string()).collect();
    let options = options.clone();

    retry_with_backoff(retry_config, label, || {
        let client = client.clone();
        let docs = docs.clone();
        let options = options.clone();
        async move {
            let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
            apply_manifests(&client, &refs, &options).await
        }
    })
    .await
}

/// Apply a single manifest via SSA, respecting `ApplyOptions`.
async fn apply_one(client: &Client, manifest: &str, options: &ApplyOptions) -> Result<(), Error> {
    let metadata = parse_manifest(manifest)?;
    let params = PatchParams::apply("lattice").force();

    let api: Api<DynamicObject> = match &metadata.namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &metadata.api_resource),
        None => Api::all_with(client.clone(), &metadata.api_resource),
    };

    match api
        .patch(&metadata.name, &params, &Patch::Apply(&metadata.value))
        .await
    {
        Ok(_) => {
            trace!(
                kind = %metadata.api_resource.kind,
                name = %metadata.name,
                namespace = ?metadata.namespace,
                "applied manifest"
            );
            Ok(())
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 && options.skip_missing_crds => {
            trace!(
                kind = %metadata.api_resource.kind,
                name = %metadata.name,
                "skipping manifest - resource type not available"
            );
            Ok(())
        }
        Err(e) => Err(Error::internal_with_context(
            "apply_manifest",
            format!(
                "failed to apply {}/{}: {}",
                metadata.api_resource.kind, metadata.name, e
            ),
        )),
    }
}

/// Get priority for a Kubernetes resource kind (lower = apply first)
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

/// Split a multi-document YAML string into individual documents.
///
/// For parsing external YAML sources (helm output, CRD files). Filters out
/// empty documents, comment-only blocks, and Helm test/delete hooks — but keeps
/// `pre-install`/`pre-upgrade` hooks because they contain setup resources (e.g.
/// cert-generation Jobs) that work fine applied as regular resources.
///
/// Normalizes output so every document has a leading `---` for kubectl apply
/// compatibility.
///
/// Not for JSON-typed resources from structured Rust generators — those are
/// added to manifest lists directly.
pub fn split_yaml_documents(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|doc| doc.trim())
        .filter(|doc| {
            let keep = !doc.is_empty() && doc.contains("kind:") && !is_filtered_helm_hook(doc);
            if !keep && !doc.is_empty() {
                tracing::debug!(
                    doc_preview = &doc[..doc.len().min(100)],
                    "Filtered out YAML document"
                );
            }
            keep
        })
        .map(|doc| {
            if doc.starts_with("---") {
                doc.to_string()
            } else {
                format!("---\n{}", doc)
            }
        })
        .collect()
}

/// Extract the registry host from a container image reference.
///
/// Images without a dot, colon, or `localhost` in the first path component are
/// implicitly from docker.io (e.g. `nginx` → `docker.io`).
pub fn extract_registry_host(image_ref: &str) -> String {
    let parts: Vec<&str> = image_ref.splitn(2, '/').collect();
    if parts.len() == 1 {
        return "docker.io".to_string();
    }
    let first = parts[0];
    if first.contains('.') || first.contains(':') || first == "localhost" {
        first.to_string()
    } else {
        "docker.io".to_string()
    }
}

/// Scan rendered manifests for `image:` lines and return the unique set of
/// registry hosts they reference.
///
/// Used to build containerd mirror configuration — every registry that the
/// cluster's managed dependencies pull from needs a mirror entry. Each
/// dependency install crate exposes its rendered manifests, and the caller
/// aggregates across all of them.
pub fn extract_image_registries<S: AsRef<str>>(
    manifests: &[S],
) -> std::collections::BTreeSet<String> {
    let mut registries = std::collections::BTreeSet::new();
    for manifest in manifests {
        for line in manifest.as_ref().lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("image:") else {
                continue;
            };
            let image_ref = rest.trim().trim_matches(|c| c == '"' || c == '\'');
            if !image_ref.is_empty() {
                registries.insert(extract_registry_host(image_ref));
            }
        }
    }
    registries
}

/// True if a YAML document is a Helm hook that should be filtered from regular apply.
///
/// Keeps `pre-install`/`pre-upgrade` hooks (setup resources like cert-generation
/// Jobs). Filters test, delete, and other hook types that only make sense during
/// `helm install`/`helm delete`.
fn is_filtered_helm_hook(doc: &str) -> bool {
    if !doc.contains("helm.sh/hook") {
        return false;
    }
    if doc.contains("pre-install") || doc.contains("pre-upgrade") {
        return false;
    }
    true
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

    #[test]
    fn split_yaml_documents_handles_multi_doc() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn split_yaml_documents_keeps_pre_install_hook() {
        let yaml = "kind: Job\nmetadata:\n  annotations:\n    helm.sh/hook: pre-install\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn split_yaml_documents_filters_test_hook() {
        let yaml =
            "kind: Pod\nmetadata:\n  annotations:\n    helm.sh/hook: test\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn split_yaml_documents_filters_pre_delete_hook() {
        let yaml = "kind: Job\nmetadata:\n  annotations:\n    helm.sh/hook: pre-delete\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn split_yaml_documents_filters_empty_and_commentless_docs() {
        let yaml = "\n---\n# comment only\n---\nkind: ConfigMap\nmetadata:\n  name: x\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn split_yaml_documents_normalizes_leading_separator() {
        let yaml = "kind: A\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].starts_with("---"));
    }

    #[test]
    fn extract_registry_host_implicit_docker_io() {
        assert_eq!(extract_registry_host("nginx"), "docker.io");
        assert_eq!(extract_registry_host("nginx:latest"), "docker.io");
        assert_eq!(extract_registry_host("library/nginx"), "docker.io");
    }

    #[test]
    fn extract_registry_host_recognizes_hosts() {
        assert_eq!(extract_registry_host("quay.io/cilium/tetragon"), "quay.io");
        assert_eq!(extract_registry_host("ghcr.io/user/img:v1"), "ghcr.io");
        assert_eq!(
            extract_registry_host("registry.k8s.io/coredns:1"),
            "registry.k8s.io"
        );
    }

    #[test]
    fn extract_registry_host_with_port() {
        assert_eq!(
            extract_registry_host("localhost:5000/my/app"),
            "localhost:5000"
        );
        assert_eq!(extract_registry_host("localhost/x"), "localhost");
    }

    #[test]
    fn extract_image_registries_dedups_across_manifests() {
        let m1 = "containers:\n  - image: quay.io/cilium/tetragon:1\n";
        let m2 = "spec:\n  image: quay.io/cilium/cilium:2\n";
        let m3 = "image: ghcr.io/user/op:latest";
        let regs = extract_image_registries(&[m1, m2, m3]);
        assert_eq!(regs.len(), 2);
        assert!(regs.contains("quay.io"));
        assert!(regs.contains("ghcr.io"));
    }

    #[test]
    fn extract_image_registries_handles_quoted_refs() {
        let m = r#"image: "registry.k8s.io/coredns:v1""#;
        let regs = extract_image_registries(&[m]);
        assert!(regs.contains("registry.k8s.io"));
    }
}
