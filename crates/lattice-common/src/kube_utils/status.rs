//! Status patching utilities for Kubernetes resources.

use kube::api::{Api, Patch, PatchParams};
use kube::Client;

/// Patch the status sub-resource of a namespaced Kubernetes resource.
///
/// Serializes `status` into `{ "status": <status> }` and applies it via
/// merge-patch. This is the standard pattern used by all Lattice controllers.
///
/// Returns `kube::Error` so callers can map to their own error type.
pub async fn patch_resource_status<T>(
    client: &Client,
    name: &str,
    namespace: &str,
    status: &impl serde::Serialize,
    field_manager: &str,
) -> std::result::Result<(), kube::Error>
where
    T: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <T as kube::Resource>::DynamicType: Default,
{
    let api: Api<T> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply(field_manager),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

/// Patch the status sub-resource of a cluster-scoped Kubernetes resource.
///
/// Same as [`patch_resource_status`] but for cluster-scoped (non-namespaced) resources.
pub async fn patch_cluster_resource_status<T>(
    client: &Client,
    name: &str,
    status: &impl serde::Serialize,
    field_manager: &str,
) -> std::result::Result<(), kube::Error>
where
    T: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <T as kube::Resource>::DynamicType: Default,
{
    let api: Api<T> = Api::all(client.clone());
    let patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply(field_manager),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}
