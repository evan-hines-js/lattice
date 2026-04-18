//! Shared plumbing for per-dependency Install CRDs.
//!
//! Each install crate (`lattice-tetragon`, `lattice-cilium`, …) has its own
//! bespoke controller, but the non-control-flow pieces — server-side-applying
//! the CR itself, and patching an `InstallStatus` only when it's changed — are
//! pure mechanics. They live here.

use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use crate::kube_utils::patch_cluster_resource_status;
use crate::status_check;
use lattice_crd::crd::InstallStatus;

/// Server-side apply a cluster-scoped resource under the given field manager.
///
/// Used by every install crate's `ensure_install` to create-or-update its
/// singleton Install CR.
pub async fn apply_cluster_resource<K>(
    client: &Client,
    resource: &K,
    name: &str,
    field_manager: &str,
) -> Result<(), kube::Error>
where
    K: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>
        + Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let api: Api<K> = Api::all(client.clone());
    api.patch(name, &PatchParams::apply(field_manager), &Patch::Apply(resource))
        .await?;
    Ok(())
}

/// Patch an `InstallStatus` only if it would change. Skip-if-unchanged prevents
/// reconcile storms — every merge patch generates a watch event, and
/// `Condition::new()` stamps a fresh `lastTransitionTime` that would otherwise
/// re-fire on every loop.
pub async fn patch_install_status<K>(
    client: &Client,
    name: &str,
    current: Option<&InstallStatus>,
    new: InstallStatus,
    field_manager: &str,
) -> Result<(), kube::Error>
where
    K: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    if status_check::is_status_unchanged(
        current,
        &new.phase,
        new.message.as_deref(),
        new.observed_generation,
    ) {
        return Ok(());
    }
    patch_cluster_resource_status::<K>(client, name, &new, field_manager).await
}
