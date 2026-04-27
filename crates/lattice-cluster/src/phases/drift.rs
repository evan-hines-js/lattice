//! Spec-drift propagation for self-managing clusters.
//!
//! After pivot a cluster owns its own CAPI resources. When a user edits
//! `LatticeCluster.spec` (e.g. bumps a worker pool's `replicas`), the
//! change must reach the CAPI CRs — but a full re-render via
//! `generate_capi_manifests` is the wrong tool: it overwrites bootstrap-
//! coupled fields on `KubeadmControlPlane` (`postKubeadmCommands`) which
//! makes CAPI see a spec change and roll the control plane.
//!
//! Instead we patch only fields that are safe to re-patch on every
//! reconcile: replica counts. The kube-apiserver treats merge patches
//! with unchanged values as no-ops (no resourceVersion bump, no controller
//! wake-up), so blast-on-every-reconcile is fine here.
//!
//! Fields that are NOT safe to re-patch blindly (because controllers
//! re-reconcile on any patch, even same-value) are deliberately excluded.
//! `BasisCluster.spec.externalIpPool` is one such field: a re-patch can
//! trigger basis-capi-provider to re-evaluate VIP allocation and rebind
//! the apiserver VIP, which is exactly the kind of correctness footgun
//! we're trying to avoid by NOT doing full re-renders. Propagating those
//! edits requires read-then-conditional-patch on the live CR plus an
//! explicit user-edit signal (status.observedGeneration vs metadata
//! generation) and is intentionally left out of this routine.

use kube::ResourceExt;

use lattice_common::Error;
use lattice_crd::crd::LatticeCluster;

use crate::controller::Context;

/// Push spec edits into the live CAPI CRs without touching anything else.
///
/// Idempotent: each underlying patch is a JSON merge patch on a single
/// scalar field, so repeated calls with unchanged values are no-ops at
/// the kube-apiserver level.
pub async fn reconcile_capi_drift(
    cluster: &LatticeCluster,
    ctx: &Context,
    capi_namespace: &str,
) -> Result<(), Error> {
    let cluster_name = cluster.name_any();
    let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();

    // Control plane replicas
    ctx.capi
        .update_cp_replicas(
            &cluster_name,
            capi_namespace,
            bootstrap,
            cluster.spec.nodes.control_plane.replicas,
        )
        .await?;

    // Worker pool replicas
    for (pool_id, pool_spec) in &cluster.spec.nodes.worker_pools {
        ctx.capi
            .scale_pool(&cluster_name, pool_id, capi_namespace, pool_spec.replicas)
            .await?;
    }

    Ok(())
}
