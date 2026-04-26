//! Production [`lattice_cell::bootstrap::LbCidrResolver`].
//!
//! `lattice-cell` defines the resolver type but cannot dispatch to
//! `lattice-capi` providers itself (would create a cycle). This crate
//! already bridges both — it owns the controller phases that drive
//! provider reconciliation — so the resolver is wired here.
//!
//! The dispatch is **per-cluster**: each `LatticeCluster` declares its
//! own `provider`, and the resolver reads that field off the CR before
//! calling the matching provider trait impl. The operator's local
//! provider plays no role — a workload cluster spec'd as `basis` is
//! resolved against `lattice-capi`'s basis provider regardless of where
//! the operator is running.
//!
//! Resolution is lazy by design: invoked at bundle-render time so
//! provider-side allocations (e.g. basis's `serviceBlockCidr`) have
//! already populated by the time we read them.

use std::sync::Arc;

use lattice_cell::bootstrap::{BootstrapError, LbCidrResolver};

pub fn capi_lb_cidr_resolver(client: kube::Client) -> LbCidrResolver {
    Arc::new(move |cluster_id: String| {
        let client = client.clone();
        Box::pin(async move {
            let api: kube::Api<lattice_crd::crd::LatticeCluster> = kube::Api::all(client.clone());
            let cluster = api.get(&cluster_id).await.map_err(|e| {
                BootstrapError::Internal(format!(
                    "lb_cidr_resolver: get LatticeCluster {cluster_id}: {e}"
                ))
            })?;
            let provider_type = cluster.spec.provider.config.provider_type();
            let provider = lattice_capi::provider::create_provider(
                provider_type,
                &lattice_common::capi_namespace(&cluster_id),
            )
            .map_err(|e| BootstrapError::Internal(e.to_string()))?;
            provider
                .lb_cidr(&cluster, &client)
                .await
                .map_err(|e| BootstrapError::Internal(e.to_string()))
        })
    })
}
