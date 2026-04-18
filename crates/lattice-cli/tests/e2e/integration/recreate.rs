//! Delete-recreate integration test
//!
//! Verifies that deleting a LatticeCluster and recreating it with the same
//! name works correctly. This exercises:
//! - Bootstrap token cleanup (deregister on delete)
//! - Istiod kubeconfig secret GC via ownerReference
//! - Remote secret recreation
//! - Full bootstrap flow with fresh token

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::api::Api;
use lattice_crd::crd::LatticeCluster;
use tracing::info;

use super::super::helpers::{
    client_from_kubeconfig, create_with_retry, load_cluster_config, wait_for_condition,
    watch_cluster_phases, POLL_INTERVAL, WORKLOAD_CLUSTER_NAME,
};

/// Delete a workload cluster and recreate it, verifying the full lifecycle.
///
/// Called from the unified E2E after the initial workload deletion.
/// The parent (mgmt) cluster must still be running.
pub async fn delete_and_recreate_workload(mgmt_kubeconfig: &str) -> Result<(), String> {
    info!("[Recreate] Verifying GC cleaned up istiod kubeconfig secret...");

    let istiod_secret_name = lattice_common::istiod_kubeconfig_secret_name(WORKLOAD_CLUSTER_NAME);

    // Verify the ownerReference GC deleted the istiod kubeconfig secret
    wait_for_condition(
        "istiod kubeconfig secret deleted by GC",
        Duration::from_secs(60),
        POLL_INTERVAL,
        || {
            let kc = mgmt_kubeconfig.to_string();
            let secret_name = istiod_secret_name.clone();
            async move {
                let client = client_from_kubeconfig(&kc).await?;
                let api: Api<k8s_openapi::api::core::v1::Secret> =
                    Api::namespaced(client, "istio-system");
                match api.get_opt(&secret_name).await {
                    Ok(None) => Ok(true),
                    Ok(Some(_)) => Ok(false),
                    Err(e) => Err(format!("failed to check secret: {e}")),
                }
            }
        },
    )
    .await?;

    info!("[Recreate] GC cleanup verified. Re-creating workload cluster...");

    // Load the same cluster fixture used during initial setup
    let workload_cluster =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?
            .cluster;

    let mgmt_client = client_from_kubeconfig(mgmt_kubeconfig).await?;
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());

    create_with_retry(&api, &workload_cluster, WORKLOAD_CLUSTER_NAME).await?;

    info!("[Recreate] LatticeCluster created, waiting for Ready...");
    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, None).await?;

    info!("[Recreate] Cluster Ready. Verifying istiod kubeconfig secret was recreated...");

    // Verify the new istiod kubeconfig secret was created with ownerReference
    wait_for_condition(
        "istiod kubeconfig secret recreated with ownerReference",
        Duration::from_secs(120),
        POLL_INTERVAL,
        || {
            let kc = mgmt_kubeconfig.to_string();
            let secret_name = istiod_secret_name.clone();
            async move {
                let client = client_from_kubeconfig(&kc).await?;
                let api: Api<k8s_openapi::api::core::v1::Secret> =
                    Api::namespaced(client, "istio-system");
                match api.get_opt(&secret_name).await {
                    Ok(Some(secret)) => {
                        let has_owner =
                            secret
                                .metadata
                                .owner_references
                                .as_ref()
                                .is_some_and(|refs| {
                                    refs.iter().any(|r| r.name == WORKLOAD_CLUSTER_NAME)
                                });
                        Ok(has_owner)
                    }
                    Ok(None) => Ok(false),
                    Err(e) => Err(format!("failed to check secret: {e}")),
                }
            }
        },
    )
    .await?;

    info!("[Recreate] Delete-recreate verified successfully!");
    Ok(())
}
