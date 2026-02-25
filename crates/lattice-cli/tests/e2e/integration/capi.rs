//! CAPI resource verification integration tests
//!
//! Tests that verify CAPI resources exist and are properly configured
//! after cluster provisioning and pivot.
//!
//! # Running Standalone
//!
//! ```bash
//! # Direct access (any cluster)
//! LATTICE_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_capi_standalone -- --ignored --nocapture
//!
//! # Workload cluster (direct or through proxy)
//! LATTICE_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_capi_workload_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::{
    get_mgmt_cluster_name, get_workload_cluster_name, run_kubectl, verify_cluster_capi_resources,
};

/// Verify CAPI resources exist on a cluster
///
/// Checks that the cluster has its own CAPI Cluster resource,
/// indicating it is properly self-managing after pivot.
///
/// # Arguments
///
/// * `kubeconfig` - Path to kubeconfig for the target cluster
/// * `cluster_name` - Name of the cluster to verify
pub async fn verify_capi_resources(
    kubeconfig: &str,
    cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/CAPI] Verifying cluster {} CAPI resources...",
        cluster_name
    );
    verify_cluster_capi_resources(kubeconfig, cluster_name).await?;
    info!(
        "[Integration/CAPI] Cluster {} has CAPI resources",
        cluster_name
    );

    Ok(())
}

/// List all CAPI clusters visible from a kubeconfig
pub async fn list_capi_clusters(kubeconfig: &str) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusters",
        "-A",
        "-o",
        "wide",
    ])
    .await
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - verify CAPI resources on the target cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access.
#[tokio::test]
#[ignore]
async fn test_capi_standalone() {
    use super::super::context::{init_e2e_test, standalone_kubeconfig};

    init_e2e_test();
    let kubeconfig =
        standalone_kubeconfig().expect("Set LATTICE_KUBECONFIG to run standalone CAPI tests");
    let cluster_name = get_mgmt_cluster_name();
    verify_capi_resources(&kubeconfig, &cluster_name)
        .await
        .unwrap();
}

/// Standalone test - verify CAPI resources on workload cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_capi_workload_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    let cluster_name = get_workload_cluster_name();
    verify_capi_resources(&resolved.kubeconfig, &cluster_name)
        .await
        .unwrap();
}

/// Standalone test - list all CAPI clusters
#[tokio::test]
#[ignore]
async fn test_list_capi_clusters_standalone() {
    use super::super::context::{init_e2e_test, standalone_kubeconfig};

    init_e2e_test();
    let kubeconfig =
        standalone_kubeconfig().expect("Set LATTICE_KUBECONFIG to list CAPI clusters");
    let clusters = list_capi_clusters(&kubeconfig).await.unwrap();
    println!("CAPI Clusters:\n{}", clusters);
}
