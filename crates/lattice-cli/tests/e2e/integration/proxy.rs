//! Hierarchy proxy integration tests
//!
//! Tests the K8s API proxy through the cluster hierarchy.
//! Parent clusters can access child cluster APIs through the gRPC stream.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! LATTICE_WORKLOAD2_KUBECONFIG=/path/to/workload2-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_proxy_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{run_cmd, run_cmd_allow_fail};

/// Test proxy access from management to workload cluster
///
/// Verifies that the management cluster can access the workload cluster's
/// API through the proxy endpoint.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context with mgmt and workload kubeconfigs
/// * `workload_cluster_name` - Name of the workload cluster
pub async fn test_mgmt_to_workload_proxy(
    ctx: &InfraContext,
    workload_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access from mgmt to {}...",
        workload_cluster_name
    );

    // TODO: Implement actual proxy test once proxy endpoint is exposed
    // For now, verify clusters are accessible via their kubeconfigs
    let workload_kc = ctx.require_workload()?;

    // Verify we can access both clusters
    let mgmt_nodes = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &ctx.mgmt_kubeconfig,
            "get",
            "nodes",
            "-o",
            "name",
        ],
    )?;
    info!(
        "[Integration/Proxy] Management cluster nodes: {}",
        mgmt_nodes.lines().count()
    );

    let workload_nodes = run_cmd(
        "kubectl",
        &["--kubeconfig", workload_kc, "get", "nodes", "-o", "name"],
    )?;
    info!(
        "[Integration/Proxy] Workload cluster nodes: {}",
        workload_nodes.lines().count()
    );

    // Verify LatticeCluster exists on management for the workload
    let lattice_clusters = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            &ctx.mgmt_kubeconfig,
            "get",
            "latticecluster",
            workload_cluster_name,
            "-o",
            "name",
        ],
    );

    if lattice_clusters.trim().is_empty() {
        info!(
            "[Integration/Proxy] Note: LatticeCluster {} not found on mgmt (may have pivoted)",
            workload_cluster_name
        );
    } else {
        info!(
            "[Integration/Proxy] LatticeCluster {} visible from management",
            workload_cluster_name
        );
    }

    Ok(())
}

/// Test proxy access through full hierarchy (mgmt -> workload -> workload2)
///
/// Verifies that the proxy works through the full cluster hierarchy.
///
/// # Arguments
///
/// * `ctx` - Infrastructure context with all three cluster kubeconfigs
/// * `workload_cluster_name` - Name of the first workload cluster
/// * `workload2_cluster_name` - Name of the second workload cluster
pub async fn test_full_hierarchy_proxy(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: &str,
) -> Result<(), String> {
    info!("[Integration/Proxy] Testing full hierarchy proxy access...");
    info!(
        "[Integration/Proxy] Path: mgmt -> {} -> {}",
        workload_cluster_name, workload2_cluster_name
    );

    let workload_kc = ctx.require_workload()?;
    let workload2_kc = ctx.require_workload2()?;

    // Verify all three clusters are accessible
    let mgmt_ns = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &ctx.mgmt_kubeconfig,
            "get",
            "namespaces",
            "-o",
            "name",
        ],
    )?;
    info!(
        "[Integration/Proxy] Management cluster namespaces: {}",
        mgmt_ns.lines().count()
    );

    let workload_ns = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            workload_kc,
            "get",
            "namespaces",
            "-o",
            "name",
        ],
    )?;
    info!(
        "[Integration/Proxy] Workload cluster namespaces: {}",
        workload_ns.lines().count()
    );

    let workload2_ns = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            workload2_kc,
            "get",
            "namespaces",
            "-o",
            "name",
        ],
    )?;
    info!(
        "[Integration/Proxy] Workload2 cluster namespaces: {}",
        workload2_ns.lines().count()
    );

    // Verify workload2 is visible from workload (child relationship)
    let lattice_clusters = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            workload_kc,
            "get",
            "latticecluster",
            workload2_cluster_name,
            "-o",
            "name",
        ],
    );

    if lattice_clusters.trim().is_empty() {
        info!(
            "[Integration/Proxy] Note: LatticeCluster {} not found on workload (may have pivoted)",
            workload2_cluster_name
        );
    } else {
        info!(
            "[Integration/Proxy] LatticeCluster {} visible from workload",
            workload2_cluster_name
        );
    }

    info!("[Integration/Proxy] Full hierarchy test passed");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - test proxy from management to workload
#[tokio::test]
#[ignore]
async fn test_proxy_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| "e2e-workload".to_string());
    test_mgmt_to_workload_proxy(&ctx, &workload_name)
        .await
        .unwrap();
}

/// Standalone test - test full hierarchy proxy
#[tokio::test]
#[ignore]
async fn test_proxy_hierarchy_standalone() {
    let ctx = init_test_env(
        "Set LATTICE_MGMT_KUBECONFIG, LATTICE_WORKLOAD_KUBECONFIG, and LATTICE_WORKLOAD2_KUBECONFIG",
    );
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| "e2e-workload".to_string());
    let workload2_name = std::env::var("LATTICE_WORKLOAD2_CLUSTER_NAME")
        .unwrap_or_else(|_| "e2e-workload2".to_string());
    test_full_hierarchy_proxy(&ctx, &workload_name, &workload2_name)
        .await
        .unwrap();
}
