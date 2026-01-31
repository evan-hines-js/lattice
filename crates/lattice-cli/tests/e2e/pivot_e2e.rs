//! Full E2E test for Lattice installation, pivot, and unpivot flow
//!
//! This test validates the complete Lattice lifecycle:
//! 1. Set up full cluster hierarchy (mgmt -> workload -> workload2)
//! 2. Run mesh tests on workload cluster
//! 3. Delete workload2 (unpivot to workload)
//! 4. Delete workload (unpivot to mgmt)
//! 5. Uninstall management cluster
//!
//! # Running
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//! ```
//!
//! # Environment Variables
//!
//! - `LATTICE_MGMT_CLUSTER_CONFIG`: Path to LatticeCluster YAML for management cluster
//! - `LATTICE_WORKLOAD_CLUSTER_CONFIG`: Path to LatticeCluster YAML for workload cluster
//! - `LATTICE_WORKLOAD2_CLUSTER_CONFIG`: Path to LatticeCluster YAML for second workload cluster
//! - `LATTICE_ENABLE_MESH_TEST=true`: Enable service mesh validation tests (default: true)

#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::time::Duration;

use tracing::info;

use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};

use super::helpers::run_id;
use super::integration::{self, setup};

const E2E_TIMEOUT: Duration = Duration::from_secs(3600);
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";

#[tokio::test]
async fn test_configurable_provider_pivot() {
    lattice_common::install_crypto_provider();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    info!("Starting E2E test: Full Lifecycle");

    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => {
            info!("TEST PASSED");
        }
        Ok(Err(e)) => {
            setup::cleanup_bootstrap_clusters();
            panic!("E2E test failed: {} (manual cleanup may be required)", e);
        }
        Err(_) => {
            setup::cleanup_bootstrap_clusters();
            panic!(
                "E2E test timed out after {:?} (manual cleanup required)",
                E2E_TIMEOUT
            );
        }
    }
}

async fn run_full_e2e() -> Result<(), String> {
    // =========================================================================
    // Phase 1-6: Set up full hierarchy using integration module
    // =========================================================================
    let config = setup::SetupConfig::with_chaos();
    let mut setup_result = integration::setup::setup_full_hierarchy(&config).await?;
    let ctx = setup_result.ctx.clone();

    // =========================================================================
    // Phase 7: Run mesh tests + delete workload2 (parallel)
    // =========================================================================
    info!("[Phase 7] Running mesh tests + deleting workload2...");

    // Start mesh tests in background
    let mesh_handle = if integration::mesh::mesh_tests_enabled() {
        let is_docker = integration::mesh::is_docker_provider(&ctx);
        Some(integration::mesh::start_mesh_tests_async(&ctx, is_docker).await?)
    } else {
        None
    };

    // Start workload2 deletion in background
    let delete_handle = integration::pivot::start_cluster_deletion_async(
        ctx.require_workload2()?.to_string(),
        ctx.require_workload()?.to_string(),
        WORKLOAD2_CLUSTER_NAME.to_string(),
        ctx.provider,
    );

    // Wait for mesh tests
    if let Some(handle) = mesh_handle {
        info!("[Phase 7] Waiting for mesh tests to complete...");
        handle
            .await
            .map_err(|e| format!("Mesh test task panicked: {}", e))??;
        info!("SUCCESS: Mesh tests complete!");
    }

    // Wait for workload2 deletion
    info!("[Phase 7] Waiting for workload2 deletion...");
    delete_handle
        .await
        .map_err(|e| format!("Delete task panicked: {}", e))??;
    info!("SUCCESS: Workload2 deleted and unpivoted!");

    // =========================================================================
    // Phase 8: Delete workload (unpivot to mgmt)
    // =========================================================================
    info!("[Phase 8] Deleting workload cluster (unpivot to mgmt)...");

    integration::pivot::delete_and_verify_unpivot(
        ctx.require_workload()?,
        &ctx.mgmt_kubeconfig,
        WORKLOAD_CLUSTER_NAME,
        ctx.provider,
    )
    .await?;

    info!("SUCCESS: Workload deleted and unpivoted!");

    // =========================================================================
    // Phase 9: Uninstall management cluster
    // =========================================================================
    info!("[Phase 9] Uninstalling management cluster...");

    // Stop chaos before uninstall
    setup_result.stop_chaos().await;

    let uninstall_args = UninstallArgs {
        kubeconfig: PathBuf::from(&ctx.mgmt_kubeconfig),
        name: Some(MGMT_CLUSTER_NAME.to_string()),
        yes: true,
        keep_bootstrap_on_failure: false,
        run_id: Some(run_id().to_string()),
    };

    let uninstaller = Uninstaller::new(&uninstall_args)
        .await
        .map_err(|e| format!("Failed to create uninstaller: {}", e))?;

    uninstaller
        .run()
        .await
        .map_err(|e| format!("Uninstall failed: {}", e))?;

    info!("SUCCESS: Management cluster uninstalled!");
    info!("E2E test complete: full lifecycle verified");

    Ok(())
}
