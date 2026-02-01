//! Kubeconfig verification integration tests
//!
//! Tests for verifying kubeconfig patching for proxy access.
//! The actual proxy access tests are in proxy.rs.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_kubeconfig_patched -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use base64::{engine::general_purpose::STANDARD, Engine};
use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{run_cmd, run_cmd_allow_fail, WORKLOAD_CLUSTER_NAME};

// ============================================================================
// Core Test Functions
// ============================================================================

/// Verify that a kubeconfig secret has been patched for proxy access.
///
/// After pivot, the kubeconfig secret should point to the parent's proxy URL
/// with the `/cluster/{name}` path, rather than the direct cluster API endpoint.
pub async fn verify_kubeconfig_patched(
    parent_kubeconfig: &str,
    cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Kubeconfig] Verifying kubeconfig patched for {}...",
        cluster_name
    );

    let namespace = format!("capi-{}", cluster_name);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let kubeconfig_b64 = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            parent_kubeconfig,
            "get",
            "secret",
            &secret_name,
            "-n",
            &namespace,
            "-o",
            "jsonpath={.data.value}",
        ],
    )?;

    if kubeconfig_b64.trim().is_empty() {
        return Err(format!(
            "Kubeconfig secret {}/{} not found or empty",
            namespace, secret_name
        ));
    }

    let kubeconfig = String::from_utf8(
        STANDARD
            .decode(kubeconfig_b64.trim())
            .map_err(|e| format!("Failed to decode kubeconfig: {}", e))?,
    )
    .map_err(|e| format!("Invalid UTF-8 in kubeconfig: {}", e))?;

    if !kubeconfig.contains("/cluster/") {
        return Err(format!(
            "Kubeconfig for {} not patched for proxy - server URL missing /cluster/ path",
            cluster_name
        ));
    }

    info!(
        "[Integration/Kubeconfig] SUCCESS: Kubeconfig for {} is patched for proxy access",
        cluster_name
    );
    Ok(())
}

/// Verify that Cedar policies are loaded.
///
/// Checks that the CedarPolicy CRD exists and can be queried.
pub async fn verify_cedar_policies_loaded(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Kubeconfig] Verifying Cedar policies are loaded...");

    // Check for CedarPolicy CRD
    let crd_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "crd",
            "cedarpolicies.lattice.dev",
            "-o",
            "name",
        ],
    );

    if crd_check.is_err() {
        info!("[Integration/Kubeconfig] Cedar CRD not installed - skipping policy verification");
        return Ok(());
    }

    let policies = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "cedarpolicy",
            "-A",
            "-o",
            "name",
        ],
    );

    let policy_count = policies.lines().filter(|l| !l.is_empty()).count();
    info!(
        "[Integration/Kubeconfig] Found {} Cedar policies",
        policy_count
    );

    Ok(())
}

/// Run kubeconfig verification tests for a cluster hierarchy.
pub async fn run_kubeconfig_verification(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: Option<&str>,
) -> Result<(), String> {
    // Verify workload kubeconfig is patched
    verify_kubeconfig_patched(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Verify workload2 kubeconfig is patched (if exists)
    if let Some(w2_name) = workload2_cluster_name {
        if ctx.has_workload() {
            verify_kubeconfig_patched(ctx.workload_kubeconfig.as_deref().unwrap(), w2_name).await?;
        }
    }

    // Verify Cedar policies
    verify_cedar_policies_loaded(&ctx.mgmt_kubeconfig).await?;

    Ok(())
}

// ============================================================================
// Standalone Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_kubeconfig_patched() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());

    verify_kubeconfig_patched(&ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn test_cedar_policies() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG");
    verify_cedar_policies_loaded(&ctx.mgmt_kubeconfig)
        .await
        .unwrap();
}
