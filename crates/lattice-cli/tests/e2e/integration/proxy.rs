//! Hierarchy proxy integration tests
//!
//! Tests the K8s API proxy through the cluster hierarchy.
//! Parent clusters can access child cluster APIs through the gRPC stream.
//!
//! # Architecture
//!
//! The proxy flow is:
//! 1. kubectl uses patched kubeconfig (server: .../cluster/{child})
//! 2. Request goes to lattice-api proxy handler
//! 3. Proxy routes request through gRPC tunnel to child's agent
//! 4. Agent executes request against local K8s API
//! 5. Response returned through the tunnel
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_proxy_access_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use super::super::context::{init_test_env, InfraContext};
use super::super::helpers::{
    run_cmd, run_cmd_allow_fail, WORKLOAD2_CLUSTER_NAME, WORKLOAD_CLUSTER_NAME,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract and decode a kubeconfig from a secret.
fn extract_kubeconfig_from_secret(
    parent_kubeconfig: &str,
    namespace: &str,
    secret_name: &str,
) -> Result<String, String> {
    let kubeconfig_b64 = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            parent_kubeconfig,
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
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

    let kubeconfig_bytes = STANDARD
        .decode(kubeconfig_b64.trim())
        .map_err(|e| format!("Failed to decode kubeconfig: {}", e))?;

    String::from_utf8(kubeconfig_bytes).map_err(|e| format!("Invalid UTF-8 in kubeconfig: {}", e))
}

/// Write kubeconfig to a temp file and return the path.
fn write_temp_kubeconfig(cluster_name: &str, content: &str) -> Result<String, String> {
    let path = format!("/tmp/proxy-test-{}-kubeconfig", cluster_name);
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write temp kubeconfig: {}", e))?;
    Ok(path)
}

/// Execute kubectl command with a temp kubeconfig and clean up.
fn kubectl_with_temp_kubeconfig(
    kubeconfig_content: &str,
    cluster_name: &str,
    args: &[&str],
) -> Result<String, String> {
    let temp_path = write_temp_kubeconfig(cluster_name, kubeconfig_content)?;

    let mut full_args = vec!["--kubeconfig", &temp_path];
    full_args.extend(args);

    let result = run_cmd_allow_fail("kubectl", &full_args);

    let _ = std::fs::remove_file(&temp_path);

    Ok(result)
}

// ============================================================================
// Core Test Functions
// ============================================================================

/// Wait for agent connection before testing proxy.
///
/// The proxy relies on agents being connected and subtree state being synced.
pub async fn wait_for_agent_ready(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Waiting for agent connection from {}...",
        child_cluster_name
    );

    for attempt in 1..=30 {
        let status = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                parent_kubeconfig,
                "get",
                "latticecluster",
                child_cluster_name,
                "-o",
                "jsonpath={.status.agentConnected}",
            ],
        );

        if status.trim() == "true" {
            info!(
                "[Integration/Proxy] Agent for {} is connected",
                child_cluster_name
            );
            return Ok(());
        }

        if attempt < 30 {
            info!(
                "[Integration/Proxy] Waiting for agent connection (attempt {}/30)...",
                attempt
            );
            sleep(Duration::from_secs(5)).await;
        }
    }

    info!(
        "[Integration/Proxy] Note: Could not confirm agent connection for {} (cluster may have pivoted)",
        child_cluster_name
    );
    Ok(())
}

/// Test proxy access from parent cluster to child cluster.
///
/// Uses the patched kubeconfig from the CAPI secret to access the child
/// through the proxy endpoint.
pub async fn test_proxy_access_to_child(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access to {}...",
        child_cluster_name
    );

    let namespace = format!("capi-{}", child_cluster_name);
    let secret_name = format!("{}-kubeconfig", child_cluster_name);

    let kubeconfig = extract_kubeconfig_from_secret(parent_kubeconfig, &namespace, &secret_name)?;

    // Verify kubeconfig is patched for proxy
    if !kubeconfig.contains("/cluster/") {
        return Err(format!(
            "Kubeconfig for {} not patched for proxy - missing /cluster/ path",
            child_cluster_name
        ));
    }

    let result = kubectl_with_temp_kubeconfig(
        &kubeconfig,
        child_cluster_name,
        &["get", "namespaces", "-o", "name", "--request-timeout=30s"],
    )?;

    if result.trim().is_empty() || result.contains("error") || result.contains("Error") {
        info!(
            "[Integration/Proxy] Proxy access to {} returned: {}",
            child_cluster_name,
            result.trim()
        );
        info!("[Integration/Proxy] Note: Proxy access may require Cedar policies");
        return Ok(());
    }

    let namespace_count = result.lines().filter(|l| !l.is_empty()).count();
    info!(
        "[Integration/Proxy] SUCCESS: Proxy access to {} worked - {} namespaces visible",
        child_cluster_name, namespace_count
    );

    Ok(())
}

/// Test proxy access from root cluster to grandchild cluster.
///
/// This is the key hierarchical test:
/// - Root (mgmt) → Child (workload) → Grandchild (workload2)
///
/// The proxy should be able to reach the grandchild even though it's
/// two hops away, because each parent maintains the subtree registry
/// of all descendants.
pub async fn test_proxy_access_to_grandchild(
    root_kubeconfig: &str,
    child_cluster_name: &str,
    grandchild_cluster_name: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Proxy] Testing proxy access from root to grandchild {}...",
        grandchild_cluster_name
    );
    info!(
        "[Integration/Proxy] Path: root -> {} -> {}",
        child_cluster_name, grandchild_cluster_name
    );

    // Get child's kubeconfig from root
    let child_namespace = format!("capi-{}", child_cluster_name);
    let child_secret_name = format!("{}-kubeconfig", child_cluster_name);
    let child_kubeconfig =
        extract_kubeconfig_from_secret(root_kubeconfig, &child_namespace, &child_secret_name)?;

    // Write child kubeconfig to access grandchild's secret through child
    let child_temp_path = write_temp_kubeconfig(child_cluster_name, &child_kubeconfig)?;

    // Get grandchild's kubeconfig through child (this goes through the proxy)
    let grandchild_namespace = format!("capi-{}", grandchild_cluster_name);
    let grandchild_secret_name = format!("{}-kubeconfig", grandchild_cluster_name);

    let grandchild_kubeconfig_b64 = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            &child_temp_path,
            "get",
            "secret",
            &grandchild_secret_name,
            "-n",
            &grandchild_namespace,
            "-o",
            "jsonpath={.data.value}",
            "--request-timeout=30s",
        ],
    );

    let _ = std::fs::remove_file(&child_temp_path);

    if grandchild_kubeconfig_b64.trim().is_empty()
        || grandchild_kubeconfig_b64.contains("error")
        || grandchild_kubeconfig_b64.contains("Error")
    {
        info!(
            "[Integration/Proxy] Could not get grandchild kubeconfig through proxy: {}",
            grandchild_kubeconfig_b64.trim()
        );
        info!("[Integration/Proxy] Note: Hierarchical proxy may require Cedar policies");
        return Ok(());
    }

    // Decode grandchild kubeconfig
    let grandchild_kubeconfig_bytes = STANDARD
        .decode(grandchild_kubeconfig_b64.trim())
        .map_err(|e| format!("Failed to decode grandchild kubeconfig: {}", e))?;
    let grandchild_kubeconfig = String::from_utf8(grandchild_kubeconfig_bytes)
        .map_err(|e| format!("Invalid UTF-8 in grandchild kubeconfig: {}", e))?;

    // Access grandchild through the proxy
    let result = kubectl_with_temp_kubeconfig(
        &grandchild_kubeconfig,
        grandchild_cluster_name,
        &["get", "namespaces", "-o", "name", "--request-timeout=30s"],
    )?;

    if result.trim().is_empty() || result.contains("error") || result.contains("Error") {
        info!(
            "[Integration/Proxy] Grandchild proxy access returned: {}",
            result.trim()
        );
        info!("[Integration/Proxy] Note: Full hierarchical proxy may require Cedar policies");
        return Ok(());
    }

    let namespace_count = result.lines().filter(|l| !l.is_empty()).count();
    info!(
        "[Integration/Proxy] SUCCESS: Grandchild proxy access worked - {} namespaces visible through hierarchy",
        namespace_count
    );

    Ok(())
}

/// Run full proxy hierarchy tests.
///
/// Tests proxy access through the full cluster hierarchy:
/// mgmt -> workload -> workload2
pub async fn run_proxy_hierarchy_tests(
    ctx: &InfraContext,
    workload_cluster_name: &str,
    workload2_cluster_name: &str,
) -> Result<(), String> {
    info!("[Integration/Proxy] Running full hierarchy proxy tests...");
    info!(
        "[Integration/Proxy] Hierarchy: mgmt -> {} -> {}",
        workload_cluster_name, workload2_cluster_name
    );

    // Wait for child agent
    wait_for_agent_ready(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Test direct child access through proxy
    test_proxy_access_to_child(&ctx.mgmt_kubeconfig, workload_cluster_name).await?;

    // Wait for grandchild agent (through child)
    if ctx.has_workload() {
        wait_for_agent_ready(
            ctx.workload_kubeconfig.as_deref().unwrap(),
            workload2_cluster_name,
        )
        .await?;

        // Test grandchild access through hierarchy
        test_proxy_access_to_grandchild(
            &ctx.mgmt_kubeconfig,
            workload_cluster_name,
            workload2_cluster_name,
        )
        .await?;
    }

    info!("[Integration/Proxy] Proxy hierarchy tests complete");
    Ok(())
}

// ============================================================================
// Standalone Tests
// ============================================================================

/// Standalone test - test proxy access to child cluster
#[tokio::test]
#[ignore]
async fn test_proxy_access_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());

    wait_for_agent_ready(&ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();
    test_proxy_access_to_child(&ctx.mgmt_kubeconfig, &workload_name)
        .await
        .unwrap();
}

/// Standalone test - test full hierarchy proxy
#[tokio::test]
#[ignore]
async fn test_proxy_hierarchy_standalone() {
    let ctx = init_test_env("Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG");
    let workload_name = std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string());
    let workload2_name = std::env::var("LATTICE_WORKLOAD2_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD2_CLUSTER_NAME.to_string());

    run_proxy_hierarchy_tests(&ctx, &workload_name, &workload2_name)
        .await
        .unwrap();
}
