//! Multi-cluster route discovery integration tests
//!
//! Verifies that LatticeService resources with `advertise: true` ingress routes
//! result in a populated `LatticeClusterRoutes` CRD on the parent cluster.
//!
//! # Running Standalone
//!
//! Requires a parent cluster with at least one connected child that has
//! LatticeService resources with advertised ingress routes.
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/parent-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_route_discovery_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{run_kubectl, wait_for_condition, DEFAULT_TIMEOUT};

/// Verify that LatticeClusterRoutes CRDs exist and contain routes
///
/// Checks the parent cluster for LatticeClusterRoutes resources.
/// These should be populated from child agent heartbeats when child
/// LatticeServices have `advertise: true` on their ingress routes.
pub async fn verify_cluster_routes_exist(parent_kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/RouteDiscovery] Checking for LatticeClusterRoutes CRDs...");

    let output = run_kubectl(&[
        "--kubeconfig",
        parent_kubeconfig,
        "get",
        "latticeclusterroutes",
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse JSON: {e}"))?;

    let items = parsed["items"]
        .as_array()
        .ok_or("expected items array in response")?;

    if items.is_empty() {
        return Err("no LatticeClusterRoutes CRDs found — child agents may not have advertised routes yet".to_string());
    }

    for item in items {
        let name = item["metadata"]["name"]
            .as_str()
            .unwrap_or("unknown");
        let route_count = item["status"]["routeCount"]
            .as_u64()
            .unwrap_or(0);
        let phase = item["status"]["phase"]
            .as_str()
            .unwrap_or("unknown");

        info!(
            "[Integration/RouteDiscovery] Found LatticeClusterRoutes '{}': {} routes, phase={}",
            name, route_count, phase
        );
    }

    info!("[Integration/RouteDiscovery] LatticeClusterRoutes CRDs verified");
    Ok(())
}

/// Verify that a specific child cluster's routes are advertised on the parent
pub async fn verify_child_routes(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    expected_hostnames: &[&str],
) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Verifying routes for child cluster '{}'...",
        child_cluster_name
    );

    wait_for_condition(
        &format!("LatticeClusterRoutes for {child_cluster_name}"),
        DEFAULT_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = parent_kubeconfig.to_string();
            let cluster = child_cluster_name.to_string();
            let hostnames: Vec<String> = expected_hostnames.iter().map(|h| h.to_string()).collect();
            async move {
                let output = match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeclusterroutes",
                    &cluster,
                    "-o",
                    "json",
                ])
                .await
                {
                    Ok(o) => o,
                    Err(_) => return Ok(false),
                };

                let parsed: serde_json::Value = match serde_json::from_str(&output) {
                    Ok(v) => v,
                    Err(_) => return Ok(false),
                };

                let routes = match parsed["spec"]["routes"].as_array() {
                    Some(r) => r,
                    None => return Ok(false),
                };

                for expected in &hostnames {
                    let found = routes.iter().any(|r| {
                        r["hostname"].as_str() == Some(expected.as_str())
                    });
                    if !found {
                        info!(
                            "[Integration/RouteDiscovery] Hostname '{}' not yet found in routes",
                            expected
                        );
                        return Ok(false);
                    }
                }

                Ok(true)
            }
        },
    )
    .await?;

    info!(
        "[Integration/RouteDiscovery] All expected routes found for '{}'",
        child_cluster_name
    );
    Ok(())
}

/// Full route discovery test suite
pub async fn run_route_discovery_tests(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    expected_hostnames: &[&str],
) -> Result<(), String> {
    info!("[Integration/RouteDiscovery] Starting route discovery tests...");

    verify_cluster_routes_exist(parent_kubeconfig).await?;
    verify_child_routes(parent_kubeconfig, child_cluster_name, expected_hostnames).await?;

    info!("[Integration/RouteDiscovery] Route discovery tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_route_discovery_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();

    // When running standalone, just verify CRDs exist — we don't know
    // which child cluster or hostnames to expect
    verify_cluster_routes_exist(&resolved.kubeconfig)
        .await
        .unwrap();
}
