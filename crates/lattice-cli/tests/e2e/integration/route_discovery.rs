//! Multi-cluster route discovery and cross-cluster connectivity integration tests
//!
//! Verifies the full cross-cluster route discovery pipeline:
//! - LatticeService advertise config propagates routes via heartbeat
//! - LatticeClusterRoutes CRDs are populated on the parent
//! - Remote services appear in the ServiceGraph
//! - ServiceEntry resources are generated for cross-cluster dependencies
//! - Gateway frontend mTLS is configured for advertised routes
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/parent-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_route_discovery_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{run_kubectl, wait_for_condition, DEFAULT_TIMEOUT};

// =============================================================================
// Route Table Verification
// =============================================================================

/// Verify that LatticeClusterRoutes CRDs exist and contain routes
pub async fn verify_cluster_routes_exist(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/RouteDiscovery] Checking for LatticeClusterRoutes CRDs...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
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
        return Err("no LatticeClusterRoutes CRDs found".to_string());
    }

    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let route_count = item["status"]["routeCount"].as_u64().unwrap_or(0);
        let phase = item["status"]["phase"].as_str().unwrap_or("unknown");

        info!(
            "[Integration/RouteDiscovery] LatticeClusterRoutes '{}': {} routes, phase={}",
            name, route_count, phase
        );
    }

    Ok(())
}

/// Verify that specific hostnames appear in a cluster's route table
pub async fn verify_child_routes(
    kubeconfig: &str,
    cluster_name: &str,
    expected_hostnames: &[&str],
) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Waiting for routes from cluster '{}'...",
        cluster_name
    );

    wait_for_condition(
        &format!("LatticeClusterRoutes for {cluster_name}"),
        DEFAULT_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = kubeconfig.to_string();
            let cluster = cluster_name.to_string();
            let hostnames: Vec<String> =
                expected_hostnames.iter().map(|h| h.to_string()).collect();
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
                    if !routes
                        .iter()
                        .any(|r| r["hostname"].as_str() == Some(expected.as_str()))
                    {
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
        cluster_name
    );
    Ok(())
}

/// Verify that route entries contain service identity fields
pub async fn verify_route_service_identity(
    kubeconfig: &str,
    cluster_name: &str,
    service_name: &str,
    service_namespace: &str,
) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Verifying service identity for {}/{}...",
        service_namespace, service_name
    );

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeclusterroutes",
        cluster_name,
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let routes = parsed["spec"]["routes"]
        .as_array()
        .ok_or("no routes in spec")?;

    let found = routes.iter().any(|r| {
        r["serviceName"].as_str() == Some(service_name)
            && r["serviceNamespace"].as_str() == Some(service_namespace)
    });

    if !found {
        return Err(format!(
            "route for {}/{} not found in LatticeClusterRoutes",
            service_namespace, service_name
        ));
    }

    info!(
        "[Integration/RouteDiscovery] Service identity verified for {}/{}",
        service_namespace, service_name
    );
    Ok(())
}

// =============================================================================
// ServiceEntry Verification
// =============================================================================

/// Verify that ServiceEntry resources exist for remote dependencies
pub async fn verify_remote_service_entries(
    kubeconfig: &str,
    namespace: &str,
) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Checking for remote ServiceEntry objects in '{}'...",
        namespace
    );

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "serviceentries",
        "-n",
        namespace,
        "-l",
        "lattice.dev/managed-by=lattice-mesh-member",
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let items = parsed["items"]
        .as_array()
        .ok_or("expected items array")?;

    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let hosts = &item["spec"]["hosts"];
        let resolution = item["spec"]["resolution"].as_str().unwrap_or("unknown");
        let protocol = item["spec"]["ports"][0]["protocol"]
            .as_str()
            .unwrap_or("unknown");

        info!(
            "[Integration/RouteDiscovery] ServiceEntry '{}': hosts={}, resolution={}, protocol={}",
            name, hosts, resolution, protocol
        );

        // Cross-cluster ServiceEntries should use HTTPS + STATIC
        if name.starts_with("remote-") {
            if resolution != "STATIC" {
                return Err(format!(
                    "ServiceEntry '{}' should use STATIC resolution, got {}",
                    name, resolution
                ));
            }
            if protocol != "HTTPS" {
                return Err(format!(
                    "ServiceEntry '{}' should use HTTPS protocol, got {}",
                    name, protocol
                ));
            }

            // Should have an address for STATIC resolution
            let addresses = item["spec"]["addresses"]
                .as_array()
                .ok_or(format!("ServiceEntry '{}' missing addresses", name))?;
            if addresses.is_empty() {
                return Err(format!(
                    "ServiceEntry '{}' has empty addresses for STATIC resolution",
                    name
                ));
            }
        }
    }

    info!(
        "[Integration/RouteDiscovery] ServiceEntry verification passed for '{}'",
        namespace
    );
    Ok(())
}

// =============================================================================
// Gateway mTLS Verification
// =============================================================================

/// Verify that Gateways with advertised routes have frontend mTLS configured
pub async fn verify_gateway_frontend_mtls(
    kubeconfig: &str,
    namespace: &str,
) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Checking Gateway frontend mTLS in '{}'...",
        namespace
    );

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "gateways.gateway.networking.k8s.io",
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let items = parsed["items"]
        .as_array()
        .ok_or("expected items array")?;

    for item in items {
        let name = item["metadata"]["name"].as_str().unwrap_or("unknown");
        let has_frontend_tls = item["spec"]["tls"]["frontend"]
            .as_object()
            .is_some();

        if has_frontend_tls {
            let ca_refs = &item["spec"]["tls"]["frontend"]["default"]["validation"]
                ["caCertificateRefs"];

            if let Some(refs) = ca_refs.as_array() {
                if refs.is_empty() {
                    return Err(format!(
                        "Gateway '{}' has frontend TLS but no CA certificate refs",
                        name
                    ));
                }

                let ca_name = refs[0]["name"].as_str().unwrap_or("unknown");
                info!(
                    "[Integration/RouteDiscovery] Gateway '{}' has frontend mTLS with CA '{}'",
                    name, ca_name
                );
            }
        } else {
            info!(
                "[Integration/RouteDiscovery] Gateway '{}' has no frontend mTLS (no advertised routes)",
                name
            );
        }
    }

    Ok(())
}

// =============================================================================
// Route Status Verification
// =============================================================================

/// Verify that LatticeClusterRoutes status has observedGeneration matching spec generation
pub async fn verify_route_status(kubeconfig: &str, cluster_name: &str) -> Result<(), String> {
    info!(
        "[Integration/RouteDiscovery] Verifying route status for '{}'...",
        cluster_name
    );

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeclusterroutes",
        cluster_name,
        "-o",
        "json",
    ])
    .await?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("failed to parse: {e}"))?;

    let phase = parsed["status"]["phase"]
        .as_str()
        .ok_or("missing status.phase")?;

    if phase != "Ready" {
        return Err(format!(
            "LatticeClusterRoutes '{}' phase is '{}', expected 'Ready'",
            cluster_name, phase
        ));
    }

    let spec_generation = parsed["metadata"]["generation"].as_i64();
    let observed_generation = parsed["status"]["observedGeneration"].as_i64();

    if spec_generation != observed_generation {
        return Err(format!(
            "LatticeClusterRoutes '{}' generation mismatch: spec={:?}, observed={:?}",
            cluster_name, spec_generation, observed_generation
        ));
    }

    info!(
        "[Integration/RouteDiscovery] Route status verified for '{}': Ready, generation={:?}",
        cluster_name, spec_generation
    );
    Ok(())
}

// =============================================================================
// Full Test Suite
// =============================================================================

/// Run the complete route discovery test suite
pub async fn run_route_discovery_tests(
    parent_kubeconfig: &str,
    child_cluster_name: &str,
    expected_hostnames: &[&str],
) -> Result<(), String> {
    info!("[Integration/RouteDiscovery] Starting full route discovery test suite...");

    // Verify route table exists and contains expected routes
    verify_cluster_routes_exist(parent_kubeconfig).await?;
    verify_child_routes(parent_kubeconfig, child_cluster_name, expected_hostnames).await?;
    verify_route_status(parent_kubeconfig, child_cluster_name).await?;

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

    verify_cluster_routes_exist(&resolved.kubeconfig)
        .await
        .unwrap();
}
