//! Per-integration E2E: Route discovery
//!
//! Sets up mgmt + workload, deploys a service with advertised routes,
//! verifies the full pipeline from heartbeat to LatticeClusterRoutes.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_route_discovery_e2e() {
    run_per_integration_e2e(
        "RouteDiscovery",
        Duration::from_secs(1200),
        |ctx| async move {
            let parent_kc = &ctx.mgmt_kubeconfig;
            let workload_name = super::helpers::WORKLOAD_CLUSTER_NAME;

            // Verify route table pipeline
            integration::route_discovery::verify_cluster_routes_exist(parent_kc).await?;
            integration::route_discovery::verify_route_status(parent_kc, workload_name).await?;

            // If workload has advertised routes, verify ServiceEntry generation
            if let Some(ref workload_kc) = ctx.workload_kubeconfig {
                integration::route_discovery::verify_gateway_frontend_mtls(
                    workload_kc,
                    "default",
                )
                .await?;
            }

            Ok(())
        },
    )
    .await;
}
