//! Per-integration E2E test: Third-Party Mesh Onboarding
//!
//! Sets up mgmt + workload, runs mesh onboarding tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_mesh_onboarding_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_mesh_onboarding_e2e() {
    run_per_integration_e2e(
        "MeshOnboarding",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::mesh_onboarding::run_mesh_onboarding_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
