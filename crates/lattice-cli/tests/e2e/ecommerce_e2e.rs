//! Per-integration E2E test: E-Commerce Microservices
//!
//! Sets up mgmt + workload, runs ecommerce tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_ecommerce_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_ecommerce_e2e() {
    run_per_integration_e2e("Ecommerce", Duration::from_secs(2400), |ctx| async move {
        integration::ecommerce::run_ecommerce_tests(ctx.require_workload()?).await
    })
    .await;
}
