//! Per-integration E2E test: Web App + PostgreSQL
//!
//! Sets up mgmt + workload, runs webapp+postgres tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_webapp_postgres_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_webapp_postgres_e2e() {
    run_per_integration_e2e(
        "WebApp+PostgreSQL",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::webapp_postgres::run_webapp_postgres_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
