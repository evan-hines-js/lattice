//! Per-integration E2E test: Celery Task Queue
//!
//! Sets up mgmt + workload, runs celery queue tests, then tears down.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_celery_queue_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_celery_queue_e2e() {
    run_per_integration_e2e("CeleryQueue", Duration::from_secs(2400), |ctx| async move {
        integration::celery_queue::run_celery_queue_tests(ctx.require_workload()?).await
    })
    .await;
}
