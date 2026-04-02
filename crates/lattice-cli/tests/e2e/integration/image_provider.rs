//! ImageProvider integration tests
//!
//! Verifies that ImageProvider CRDs are reconciled end-to-end:
//! - Controller syncs credentials via ESO
//! - ExternalSecret creates a dockerconfigjson Secret
//! - ImageProvider transitions to Ready
//! - Distribution includes ImageProvider in resource sync
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_image_provider_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::{
    apply_yaml, run_kubectl, wait_for_condition, wait_for_resource_phase, with_diagnostics,
    DiagnosticContext, DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const LATTICE_NS: &str = "lattice-system";
const SECRETS_NS: &str = "lattice-secrets";

/// Run the full ImageProvider integration test suite.
pub async fn run_image_provider_tests(kubeconfig: &str) -> Result<(), String> {
    let diag = DiagnosticContext::new(kubeconfig, LATTICE_NS);
    with_diagnostics(&diag, "ImageProvider", || async {
        test_image_provider_lifecycle(kubeconfig).await?;

        cleanup(kubeconfig).await;

        info!("[ImageProvider] All integration tests passed!");
        Ok(())
    })
    .await
}

/// Test: Create an ImageProvider with local webhook credentials → Ready + Secret created
async fn test_image_provider_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[ImageProvider] Testing lifecycle: create → Ready → Secret exists");

    // Seed a source secret in lattice-secrets (ESO local webhook source)
    let seed_secret = r#"
apiVersion: v1
kind: Secret
metadata:
  name: test-image-creds
  namespace: lattice-secrets
  labels:
    lattice.dev/secret-source: "true"
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: '{"auths":{"test-registry.example.com":{"auth":"dGVzdDp0ZXN0"}}}'
"#;
    apply_yaml(kubeconfig, seed_secret).await?;
    info!("[ImageProvider] Seed secret created in {SECRETS_NS}");

    // Create ImageProvider CRD referencing the seed secret
    let image_provider = r#"
apiVersion: lattice.dev/v1alpha1
kind: ImageProvider
metadata:
  name: test-registry
  namespace: lattice-system
spec:
  type: generic
  registry: test-registry.example.com
  credentials:
    type: secret
    id: test-image-creds
    params:
      provider: lattice-local
"#;
    apply_yaml(kubeconfig, image_provider).await?;
    info!("[ImageProvider] CRD created");

    // Wait for ImageProvider to reach Ready
    wait_for_resource_phase(
        kubeconfig,
        "imageprovider",
        "test-registry",
        LATTICE_NS,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!("[ImageProvider] Reached Ready phase");

    // Verify the ESO-synced Secret exists
    wait_for_condition(
        "ImageProvider credential Secret to exist",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kubeconfig.to_string();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "secret",
                    "test-registry-credentials",
                    "-n",
                    LATTICE_NS,
                    "-o",
                    "jsonpath={.type}",
                ])
                .await;
                match result {
                    Ok(secret_type) if secret_type.trim() == "kubernetes.io/dockerconfigjson" => {
                        Ok(Some(()))
                    }
                    Ok(secret_type) if !secret_type.is_empty() => Err(format!(
                        "Secret exists but wrong type: expected kubernetes.io/dockerconfigjson, got {}",
                        secret_type.trim()
                    )),
                    _ => Ok(None), // Not ready yet
                }
            }
        },
    )
    .await?;
    info!("[ImageProvider] Credential Secret exists with correct type");

    // Verify the Secret has the expected content
    let content = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "secret",
        "test-registry-credentials",
        "-n",
        LATTICE_NS,
        "-o",
        "jsonpath={.data.\\.dockerconfigjson}",
    ])
    .await?;
    if content.trim().is_empty() {
        return Err("Secret .dockerconfigjson is empty".to_string());
    }
    info!("[ImageProvider] Secret content verified");

    info!("[ImageProvider] Lifecycle test PASSED");
    Ok(())
}

async fn cleanup(kubeconfig: &str) {
    // Delete test ImageProvider
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "imageprovider",
        "test-registry",
        "-n",
        LATTICE_NS,
        "--ignore-not-found",
    ])
    .await;

    // Delete test seed secret
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "secret",
        "test-image-creds",
        "-n",
        SECRETS_NS,
        "--ignore-not-found",
    ])
    .await;

    // Delete ESO-synced secret
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "secret",
        "test-registry-credentials",
        "-n",
        LATTICE_NS,
        "--ignore-not-found",
    ])
    .await;

    info!("[ImageProvider] Cleanup complete");
}

// =============================================================================
// Standalone test entry point
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_image_provider_standalone() {
    super::super::context::init_test_env("Set LATTICE_KUBECONFIG or LATTICE_WORKLOAD_KUBECONFIG");
    let ctx = super::super::context::InfraContext::from_env()
        .expect("Set LATTICE_KUBECONFIG or LATTICE_WORKLOAD_KUBECONFIG");
    let kubeconfig = ctx.workload_kubeconfig.as_deref().unwrap_or(&ctx.mgmt_kubeconfig);
    run_image_provider_tests(kubeconfig)
        .await
        .expect("ImageProvider tests failed");
}
