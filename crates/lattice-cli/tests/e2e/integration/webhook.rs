//! Admission webhook integration tests
//!
//! Verifies that the ValidatingAdmissionWebhook rejects invalid Lattice CRDs
//! at admission time and allows valid ones through.
//!
//! Run standalone:
//! ```
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/xxx-e2e-workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_webhook_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{run_kubectl, wait_for_condition};

const WEBHOOK_TEST_NS: &str = "webhook-test";

/// Sanitize a test description for use in a file path
fn sanitize_desc(desc: &str) -> String {
    desc.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Apply YAML via kubectl and expect it to succeed
async fn apply_should_succeed(kubeconfig: &str, yaml: &str, desc: &str) -> Result<(), String> {
    let tmpfile = format!("/tmp/webhook-test-{}.yaml", sanitize_desc(desc));
    tokio::fs::write(&tmpfile, yaml)
        .await
        .map_err(|e| format!("Failed to write temp file: {e}"))?;

    run_kubectl(&["--kubeconfig", kubeconfig, "apply", "-f", &tmpfile]).await?;

    info!("[Webhook] {desc}: accepted (expected)");
    Ok(())
}

/// Apply YAML via kubectl and expect it to be rejected by the admission webhook.
///
/// Returns the error message from the rejection for further assertions.
async fn apply_should_be_rejected(
    kubeconfig: &str,
    yaml: &str,
    desc: &str,
) -> Result<String, String> {
    let tmpfile = format!("/tmp/webhook-test-{}.yaml", sanitize_desc(desc));
    tokio::fs::write(&tmpfile, yaml)
        .await
        .map_err(|e| format!("Failed to write temp file: {e}"))?;

    // kubectl apply should fail — that's the expected behavior
    let result = tokio::process::Command::new("kubectl")
        .args(["--kubeconfig", kubeconfig, "apply", "-f", &tmpfile])
        .output()
        .await
        .map_err(|e| format!("Failed to spawn kubectl: {e}"))?;

    if result.status.success() {
        return Err(format!(
            "[Webhook] {desc}: was accepted but should have been REJECTED"
        ));
    }

    let stderr = String::from_utf8_lossy(&result.stderr).to_string();
    info!("[Webhook] {desc}: rejected (expected): {stderr}");
    Ok(stderr)
}

/// Wait for the admission webhook to be responsive.
///
/// The webhook server starts on all pods before leader election, but the
/// ValidatingWebhookConfiguration is applied by the leader after CRD installation.
/// This function polls until the webhook is active by checking if the
/// ValidatingWebhookConfiguration exists.
async fn wait_for_webhook_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Webhook] Waiting for admission webhook to be ready...");

    wait_for_condition(
        "ValidatingWebhookConfiguration to exist",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kubeconfig.to_string();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "validatingwebhookconfiguration",
                    "lattice-validating-webhook",
                    "-o",
                    "name",
                ])
                .await;

                match output {
                    Ok(name) if name.contains("lattice-validating-webhook") => Ok(true),
                    _ => Ok(false),
                }
            }
        },
    )
    .await?;

    info!("[Webhook] Admission webhook is ready");
    Ok(())
}

/// Ensure the test namespace exists
async fn ensure_test_namespace(kubeconfig: &str) -> Result<(), String> {
    let ns_yaml = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {WEBHOOK_TEST_NS}");
    let tmpfile = "/tmp/webhook-test-ns.yaml";
    tokio::fs::write(tmpfile, &ns_yaml)
        .await
        .map_err(|e| format!("Failed to write namespace yaml: {e}"))?;

    run_kubectl(&["--kubeconfig", kubeconfig, "apply", "-f", tmpfile]).await?;
    Ok(())
}

/// Test: valid LatticeService is accepted
async fn test_valid_service_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: webhook-test-svc
  namespace: {WEBHOOK_TEST_NS}
spec:
  workload:
    containers:
      main:
        image: nginx:latest
        resources:
          limits:
            cpu: "100m"
            memory: "64Mi"
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeService").await
}

/// Test: LatticeService with replicas > autoscaling.max is rejected
async fn test_invalid_service_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: webhook-test-bad-svc
  namespace: {WEBHOOK_TEST_NS}
spec:
  replicas: 10
  autoscaling:
    max: 5
  workload:
    containers:
      main:
        image: nginx:latest
        resources:
          limits:
            cpu: "100m"
            memory: "64Mi"
"#
    );
    let err =
        apply_should_be_rejected(kubeconfig, &yaml, "service replicas > autoscaling max").await?;
    if !err.contains("replicas") || !err.contains("autoscaling") {
        return Err(format!(
            "Expected rejection to mention replicas/autoscaling, got: {err}"
        ));
    }
    Ok(())
}

/// Test: valid LatticeModel is accepted
async fn test_valid_model_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: webhook-test-model
  namespace: {WEBHOOK_TEST_NS}
spec:
  roles:
    prefill:
      replicas: 1
      entryWorkload:
        containers:
          main:
            image: vllm:latest
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeModel").await
}

/// Test: LatticeModel with role replicas > autoscaling.max is rejected
async fn test_invalid_model_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: webhook-test-bad-model
  namespace: {WEBHOOK_TEST_NS}
spec:
  roles:
    decode:
      replicas: 10
      autoscaling:
        max: 5
      entryWorkload:
        containers:
          main:
            image: vllm:latest
"#
    );
    let err = apply_should_be_rejected(kubeconfig, &yaml, "model role replicas > autoscaling max")
        .await?;
    if !err.contains("decode") {
        return Err(format!(
            "Expected rejection to mention the role name 'decode', got: {err}"
        ));
    }
    Ok(())
}

/// Test: valid LatticeMeshMember is accepted
async fn test_valid_mesh_member_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: webhook-test-mesh
  namespace: {WEBHOOK_TEST_NS}
spec:
  target:
    selector:
      app: test
  ports:
    - port: 8080
      name: http
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeMeshMember").await
}

/// Test: LatticeMeshMember with no ports/deps/egress is rejected
async fn test_invalid_mesh_member_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: webhook-test-bad-mesh
  namespace: {WEBHOOK_TEST_NS}
spec:
  target:
    selector:
      app: test
  ports: []
  dependencies: []
  egress: []
"#
    );
    apply_should_be_rejected(kubeconfig, &yaml, "mesh member with no ports/deps/egress").await?;
    Ok(())
}

/// Cleanup test resources
async fn cleanup(kubeconfig: &str) {
    info!("[Webhook] Cleaning up test namespace...");
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "namespace",
        WEBHOOK_TEST_NS,
    ])
    .await;
}

/// Run all webhook integration tests
pub async fn run_webhook_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Webhook] Running admission webhook integration tests on {kubeconfig}");

    wait_for_webhook_ready(kubeconfig).await?;
    ensure_test_namespace(kubeconfig).await?;

    // Valid resources should be accepted
    test_valid_service_accepted(kubeconfig).await?;
    test_valid_model_accepted(kubeconfig).await?;
    test_valid_mesh_member_accepted(kubeconfig).await?;

    // Invalid resources should be rejected by the webhook
    test_invalid_service_rejected(kubeconfig).await?;
    test_invalid_model_rejected(kubeconfig).await?;
    test_invalid_mesh_member_rejected(kubeconfig).await?;

    cleanup(kubeconfig).await;

    info!("[Webhook] All admission webhook integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_webhook_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run standalone webhook tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_webhook_tests(&session.ctx).await {
        panic!("Webhook tests failed: {e}");
    }
}
