//! LatticeModel integration tests
//!
//! Verifies that deploying a LatticeModel creates the expected Kthena ModelServing,
//! tracing policies, and correct role structure.
//!
//! Run standalone:
//! ```
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/xxx-e2e-workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_model_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    apply_apparmor_override_policy, apply_yaml_with_retry, delete_namespace, load_fixture_config,
    run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
};

const MODEL_NAMESPACE: &str = "serving";
const MODEL_NAME: &str = "llm-serving";

/// Load the model-serving fixture
fn load_model_fixture() -> Result<lattice_common::crd::LatticeModel, String> {
    load_fixture_config("model-serving.yaml")
}

/// Wait for a LatticeModel to reach the expected phase
async fn wait_for_model_phase(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    phase: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let model_name = name.to_string();
    let expected_phase = phase.to_string();

    wait_for_condition(
        &format!(
            "LatticeModel {}/{} to reach {}",
            namespace, name, phase
        ),
        timeout,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let model_name = model_name.clone();
            let expected_phase = expected_phase.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticemodel",
                    &model_name,
                    "-n",
                    &ns,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;

                match output {
                    Ok(current_phase) => {
                        let current = current_phase.trim();
                        info!("LatticeModel {}/{} phase: {}", ns, model_name, current);
                        Ok(current == expected_phase)
                    }
                    Err(e) => {
                        info!("LatticeModel {}/{} not ready: {}", ns, model_name, e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Deploy a LatticeModel and verify the controller starts reconciling
async fn test_model_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Deploying LatticeModel from fixture...");

    super::super::helpers::services::ensure_namespace(kubeconfig, MODEL_NAMESPACE).await?;

    let model = load_model_fixture()?;
    let yaml = serde_json::to_string(&model)
        .map_err(|e| format!("Failed to serialize model fixture: {e}"))?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for controller to pick up and transition to Loading
    wait_for_model_phase(
        kubeconfig,
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Loading",
        Duration::from_secs(120),
    )
    .await?;

    info!("[Model] LatticeModel reached Loading phase");
    Ok(())
}

/// Verify ModelServing resource was created with expected role structure
async fn test_model_serving_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying ModelServing creation...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse ModelServing JSON: {e}"))?;

    // Verify roles Vec has 2 entries (decode, prefill — sorted by BTreeMap)
    let roles = ms["spec"]["template"]["roles"]
        .as_array()
        .ok_or("ModelServing spec.template.roles is not an array")?;

    if roles.len() != 2 {
        return Err(format!("Expected 2 roles, got: {}", roles.len()));
    }

    // Roles are ordered by BTreeMap key: decode first, then prefill
    let decode = roles
        .iter()
        .find(|r| r["name"].as_str() == Some("decode"))
        .ok_or("decode role not found")?;
    let prefill = roles
        .iter()
        .find(|r| r["name"].as_str() == Some("prefill"))
        .ok_or("prefill role not found")?;

    // Verify decode role: replicas=2, workerReplicas=4, both templates present
    if decode["replicas"].as_u64() != Some(2) {
        return Err(format!(
            "decode role: expected replicas=2, got: {}",
            decode["replicas"]
        ));
    }
    if decode["workerReplicas"].as_u64() != Some(4) {
        return Err(format!(
            "decode role: expected workerReplicas=4, got: {}",
            decode["workerReplicas"]
        ));
    }
    if decode["entryTemplate"].is_null() {
        return Err("decode role: entryTemplate is null".to_string());
    }
    if decode["workerTemplate"].is_null() {
        return Err("decode role: workerTemplate is null".to_string());
    }

    // Verify prefill role: replicas=1, no workerReplicas/workerTemplate
    if prefill["replicas"].as_u64() != Some(1) {
        return Err(format!(
            "prefill role: expected replicas=1, got: {}",
            prefill["replicas"]
        ));
    }
    if !prefill["workerReplicas"].is_null() {
        return Err(format!(
            "prefill role: expected no workerReplicas, got: {}",
            prefill["workerReplicas"]
        ));
    }
    if !prefill["workerTemplate"].is_null() {
        return Err(format!(
            "prefill role: expected no workerTemplate, got: {}",
            prefill["workerTemplate"]
        ));
    }

    // Verify gangPolicy.minRoleReplicas
    let gang = &ms["spec"]["template"]["gangPolicy"];
    if gang.is_null() {
        return Err("gangPolicy is null".to_string());
    }
    let min_replicas = &gang["minRoleReplicas"];
    if min_replicas["decode"].as_u64() != Some(2) {
        return Err(format!(
            "gangPolicy: expected decode minRoleReplicas=2, got: {}",
            min_replicas["decode"]
        ));
    }
    if min_replicas["prefill"].as_u64() != Some(1) {
        return Err(format!(
            "gangPolicy: expected prefill minRoleReplicas=1, got: {}",
            min_replicas["prefill"]
        ));
    }

    // Verify schedulerName
    let scheduler = ms["spec"]["schedulerName"]
        .as_str()
        .unwrap_or_default();
    if scheduler != "volcano" {
        return Err(format!(
            "Expected schedulerName 'volcano', got: '{scheduler}'"
        ));
    }

    // Verify restartGracePeriodSeconds
    if ms["spec"]["template"]["restartGracePeriodSeconds"].as_i64() != Some(30) {
        return Err(format!(
            "Expected restartGracePeriodSeconds=30, got: {}",
            ms["spec"]["template"]["restartGracePeriodSeconds"]
        ));
    }

    // Verify ownerReferences
    let owner_kind = ms["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if owner_kind != "LatticeModel" {
        return Err(format!(
            "Expected ownerReference kind 'LatticeModel', got: '{owner_kind}'"
        ));
    }

    info!("[Model] ModelServing verified: 2 roles (decode+prefill), gang policy, correct owner reference");
    Ok(())
}

/// Verify TracingPolicyNamespaced resources were created for each role
async fn test_tracing_policies_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying TracingPolicyNamespaced resources...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "tracingpolicynamespaced",
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await?;

    let policies: Vec<&str> = output.trim().split_whitespace().collect();
    info!("[Model] Found tracing policies: {:?}", policies);

    // Each role's entry should have a tracing policy, plus workers for decode
    let expected = [
        format!("allow-binaries-{}-prefill", MODEL_NAME),
        format!("allow-binaries-{}-decode", MODEL_NAME),
        format!("allow-binaries-{}-decode-worker", MODEL_NAME),
    ];

    for expected_name in &expected {
        if !policies.contains(&expected_name.as_str()) {
            return Err(format!(
                "Expected tracing policy '{}', found: {:?}",
                expected_name, policies
            ));
        }
    }

    info!("[Model] TracingPolicyNamespaced resources verified (prefill + decode entry + decode worker)");
    Ok(())
}

/// Wait for the model to reach Serving phase (Kthena processes ModelServing)
async fn test_model_serving_phase(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Waiting for Serving phase (Kthena processing)...");

    wait_for_model_phase(
        kubeconfig,
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Serving",
        Duration::from_secs(300),
    )
    .await?;

    // Verify observedGeneration was set
    let observed = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticemodel",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "jsonpath={.status.observedGeneration}",
    ])
    .await?;

    let gen = observed.trim();
    if gen.is_empty() || gen == "0" {
        return Err(format!("Expected observedGeneration > 0, got: '{gen}'"));
    }

    info!("[Model] Model reached Serving phase (observedGeneration={gen})");
    Ok(())
}

/// Verify ModelServer and ModelRoute resources were created for routing
async fn test_model_routing_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying routing resources (ModelServer + ModelRoute)...");

    // Verify ModelServer
    let ms_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservers.networking.serving.volcano.sh",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&ms_output)
        .map_err(|e| format!("Failed to parse ModelServer JSON: {e}"))?;

    // Verify workloadSelector matches the model name
    let match_labels = &ms["spec"]["workloadSelector"]["matchLabels"];
    let selector_value = match_labels["modelserving.volcano.sh/name"]
        .as_str()
        .unwrap_or_default();
    if selector_value != MODEL_NAME {
        return Err(format!(
            "ModelServer workloadSelector should match model name '{}', got: '{}'",
            MODEL_NAME, selector_value
        ));
    }

    // Verify inference engine
    let engine = ms["spec"]["inferenceEngine"]
        .as_str()
        .unwrap_or_default();
    if engine != "vLLM" {
        return Err(format!(
            "ModelServer inferenceEngine should be 'vLLM', got: '{engine}'"
        ));
    }

    // Verify workload port
    if ms["spec"]["workloadPort"]["port"].as_u64() != Some(8000) {
        return Err(format!(
            "ModelServer workloadPort should be 8000, got: {}",
            ms["spec"]["workloadPort"]["port"]
        ));
    }

    info!("[Model] ModelServer verified: correct workload selector and inference engine");

    // Verify ModelRoute
    let route_name = format!("{}-default", MODEL_NAME);
    let mr_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelroutes.networking.serving.volcano.sh",
        &route_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let mr: serde_json::Value = serde_json::from_str(&mr_output)
        .map_err(|e| format!("Failed to parse ModelRoute JSON: {e}"))?;

    // Verify target model server name defaults to model name
    let target = &mr["spec"]["rules"][0]["targetModels"][0];
    let target_name = target["modelServerName"]
        .as_str()
        .unwrap_or_default();
    if target_name != MODEL_NAME {
        return Err(format!(
            "ModelRoute targetModels should reference '{}', got: '{}'",
            MODEL_NAME, target_name
        ));
    }

    info!("[Model] ModelRoute verified: correct target model server reference");
    Ok(())
}

/// Verify LatticeMeshMember resources include Kthena router as allowed caller
async fn test_model_mesh_members(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying mesh members allow Kthena router traffic...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticemeshmembers",
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let members: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse LatticeMeshMember list: {e}"))?;

    let items = members["items"]
        .as_array()
        .ok_or("LatticeMeshMember items is not an array")?;

    if items.is_empty() {
        return Err("No LatticeMeshMember resources found".to_string());
    }

    for item in items {
        let mm_name = item["metadata"]["name"]
            .as_str()
            .unwrap_or("unknown");

        // Check that the Kthena router is in allowed_callers
        let empty_arr = vec![];
        let callers = item["spec"]["allowedCallers"]
            .as_array()
            .unwrap_or(&empty_arr);
        let has_router = callers.iter().any(|c| {
            c["name"].as_str() == Some("kthena-router")
                && c["namespace"].as_str() == Some("kthena-system")
        });
        if !has_router {
            return Err(format!(
                "LatticeMeshMember '{}' is missing Kthena router in allowedCallers",
                mm_name
            ));
        }

        // Check inference port is present
        let empty_ports = vec![];
        let ports = item["spec"]["ports"]
            .as_array()
            .unwrap_or(&empty_ports);
        let has_inference_port = ports.iter().any(|p| p["port"].as_u64() == Some(8000));
        if !has_inference_port {
            return Err(format!(
                "LatticeMeshMember '{}' is missing inference port 8000",
                mm_name
            ));
        }

        info!(
            "[Model] MeshMember '{}': Kthena router allowed, inference port present",
            mm_name
        );
    }

    info!("[Model] All mesh members correctly configured for Kthena routing");
    Ok(())
}

/// Run all model integration tests
pub async fn run_model_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Model] Running LatticeModel integration tests on {kubeconfig}");

    // GHCR registry credentials (model uses ghcr.io/evan-hines-js/busybox)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Cedar policy for AppArmor override (kind clusters lack AppArmor)
    apply_apparmor_override_policy(kubeconfig).await?;

    // Deploy the model
    test_model_deployment(kubeconfig).await?;

    // Verify resources were created
    test_model_serving_created(kubeconfig).await?;
    test_tracing_policies_created(kubeconfig).await?;
    test_model_routing_created(kubeconfig).await?;
    test_model_mesh_members(kubeconfig).await?;

    // Wait for full lifecycle (Kthena processing)
    test_model_serving_phase(kubeconfig).await?;

    // Cleanup
    delete_namespace(kubeconfig, MODEL_NAMESPACE).await;

    info!("[Model] All LatticeModel integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_model_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_WORKLOAD_KUBECONFIG to run standalone model tests",
    )
    .await
    .expect("Failed to create test session");

    if let Err(e) = run_model_tests(&session.ctx).await {
        panic!("Model tests failed: {e}");
    }
}
