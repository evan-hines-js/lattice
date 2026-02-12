//! KEDA pod autoscaling integration tests
//!
//! Tests that verify KEDA ScaledObject creation and actual pod scale-up
//! for LatticeService resources with autoscaling configured.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_autoscaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use lattice_common::crd::{
    AutoscalingMetric, AutoscalingSpec, ContainerSpec, ResourceQuantity, ResourceRequirements,
    SecurityContext,
};

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace, run_kubectl,
    service_pod_selector, setup_regcreds_infrastructure, wait_for_condition, BUSYBOX_IMAGE,
};
use super::super::mesh_fixtures::build_lattice_service;
use super::cedar::apply_e2e_default_policy;

// =============================================================================
// Constants
// =============================================================================

const AUTOSCALING_NAMESPACE: &str = "autoscaling-test";
const CPU_BURNER_NAME: &str = "cpu-burner";

const SCALEDOBJECT_TIMEOUT: Duration = Duration::from_secs(120);
const SCALEUP_TIMEOUT: Duration = Duration::from_secs(300);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// =============================================================================
// Service Builder
// =============================================================================

/// Build a LatticeService that burns CPU to trigger KEDA autoscaling.
///
/// Uses busybox with an infinite loop (`while true; do :; done`) to consume
/// 100% of one CPU core. With a 10m CPU request and 20% target threshold,
/// KEDA will immediately detect massive utilization and scale up.
fn build_cpu_burner_service() -> lattice_common::crd::LatticeService {
    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), "while true; do :; done".to_string()]),
        resources: Some(ResourceRequirements {
            requests: Some(ResourceQuantity {
                cpu: Some("10m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
            limits: Some(ResourceQuantity {
                cpu: Some("1000m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
        }),
        security: Some(SecurityContext {
            apparmor_profile: Some("Unconfined".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let resources = BTreeMap::new();
    let mut svc = build_lattice_service(
        CPU_BURNER_NAME,
        AUTOSCALING_NAMESPACE,
        resources,
        false,
        container,
    );

    svc.spec.replicas = 1;
    svc.spec.autoscaling = Some(AutoscalingSpec {
        max: 3,
        metrics: vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 20,
        }],
    });

    svc
}

// =============================================================================
// Test Logic
// =============================================================================

/// Run KEDA autoscaling tests against an existing workload cluster.
///
/// 1. Deploys a CPU-burning LatticeService with autoscaling configured
/// 2. Verifies the ScaledObject is created with correct spec
/// 3. Waits for KEDA to scale pods beyond the initial replica count
pub async fn run_autoscaling_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;

    info!("[Integration/Autoscaling] Starting KEDA autoscaling test...");

    // Phase 0: Setup namespace and regcreds
    info!("[Integration/Autoscaling] Phase 0: Setting up namespace...");
    ensure_fresh_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Phase 1: Deploy the CPU-burner LatticeService
    info!("[Integration/Autoscaling] Phase 1: Deploying cpu-burner service...");
    let service = build_cpu_burner_service();
    deploy_and_wait_for_phase(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        service,
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    // Phase 2: Verify ScaledObject exists with correct spec
    info!("[Integration/Autoscaling] Phase 2: Verifying ScaledObject...");
    verify_scaled_object(kubeconfig).await?;

    // Phase 3: Wait for replica count > 1 (actual KEDA scale-up)
    info!("[Integration/Autoscaling] Phase 3: Waiting for scale-up...");
    wait_for_scale_up(kubeconfig).await?;

    // Cleanup
    info!("[Integration/Autoscaling] Cleaning up namespace...");
    delete_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await;

    info!("[Integration/Autoscaling] All autoscaling tests passed!");
    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Verify the ScaledObject was created by the operator with correct fields.
async fn verify_scaled_object(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();

    wait_for_condition(
        "ScaledObject to exist for cpu-burner",
        SCALEDOBJECT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig", &kc,
                    "get", "scaledobject", CPU_BURNER_NAME,
                    "-n", AUTOSCALING_NAMESPACE,
                    "-o", "jsonpath={.apiVersion} {.spec.scaleTargetRef.name} {.spec.minReplicaCount} {.spec.maxReplicaCount} {.spec.triggers[0].type}",
                ]).await;

                match output {
                    Ok(raw) => {
                        let parts: Vec<&str> = raw.split_whitespace().collect();
                        if parts.len() < 5 {
                            info!("[Integration/Autoscaling] ScaledObject not yet available (got {} fields)", parts.len());
                            return Ok(false);
                        }

                        let api_version = parts[0];
                        let target_name = parts[1];
                        let min_replicas = parts[2];
                        let max_replicas = parts[3];
                        let trigger_type = parts[4];

                        info!(
                            "[Integration/Autoscaling] ScaledObject: apiVersion={}, target={}, min={}, max={}, trigger={}",
                            api_version, target_name, min_replicas, max_replicas, trigger_type
                        );

                        if api_version != "keda.sh/v1alpha1" {
                            return Err(format!("Expected apiVersion keda.sh/v1alpha1, got {}", api_version));
                        }
                        if target_name != CPU_BURNER_NAME {
                            return Err(format!("Expected scaleTargetRef.name {}, got {}", CPU_BURNER_NAME, target_name));
                        }
                        if min_replicas != "1" {
                            return Err(format!("Expected minReplicaCount 1, got {}", min_replicas));
                        }
                        if max_replicas != "3" {
                            return Err(format!("Expected maxReplicaCount 3, got {}", max_replicas));
                        }
                        if trigger_type != "cpu" {
                            return Err(format!("Expected trigger type cpu, got {}", trigger_type));
                        }

                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    ).await
}

/// Wait for KEDA to scale the cpu-burner deployment beyond 1 replica.
async fn wait_for_scale_up(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let selector = service_pod_selector(CPU_BURNER_NAME);

    wait_for_condition(
        "cpu-burner to scale beyond 1 replica",
        SCALEUP_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let selector = selector.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pods",
                    "-n",
                    AUTOSCALING_NAMESPACE,
                    "-l",
                    &selector,
                    "-o",
                    "jsonpath={.items[*].status.phase}",
                ])
                .await;

                match output {
                    Ok(phases) => {
                        let running = phases
                            .split_whitespace()
                            .filter(|p| *p == "Running")
                            .count();
                        info!(
                            "[Integration/Autoscaling] Pods running: {} (need > 1 for scale-up)",
                            running
                        );
                        Ok(running > 1)
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — verify KEDA pod autoscaling on workload cluster
#[tokio::test]
#[ignore]
async fn test_autoscaling_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_MGMT_KUBECONFIG and LATTICE_WORKLOAD_KUBECONFIG to run standalone autoscaling tests",
    )
    .await
    .unwrap();
    apply_e2e_default_policy(&session.ctx.mgmt_kubeconfig)
        .await
        .unwrap();
    run_autoscaling_tests(&session.ctx).await.unwrap();
}
