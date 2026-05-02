//! KEDA pod autoscaling integration tests
//!
//! Tests that verify KEDA ScaledObject creation and actual pod scale-up
//! for LatticeService resources with autoscaling configured.
//!
//! # Running Standalone
//!
//! ```bash
//! # Direct access
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_autoscaling_standalone -- --ignored --nocapture
//!
//! # Or via proxy
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_autoscaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use lattice_crd::crd::{
    AutoscalingMetric, AutoscalingSpec, ContainerSpec, PortSpec, ResourceQuantity,
    ResourceRequirements, SecurityContext, ServicePortsSpec, VolumeMount,
};

use super::super::helpers::{
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace, run_kubectl,
    service_pod_selector, setup_regcreds_infrastructure, wait_for_condition, with_diagnostics,
    DiagnosticContext, BUSYBOX_IMAGE, DEFAULT_TIMEOUT,
};
use super::super::mesh_fixtures::build_lattice_service;

// =============================================================================
// Constants
// =============================================================================

const AUTOSCALING_NAMESPACE: &str = "autoscaling-test";
const PROM_NAMESPACE: &str = "autoscaling-prom-test";
const CPU_BURNER_NAME: &str = "cpu-burner";
const METRICS_SERVER_NAME: &str = "metrics-server";
const CUSTOM_METRIC_NAME: &str = "test_scale_metric";

/// Cold-start latency for the Prometheus pipeline on a fresh cluster
/// stacks: VictoriaMetrics-operator polls VMServiceScrape changes, vmagent
/// reloads its config, vmagent's first scrape interval fires, the data
/// flows to VMSingle, KEDA's metrics-apiserver polls VMSingle, KEDA
/// reports an Active trigger, then the HPA reconciles. Each step is
/// 30–90s and they don't overlap. 15 minutes covers an unloaded run; on
/// a heavily-loaded shared box I've seen this take longer.
const PROM_METRIC_VISIBLE_TIMEOUT: Duration = Duration::from_secs(900);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// =============================================================================
// Service Builder
// =============================================================================

/// Build a LatticeService that burns CPU to trigger KEDA autoscaling.
///
/// Uses busybox with an infinite loop (`while true; do :; done`) to consume
/// 100% of one CPU core. With a 10m CPU request and 20% target threshold,
/// KEDA will immediately detect massive utilization and scale up.
fn build_cpu_burner_service() -> lattice_crd::crd::LatticeService {
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
            run_as_user: Some(65534),
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
            target: 20.0,
        }],
    });

    svc
}

/// Build a LatticeService that serves a static Prometheus metric to trigger
/// KEDA Prometheus-based autoscaling.
///
/// Uses busybox httpd to serve a `/metrics` endpoint returning a high-value
/// gauge. The service exposes a port named `metrics` (port 9090) which triggers
/// automatic VMServiceScrape generation by the compiler. VictoriaMetrics scrapes
/// this via the VMServiceScrape, and KEDA queries VictoriaMetrics to trigger scale-up.
fn build_metrics_server_service() -> lattice_crd::crd::LatticeService {
    // busybox httpd serves static files — write metrics content then start httpd
    let script = format!(
        concat!(
            "mkdir -p /tmp/www && ",
            "printf '# HELP {m} A test metric for autoscaling\\n",
            "# TYPE {m} gauge\\n",
            "{m} 100\\n' > /tmp/www/metrics && ",
            "httpd -f -p 9090 -h /tmp/www"
        ),
        m = CUSTOM_METRIC_NAME,
    );

    let mut volumes = BTreeMap::new();
    volumes.insert(
        "/tmp".to_string(),
        VolumeMount {
            source: None,
            path: None,
            read_only: None,
            medium: None,
            size_limit: None,
        },
    );

    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        resources: Some(ResourceRequirements {
            requests: Some(ResourceQuantity {
                cpu: Some("10m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
            limits: Some(ResourceQuantity {
                cpu: Some("100m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
        }),
        volumes,
        security: Some(SecurityContext {
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let resources = BTreeMap::new();

    // Build with a metrics port so the compiler generates a VMServiceScrape
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut ports = BTreeMap::new();
    ports.insert(
        "metrics".to_string(),
        PortSpec {
            port: 9090,
            target_port: None,
            protocol: None,
        },
    );

    let mut svc = build_lattice_service(
        METRICS_SERVER_NAME,
        PROM_NAMESPACE,
        resources,
        false, // we set the port manually below
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            ..Default::default()
        },
    );

    // Override the workload with our actual container and metrics port
    svc.spec.workload.containers = containers;
    svc.spec.workload.service = Some(ServicePortsSpec {
        ports,
        ..Default::default()
    });

    svc.spec.replicas = 1;
    svc.spec.autoscaling = Some(AutoscalingSpec {
        max: 3,
        metrics: vec![AutoscalingMetric {
            metric: CUSTOM_METRIC_NAME.to_string(),
            target: 10.0,
        }],
    });

    svc
}

// =============================================================================
// Test Logic
// =============================================================================

/// Run all KEDA autoscaling tests against an existing workload cluster.
///
/// Runs the CPU-based test and the Prometheus-based test sequentially.
pub async fn run_autoscaling_tests(kubeconfig: &str) -> Result<(), String> {
    // The Prometheus-based test queries VMSingle; on a Rook-backed fixture
    // VMSingle's PVC stays Pending until `RookInstall` is Ready, so the
    // metric scrape would race the storage backend coming up. No-op when
    // storage isn't enabled (local-path is synchronous).
    super::storage::wait_for_storage_ready(kubeconfig).await?;

    // CPU and Prometheus tests use different namespaces — run in parallel.
    let kc1 = kubeconfig.to_string();
    let kc2 = kubeconfig.to_string();
    let (cpu_result, prom_result) = tokio::join!(
        async {
            let diag = DiagnosticContext::new(&kc1, AUTOSCALING_NAMESPACE);
            with_diagnostics(&diag, "Autoscaling/CPU", || run_cpu_autoscaling_test(&kc1)).await
        },
        async {
            let diag = DiagnosticContext::new(&kc2, PROM_NAMESPACE);
            with_diagnostics(&diag, "Autoscaling/Prom", || {
                run_prometheus_autoscaling_test(&kc2)
            })
            .await
        },
    );
    cpu_result?;
    prom_result?;
    info!("[Integration/Autoscaling] All autoscaling tests passed!");
    Ok(())
}

/// CPU-based autoscaling test:
/// 1. Deploys a CPU-burning LatticeService with autoscaling configured
/// 2. Verifies the ScaledObject is created with correct spec
/// 3. Waits for KEDA to scale pods beyond the initial replica count
async fn run_cpu_autoscaling_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Autoscaling/CPU] Starting CPU autoscaling test...");

    ensure_fresh_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await?;

    info!("[Integration/Autoscaling/CPU] Deploying cpu-burner service...");
    let service = build_cpu_burner_service();
    deploy_and_wait_for_phase(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        service,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Verifying ScaledObject...");
    verify_scaled_object(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        CPU_BURNER_NAME,
        "1",
        "3",
        "cpu",
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Waiting for scale-up...");
    wait_for_scale_up(
        kubeconfig,
        AUTOSCALING_NAMESPACE,
        CPU_BURNER_NAME,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/CPU] Cleaning up...");
    delete_namespace(kubeconfig, AUTOSCALING_NAMESPACE).await;

    info!("[Integration/Autoscaling/CPU] CPU autoscaling test passed!");
    Ok(())
}

/// Prometheus-based autoscaling test:
/// 1. Deploys an HTTP server exposing a custom Prometheus metric via /metrics
/// 2. Verifies the ScaledObject is created with a prometheus trigger
/// 3. Waits for VictoriaMetrics to scrape the metric and KEDA to scale up
async fn run_prometheus_autoscaling_test(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Autoscaling/Prom] Starting Prometheus autoscaling test...");

    ensure_fresh_namespace(kubeconfig, PROM_NAMESPACE).await?;

    info!("[Integration/Autoscaling/Prom] Deploying metrics-server service...");
    let service = build_metrics_server_service();
    deploy_and_wait_for_phase(
        kubeconfig,
        PROM_NAMESPACE,
        service,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Verifying ScaledObject...");
    verify_scaled_object(
        kubeconfig,
        PROM_NAMESPACE,
        METRICS_SERVER_NAME,
        "1",
        "3",
        "prometheus",
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Verifying VMServiceScrape exists...");
    verify_vm_service_scrape(kubeconfig).await?;

    // Block on the scrape pipeline being warm so the scale-up timer below
    // measures HPA-decision-to-pod-Ready, not vmagent-config-reload-plus-
    // first-scrape-plus-KEDA-poll. Without this gate the scale-up timeout
    // has to absorb the entire cold-start chain on every fresh cluster.
    info!("[Integration/Autoscaling/Prom] Waiting for KEDA to see the metric...");
    wait_for_metric_visible_to_keda(
        kubeconfig,
        PROM_NAMESPACE,
        METRICS_SERVER_NAME,
        PROM_METRIC_VISIBLE_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Waiting for Prometheus-driven scale-up...");
    wait_for_scale_up(
        kubeconfig,
        PROM_NAMESPACE,
        METRICS_SERVER_NAME,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Integration/Autoscaling/Prom] Cleaning up...");
    delete_namespace(kubeconfig, PROM_NAMESPACE).await;

    info!("[Integration/Autoscaling/Prom] Prometheus autoscaling test passed!");
    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Verify the ScaledObject was created by the operator with correct fields.
async fn verify_scaled_object(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    expected_min: &str,
    expected_max: &str,
    expected_trigger: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let svc_name = name.to_string();
    let exp_min = expected_min.to_string();
    let exp_max = expected_max.to_string();
    let exp_trigger = expected_trigger.to_string();

    wait_for_condition(
        &format!("ScaledObject to exist for {}", name),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let svc_name = svc_name.clone();
            let exp_min = exp_min.clone();
            let exp_max = exp_max.clone();
            let exp_trigger = exp_trigger.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig", &kc,
                    "get", "scaledobject", &svc_name,
                    "-n", &ns,
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
                        if target_name != svc_name {
                            return Err(format!("Expected scaleTargetRef.name {}, got {}", svc_name, target_name));
                        }
                        if min_replicas != exp_min {
                            return Err(format!("Expected minReplicaCount {}, got {}", exp_min, min_replicas));
                        }
                        if max_replicas != exp_max {
                            return Err(format!("Expected maxReplicaCount {}, got {}", exp_max, max_replicas));
                        }
                        if trigger_type != exp_trigger {
                            return Err(format!("Expected trigger type {}, got {}", exp_trigger, trigger_type));
                        }

                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    ).await
}

/// Verify the VMServiceScrape was created for the metrics-server service.
async fn verify_vm_service_scrape(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let scrape_name = format!("{}-scrape", METRICS_SERVER_NAME);

    wait_for_condition(
        &format!("VMServiceScrape {} to exist", scrape_name),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let scrape_name = scrape_name.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "vmservicescrape",
                    &scrape_name,
                    "-n",
                    PROM_NAMESPACE,
                    "-o",
                    "jsonpath={.spec.endpoints[0].port}",
                ])
                .await;

                match output {
                    Ok(port) => {
                        if port == "metrics" {
                            info!(
                                "[Integration/Autoscaling/Prom] VMServiceScrape {} found, scraping port: {}",
                                scrape_name, port
                            );
                            Ok(true)
                        } else {
                            info!(
                                "[Integration/Autoscaling/Prom] VMServiceScrape port mismatch: {}",
                                port
                            );
                            Ok(false)
                        }
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

/// Wait for KEDA to scale a deployment beyond 1 replica.
async fn wait_for_scale_up(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let selector = service_pod_selector(name);
    let desc = format!("{} to scale beyond 1 replica", name);

    wait_for_condition(&desc, timeout, POLL_INTERVAL, || {
        let kc = kc.clone();
        let ns = ns.clone();
        let selector = selector.clone();
        async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                &kc,
                "get",
                "pods",
                "-n",
                &ns,
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
                        "[Integration/Autoscaling] {} pods running: {} (need > 1)",
                        name, running
                    );
                    Ok(running > 1)
                }
                Err(_) => Ok(false),
            }
        }
    })
    .await
}

/// Block until KEDA confirms the metric pipeline is warm.
///
/// We accept either of two signals as proof:
///   1. `ScaledObject.status.lastActiveTime` set — KEDA's own record of
///      "I successfully polled the trigger and got a sample". Most direct.
///   2. `HPA.status.currentMetrics[*].external.current.value` non-zero —
///      the HPAv2 view of the same fact, populated after HPA reconciles
///      KEDA's metrics-apiserver response.
///
/// Logging both each tick keeps the failure mode diagnosable: if neither
/// fires within the timeout, the log shows whether KEDA never queried,
/// or queried-but-saw-zero, or queried-positive-but-HPA-didn't-reconcile.
async fn wait_for_metric_visible_to_keda(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let hpa_name = format!("keda-hpa-{name}");
    let so_name = name.to_string();
    let desc = format!("KEDA to surface a sample for {so_name}");

    wait_for_condition(&desc, timeout, POLL_INTERVAL, || {
        let kc = kc.clone();
        let ns = ns.clone();
        let hpa_name = hpa_name.clone();
        let so_name = so_name.clone();
        async move {
            let so_active = run_kubectl(&[
                "--kubeconfig",
                &kc,
                "get",
                "scaledobject",
                &so_name,
                "-n",
                &ns,
                "-o",
                "jsonpath={.status.lastActiveTime}",
            ])
            .await
            .unwrap_or_default();

            let hpa_values = run_kubectl(&[
                "--kubeconfig",
                &kc,
                "get",
                "hpa",
                &hpa_name,
                "-n",
                &ns,
                "-o",
                "jsonpath={.status.currentMetrics[*].external.current.value}",
            ])
            .await
            .unwrap_or_default();

            let so_fired = !so_active.trim().is_empty();
            let hpa_positive = hpa_values
                .split_whitespace()
                .any(|v| !v.is_empty() && v != "0" && v != "0m");
            info!(
                "[Integration/Autoscaling/Prom] ScaledObject lastActiveTime='{}' \
                 HPA currentMetrics='{}' (so_fired={so_fired}, hpa_positive={hpa_positive})",
                so_active.trim(),
                hpa_values.trim()
            );
            Ok(so_fired || hpa_positive)
        }
    })
    .await
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test — verify KEDA pod autoscaling on workload cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_autoscaling_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_autoscaling_tests(&resolved.kubeconfig).await.unwrap();
}
