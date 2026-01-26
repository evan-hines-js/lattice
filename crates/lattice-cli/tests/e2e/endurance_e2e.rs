//! Endurance test for Lattice - runs forever creating/deleting clusters
//!
//! This test is designed to run continuously (overnight, during work, etc.)
//! to catch rare timing issues, race conditions, and resource leaks.
//!
//! # Design
//!
//! Two independent cluster lifecycle threads run concurrently:
//! - Thread A: workload cluster (create → verify → delete → repeat)
//! - Thread B: workload2 cluster (create → verify → delete → repeat)
//!
//! Plus aggressive chaos monkey running continuously:
//! - Pod kills every 5-15 seconds
//! - Network blackouts every 10-30 seconds
//!
//! This creates maximum stress on the system - clusters being created while
//! others are being deleted, all while pods are being killed and networks cut.
//!
//! # Failure Conditions
//!
//! - Any step taking longer than 10 minutes = FAILURE
//! - Any cluster failing to provision = FAILURE
//! - Any cluster failing to delete = FAILURE
//!
//! # Running
//!
//! ```bash
//! # Run with Docker clusters (chaos enabled by default)
//! cargo test --features provider-e2e --test e2e endurance_e2e -- --nocapture
//!
//! # Run WITHOUT chaos (not recommended - defeats the purpose)
//! LATTICE_CHAOS_ENABLED=false cargo test --features provider-e2e --test e2e endurance_e2e -- --nocapture
//! ```
//!
//! # Environment Variables
//!
//! - LATTICE_MGMT_CLUSTER_CONFIG: Path to LatticeCluster YAML for management cluster
//! - LATTICE_WORKLOAD_CLUSTER_CONFIG: Path to LatticeCluster YAML for workload cluster
//! - LATTICE_WORKLOAD2_CLUSTER_CONFIG: Path to LatticeCluster YAML for second workload cluster
//! - LATTICE_CHAOS_ENABLED: Set to "false" to disable chaos (default: true)
//! - LATTICE_STEP_TIMEOUT_MINS: Timeout per step in minutes (default: 10)

#![cfg(feature = "provider-e2e")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kube::api::{Api, PostParams};
use parking_lot::RwLock;
use tracing::{error, info};

use lattice_cli::commands::install::Installer;
use lattice_operator::crd::{BootstrapProvider, LatticeCluster};

use super::chaos::{ChaosConfig, ChaosMonkey, ChaosTargets};
use super::helpers::{
    build_and_push_lattice_image, client_from_kubeconfig, delete_cluster_and_wait,
    ensure_docker_network, extract_docker_cluster_kubeconfig, force_delete_docker_cluster,
    get_docker_kubeconfig, load_cluster_config, load_registry_credentials, run_cmd_allow_fail,
    verify_cluster_capi_resources, watch_cluster_phases, watch_cluster_phases_with_kubeconfig,
    watch_worker_scaling,
};
use super::providers::InfraProvider;

// =============================================================================
// Configuration
// =============================================================================

const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

fn step_timeout() -> Duration {
    let mins = std::env::var("LATTICE_STEP_TIMEOUT_MINS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    Duration::from_secs(mins * 60)
}

fn chaos_enabled() -> bool {
    // Chaos is ON by default for endurance testing - set to "false" to disable
    std::env::var("LATTICE_CHAOS_ENABLED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

// =============================================================================
// Shared state for cluster lifecycle threads
// =============================================================================

struct ClusterConfig {
    cluster: LatticeCluster,
    bootstrap: BootstrapProvider,
    provider: InfraProvider,
}

struct EnduranceState {
    mgmt_kubeconfig: String,
    workload_config: ClusterConfig,
    workload2_config: ClusterConfig,
    chaos_targets: Arc<ChaosTargets>,
    workload_iterations: AtomicU64,
    workload2_iterations: AtomicU64,
    test_start: Instant,
    // Track if workload is ready (workload2 creates off workload)
    workload_kubeconfig: RwLock<Option<String>>,
}

// =============================================================================
// Timeout wrapper
// =============================================================================

async fn with_timeout<T, F>(step_name: &str, future: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let timeout = step_timeout();
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "TIMEOUT: {} exceeded {:?} limit",
            step_name, timeout
        )),
    }
}

// =============================================================================
// Cleanup
// =============================================================================

fn cleanup_bootstrap_clusters() {
    info!("Cleaning up kind bootstrap cluster...");
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-bootstrap"],
    );
}

// =============================================================================
// Main Test
// =============================================================================

#[tokio::test]
async fn test_endurance_loop() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    info!("=========================================================");
    info!("ENDURANCE TEST - RUNS FOREVER UNTIL FAILURE");
    info!("=========================================================");
    info!("Step timeout: {:?}", step_timeout());
    info!("Chaos enabled: {}", chaos_enabled());
    info!("Press Ctrl+C to stop");
    info!("=========================================================");

    cleanup_bootstrap_clusters();

    if let Err(e) = build_and_push_lattice_image(LATTICE_IMAGE).await {
        panic!("Failed to build Lattice image: {}", e);
    }

    match run_endurance_test().await {
        Ok(()) => {
            // Should never reach here - test runs forever
            info!("TEST ENDED (unexpected)");
        }
        Err(e) => {
            error!("=========================================================");
            error!("ENDURANCE TEST FAILED");
            error!("=========================================================");
            error!("Error: {}", e);
            error!("=========================================================");
            cleanup_bootstrap_clusters();
            panic!("Endurance test failed: {}", e);
        }
    }
}

async fn run_endurance_test() -> Result<(), String> {
    // Load configurations upfront
    let (mgmt_config_content, mgmt_cluster) =
        load_cluster_config("LATTICE_MGMT_CLUSTER_CONFIG", "docker-mgmt.yaml")?;
    let mgmt_provider: InfraProvider = mgmt_cluster.spec.provider.provider_type().into();

    let (_, workload_cluster) =
        load_cluster_config("LATTICE_WORKLOAD_CLUSTER_CONFIG", "docker-workload.yaml")?;
    let workload_provider: InfraProvider = workload_cluster.spec.provider.provider_type().into();
    let workload_bootstrap = workload_cluster.spec.provider.kubernetes.bootstrap.clone();

    let (_, workload2_cluster) =
        load_cluster_config("LATTICE_WORKLOAD2_CLUSTER_CONFIG", "docker-workload2.yaml")?;
    let workload2_bootstrap = workload2_cluster.spec.provider.kubernetes.bootstrap.clone();

    info!("Configuration loaded");

    // Setup Docker network if needed
    if mgmt_provider == InfraProvider::Docker {
        ensure_docker_network().map_err(|e| format!("Failed to setup Docker network: {}", e))?;
    }

    // =========================================================================
    // ONE-TIME SETUP: Install Management Cluster
    // =========================================================================
    info!("");
    info!("[SETUP] Installing management cluster...");

    let registry_credentials = load_registry_credentials();

    with_timeout("install management cluster", async {
        let installer = Installer::new(
            mgmt_config_content,
            LATTICE_IMAGE.to_string(),
            true,
            registry_credentials,
            None,
        )
        .map_err(|e| format!("Failed to create installer: {}", e))?;

        installer
            .run()
            .await
            .map_err(|e| format!("Installer failed: {}", e))
    })
    .await?;

    let mgmt_kubeconfig = get_docker_kubeconfig(MGMT_CLUSTER_NAME)?;
    let mgmt_client = client_from_kubeconfig(&mgmt_kubeconfig).await?;

    // Verify management cluster is self-managing
    with_timeout("verify management cluster", async {
        watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME, Some(600)).await
    })
    .await?;

    info!("[SETUP] Management cluster ready!");

    // Create shared state
    let chaos_targets = Arc::new(ChaosTargets::new());
    chaos_targets.add(MGMT_CLUSTER_NAME, &mgmt_kubeconfig);

    let state = Arc::new(EnduranceState {
        mgmt_kubeconfig: mgmt_kubeconfig.clone(),
        workload_config: ClusterConfig {
            cluster: workload_cluster,
            bootstrap: workload_bootstrap,
            provider: workload_provider,
        },
        workload2_config: ClusterConfig {
            cluster: workload2_cluster,
            bootstrap: workload2_bootstrap,
            provider: workload_provider,
        },
        chaos_targets: chaos_targets.clone(),
        workload_iterations: AtomicU64::new(0),
        workload2_iterations: AtomicU64::new(0),
        test_start: Instant::now(),
        workload_kubeconfig: RwLock::new(None),
    });

    // Start aggressive chaos monkey
    let _chaos = if chaos_enabled() {
        info!("[CHAOS] Starting aggressive chaos monkey...");
        Some(ChaosMonkey::start_with_config(
            chaos_targets,
            ChaosConfig::aggressive(),
        ))
    } else {
        None
    };

    // =========================================================================
    // SPAWN INDEPENDENT CLUSTER LIFECYCLE THREADS
    // =========================================================================
    info!("");
    info!("[THREADS] Spawning cluster lifecycle threads...");

    let state1 = state.clone();
    let workload_thread = tokio::spawn(async move {
        workload_lifecycle_loop(state1).await
    });

    let state2 = state.clone();
    let workload2_thread = tokio::spawn(async move {
        workload2_lifecycle_loop(state2).await
    });

    // Spawn a status reporter thread
    let state3 = state.clone();
    let _status_thread = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let w1 = state3.workload_iterations.load(Ordering::Relaxed);
            let w2 = state3.workload2_iterations.load(Ordering::Relaxed);
            info!(
                "[STATUS] workload: {} iterations, workload2: {} iterations, runtime: {:?}",
                w1,
                w2,
                state3.test_start.elapsed()
            );
        }
    });

    // Wait for either thread to fail (they run forever otherwise)
    tokio::select! {
        result = workload_thread => {
            match result {
                Ok(Ok(())) => Err("Workload thread exited unexpectedly".to_string()),
                Ok(Err(e)) => Err(format!("Workload thread failed: {}", e)),
                Err(e) => Err(format!("Workload thread panicked: {}", e)),
            }
        }
        result = workload2_thread => {
            match result {
                Ok(Ok(())) => Err("Workload2 thread exited unexpectedly".to_string()),
                Ok(Err(e)) => Err(format!("Workload2 thread failed: {}", e)),
                Err(e) => Err(format!("Workload2 thread panicked: {}", e)),
            }
        }
    }
}

// =============================================================================
// Workload Cluster Lifecycle Loop (runs on mgmt cluster)
// =============================================================================

async fn workload_lifecycle_loop(state: Arc<EnduranceState>) -> Result<(), String> {
    loop {
        let iteration = state.workload_iterations.fetch_add(1, Ordering::Relaxed) + 1;
        info!("[WORKLOAD #{}] Starting lifecycle...", iteration);

        // Create
        let mgmt_client = client_from_kubeconfig(&state.mgmt_kubeconfig).await?;

        with_timeout("create workload", async {
            let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
            api.create(&PostParams::default(), &state.workload_config.cluster)
                .await
                .map_err(|e| format!("Failed to create: {}", e))?;
            Ok(())
        })
        .await?;

        let kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);

        // Wait for ready
        with_timeout("provision workload", async {
            if state.workload_config.provider == InfraProvider::Docker {
                watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME, Some(600)).await
            } else {
                watch_cluster_phases_with_kubeconfig(
                    &state.mgmt_kubeconfig,
                    WORKLOAD_CLUSTER_NAME,
                    Some(600),
                    &kubeconfig_path,
                )
                .await
            }
        })
        .await?;

        // Extract kubeconfig for Docker
        if state.workload_config.provider == InfraProvider::Docker {
            extract_docker_cluster_kubeconfig(
                WORKLOAD_CLUSTER_NAME,
                &state.workload_config.bootstrap,
                &kubeconfig_path,
            )?;
        }

        // Verify
        with_timeout("verify workload", async {
            verify_cluster_capi_resources(&kubeconfig_path, WORKLOAD_CLUSTER_NAME).await?;
            watch_worker_scaling(&kubeconfig_path, WORKLOAD_CLUSTER_NAME, 1).await
        })
        .await?;

        // Add to chaos targets and make kubeconfig available to workload2
        if chaos_enabled() {
            state.chaos_targets.add(WORKLOAD_CLUSTER_NAME, &kubeconfig_path);
        }
        *state.workload_kubeconfig.write() = Some(kubeconfig_path.clone());

        info!("[WORKLOAD #{}] Ready!", iteration);

        // Wait a bit before deleting (let workload2 potentially use it)
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Clear kubeconfig before delete (workload2 should handle this gracefully)
        *state.workload_kubeconfig.write() = None;

        // Delete
        info!("[WORKLOAD #{}] Deleting...", iteration);
        with_timeout("delete workload", async {
            delete_cluster_and_wait(
                &kubeconfig_path,
                &state.mgmt_kubeconfig,
                WORKLOAD_CLUSTER_NAME,
                state.workload_config.provider,
            )
            .await
        })
        .await?;

        info!("[WORKLOAD #{}] Deleted!", iteration);
    }
}

// =============================================================================
// Workload2 Cluster Lifecycle Loop (runs on workload cluster when available)
// =============================================================================

async fn workload2_lifecycle_loop(state: Arc<EnduranceState>) -> Result<(), String> {
    loop {
        // Wait for workload to be available
        let parent_kubeconfig = loop {
            if let Some(kc) = state.workload_kubeconfig.read().clone() {
                break kc;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        };

        let iteration = state.workload2_iterations.fetch_add(1, Ordering::Relaxed) + 1;
        info!("[WORKLOAD2 #{}] Starting lifecycle (parent: workload)...", iteration);

        // Try to create - if parent disappeared, just retry
        let workload_client = match client_from_kubeconfig(&parent_kubeconfig).await {
            Ok(c) => c,
            Err(e) => {
                info!("[WORKLOAD2 #{}] Parent unavailable ({}), retrying...", iteration, e);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let create_result = with_timeout("create workload2", async {
            let api: Api<LatticeCluster> = Api::all(workload_client.clone());
            api.create(&PostParams::default(), &state.workload2_config.cluster)
                .await
                .map_err(|e| format!("Failed to create: {}", e))?;
            Ok(())
        })
        .await;

        if let Err(e) = create_result {
            // Parent might have been deleted - just retry
            if e.contains("refused") || e.contains("unreachable") {
                info!("[WORKLOAD2 #{}] Parent gone during create ({}), retrying...", iteration, e);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            return Err(e);
        }

        let kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD2_CLUSTER_NAME);

        // Wait for ready - handle parent disappearing
        let provision_result = with_timeout("provision workload2", async {
            if state.workload2_config.provider == InfraProvider::Docker {
                watch_cluster_phases(&workload_client, WORKLOAD2_CLUSTER_NAME, Some(600)).await
            } else {
                watch_cluster_phases_with_kubeconfig(
                    &parent_kubeconfig,
                    WORKLOAD2_CLUSTER_NAME,
                    Some(600),
                    &kubeconfig_path,
                )
                .await
            }
        })
        .await;

        if let Err(e) = provision_result {
            // Check if it's a connectivity issue (parent deleted)
            if e.contains("refused") || e.contains("unreachable") || e.contains("no such host") {
                info!("[WORKLOAD2 #{}] Parent gone during provision ({}), retrying...", iteration, e);
                // Try to clean up
                let _ = force_delete_docker_cluster(WORKLOAD2_CLUSTER_NAME);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            return Err(e);
        }

        // Extract kubeconfig for Docker
        if state.workload2_config.provider == InfraProvider::Docker {
            if let Err(e) = extract_docker_cluster_kubeconfig(
                WORKLOAD2_CLUSTER_NAME,
                &state.workload2_config.bootstrap,
                &kubeconfig_path,
            ) {
                info!("[WORKLOAD2 #{}] Failed to extract kubeconfig ({}), cleaning up...", iteration, e);
                let _ = force_delete_docker_cluster(WORKLOAD2_CLUSTER_NAME);
                continue;
            }
        }

        // Verify
        let verify_result = with_timeout("verify workload2", async {
            verify_cluster_capi_resources(&kubeconfig_path, WORKLOAD2_CLUSTER_NAME).await
        })
        .await;

        if let Err(e) = verify_result {
            info!("[WORKLOAD2 #{}] Verify failed ({}), cleaning up...", iteration, e);
            let _ = force_delete_docker_cluster(WORKLOAD2_CLUSTER_NAME);
            continue;
        }

        info!("[WORKLOAD2 #{}] Ready!", iteration);

        // Delete immediately (don't wait)
        info!("[WORKLOAD2 #{}] Deleting...", iteration);

        let delete_result = with_timeout("delete workload2", async {
            delete_cluster_and_wait(
                &kubeconfig_path,
                &parent_kubeconfig,
                WORKLOAD2_CLUSTER_NAME,
                state.workload2_config.provider,
            )
            .await
        })
        .await;

        if let Err(e) = delete_result {
            // Parent might be gone - force cleanup
            if e.contains("refused") || e.contains("unreachable") {
                info!("[WORKLOAD2 #{}] Parent gone during delete ({}), force cleanup...", iteration, e);
                let _ = force_delete_docker_cluster(WORKLOAD2_CLUSTER_NAME);
                continue;
            }
            return Err(e);
        }

        info!("[WORKLOAD2 #{}] Deleted!", iteration);
    }
}

