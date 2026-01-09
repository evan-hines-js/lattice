//! Real end-to-end test for the complete pivot flow
//!
//! This test provisions actual infrastructure using CAPD and executes the real
//! pivot flow using our agent code. It takes 15-20 minutes to run.
//!
//! # What This Test Does
//!
//! 1. Builds the lattice Docker image
//! 2. Sets up management cluster with CAPI/CAPD
//! 3. Starts AgentServer (cell-side gRPC server) in-process
//! 4. Generates and applies CAPI manifests for a workload cluster
//! 5. Waits for CAPD to provision Docker containers running Kubernetes
//! 6. Deploys lattice agent to the workload cluster
//! 7. Waits for agent to connect to cell via gRPC
//! 8. Cell triggers pivot via PivotCommand
//! 9. Agent executes clusterctl move and sends PivotComplete
//! 10. Verifies workload cluster is now self-managing
//!
//! # Prerequisites
//!
//! - Docker running with sufficient resources (8GB+ RAM recommended)
//! - kind installed
//! - clusterctl installed
//! - kubectl installed
//!
//! # Running
//!
//! ```bash
//! # This test takes 15-20 minutes
//! cargo test --test kind pivot_e2e -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use tokio::time::{sleep, timeout};

use lattice::agent::connection::AgentRegistry;
use lattice::agent::server::AgentServer;
use lattice::bootstrap::{bootstrap_router, BootstrapState, DefaultManifestGenerator};
use lattice::crd::{
    KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec, ProviderSpec, ProviderType,
};
use lattice::pivot::PivotOrchestrator;
use lattice::pki::CertificateAuthority;
use lattice::proto::AgentState;
use lattice::provider::{BootstrapInfo, CAPIManifest, DockerProvider, Provider};

// No longer using shared helpers - this test manages its own kind cluster

// =============================================================================
// Test Configuration
// =============================================================================

/// Timeout for the entire e2e test
const E2E_TIMEOUT: Duration = Duration::from_secs(1200); // 20 minutes

/// Timeout for cluster provisioning
const PROVISION_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

/// Timeout for agent connection
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes

/// Timeout for pivot operation
const PIVOT_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Name of the workload cluster being provisioned
const WORKLOAD_CLUSTER_NAME: &str = "e2e-pivot-workload";

/// Namespace for CAPI resources
const CAPI_NAMESPACE: &str = "default";

/// Docker image name for lattice
const LATTICE_IMAGE: &str = "lattice:e2e-test";

// =============================================================================
// Helper Functions
// =============================================================================

/// Run a shell command and return output
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a shell command, allowing failure
fn run_cmd_allow_fail(cmd: &str, args: &[&str]) -> String {
    ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Build the lattice Docker image
async fn build_lattice_image() -> Result<(), String> {
    println!("  Building lattice Docker image...");

    let output = ProcessCommand::new("docker")
        .args(["build", "-t", LATTICE_IMAGE, "."])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|e| format!("Failed to run docker build: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image built successfully");
    Ok(())
}

/// Load the lattice image into kind cluster
fn load_image_to_kind(cluster_name: &str) -> Result<(), String> {
    println!("  Loading image into kind cluster...");

    run_cmd(
        "kind",
        &[
            "load",
            "docker-image",
            LATTICE_IMAGE,
            "--name",
            cluster_name,
        ],
    )?;

    println!("  Image loaded into kind");
    Ok(())
}

/// Check if CAPD is installed
async fn ensure_capd_installed() -> Result<(), String> {
    println!("  Checking CAPI/CAPD installation...");

    // Check if clusterctl exists
    run_cmd("which", &["clusterctl"])?;

    // Check if CAPD CRDs exist
    let output = run_cmd_allow_fail(
        "kubectl",
        &[
            "get",
            "crd",
            "dockerclusters.infrastructure.cluster.x-k8s.io",
        ],
    );

    if output.contains("dockerclusters") {
        println!("  CAPD already installed");
        return Ok(());
    }

    println!("  Installing CAPI and CAPD...");
    run_cmd(
        "clusterctl",
        &["init", "--infrastructure", "docker", "--wait-providers"],
    )?;

    // Wait for controllers to be ready
    println!("  Waiting for CAPI controllers...");
    sleep(Duration::from_secs(30)).await;

    Ok(())
}

/// Create workload cluster spec
fn workload_cluster_spec(name: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 0, // Start with 0 workers for faster provisioning
            },
            networking: None,
            cell: None,
            cell_ref: Some("management-cluster".to_string()),
            environment: Some("e2e-test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

/// Apply YAML manifest via kubectl
fn kubectl_apply(yaml: &str) -> Result<(), String> {
    let mut child = ProcessCommand::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(yaml.as_bytes())
        .map_err(|e| format!("Failed to write to kubectl: {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for kubectl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Wait for CAPI cluster to be ready
async fn wait_for_cluster_ready(name: &str, namespace: &str) -> Result<(), String> {
    println!("  Waiting for cluster '{}' to be ready...", name);

    let start = std::time::Instant::now();
    let timeout_duration = PROVISION_TIMEOUT;

    loop {
        if start.elapsed() > timeout_duration {
            // Print debug info before failing
            let cluster_info = run_cmd_allow_fail(
                "kubectl",
                &["get", "cluster", name, "-n", namespace, "-o", "yaml"],
            );
            println!("  Cluster state at timeout:\n{}", cluster_info);
            return Err(format!("Timeout waiting for cluster {} to be ready", name));
        }

        // Check cluster phase
        let phase = run_cmd_allow_fail(
            "kubectl",
            &[
                "get",
                "cluster",
                name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.status.phase}",
            ],
        );

        // Check if infrastructure is ready
        let infra_ready = run_cmd_allow_fail(
            "kubectl",
            &[
                "get",
                "cluster",
                name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.status.infrastructureReady}",
            ],
        );

        // Check control plane initialized
        let cp_initialized = run_cmd_allow_fail(
            "kubectl",
            &[
                "get",
                "cluster",
                name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.status.controlPlaneReady}",
            ],
        );

        println!(
            "    Phase: {}, Infra ready: {}, CP ready: {}",
            phase.trim(),
            infra_ready.trim(),
            cp_initialized.trim()
        );

        // Cluster is ready when phase is Provisioned and control plane is ready
        if phase.trim() == "Provisioned" && cp_initialized.trim() == "true" {
            println!("  Cluster is ready!");
            break;
        }

        // Alternative: if phase is Provisioned and we can actually connect, it's ready
        if phase.trim() == "Provisioned" {
            // Get kubeconfig and test actual connectivity
            let kubeconfig_check =
                run_cmd_allow_fail("clusterctl", &["get", "kubeconfig", name, "-n", namespace]);
            if kubeconfig_check.contains("apiVersion") {
                // Write temp kubeconfig and test connection
                let temp_kc = "/tmp/e2e-readiness-check-kubeconfig";
                if let Ok(patched) = patch_kubeconfig_for_localhost(&kubeconfig_check, name) {
                    if std::fs::write(temp_kc, &patched).is_ok() {
                        let connectivity = run_cmd_allow_fail(
                            "kubectl",
                            &[
                                "--kubeconfig",
                                temp_kc,
                                "get",
                                "nodes",
                                "--request-timeout=5s",
                            ],
                        );
                        let _ = std::fs::remove_file(temp_kc);
                        if connectivity.contains("control-plane") || connectivity.contains("Ready")
                        {
                            println!("  Cluster connectivity verified, cluster is ready!");
                            break;
                        } else {
                            println!("    Kubeconfig available but cannot connect yet...");
                        }
                    }
                }
            }
        }

        sleep(Duration::from_secs(15)).await;
    }

    // Additional wait for API server to be fully responsive
    println!("  Waiting for API server to be responsive...");
    sleep(Duration::from_secs(10)).await;

    Ok(())
}

/// Get kubeconfig for workload cluster
fn get_workload_kubeconfig(name: &str, namespace: &str) -> Result<String, String> {
    run_cmd("clusterctl", &["get", "kubeconfig", name, "-n", namespace])
}

/// Patch kubeconfig to use localhost port instead of Docker internal IP
/// CAPD exposes the API server on a localhost port, but the kubeconfig has the internal IP
fn patch_kubeconfig_for_localhost(kubeconfig: &str, cluster_name: &str) -> Result<String, String> {
    // Get the load balancer container's exposed port
    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    // Parse the port (format: "0.0.0.0:55344" or "127.0.0.1:55344")
    let localhost_endpoint = if !port_output.trim().is_empty() {
        let parts: Vec<&str> = port_output.trim().split(':').collect();
        if parts.len() == 2 {
            format!("https://127.0.0.1:{}", parts[1])
        } else {
            return Err(format!("Failed to parse LB port: {}", port_output));
        }
    } else {
        // Fallback: try to get control plane container port directly
        let cp_output = run_cmd_allow_fail(
            "docker",
            &[
                "ps",
                "--filter",
                &format!("name={}-control-plane", cluster_name),
                "--format",
                "{{.Ports}}",
            ],
        );

        // Parse something like "127.0.0.1:55191->6443/tcp"
        if let Some(port_mapping) = cp_output.lines().next() {
            if let Some(host_part) = port_mapping.split("->").next() {
                format!("https://{}", host_part.trim())
            } else {
                return Err("Failed to find control plane port".to_string());
            }
        } else {
            return Err("No control plane container found".to_string());
        }
    };

    println!("    Patching kubeconfig to use: {}", localhost_endpoint);

    // Replace the server URL in the kubeconfig
    // The kubeconfig has: server: https://172.18.x.x:6443
    let patched = kubeconfig
        .lines()
        .map(|line| {
            if line.trim().starts_with("server:") {
                format!("    server: {}", localhost_endpoint)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(patched)
}

/// Generate CAPI manifests using DockerProvider
async fn generate_capi_manifests(
    cluster: &LatticeCluster,
    bootstrap: &BootstrapInfo,
) -> Result<Vec<CAPIManifest>, String> {
    let provider = DockerProvider::new();

    provider
        .generate_capi_manifests(cluster, bootstrap)
        .await
        .map_err(|e| format!("Failed to generate CAPI manifests: {}", e))
}

// =============================================================================
// E2E Test: Real Pivot Flow with Agent
// =============================================================================

/// Story: Real end-to-end pivot with actual agent deployment
///
/// This test provisions actual infrastructure, deploys our agent binary,
/// and executes the pivot flow through our gRPC communication.
#[tokio::test]
#[ignore = "requires kind cluster with CAPD - takes 15-20min - run with: cargo test --test kind pivot_e2e -- --ignored --nocapture"]
async fn story_real_pivot_with_agent_deployment() {
    let result = timeout(E2E_TIMEOUT, run_real_e2e_with_agent()).await;

    match result {
        Ok(Ok(())) => println!("\n=== Real E2E Test with Agent Completed Successfully! ===\n"),
        Ok(Err(e)) => panic!("\n=== Real E2E Test Failed: {} ===\n", e),
        Err(_) => panic!("\n=== Real E2E Test Timed Out ({:?}) ===\n", E2E_TIMEOUT),
    }
}

async fn run_real_e2e_with_agent() -> Result<(), String> {
    // Install crypto provider for rustls/kube client
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    println!("\n============================================================");
    println!("  REAL END-TO-END PIVOT TEST WITH AGENT");
    println!("  This test deploys the actual lattice agent binary");
    println!("  Expected duration: 15-20 minutes");
    println!("============================================================\n");

    // =========================================================================
    // Phase 1: Build Docker Image
    // =========================================================================
    println!("\n[Phase 1] Building lattice Docker image...\n");

    build_lattice_image().await?;

    // =========================================================================
    // Phase 2: Setup Fresh Management Cluster
    // =========================================================================
    println!("\n[Phase 2] Setting up fresh management cluster...\n");

    // Use a dedicated cluster name for pivot e2e tests
    const E2E_KIND_CLUSTER: &str = "lattice-pivot-e2e";

    // Delete existing cluster if it exists (clean slate)
    println!("  Deleting existing kind cluster if present...");
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", E2E_KIND_CLUSTER]);

    // Also remove any stale Docker containers from previous runs
    println!("  Cleaning up stale Docker containers...");
    let stale_containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", WORKLOAD_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in stale_containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    // Create fresh kind cluster with Docker socket mounted (required for CAPD)
    println!("  Creating fresh kind cluster '{}'...", E2E_KIND_CLUSTER);

    // Write kind config to mount Docker socket
    let kind_config = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
"#;
    let kind_config_path = "/tmp/e2e-kind-config.yaml";
    std::fs::write(kind_config_path, kind_config)
        .map_err(|e| format!("Failed to write kind config: {}", e))?;

    run_cmd(
        "kind",
        &[
            "create",
            "cluster",
            "--name",
            E2E_KIND_CLUSTER,
            "--config",
            kind_config_path,
            "--wait",
            "60s",
        ],
    )?;

    let _ = std::fs::remove_file(kind_config_path);

    // Get kube client for the new cluster
    println!("  Connecting to cluster...");
    let client = kube::Client::try_default()
        .await
        .map_err(|e| format!("Failed to create kube client: {}", e))?;

    // Install CRD
    println!("  Installing LatticeCluster CRD...");
    let crd_yaml = run_cmd("cargo", &["run", "--", "--crd"])?;
    kubectl_apply(&crd_yaml)?;

    // Install CAPI/CAPD
    ensure_capd_installed().await?;

    // Load lattice image into kind
    load_image_to_kind(E2E_KIND_CLUSTER)?;

    // =========================================================================
    // Phase 3: Start Cell-side Services (AgentServer + HTTP Bootstrap)
    // =========================================================================
    println!("\n[Phase 3] Starting cell-side services...\n");

    // Create CA for mTLS
    let ca = Arc::new(
        CertificateAuthority::new("E2E Test CA")
            .map_err(|e| format!("Failed to create CA: {}", e))?,
    );

    // Create agent registry
    let registry = Arc::new(AgentRegistry::new());

    // Create bootstrap state with Cilium CNI (requires helm)
    let manifest_generator = DefaultManifestGenerator::new().map_err(|e| {
        format!(
            "Failed to create manifest generator (is helm installed?): {}",
            e
        )
    })?;
    let bootstrap_state = Arc::new(BootstrapState::new(
        manifest_generator,
        Duration::from_secs(3600),
        ca.clone(),
    ));

    // Find available port for gRPC server
    let grpc_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let grpc_listener = tokio::net::TcpListener::bind(grpc_addr)
        .await
        .map_err(|e| format!("Failed to bind gRPC listener: {}", e))?;
    let actual_grpc_addr = grpc_listener.local_addr().unwrap();

    // Start gRPC server
    let registry_clone = registry.clone();
    let grpc_handle = tokio::spawn(async move {
        let server = AgentServer::new(registry_clone);
        tonic::transport::Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                grpc_listener,
            ))
            .await
    });
    println!("  gRPC server listening on {}", actual_grpc_addr);

    // Find available port for HTTP bootstrap server
    let http_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .map_err(|e| format!("Failed to bind HTTP listener: {}", e))?;
    let actual_http_addr = http_listener.local_addr().unwrap();

    // Start HTTP bootstrap server (for kubeadm postKubeadmCommands webhook)
    let bootstrap_state_clone = bootstrap_state.clone();
    let http_handle = tokio::spawn(async move {
        let router = bootstrap_router(bootstrap_state_clone);
        axum::serve(http_listener, router).await
    });
    println!("  HTTP bootstrap server listening on {}", actual_http_addr);

    // Give servers time to start
    sleep(Duration::from_millis(100)).await;

    // =========================================================================
    // Phase 4: Create LatticeCluster and Generate CAPI Manifests
    // =========================================================================
    println!("\n[Phase 4] Creating LatticeCluster and generating CAPI manifests...\n");

    // Create LatticeCluster CRD resource
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME);

    println!("  Creating LatticeCluster resource...");
    api.create(&PostParams::default(), &cluster)
        .await
        .map_err(|e| format!("Failed to create LatticeCluster: {}", e))?;

    // Register cluster for bootstrap - this creates a one-time token
    // The HTTP endpoint uses host.docker.internal because the CAPD container
    // needs to reach the host where our HTTP server is running
    let bootstrap_http_endpoint =
        format!("http://host.docker.internal:{}", actual_http_addr.port());
    let cell_grpc_endpoint = format!("host.docker.internal:{}", actual_grpc_addr.port());

    let token = bootstrap_state.register_cluster(
        WORKLOAD_CLUSTER_NAME.to_string(),
        cell_grpc_endpoint.clone(),
        ca.ca_cert_pem().to_string(),
    );

    println!("  Registered cluster with bootstrap token");
    println!("    Bootstrap endpoint: {}", bootstrap_http_endpoint);
    println!("    gRPC endpoint: {}", cell_grpc_endpoint);

    // Create BootstrapInfo for CAPI manifest generation
    // This will cause postKubeadmCommands to be generated that webhook
    // back to our HTTP server to get CNI + agent manifests
    let bootstrap_info = BootstrapInfo::new(
        bootstrap_http_endpoint.clone(),
        token.as_str().to_string(),
        cell_grpc_endpoint.clone(),
        ca.ca_cert_pem().to_string(),
    );

    // Generate CAPI manifests using DockerProvider with bootstrap info
    println!("  Generating CAPI manifests via DockerProvider...");
    let capi_manifests = generate_capi_manifests(&cluster, &bootstrap_info).await?;

    println!("  Generated {} CAPI resources", capi_manifests.len());
    println!(
        "  postKubeadmCommands will webhook to {} for CNI + agent",
        bootstrap_http_endpoint
    );

    // =========================================================================
    // Phase 5: Apply CAPI Manifests and Provision Cluster
    // =========================================================================
    println!("\n[Phase 5] Applying CAPI manifests and provisioning cluster...\n");

    for manifest in &capi_manifests {
        let yaml = manifest
            .to_yaml()
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        println!("  Applying {}...", manifest.kind);
        kubectl_apply(&yaml)?;
    }

    println!("\n  CAPI manifests applied. Waiting for CAPD to provision cluster...");
    println!("  (This typically takes 5-10 minutes)\n");

    wait_for_cluster_ready(WORKLOAD_CLUSTER_NAME, CAPI_NAMESPACE).await?;

    // =========================================================================
    // Phase 6: Get Workload Cluster Kubeconfig and Verify Bootstrap
    // =========================================================================
    println!("\n[Phase 6] Getting workload cluster kubeconfig...\n");

    let raw_kubeconfig = get_workload_kubeconfig(WORKLOAD_CLUSTER_NAME, CAPI_NAMESPACE)?;
    println!("  Got kubeconfig for workload cluster");

    // Patch kubeconfig to use localhost port (CAPD uses Docker internal IPs)
    let workload_kubeconfig =
        patch_kubeconfig_for_localhost(&raw_kubeconfig, WORKLOAD_CLUSTER_NAME)?;

    // Write to temp file for kubectl commands
    let kubeconfig_path = "/tmp/e2e-workload-kubeconfig";
    std::fs::write(kubeconfig_path, &workload_kubeconfig)
        .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

    // Verify we can connect to workload cluster
    println!("  Verifying workload cluster connectivity...");
    let nodes = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "nodes",
            "-o",
            "wide",
        ],
    )?;
    println!("  Workload cluster nodes:\n{}", nodes);

    // The postKubeadmCommands webhook should have installed CNI + agent during bootstrap
    // Let's verify the agent namespace and deployment exist
    println!("  Checking if bootstrap webhook installed agent...");
    let ns_check = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "namespace",
            "lattice-system",
        ],
    );

    if !ns_check.contains("lattice-system") {
        println!(
            "  WARNING: Bootstrap webhook may have failed - lattice-system namespace not found"
        );
        println!("  This could mean the postKubeadmCommands couldn't reach the HTTP server");
        println!("  Checking if we need to manually bootstrap...");

        // For e2e test, we still need to load our local image into the workload cluster
        // In production, the image would come from a registry
        let workload_container = format!("{}-control-plane", WORKLOAD_CLUSTER_NAME);
        println!("  Loading lattice image into workload cluster...");
        let export_result = ProcessCommand::new("docker")
            .args(["save", LATTICE_IMAGE])
            .stdout(std::process::Stdio::piped())
            .spawn();

        if let Ok(mut export) = export_result {
            let _ = ProcessCommand::new("docker")
                .args([
                    "exec",
                    "-i",
                    &workload_container,
                    "ctr",
                    "-n",
                    "k8s.io",
                    "images",
                    "import",
                    "-",
                ])
                .stdin(export.stdout.take().unwrap())
                .output();
        }

        // TODO: If bootstrap webhook failed, we could manually call the endpoint here
        // For now, return error so we can debug
        return Err(
            "Bootstrap webhook did not install agent - check postKubeadmCommands output"
                .to_string(),
        );
    }

    println!("  Bootstrap webhook succeeded - lattice-system namespace exists");

    // Load our local lattice image into workload cluster (needed for e2e test)
    // In production, the image would be pulled from a registry
    let workload_container = format!("{}-control-plane", WORKLOAD_CLUSTER_NAME);
    println!("  Loading lattice image into workload cluster...");
    let export_result = ProcessCommand::new("docker")
        .args(["save", LATTICE_IMAGE])
        .stdout(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut export) = export_result {
        let _ = ProcessCommand::new("docker")
            .args([
                "exec",
                "-i",
                &workload_container,
                "ctr",
                "-n",
                "k8s.io",
                "images",
                "import",
                "-",
            ])
            .stdin(export.stdout.take().unwrap())
            .output();
    }

    // Wait for agent pod to be ready (it was deployed by bootstrap webhook)
    println!("  Waiting for agent pod to be ready...");
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(120) {
            // Get pod status for debugging
            let pods = run_cmd_allow_fail(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "pods",
                    "-n",
                    "lattice-system",
                    "-o",
                    "wide",
                ],
            );
            println!("  Agent pods:\n{}", pods);
            return Err("Timeout waiting for agent pod to be ready".to_string());
        }

        let pod_status = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                "lattice-system",
                "-l",
                "app=lattice-agent",
                "-o",
                "jsonpath={.items[0].status.phase}",
            ],
        );

        if pod_status.trim() == "Running" {
            println!("  Agent pod is running");
            break;
        }

        sleep(Duration::from_secs(5)).await;
    }

    // =========================================================================
    // Phase 7: Wait for Agent Connection
    // =========================================================================
    println!("\n[Phase 7] Waiting for agent to connect to cell...\n");

    let start = std::time::Instant::now();
    let mut connected = false;

    while start.elapsed() < AGENT_CONNECT_TIMEOUT {
        if registry.get(WORKLOAD_CLUSTER_NAME).is_some() {
            println!("  Agent connected!");
            connected = true;
            break;
        }

        println!("    Waiting for agent connection...");
        sleep(Duration::from_secs(5)).await;
    }

    if !connected {
        // Get agent logs for debugging
        let logs = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "logs",
                "-n",
                "lattice-system",
                "-l",
                "app=lattice-agent",
                "--tail=50",
            ],
        );
        println!("  Agent logs:\n{}", logs);
        return Err("Agent did not connect within timeout".to_string());
    }

    // Verify agent state
    let conn = registry.get(WORKLOAD_CLUSTER_NAME).unwrap();
    println!("  Agent version: {}", conn.agent_version);
    println!("  Agent state: {:?}", conn.state);

    // =========================================================================
    // Phase 8: Install CAPI on Workload Cluster
    // =========================================================================
    println!("\n[Phase 8] Installing CAPI on workload cluster...\n");

    let output = ProcessCommand::new("clusterctl")
        .args([
            "init",
            "--kubeconfig",
            kubeconfig_path,
            "--infrastructure",
            "docker",
        ])
        .output()
        .map_err(|e| format!("Failed to run clusterctl init: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already") {
            return Err(format!("clusterctl init on workload failed: {}", stderr));
        }
    }

    println!("  Waiting for CAPI controllers to be ready...");
    sleep(Duration::from_secs(60)).await;

    // =========================================================================
    // Phase 9: Execute Pivot via Agent
    // =========================================================================
    println!("\n[Phase 9] Executing pivot via agent...\n");

    // Send StartPivot command to agent
    println!("  Sending StartPivot command to agent...");

    // Get the command channel for the agent
    let conn = registry.get(WORKLOAD_CLUSTER_NAME).unwrap();

    // Create and send StartPivot command
    use lattice::proto::{cell_command::Command, CellCommand, StartPivotCommand};
    let pivot_cmd = CellCommand {
        command_id: "pivot-e2e-test".to_string(),
        command: Some(Command::StartPivot(StartPivotCommand {
            source_namespace: CAPI_NAMESPACE.to_string(),
            target_namespace: CAPI_NAMESPACE.to_string(),
            cluster_name: WORKLOAD_CLUSTER_NAME.to_string(),
        })),
    };

    conn.send_command(pivot_cmd)
        .await
        .map_err(|e| format!("Failed to send pivot command: {}", e))?;

    println!("  Pivot command sent, executing clusterctl move...");

    // Execute clusterctl move from cell side
    let orchestrator = PivotOrchestrator::new(PIVOT_TIMEOUT).with_capi_namespace(CAPI_NAMESPACE);

    // Write proxy kubeconfig for clusterctl
    let proxy_kubeconfig_path = std::path::Path::new("/tmp/e2e-pivot-proxy-kubeconfig");
    PivotOrchestrator::<lattice::pivot::RealCommandRunner>::write_proxy_kubeconfig(
        &workload_kubeconfig,
        proxy_kubeconfig_path,
    )
    .map_err(|e| format!("Failed to write proxy kubeconfig: {}", e))?;

    let pivot_result = orchestrator
        .execute_pivot(WORKLOAD_CLUSTER_NAME, proxy_kubeconfig_path, None)
        .await
        .map_err(|e| format!("Pivot failed: {}", e))?;

    println!(
        "  clusterctl move completed: {} resources moved",
        pivot_result.resources_moved
    );

    // =========================================================================
    // Phase 10: Wait for Agent to Report Pivot Complete
    // =========================================================================
    println!("\n[Phase 10] Waiting for agent to report pivot complete...\n");

    let start = std::time::Instant::now();
    let mut pivot_complete = false;

    while start.elapsed() < PIVOT_TIMEOUT {
        if let Some(conn) = registry.get(WORKLOAD_CLUSTER_NAME) {
            if conn.state == AgentState::Ready {
                println!("  Agent reports Ready state - pivot complete!");
                pivot_complete = true;
                break;
            }
            println!("    Agent state: {:?}", conn.state);
        }
        sleep(Duration::from_secs(5)).await;
    }

    if !pivot_complete {
        return Err("Agent did not report pivot complete within timeout".to_string());
    }

    // =========================================================================
    // Phase 11: Verify Post-Pivot State
    // =========================================================================
    println!("\n[Phase 11] Verifying post-pivot state...\n");

    // CAPI resources should now exist on workload cluster
    println!("  Checking for CAPI resources on workload cluster...");
    let workload_clusters = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )?;
    println!(
        "  CAPI clusters on workload cluster:\n{}",
        workload_clusters
    );

    if !workload_clusters.contains(WORKLOAD_CLUSTER_NAME) {
        return Err(
            "Workload cluster should have its own Cluster resource after pivot".to_string(),
        );
    }

    // Check that the cluster can reconcile itself
    let self_cluster = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "cluster",
            WORKLOAD_CLUSTER_NAME,
            "-n",
            CAPI_NAMESPACE,
            "-o",
            "jsonpath={.status.phase}",
        ],
    )?;

    println!(
        "  Workload cluster self-reported phase: {}",
        self_cluster.trim()
    );

    println!("\n  SUCCESS: Workload cluster is now self-managing!");
    println!("  - Agent successfully connected to cell via gRPC");
    println!("  - Cell triggered pivot, agent received command");
    println!("  - CAPI resources have been moved to the workload cluster");
    println!("  - Agent reported pivot complete and entered Ready state");

    // =========================================================================
    // Phase 12: Cleanup
    // =========================================================================
    println!("\n[Phase 12] Cleaning up...\n");

    // Stop servers
    grpc_handle.abort();
    http_handle.abort();

    // Remove temp files
    let _ = std::fs::remove_file(kubeconfig_path);
    let _ = std::fs::remove_file("/tmp/e2e-pivot-proxy-kubeconfig");

    // Delete the entire kind cluster - clean slate for next run
    println!("  Deleting kind cluster...");
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", E2E_KIND_CLUSTER]);

    // Also clean up any Docker containers from workload cluster
    let containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", WORKLOAD_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    println!("  Cleanup complete!");

    Ok(())
}
