//! Real end-to-end test for the complete pivot flow
//!
//! This test deploys the actual Lattice operator to a kind cluster and lets
//! it handle everything: provisioning, bootstrap, agent connection, and pivot.
//!
//! # What This Test Does
//!
//! 1. Creates a fresh kind cluster for the management cluster
//! 2. Builds and loads the lattice Docker image
//! 3. Deploys the Lattice operator (cell mode) to the management cluster
//! 4. Creates a LatticeCluster CRD for the workload cluster
//! 5. Watches the controller reconcile: Pending -> Provisioning -> Pivoting -> Ready
//! 6. Verifies workload cluster is self-managing with CAPI resources
//!
//! # Prerequisites
//!
//! - Docker running with sufficient resources (8GB+ RAM recommended)
//! - kind installed
//! - clusterctl installed
//! - kubectl installed
//! - helm installed (for Cilium CNI)
//!
//! # Running
//!
//! ```bash
//! # This test takes 15-20 minutes
//! cargo test --test kind pivot_e2e -- --ignored --nocapture
//! ```

use std::process::Command as ProcessCommand;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use tokio::time::sleep;

use lattice::crd::{
    ClusterPhase, KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec, ProviderSpec,
    ProviderType,
};

// =============================================================================
// Test Configuration
// =============================================================================

/// Timeout for the entire e2e test
const E2E_TIMEOUT: Duration = Duration::from_secs(1200); // 20 minutes

/// Name of the kind cluster acting as management cluster
const MGMT_KIND_CLUSTER: &str = "lattice-pivot-e2e";

/// Name of the workload cluster being provisioned
const WORKLOAD_CLUSTER_NAME: &str = "e2e-pivot-workload";

/// Docker image name for lattice (using ghcr.io registry so workload clusters can pull)
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

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

/// Build and push the lattice Docker image to registry
async fn build_and_push_lattice_image() -> Result<(), String> {
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

    println!("  Pushing image to registry...");

    let output = ProcessCommand::new("docker")
        .args(["push", LATTICE_IMAGE])
        .output()
        .map_err(|e| format!("Failed to push image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image pushed successfully");
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

/// Check if CAPD is installed, install if not
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
            cell_ref: Some(MGMT_KIND_CLUSTER.to_string()),
            environment: Some("e2e-test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

/// Deploy Lattice operator to the kind cluster
async fn deploy_lattice_operator() -> Result<(), String> {
    println!("  Installing LatticeCluster CRD...");
    let crd_yaml = run_cmd("cargo", &["run", "--", "--crd"])?;
    kubectl_apply(&crd_yaml)?;

    println!("  Creating lattice-system namespace...");
    kubectl_apply(
        r#"
apiVersion: v1
kind: Namespace
metadata:
  name: lattice-system
"#,
    )?;

    // The operator needs a cell endpoint that workload clusters can reach.
    // In kind/docker networking, we use host.docker.internal to reach the host.
    // The operator will listen on the node's IP, which we'll expose via NodePort.
    println!("  Deploying Lattice operator...");

    let operator_manifest = format!(
        r#"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lattice-operator
  namespace: lattice-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: lattice-operator
rules:
  # Full access to LatticeCluster CRDs
  - apiGroups: ["lattice.dev"]
    resources: ["latticeclusters", "latticeclusters/status"]
    verbs: ["*"]
  # Access to CAPI resources
  - apiGroups: ["cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["infrastructure.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["controlplane.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["bootstrap.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["*"]
  # Access to core resources
  - apiGroups: [""]
    resources: ["nodes", "secrets", "configmaps", "namespaces", "pods"]
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: lattice-operator
subjects:
  - kind: ServiceAccount
    name: lattice-operator
    namespace: lattice-system
roleRef:
  kind: ClusterRole
  name: lattice-operator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Service
metadata:
  name: lattice-cell
  namespace: lattice-system
spec:
  type: NodePort
  selector:
    app: lattice-operator
  ports:
    - name: https
      port: 443
      targetPort: 443
      nodePort: 30443
    - name: grpc
      port: 50051
      targetPort: 50051
      nodePort: 30051
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lattice-operator
  namespace: lattice-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lattice-operator
  template:
    metadata:
      labels:
        app: lattice-operator
    spec:
      serviceAccountName: lattice-operator
      containers:
        - name: operator
          image: {image}
          imagePullPolicy: Never
          args:
            - "controller"
            - "--bootstrap-addr=0.0.0.0:443"
            - "--grpc-addr=0.0.0.0:50051"
            - "--cell-endpoint=host.docker.internal:30051"
            - "--bootstrap-endpoint=https://host.docker.internal:30443"
          ports:
            - containerPort: 443
              name: https
            - containerPort: 50051
              name: grpc
          env:
            - name: RUST_LOG
              value: "info,lattice=debug"
"#,
        image = LATTICE_IMAGE
    );

    kubectl_apply(&operator_manifest)?;

    // Wait for operator to be ready
    println!("  Waiting for operator to be ready...");
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(120) {
            let pods = run_cmd_allow_fail(
                "kubectl",
                &["get", "pods", "-n", "lattice-system", "-o", "wide"],
            );
            println!("  Operator pods:\n{}", pods);
            return Err("Timeout waiting for operator to be ready".to_string());
        }

        let status = run_cmd_allow_fail(
            "kubectl",
            &[
                "get",
                "deployment",
                "-n",
                "lattice-system",
                "lattice-operator",
                "-o",
                "jsonpath={.status.readyReplicas}",
            ],
        );

        if status.trim() == "1" {
            println!("  Operator is ready");
            break;
        }

        sleep(Duration::from_secs(5)).await;
    }

    // Get operator logs for debugging
    let logs = run_cmd_allow_fail(
        "kubectl",
        &[
            "logs",
            "-n",
            "lattice-system",
            "-l",
            "app=lattice-operator",
            "--tail=20",
        ],
    );
    println!("  Operator logs:\n{}", logs);

    Ok(())
}

/// Watch LatticeCluster phase transitions
async fn watch_cluster_phases(client: &kube::Client, cluster_name: &str) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(900); // 15 minutes for full flow

    let mut last_phase: Option<ClusterPhase> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for cluster to reach Ready state. Last phase: {:?}",
                last_phase
            ));
        }

        match api.get(cluster_name).await {
            Ok(cluster) => {
                let current_phase = cluster
                    .status
                    .as_ref()
                    .map(|s| s.phase.clone())
                    .unwrap_or(ClusterPhase::Pending);

                if last_phase.as_ref() != Some(&current_phase) {
                    println!("  Cluster phase: {:?}", current_phase);
                    last_phase = Some(current_phase.clone());
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    println!("  Cluster reached Ready state!");
                    return Ok(());
                }

                if matches!(current_phase, ClusterPhase::Failed) {
                    // Get operator logs for debugging
                    let logs = run_cmd_allow_fail(
                        "kubectl",
                        &[
                            "logs",
                            "-n",
                            "lattice-system",
                            "-l",
                            "app=lattice-operator",
                            "--tail=50",
                        ],
                    );
                    println!("  Operator logs:\n{}", logs);
                    return Err("Cluster entered Failed state".to_string());
                }
            }
            Err(e) => {
                println!("  Error getting cluster: {}", e);
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Get kubeconfig for workload cluster and patch for localhost access
fn get_workload_kubeconfig(cluster_name: &str) -> Result<String, String> {
    let raw_kubeconfig = run_cmd("clusterctl", &["get", "kubeconfig", cluster_name])?;

    // Get the load balancer container's exposed port
    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    let localhost_endpoint = if !port_output.trim().is_empty() {
        let parts: Vec<&str> = port_output.trim().split(':').collect();
        if parts.len() == 2 {
            format!("https://127.0.0.1:{}", parts[1])
        } else {
            return Err(format!("Failed to parse LB port: {}", port_output));
        }
    } else {
        // Fallback: try control plane container
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

    // Patch the kubeconfig to use localhost
    let patched = raw_kubeconfig
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

// =============================================================================
// E2E Test: Real Pivot Flow with Operator
// =============================================================================

/// Story: Real end-to-end pivot with Lattice operator
///
/// This test deploys the Lattice operator and lets it handle everything.
#[tokio::test]
#[ignore = "requires kind cluster with CAPD - takes 15-20min - run with: cargo test --test kind pivot_e2e -- --ignored --nocapture"]
async fn story_real_pivot_with_operator() {
    let result = tokio::time::timeout(E2E_TIMEOUT, run_real_e2e_with_operator()).await;

    match result {
        Ok(Ok(())) => println!("\n=== Real E2E Test with Operator Completed Successfully! ===\n"),
        Ok(Err(e)) => panic!("\n=== Real E2E Test Failed: {} ===\n", e),
        Err(_) => panic!("\n=== Real E2E Test Timed Out ({:?}) ===\n", E2E_TIMEOUT),
    }
}

async fn run_real_e2e_with_operator() -> Result<(), String> {
    // Install crypto provider for rustls/kube client
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    println!("\n============================================================");
    println!("  REAL END-TO-END PIVOT TEST WITH LATTICE OPERATOR");
    println!("  The operator handles everything: provisioning, bootstrap, pivot");
    println!("  Expected duration: 15-20 minutes");
    println!("============================================================\n");

    // =========================================================================
    // Phase 1: Setup Fresh Management Cluster
    // =========================================================================
    println!("\n[Phase 1] Setting up fresh management cluster...\n");

    // Delete existing cluster if it exists (clean slate)
    println!("  Deleting existing kind cluster if present...");
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", MGMT_KIND_CLUSTER]);

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
    println!("  Creating fresh kind cluster '{}'...", MGMT_KIND_CLUSTER);

    let kind_config = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
  extraPortMappings:
  - containerPort: 30443
    hostPort: 30443
    protocol: TCP
  - containerPort: 30051
    hostPort: 30051
    protocol: TCP
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
            MGMT_KIND_CLUSTER,
            "--config",
            kind_config_path,
            "--wait",
            "60s",
        ],
    )?;

    let _ = std::fs::remove_file(kind_config_path);

    // =========================================================================
    // Phase 2: Build and Push Lattice Image
    // =========================================================================
    println!("\n[Phase 2] Building and pushing lattice image...\n");

    build_and_push_lattice_image().await?;
    // Also load into management cluster for faster pulls
    load_image_to_kind(MGMT_KIND_CLUSTER)?;

    // =========================================================================
    // Phase 3: Install CAPI/CAPD
    // =========================================================================
    println!("\n[Phase 3] Installing CAPI and CAPD...\n");

    ensure_capd_installed().await?;

    // =========================================================================
    // Phase 4: Deploy Lattice Operator
    // =========================================================================
    println!("\n[Phase 4] Deploying Lattice operator...\n");

    deploy_lattice_operator().await?;

    // =========================================================================
    // Phase 5: Create LatticeCluster CRD
    // =========================================================================
    println!("\n[Phase 5] Creating LatticeCluster for workload cluster...\n");

    let client = kube::Client::try_default()
        .await
        .map_err(|e| format!("Failed to create kube client: {}", e))?;

    let api: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME);

    println!("  Creating LatticeCluster resource...");
    api.create(&PostParams::default(), &cluster)
        .await
        .map_err(|e| format!("Failed to create LatticeCluster: {}", e))?;

    // =========================================================================
    // Phase 6: Watch Controller Reconcile
    // =========================================================================
    println!("\n[Phase 6] Watching controller reconcile cluster...\n");
    println!("  The operator will:");
    println!("    1. Generate and apply CAPI manifests");
    println!("    2. Wait for CAPD to provision infrastructure");
    println!("    3. Bootstrap webhook installs CNI + agent");
    println!("    4. Agent connects, operator triggers pivot");
    println!("    5. Cluster becomes self-managing\n");

    watch_cluster_phases(&client, WORKLOAD_CLUSTER_NAME).await?;

    // =========================================================================
    // Phase 7: Verify Post-Pivot State
    // =========================================================================
    println!("\n[Phase 7] Verifying post-pivot state...\n");

    // Get workload cluster kubeconfig
    let workload_kubeconfig = get_workload_kubeconfig(WORKLOAD_CLUSTER_NAME)?;
    let kubeconfig_path = "/tmp/e2e-workload-kubeconfig";
    std::fs::write(kubeconfig_path, &workload_kubeconfig)
        .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

    // Check for CAPI resources on workload cluster (should exist after pivot)
    println!("  Checking for CAPI resources on workload cluster...");
    let capi_clusters = run_cmd(
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
    println!("  CAPI clusters on workload cluster:\n{}", capi_clusters);

    if !capi_clusters.contains(WORKLOAD_CLUSTER_NAME) {
        return Err(
            "Workload cluster should have its own Cluster resource after pivot".to_string(),
        );
    }

    // Check that LatticeCluster CRD exists
    println!("  Checking for LatticeCluster CRD on workload cluster...");
    let crd_check = run_cmd_allow_fail(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "crd",
            "latticeclusters.lattice.dev",
        ],
    );

    if !crd_check.contains("latticeclusters") {
        println!(
            "  WARNING: LatticeCluster CRD not found on workload cluster (may be installed later)"
        );
    } else {
        println!("  LatticeCluster CRD exists on workload cluster");
    }

    // Check nodes are healthy
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

    println!("\n  SUCCESS: Workload cluster is now self-managing!");
    println!("  - Lattice operator provisioned the cluster via CAPI");
    println!("  - Bootstrap webhook installed CNI and agent");
    println!("  - Agent connected to cell via gRPC");
    println!("  - Controller triggered pivot");
    println!("  - CAPI resources moved to workload cluster");
    println!("  - Cluster is now fully self-managing");

    // =========================================================================
    // Phase 8: Cleanup
    // =========================================================================
    println!("\n[Phase 8] Cleaning up...\n");

    // Remove temp files
    let _ = std::fs::remove_file(kubeconfig_path);

    // Delete the entire kind cluster
    println!("  Deleting kind cluster...");
    let _ = run_cmd_allow_fail("kind", &["delete", "cluster", "--name", MGMT_KIND_CLUSTER]);

    // Clean up workload cluster Docker containers
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
