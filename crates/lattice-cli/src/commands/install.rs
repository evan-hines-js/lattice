//! Install command - Bootstrap a new Lattice management cluster
//!
//! This command creates a new Lattice installation by:
//! 1. Reading cluster config from a git repository or local path
//! 2. Creating a temporary kind bootstrap cluster
//! 3. Installing CAPI providers and Lattice operator
//! 4. Provisioning the management cluster
//! 5. Pivoting CAPI resources to make it self-managing
//! 6. Optionally installing Flux for GitOps

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use clap::Args;
use kube::Client;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::info;

use lattice_common::clusterctl::{export_for_pivot, import_from_manifests};
use lattice_common::kube_utils;
use lattice_operator::bootstrap::{
    capmox_credentials_manifests, generate_all_manifests, generate_crs_yaml_manifests,
    DefaultManifestGenerator, ManifestConfig, ManifestGenerator,
};
use lattice_operator::crd::{BootstrapProvider, LatticeCluster, ProviderType};
use lattice_operator::fips;

use crate::{git, Error, Result};

/// Install Lattice from a git repository or local path
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Path to LatticeCluster YAML config file
    #[arg(short = 'f', long = "config")]
    pub config_file: Option<PathBuf>,

    /// Git repository URL containing cluster definitions
    #[arg(long)]
    pub git_repo: Option<String>,

    /// Git branch to use
    #[arg(long, default_value = "main")]
    pub git_branch: String,

    /// Path to existing local repository (alternative to --git-repo)
    #[arg(long)]
    pub local_path: Option<PathBuf>,

    /// Path to git credentials (SSH key or token file)
    #[arg(long)]
    pub git_credentials: Option<PathBuf>,

    /// Lattice container image
    #[arg(
        long,
        env = "LATTICE_IMAGE",
        default_value = "ghcr.io/evan-hines-js/lattice:latest"
    )]
    pub image: String,

    /// Path to registry credentials file (dockerconfigjson format)
    #[arg(long, env = "REGISTRY_CREDENTIALS_FILE")]
    pub registry_credentials_file: Option<PathBuf>,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    pub keep_bootstrap_on_failure: bool,

    /// Timeout for the entire installation in seconds
    #[arg(long, default_value = "1200")]
    pub timeout_secs: u64,

    /// Kubernetes bootstrap provider (overrides config file if set)
    #[arg(long, value_parser = parse_bootstrap_provider)]
    pub bootstrap: Option<BootstrapProvider>,

    /// Dry run - show what would be done without making changes
    #[arg(long)]
    pub dry_run: bool,
}

fn parse_bootstrap_provider(s: &str) -> std::result::Result<BootstrapProvider, String> {
    match s.to_lowercase().as_str() {
        "rke2" => Ok(BootstrapProvider::Rke2),
        "kubeadm" => Ok(BootstrapProvider::Kubeadm),
        _ => Err(format!(
            "invalid bootstrap provider '{}', must be 'rke2' or 'kubeadm'",
            s
        )),
    }
}

/// Configuration for the installer
#[derive(Debug, Clone)]
pub struct InstallConfig {
    /// Raw YAML content of the cluster configuration
    pub cluster_config_content: String,
    /// Lattice container image
    pub image: String,
    /// Keep bootstrap cluster on failure
    pub keep_bootstrap_on_failure: bool,
    /// Optional registry credentials (dockerconfigjson format)
    pub registry_credentials: Option<String>,
    /// Optional bootstrap provider override
    pub bootstrap_override: Option<BootstrapProvider>,
}

/// The Lattice installer
pub struct Installer {
    config: InstallConfig,
    cluster: LatticeCluster,
    cluster_name: String,
}

/// Fixed bootstrap cluster name - concurrent installs are not supported
const BOOTSTRAP_CLUSTER_NAME: &str = "lattice-bootstrap";

impl Installer {
    /// Create a new installer with the given configuration
    pub fn new(config: InstallConfig) -> Result<Self> {
        let mut cluster: LatticeCluster =
            serde_yaml::from_str(&config.cluster_config_content).map_err(Error::Yaml)?;

        if let Some(bootstrap) = &config.bootstrap_override {
            cluster.spec.provider.kubernetes.bootstrap = bootstrap.clone();
        }

        let cluster_name = cluster
            .metadata
            .name
            .clone()
            .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;

        Ok(Self {
            config,
            cluster,
            cluster_name,
        })
    }

    fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    fn bootstrap_kubeconfig_path(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/{}-kubeconfig", BOOTSTRAP_CLUSTER_NAME))
    }

    fn management_kubeconfig_path(&self) -> PathBuf {
        PathBuf::from(format!("/tmp/{}-kubeconfig", self.cluster_name))
    }

    fn provider(&self) -> ProviderType {
        self.cluster.spec.provider.provider_type()
    }

    fn clusterctl_init_args(&self) -> Vec<String> {
        let infra_arg = match self.provider() {
            ProviderType::Docker => "--infrastructure=docker",
            ProviderType::Proxmox => "--infrastructure=proxmox",
            ProviderType::OpenStack => "--infrastructure=openstack",
            ProviderType::Aws => "--infrastructure=aws",
            ProviderType::Gcp => "--infrastructure=gcp",
            ProviderType::Azure => "--infrastructure=azure",
        };

        let config_path = env!("CLUSTERCTL_CONFIG");

        let mut args = vec![
            "init".to_string(),
            infra_arg.to_string(),
            "--bootstrap=kubeadm,rke2".to_string(),
            "--control-plane=kubeadm,rke2".to_string(),
            format!("--config={}", config_path),
            "--wait-providers".to_string(),
        ];

        if self.provider() == ProviderType::Proxmox {
            args.push("--ipam=in-cluster".to_string());
        }

        args
    }

    /// Run the installation
    pub async fn run(&self) -> Result<()> {
        let start = Instant::now();

        self.check_prerequisites().await?;

        let bootstrap_result = self.run_bootstrap().await;

        if bootstrap_result.is_err() && !self.config.keep_bootstrap_on_failure {
            info!("Deleting bootstrap cluster due to failure...");
            let _ = self.delete_kind_cluster().await;
        }

        bootstrap_result?;

        info!("Installation complete in {:?}", start.elapsed());
        info!(
            "Management cluster '{}' is now self-managing.",
            self.cluster_name()
        );

        Ok(())
    }

    async fn check_prerequisites(&self) -> Result<()> {
        info!("Checking prerequisites...");

        // Only check for tools we actually need (no kubectl!)
        let tools = [
            (
                "docker",
                "Install Docker: https://docs.docker.com/get-docker/",
            ),
            (
                "kind",
                "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation",
            ),
            (
                "clusterctl",
                "Install clusterctl: https://cluster-api.sigs.k8s.io/user/quick-start#install-clusterctl",
            ),
        ];

        for (tool, hint) in tools {
            if !self.check_tool(tool).await? {
                return Err(Error::command_failed(format!(
                    "{} not found. {}",
                    tool, hint
                )));
            }
        }

        Ok(())
    }

    async fn check_tool(&self, tool: &str) -> Result<bool> {
        let result = Command::new("which").arg(tool).output().await?;
        Ok(result.status.success())
    }

    async fn run_bootstrap(&self) -> Result<()> {
        info!("[Phase 1] Creating kind bootstrap cluster...");
        self.create_kind_cluster().await?;

        let bootstrap_client = self.bootstrap_client().await?;

        if self.provider() == ProviderType::Proxmox {
            info!("[Phase 1.5] Creating Proxmox credentials...");
            self.create_capmox_credentials(&bootstrap_client).await?;
        }

        info!("[Phase 2] Deploying Lattice operator...");
        self.deploy_lattice_operator(&bootstrap_client).await?;

        info!("[Phase 3] Creating management cluster LatticeCluster CR...");
        self.create_management_cluster_crd(&bootstrap_client).await?;

        info!("[Phase 4] Waiting for management cluster to be provisioned...");
        self.wait_for_management_cluster(&bootstrap_client).await?;

        info!("[Phase 5] Applying bootstrap manifests to management cluster...");
        self.apply_bootstrap_to_management(&bootstrap_client).await?;

        info!("[Phase 6] Pivoting CAPI resources to management cluster...");
        self.pivot_capi_resources().await?;

        info!("[Phase 7] Deleting bootstrap cluster...");
        self.delete_kind_cluster().await?;

        Ok(())
    }

    async fn bootstrap_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.bootstrap_kubeconfig_path()))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    async fn management_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.management_kubeconfig_path()))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    async fn create_kind_cluster(&self) -> Result<()> {
        let kind_config = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        tls-cipher-suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
"#;

        info!("Creating bootstrap cluster: {}", BOOTSTRAP_CLUSTER_NAME);

        let mut child = Command::new("kind")
            .args([
                "create",
                "cluster",
                "--name",
                BOOTSTRAP_CLUSTER_NAME,
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(kind_config.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "kind create cluster failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Export kubeconfig
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let export_output = Command::new("kind")
            .args([
                "export",
                "kubeconfig",
                "--name",
                BOOTSTRAP_CLUSTER_NAME,
                "--kubeconfig",
                bootstrap_kubeconfig.to_str().unwrap(),
            ])
            .output()
            .await?;

        if !export_output.status.success() {
            return Err(Error::command_failed(format!(
                "kind export kubeconfig failed: {}",
                String::from_utf8_lossy(&export_output.stderr)
            )));
        }

        // Wait for nodes using kube-rs
        let client = self.bootstrap_client().await?;
        kube_utils::wait_for_nodes_ready(&client, Duration::from_secs(120))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        Ok(())
    }

    async fn delete_kind_cluster(&self) -> Result<()> {
        let output = Command::new("kind")
            .args(["delete", "cluster", "--name", BOOTSTRAP_CLUSTER_NAME])
            .output()
            .await?;

        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "kind delete cluster failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    async fn deploy_lattice_operator(&self, client: &Client) -> Result<()> {
        let generator = DefaultManifestGenerator::new();
        let all_manifests = generator.generate(
            &self.config.image,
            self.config.registry_credentials.as_deref(),
            Some("lattice-installer"),
            None,
        );

        let provider_str = self.provider().to_string();
        let operator_manifests: Vec<String> = all_manifests
            .iter()
            .filter(|m: &&String| m.starts_with("{"))
            .map(|s| {
                if fips::is_deployment(s) {
                    let with_fips = fips::add_fips_relax_env(s);
                    let with_root = fips::add_root_install_env(&with_fips);
                    add_bootstrap_env(&with_root, &provider_str)
                } else {
                    s.to_string()
                }
            })
            .collect();

        for manifest in &operator_manifests {
            kube_utils::apply_manifest(client, manifest)
                .await
                .map_err(|e| Error::command_failed(e.to_string()))?;
        }

        info!("Waiting for Lattice operator to be ready...");
        kube_utils::wait_for_deployment(client, "lattice-operator", "lattice-system", Duration::from_secs(300))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        info!("Waiting for CAPI to be installed...");
        self.wait_for_capi_crds(client).await?;

        Ok(())
    }

    async fn wait_for_capi_crds(&self, client: &Client) -> Result<()> {
        let required_crds = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "clusterresourcesets.addons.cluster.x-k8s.io",
        ];

        for crd in required_crds {
            kube_utils::wait_for_crd(client, crd, Duration::from_secs(300))
                .await
                .map_err(|e| Error::command_failed(e.to_string()))?;
        }

        Ok(())
    }

    async fn create_bootstrap_crs(&self, client: &Client) -> Result<()> {
        let generator = DefaultManifestGenerator::new();
        let cluster_name = self.cluster_name();
        let provider_str = self.cluster.spec.provider.provider_type().to_string();
        let namespace = format!("capi-{}", cluster_name);

        let proxmox_ipv4_pool = self
            .cluster
            .spec
            .provider
            .config
            .proxmox
            .as_ref()
            .map(|p| &p.ipv4_pool);

        let config = ManifestConfig {
            image: &self.config.image,
            registry_credentials: self.config.registry_credentials.as_deref(),
            networking: self.cluster.spec.networking.as_ref(),
            proxmox_ipv4_pool,
            cluster_name: Some(cluster_name),
            provider: Some(&provider_str),
            parent_host: None,
            parent_grpc_port: lattice_operator::DEFAULT_GRPC_PORT,
            relax_fips: self
                .cluster
                .spec
                .provider
                .kubernetes
                .bootstrap
                .needs_fips_relax(),
        };

        let all_manifests = generate_all_manifests(&generator, &config);

        let capmox_credentials = if self.provider() == ProviderType::Proxmox {
            let (url, token, secret) = Self::get_proxmox_credentials()?;
            Some((url, token, secret))
        } else {
            None
        };

        let crs_manifests = generate_crs_yaml_manifests(
            cluster_name,
            &namespace,
            &all_manifests,
            capmox_credentials
                .as_ref()
                .map(|(u, t, s)| (u.as_str(), t.as_str(), s.as_str())),
        );

        kube_utils::create_namespace(client, &namespace)
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        for (i, manifest) in crs_manifests.iter().enumerate() {
            if i == crs_manifests.len() - 1 {
                kube_utils::apply_manifest_with_retry(client, manifest, Duration::from_secs(120))
                    .await
                    .map_err(|e| Error::command_failed(e.to_string()))?;
            } else {
                kube_utils::apply_manifest(client, manifest)
                    .await
                    .map_err(|e| Error::command_failed(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn create_management_cluster_crd(&self, client: &Client) -> Result<()> {
        kube_utils::apply_manifest_with_retry(client, &self.config.cluster_config_content, Duration::from_secs(120))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;
        self.create_bootstrap_crs(client).await?;
        Ok(())
    }

    async fn wait_for_management_cluster(&self, client: &Client) -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(600);
        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());

        // Wait for Ready/Pivoting phase
        loop {
            if start.elapsed() > timeout {
                return Err(Error::command_failed("Timeout waiting for cluster"));
            }

            let phase = get_latticecluster_phase(client, self.cluster_name()).await?;
            info!("Cluster phase: {}", if phase.is_empty() { "Pending" } else { &phase });

            match phase.as_str() {
                "Ready" | "Pivoting" => break,
                "Failed" => return Err(Error::command_failed("Cluster provisioning failed")),
                _ => tokio::time::sleep(Duration::from_secs(10)).await,
            }
        }

        // Wait for kubeconfig secret
        kube_utils::wait_for_secret(client, &secret_name, &namespace, timeout)
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        Ok(())
    }

    async fn apply_bootstrap_to_management(&self, bootstrap_client: &Client) -> Result<()> {
        let namespace = format!("capi-{}", self.cluster_name());
        let secret_name = format!("{}-kubeconfig", self.cluster_name());

        // Get kubeconfig from secret
        let kubeconfig_bytes = kube_utils::get_secret_data(bootstrap_client, &secret_name, &namespace, "value")
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        let mut kubeconfig = String::from_utf8(kubeconfig_bytes)
            .map_err(|e| Error::command_failed(format!("Invalid kubeconfig encoding: {}", e)))?;

        // Rewrite Docker provider kubeconfig to use localhost
        if self.cluster.spec.provider.provider_type() == ProviderType::Docker {
            let lb_container = format!("{}-lb", self.cluster_name());
            let port_output = Command::new("docker")
                .args(["port", &lb_container, "6443"])
                .output()
                .await?;

            if port_output.status.success() {
                let port_str = String::from_utf8_lossy(&port_output.stdout);
                if let Some(port) = port_str.trim().split(':').next_back() {
                    let localhost_url = format!("https://127.0.0.1:{}", port);
                    if let Some(start) = kubeconfig.find("server: https://") {
                        if let Some(end) = kubeconfig[start..].find('\n') {
                            let old_server = &kubeconfig[start..start + end];
                            kubeconfig = kubeconfig.replace(old_server, &format!("server: {}", localhost_url));
                        }
                    }
                }
            }
        }

        let kubeconfig_path = self.management_kubeconfig_path();
        tokio::fs::write(&kubeconfig_path, &kubeconfig).await?;

        // Wait for API server
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                return Err(Error::command_failed("Timeout waiting for API server"));
            }

            match self.management_client().await {
                Ok(client) => {
                    if kube_utils::wait_for_nodes_ready(&client, Duration::from_secs(5)).await.is_ok() {
                        break;
                    }
                }
                Err(_) => {}
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        let mgmt_client = self.management_client().await?;

        // Wait for nodes to be ready
        kube_utils::wait_for_nodes_ready(&mgmt_client, Duration::from_secs(300))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        // Install CAPI via clusterctl
        let init_args = self.clusterctl_init_args();
        let init_args_ref: Vec<&str> = init_args.iter().map(|s| s.as_str()).collect();
        self.run_clusterctl(&init_args_ref, &kubeconfig_path).await?;

        // Wait for CAPI controllers
        kube_utils::wait_for_all_deployments(&mgmt_client, "capi-system", Duration::from_secs(300))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        // Wait for Lattice operator
        kube_utils::wait_for_deployment(&mgmt_client, "lattice-operator", "lattice-system", Duration::from_secs(120))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        // Apply self-referential LatticeCluster CR
        kube_utils::apply_manifest_with_retry(&mgmt_client, &self.config.cluster_config_content, Duration::from_secs(120))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        Ok(())
    }

    fn get_proxmox_credentials() -> Result<(String, String, String)> {
        let url = std::env::var("PROXMOX_URL").map_err(|_| {
            Error::validation("PROXMOX_URL environment variable required for Proxmox provider")
        })?;
        let token = std::env::var("PROXMOX_TOKEN").map_err(|_| {
            Error::validation("PROXMOX_TOKEN environment variable required for Proxmox provider")
        })?;
        let secret = std::env::var("PROXMOX_SECRET").map_err(|_| {
            Error::validation("PROXMOX_SECRET environment variable required for Proxmox provider")
        })?;
        Ok((url, token, secret))
    }

    async fn create_capmox_credentials(&self, client: &Client) -> Result<()> {
        let (url, token, secret) = Self::get_proxmox_credentials()?;
        info!("PROXMOX_URL: {}", url);

        let manifests = capmox_credentials_manifests(&url, &token, &secret);
        kube_utils::apply_manifest_with_retry(client, &manifests, Duration::from_secs(30))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    async fn pivot_capi_resources(&self) -> Result<()> {
        let namespace = format!("capi-{}", self.cluster_name());
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let mgmt_kubeconfig = self.management_kubeconfig_path();
        let bootstrap_client = self.bootstrap_client().await?;

        // Wait for CAPI CRDs on target cluster
        info!("Waiting for CAPI CRDs on management cluster...");
        let mgmt_client = self.management_client().await?;
        kube_utils::wait_for_crd(&mgmt_client, "clusters.cluster.x-k8s.io", Duration::from_secs(300))
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        // Wait for all machines to be provisioned
        info!("Waiting for all machines to be provisioned...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(600) {
                return Err(Error::command_failed("Timeout waiting for machines to be provisioned"));
            }

            let phases = kube_utils::get_machine_phases(&bootstrap_client, &namespace)
                .await
                .map_err(|e| Error::command_failed(e.to_string()))?;

            let all_running = !phases.is_empty() && phases.iter().all(|p| p == "Running");
            if all_running {
                info!("All machines are Running");
                break;
            }
            info!("Machine phases: {}", phases.join(" "));

            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        // Export and import via clusterctl
        info!("Exporting CAPI resources from bootstrap cluster...");
        let manifests = export_for_pivot(Some(&bootstrap_kubeconfig), &namespace, self.cluster_name())
            .await
            .map_err(|e| Error::command_failed(e.to_string()))?;

        info!("Importing CAPI resources into management cluster...");
        import_from_manifests(Some(&mgmt_kubeconfig), &namespace, &manifests)
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    async fn run_clusterctl(&self, args: &[&str], kubeconfig: &Path) -> Result<()> {
        let mut command = Command::new("clusterctl");
        command
            .args(args)
            .env("KUBECONFIG", kubeconfig)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;

        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await? {
                info!("{}", line);
            }
        }

        let status = child.wait().await?;
        if !status.success() {
            return Err(Error::command_failed(format!(
                "clusterctl {} failed",
                args.join(" ")
            )));
        }

        Ok(())
    }
}

/// Get LatticeCluster phase using dynamic API
async fn get_latticecluster_phase(client: &Client, name: &str) -> Result<String> {
    use kube::api::{Api, DynamicObject};
    use kube::discovery::ApiResource;

    let ar = ApiResource {
        group: "lattice.io".to_string(),
        version: "v1alpha1".to_string(),
        kind: "LatticeCluster".to_string(),
        api_version: "lattice.io/v1alpha1".to_string(),
        plural: "latticeclusters".to_string(),
    };

    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    match api.get(name).await {
        Ok(cluster) => {
            let phase = cluster
                .data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .unwrap_or("Pending");
            Ok(phase.to_string())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok("Pending".to_string()),
        Err(e) => Err(Error::command_failed(format!(
            "Failed to get LatticeCluster {}: {}",
            name, e
        ))),
    }
}

/// Add bootstrap cluster environment variables to a deployment.
fn add_bootstrap_env(deployment_json: &str, provider: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(deployment_json) else {
        return deployment_json.to_string();
    };

    let Some(containers) = value
        .pointer_mut("/spec/template/spec/containers")
        .and_then(|c| c.as_array_mut())
    else {
        return deployment_json.to_string();
    };

    for container in containers {
        let Some(env) = container.as_object_mut().and_then(|c| {
            c.entry("env")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
        }) else {
            continue;
        };

        if !env
            .iter()
            .any(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER"))
        {
            env.push(serde_json::json!({"name": "LATTICE_BOOTSTRAP_CLUSTER", "value": "true"}));
        }

        if !env
            .iter()
            .any(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER"))
        {
            env.push(serde_json::json!({"name": "LATTICE_PROVIDER", "value": provider}));
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
}

pub async fn run(args: InstallArgs) -> Result<()> {
    let (config_path, config_content) = if let Some(ref config_file) = args.config_file {
        let content = tokio::fs::read_to_string(config_file).await?;
        (config_file.clone(), content)
    } else {
        let repo_path = get_repository(&args).await?;
        let cluster_yaml = repo_path.join("cluster.yaml");

        if !cluster_yaml.exists() {
            return Err(Error::NotLatticeRepo { path: repo_path });
        }

        let content = tokio::fs::read_to_string(&cluster_yaml).await?;
        (cluster_yaml, content)
    };

    let cluster: LatticeCluster = serde_yaml::from_str(&config_content)?;
    let cluster_name = cluster
        .metadata
        .name
        .as_ref()
        .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;
    let provider = cluster.spec.provider.provider_type();

    info!("Config file: {:?}", config_path);
    info!("Management cluster: {}", cluster_name);
    info!("Provider: {}", provider);
    info!(
        "Kubernetes version: {}",
        cluster.spec.provider.kubernetes.version
    );

    if args.dry_run {
        info!("Dry run - would perform the following:");
        info!("1. Create bootstrap kind cluster");
        info!("2. Install CAPI controllers");
        info!("3. Install Lattice operator");
        info!("4. Apply root cluster: {}", config_path.display());
        info!("5. Wait for cluster provisioning");
        info!("6. Pivot CAPI resources");
        info!("7. Delete bootstrap cluster");
        return Ok(());
    }

    let registry_credentials = if let Some(creds_path) = &args.registry_credentials_file {
        Some(tokio::fs::read_to_string(creds_path).await?)
    } else {
        None
    };

    let config = InstallConfig {
        cluster_config_content: config_content,
        image: args.image,
        keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        registry_credentials,
        bootstrap_override: args.bootstrap,
    };

    let installer = Installer::new(config)?;
    installer.run().await
}

async fn get_repository(args: &InstallArgs) -> Result<PathBuf> {
    if let Some(ref local_path) = args.local_path {
        if !local_path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Local path not found: {}", local_path.display()),
            )));
        }
        return Ok(local_path.clone());
    }

    if let Some(ref git_url) = args.git_repo {
        let temp_dir = tempfile::tempdir()?;
        let repo_path = temp_dir.path().to_path_buf();
        std::mem::forget(temp_dir);

        info!(url = git_url, "Cloning repository...");
        git::clone_repo(git_url, &repo_path, args.git_credentials.as_deref())?;
        git::checkout_branch(&repo_path, &args.git_branch)?;

        return Ok(repo_path);
    }

    Ok(PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_provider_rke2() {
        assert!(matches!(
            parse_bootstrap_provider("rke2"),
            Ok(BootstrapProvider::Rke2)
        ));
        assert!(matches!(
            parse_bootstrap_provider("RKE2"),
            Ok(BootstrapProvider::Rke2)
        ));
    }

    #[test]
    fn test_parse_bootstrap_provider_kubeadm() {
        assert!(matches!(
            parse_bootstrap_provider("kubeadm"),
            Ok(BootstrapProvider::Kubeadm)
        ));
        assert!(matches!(
            parse_bootstrap_provider("KUBEADM"),
            Ok(BootstrapProvider::Kubeadm)
        ));
    }

    #[test]
    fn test_parse_bootstrap_provider_invalid() {
        assert!(parse_bootstrap_provider("invalid").is_err());
    }

    #[test]
    fn test_add_bootstrap_env_adds_both_env_vars() {
        let deployment = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "lattice",
                            "image": "lattice:latest"
                        }]
                    }
                }
            }
        }"#;

        let result = add_bootstrap_env(deployment, "proxmox");
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .unwrap()
            .as_array()
            .unwrap();

        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER")
                && e.get("value").and_then(|v| v.as_str()) == Some("true")
        }));

        assert!(env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER")
                && e.get("value").and_then(|v| v.as_str()) == Some("proxmox")
        }));
    }

    #[test]
    fn test_add_bootstrap_env_idempotent() {
        let deployment = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "lattice",
                            "env": [
                                {"name": "LATTICE_BOOTSTRAP_CLUSTER", "value": "true"},
                                {"name": "LATTICE_PROVIDER", "value": "docker"}
                            ]
                        }]
                    }
                }
            }
        }"#;

        let result = add_bootstrap_env(deployment, "docker");
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .unwrap()
            .as_array()
            .unwrap();

        let bootstrap_count = env
            .iter()
            .filter(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_BOOTSTRAP_CLUSTER"))
            .count();
        assert_eq!(bootstrap_count, 1);

        let provider_count = env
            .iter()
            .filter(|e| e.get("name").and_then(|n| n.as_str()) == Some("LATTICE_PROVIDER"))
            .count();
        assert_eq!(provider_count, 1);
    }

    #[test]
    fn test_add_bootstrap_env_invalid_json() {
        let invalid = "not json";
        let result = add_bootstrap_env(invalid, "docker");
        assert_eq!(result, invalid);
    }
}
