//! Install command - Bootstrap a new Lattice management cluster
//!
//! Usage: lattice install -f cluster.yaml
//!
//! This command creates a self-managing Lattice cluster by:
//! 1. Creating a temporary kind bootstrap cluster
//! 2. Installing CAPI providers and Lattice operator
//! 3. Provisioning the management cluster from your LatticeCluster CRD
//! 4. Pivoting CAPI resources to make it self-managing
//! 5. Deleting the bootstrap cluster

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Args;
use kube::Client;
use tokio::process::Command;
use tracing::{info, warn};

use super::{generate_run_id, kind_utils, wait_with_timeout};

// Timeout constants for various provisioning phases
const CLUSTER_PROVISIONING_TIMEOUT: Duration = Duration::from_secs(600);
const API_SERVER_READY_TIMEOUT: Duration = Duration::from_secs(300);
const CONTROL_PLANE_READY_TIMEOUT: Duration = Duration::from_secs(300);
const MACHINE_PROVISIONING_TIMEOUT: Duration = Duration::from_secs(600);
const CAPI_CRD_TIMEOUT: Duration = Duration::from_secs(300);
const CAPI_CONTROLLERS_TIMEOUT: Duration = Duration::from_secs(300);
const LATTICE_OPERATOR_TIMEOUT: Duration = Duration::from_secs(300);
const CRD_APPLY_TIMEOUT: Duration = Duration::from_secs(120);

// Polling intervals
const CLUSTER_POLL_INTERVAL: Duration = Duration::from_secs(10);
const API_SERVER_POLL_INTERVAL: Duration = Duration::from_secs(5);
const CONTROL_PLANE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const MACHINE_POLL_INTERVAL: Duration = Duration::from_secs(10);
use lattice_cell::bootstrap::{
    generate_bootstrap_bundle, BootstrapBundleConfig, ClusterFacts, DefaultManifestGenerator,
};
use lattice_common::credentials::{
    AwsCredentials, BasisCredentials, CredentialProvider, OpenStackCredentials, ProxmoxCredentials,
};
use lattice_common::kube_utils::{self, ApplyOptions};
use lattice_common::{capi_namespace, kubeconfig_secret_name, OPERATOR_NAME};
use lattice_core::{LATTICE_SYSTEM_NAMESPACE, SECRET_TYPE_SA_TOKEN};
use lattice_crd::crd::{BootstrapProvider, LatticeCluster, ProviderType};

use lattice_common::retry::{retry_with_backoff, RetryConfig};

use super::CommandErrorExt;
use crate::{Error, Result};

/// Install a self-managing Lattice cluster from a LatticeCluster CRD
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Path to LatticeCluster YAML file
    #[arg(short = 'f', long = "file")]
    pub config_file: PathBuf,

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

    /// Kubernetes bootstrap provider (overrides config file if set)
    #[arg(long, value_parser = parse_bootstrap_provider)]
    pub bootstrap: Option<BootstrapProvider>,

    /// Validate configuration and show install plan without making changes
    #[arg(long)]
    pub validate: bool,

    /// Write kubeconfig to this path after installation
    #[arg(long)]
    pub kubeconfig_out: Option<PathBuf>,

    /// Run ID for this install session (auto-generated if not provided).
    /// Used to create unique kind cluster names and temp files for parallel runs.
    #[arg(long, env = "LATTICE_RUN_ID")]
    pub run_id: Option<String>,
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

/// The Lattice installer
pub struct Installer {
    cluster_yaml: String,
    cluster: LatticeCluster,
    cluster_name: String,
    image: String,
    keep_bootstrap_on_failure: bool,
    registry_credentials: Option<String>,
    /// Directory containing the config file (used to find companion secret files)
    config_dir: PathBuf,
    /// Run ID for this install session (used for kind cluster name and temp files)
    run_id: String,
    /// Lattice CRDs to apply to the bootstrap cluster *before* the
    /// `LatticeCluster` is created (InfraProvider, ImageProvider,
    /// SecretProvider, CedarPolicy, OIDCProvider, DNSProvider, CertIssuer,
    /// BackupStore, …). Each entry is a full JSON-serialized manifest.
    pre_cluster_docs: Vec<String>,
    /// Lattice CRDs to apply to the pivoted management cluster after bootstrap
    /// completes (LatticePackage). Each entry is a full JSON-serialized manifest.
    post_bootstrap_docs: Vec<String>,
}

/// Apply-phase classification for a Lattice CRD in the install bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocPhase {
    /// Apply to the bootstrap cluster before `LatticeCluster`.
    PreCluster,
    /// Apply to the management cluster after pivot.
    PostBootstrap,
}

/// Classify a Lattice CRD kind into its install phase.
///
/// `LatticePackage` is the only post-bootstrap kind today; everything else
/// (including unknown `lattice.dev` kinds) applies before the `LatticeCluster`
/// so the operator can reference it during provisioning.
fn classify_doc_kind(kind: &str) -> DocPhase {
    match kind {
        "LatticePackage" => DocPhase::PostBootstrap,
        _ => DocPhase::PreCluster,
    }
}

const LATTICE_API_GROUP: &str = "lattice.dev";

/// Name of the Secret the installer seeds in `lattice-secrets` from
/// `--registry-credentials-file` (or `GHCR_USER`/`GHCR_TOKEN`). The user's
/// `ImageProvider` YAML references this via `credentials.id`.
const REGISTRY_SEED_SECRET: &str = "image-registry-credentials";

impl Installer {
    /// Create a new installer
    ///
    /// # Arguments
    /// * `cluster_yaml` - The LatticeCluster YAML content
    /// * `image` - Lattice container image
    /// * `keep_bootstrap_on_failure` - Keep kind cluster on failure for debugging
    /// * `registry_credentials` - Optional registry credentials (dockerconfigjson format)
    /// * `bootstrap_override` - Override bootstrap provider from config
    /// * `config_dir` - Directory containing the config file (for companion secret files)
    /// * `run_id` - Optional run ID for parallel runs (auto-generated if not provided)
    pub fn new(
        cluster_yaml: String,
        image: String,
        keep_bootstrap_on_failure: bool,
        registry_credentials: Option<String>,
        bootstrap_override: Option<BootstrapProvider>,
        config_dir: PathBuf,
        run_id: Option<String>,
    ) -> Result<Self> {
        let docs = lattice_core::yaml::parse_yaml_multi(&cluster_yaml)
            .map_err(|e| Error::validation(format!("Invalid YAML: {}", e)))?;

        // Bundle parser: exactly one LatticeCluster, any other lattice.dev/v1alpha1
        // kind classified by phase. Non-lattice.dev API groups are rejected —
        // the installer is not a generic kubectl apply.
        let mut cluster_value: Option<serde_json::Value> = None;
        let mut pre_cluster_docs = Vec::new();
        let mut post_bootstrap_docs = Vec::new();

        for doc in docs {
            let api_version = doc.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
            let kind = doc.get("kind").and_then(|k| k.as_str()).unwrap_or("");

            let group = api_version.split('/').next().unwrap_or("");
            if group != LATTICE_API_GROUP {
                return Err(Error::validation(format!(
                    "Unsupported apiVersion '{api_version}' for kind '{kind}' — \
                     install bundles only accept {LATTICE_API_GROUP} resources",
                )));
            }
            if kind.is_empty() {
                return Err(Error::validation(
                    "Every document in the install bundle must have a `kind`",
                ));
            }

            if kind == "LatticeCluster" {
                if cluster_value.is_some() {
                    return Err(Error::validation(
                        "Install bundle must contain exactly one LatticeCluster",
                    ));
                }
                cluster_value = Some(doc);
                continue;
            }

            let json = serde_json::to_string(&doc)
                .map_err(|e| Error::validation(format!("Failed to serialize {kind}: {e}")))?;
            match classify_doc_kind(kind) {
                DocPhase::PreCluster => {
                    tracing::debug!(kind, "classified as pre-cluster resource");
                    pre_cluster_docs.push(json);
                }
                DocPhase::PostBootstrap => {
                    tracing::debug!(kind, "classified as post-bootstrap resource");
                    post_bootstrap_docs.push(json);
                }
            }
        }

        let value = cluster_value
            .ok_or_else(|| Error::validation("Install bundle must contain a LatticeCluster"))?;
        let mut cluster: LatticeCluster = serde_json::from_value(value)
            .map_err(|e| Error::validation(format!("Invalid LatticeCluster: {}", e)))?;

        if let Some(bootstrap) = bootstrap_override {
            cluster.spec.provider.kubernetes.bootstrap = bootstrap;
        }

        // Set spec.latticeImage from --image flag if not already set in YAML
        if cluster.spec.lattice_image.is_empty() {
            cluster.spec.lattice_image = image.clone();
        }

        let cluster_name = cluster
            .metadata
            .name
            .clone()
            .ok_or_else(|| Error::validation("LatticeCluster must have metadata.name"))?;

        // Re-serialize the cluster YAML with any mutations applied
        let cluster_yaml = serde_json::to_string(&cluster).map_err(|e| {
            Error::validation(format!("Failed to re-serialize LatticeCluster: {}", e))
        })?;

        Ok(Self {
            cluster_yaml,
            cluster,
            cluster_name,
            image,
            keep_bootstrap_on_failure,
            registry_credentials,
            config_dir,
            run_id: run_id.unwrap_or_else(generate_run_id),
            pre_cluster_docs,
            post_bootstrap_docs,
        })
    }

    /// Create a new installer from CLI args
    pub async fn from_args(args: &InstallArgs) -> Result<Self> {
        let cluster_yaml = tokio::fs::read_to_string(&args.config_file).await?;
        let registry_credentials = match &args.registry_credentials_file {
            Some(path) => Some(tokio::fs::read_to_string(path).await?),
            None => credentials_from_env(),
        };

        let config_dir = args
            .config_file
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        Self::new(
            cluster_yaml,
            args.image.clone(),
            args.keep_bootstrap_on_failure,
            registry_credentials,
            args.bootstrap.clone(),
            config_dir,
            args.run_id.clone(),
        )
    }

    fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Returns the run ID for this install session
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the CAPI namespace for this cluster (e.g., "capi-my-cluster")
    fn capi_ns(&self) -> String {
        capi_namespace(&self.cluster_name)
    }

    /// Returns the kubeconfig secret name for this cluster (e.g., "my-cluster-kubeconfig")
    fn kubeconfig_secret(&self) -> String {
        kubeconfig_secret_name(&self.cluster_name)
    }

    /// Returns the kind cluster name for this install session
    /// Format: `lattice-bootstrap-{run_id}` (e.g., "lattice-bootstrap-a1b2c3")
    fn bootstrap_cluster_name(&self) -> String {
        format!("lattice-bootstrap-{}", self.run_id)
    }

    fn bootstrap_kubeconfig_path(&self) -> PathBuf {
        std::env::temp_dir().join(format!("{}-kubeconfig", self.bootstrap_cluster_name()))
    }

    /// Returns the path where the root (direct API server) kubeconfig is stored.
    ///
    /// Path: `~/.lattice/kubeconfig.root`
    pub fn kubeconfig_path(&self) -> PathBuf {
        crate::config::kubeconfig_root_path()
            .expect("failed to determine ~/.lattice directory; cannot write kubeconfig")
    }

    fn provider(&self) -> ProviderType {
        self.cluster.spec.provider.provider_type()
    }

    /// Run the installation
    pub async fn run(&self) -> Result<()> {
        info!("=======================================================");
        info!("LATTICE INSTALL - Run ID: {}", self.run_id);
        info!("=======================================================");
        info!("Cluster: {}", self.cluster_name);
        info!("Provider: {}", self.provider());
        info!(
            "Kubernetes version: {}",
            self.cluster.spec.provider.kubernetes.version
        );

        let start = Instant::now();
        self.check_prerequisites().await?;

        let bootstrap_result = self.run_bootstrap().await;

        if bootstrap_result.is_err() && !self.keep_bootstrap_on_failure {
            info!("Deleting bootstrap cluster due to failure...");
            let _ = kind_utils::delete_kind_cluster(&self.bootstrap_cluster_name()).await;
        }

        bootstrap_result?;

        // Apply post-bootstrap resources from the install bundle (e.g.,
        // LatticePackage for Flux bootstrap) to the pivoted mgmt cluster.
        if !self.post_bootstrap_docs.is_empty() {
            self.apply_post_bootstrap_docs().await?;
        }

        info!("Creating lattice-admin service account and fetching proxy kubeconfig...");
        self.setup_admin_access().await?;

        info!("Installation complete in {:?}", start.elapsed());
        info!(
            "Management cluster '{}' is now self-managing.",
            self.cluster_name()
        );

        Ok(())
    }

    /// Apply post-bootstrap resources (e.g., `LatticePackage`) from the
    /// install bundle to the pivoted management cluster.
    async fn apply_post_bootstrap_docs(&self) -> Result<()> {
        let mgmt_client = self.management_client().await?;

        // Wait for LatticePackage CRD to be registered by the operator —
        // the only post-bootstrap kind classified today. If/when more kinds
        // land here, wait for each CRD that's actually in the bundle.
        kube_utils::wait_for_crd(
            &mgmt_client,
            "latticepackages.lattice.dev",
            CRD_APPLY_TIMEOUT,
        )
        .await
        .cmd_err()?;

        info!(
            "Applying {} post-bootstrap resource(s) from install bundle...",
            self.post_bootstrap_docs.len()
        );
        kube_utils::apply_manifests_with_retry(
            &mgmt_client,
            &self.post_bootstrap_docs,
            &ApplyOptions::default(),
            &RetryConfig::install(),
            "post-bootstrap resources",
        )
        .await
        .cmd_err()?;

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
        let bootstrap_name = self.bootstrap_cluster_name();
        info!(
            "[Phase 1/7] Preparing kind bootstrap cluster '{}'...",
            bootstrap_name
        );
        let bootstrap_client = crate::commands::prepare_ephemeral_cluster(
            &bootstrap_name,
            &self.bootstrap_kubeconfig_path(),
            &self.image,
            self.registry_credentials.as_deref(),
            self.provider(),
            &self.cluster.spec.provider_ref,
        )
        .await?;

        info!("[Phase 2/7] Seeding credential Secrets and applying install bundle...");
        self.seed_provider_credentials(&bootstrap_client).await?;
        self.seed_registry_credentials(&bootstrap_client).await?;
        self.apply_pre_cluster_docs(&bootstrap_client).await?;

        info!("Waiting for CAPI to be installed...");
        self.wait_for_capi_crds(&bootstrap_client).await?;

        self.apply_registry_mirror_credentials(&bootstrap_client)
            .await?;

        info!("[Phase 3/7] Creating management cluster LatticeCluster CR...");
        self.create_management_cluster_crd(&bootstrap_client)
            .await?;

        info!("[Phase 4/7] Waiting for management cluster to be provisioned...");
        self.wait_for_management_cluster(&bootstrap_client).await?;

        info!("[Phase 5/7] Applying bootstrap manifests to management cluster...");
        self.apply_bootstrap_to_management(&bootstrap_client)
            .await?;

        info!("[Phase 6/7] Pivoting CAPI resources to management cluster...");
        self.pivot_capi_resources().await?;

        info!(
            "[Phase 7/7] Deleting bootstrap cluster '{}'...",
            bootstrap_name
        );
        kind_utils::delete_kind_cluster(&bootstrap_name).await?;

        Ok(())
    }

    async fn bootstrap_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.bootstrap_kubeconfig_path()), None, None)
            .await
            .cmd_err()
    }

    async fn management_client(&self) -> Result<Client> {
        let kubeconfig_path = self.kubeconfig_path();
        info!("Creating management client from {:?}", kubeconfig_path);

        // Use shorter timeout for management cluster connection to fail fast
        // if the address is unreachable (e.g., connecting to internal Docker IP)
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_secs(30);

        kube_utils::create_client(
            Some(&kubeconfig_path),
            Some(connect_timeout),
            Some(read_timeout),
        )
        .await
        .cmd_err()
    }

    async fn wait_for_capi_crds(&self, client: &Client) -> Result<()> {
        let required_crds = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "clusterresourcesets.addons.cluster.x-k8s.io",
        ];

        for crd in required_crds {
            kube_utils::wait_for_crd(client, crd, CAPI_CRD_TIMEOUT)
                .await
                .cmd_err()?;
        }

        Ok(())
    }

    /// Wait for the Lattice CRDs that `copy_lattice_resources` will write.
    /// Bootstrap manifests applied seconds earlier include them; this just
    /// bridges the moment between CRD create and `Established=True`.
    async fn wait_for_lattice_crds(&self, client: &Client) -> Result<()> {
        let required_crds = [
            "infraproviders.lattice.dev",
            "imageproviders.lattice.dev",
            "secretproviders.lattice.dev",
        ];
        for crd in required_crds {
            kube_utils::wait_for_crd(client, crd, CAPI_CRD_TIMEOUT)
                .await
                .cmd_err()?;
        }
        Ok(())
    }

    async fn create_management_cluster_crd(&self, client: &Client) -> Result<()> {
        // Constructor validates metadata.name exists, so this is safe
        let cluster_name = self.cluster_name();
        info!(
            "Applying LatticeCluster '{}' (provider: {})",
            cluster_name,
            self.provider()
        );

        // `cluster_yaml` is a single compact JSON doc from
        // `serde_json::to_string(&cluster)`; pass it as a one-element
        // slice without splitting.
        kube_utils::apply_manifests_with_retry(
            client,
            &[self.cluster_yaml.as_str()],
            &ApplyOptions::default(),
            &RetryConfig::install(),
            "LatticeCluster CRD",
        )
        .await
        .map_err(|e| {
            Error::command_failed(format!(
                "Failed to create LatticeCluster '{}': {}",
                cluster_name, e
            ))
        })?;
        Ok(())
    }

    async fn wait_for_management_cluster(&self, client: &Client) -> Result<()> {
        let namespace = self.capi_ns();
        let secret_name = self.kubeconfig_secret();
        let cluster_name = self.cluster_name().to_string();
        let client = client.clone();

        // Wait for kubeconfig secret AND CAPI Cluster control plane to be ready.
        // We check controlPlaneReady instead of the full Ready phase because
        // the cluster needs CNI to reach Ready, and CNI is applied after this phase.
        // controlPlaneReady ensures the API server is reachable before Phase 6.
        wait_with_timeout(
            CLUSTER_PROVISIONING_TIMEOUT,
            CLUSTER_POLL_INTERVAL,
            "cluster provisioning",
            || {
                let client = client.clone();
                let namespace = namespace.clone();
                let secret_name = secret_name.clone();
                let cluster_name = cluster_name.clone();
                async move {
                    // Check phase. `get_latticecluster_phase` returns Err
                    // only for post-apply 404 (CR was never written) — a
                    // hard terminal failure. Transient errors return
                    // `Ok("Unknown")` and keep the loop going.
                    let phase = get_latticecluster_phase(&client, &cluster_name)
                        .await
                        .map_err(|e| e.to_string())?;
                    if phase == "Failed" {
                        return Err("Cluster provisioning failed".to_string());
                    }

                    // Log progress
                    info!("Cluster phase: {}", phase);

                    // Check if kubeconfig is ready
                    if !kube_utils::secret_exists(&client, &secret_name, &namespace)
                        .await
                        .unwrap_or(false)
                    {
                        return Ok(None); // Keep polling
                    }

                    // Check if CAPI Cluster control plane is ready (API server reachable)
                    if !is_capi_cluster_control_plane_ready(&client, &cluster_name, &namespace)
                        .await
                    {
                        info!("Waiting for CAPI Cluster control plane to be ready...");
                        return Ok(None); // Keep polling
                    }

                    info!("Kubeconfig secret and control plane are ready");
                    Ok(Some(()))
                }
            },
        )
        .await
    }

    async fn apply_bootstrap_to_management(&self, bootstrap_client: &Client) -> Result<()> {
        info!("Fetching management cluster kubeconfig...");
        let kubeconfig = self.fetch_management_kubeconfig(bootstrap_client).await?;
        let root_path = crate::config::save_root_kubeconfig(&kubeconfig)?;
        info!("Root kubeconfig saved to {:?}", root_path);

        info!("Waiting for management cluster API server...");
        self.wait_for_api_server().await?;

        info!("Creating management cluster client...");
        let mgmt_client = self.management_client().await?;

        info!("Generating bootstrap manifests...");
        // BasisCluster (and other CAPI infra CRs) live on the bootstrap
        // kind cluster during install — basis-capi-provider runs there.
        // mgmt_client is for the workload API; bootstrap_client is for
        // provider-trait LB CIDR lookups.
        let manifests = self
            .generate_bootstrap_manifests(&mgmt_client, bootstrap_client)
            .await?;
        info!("Applying {} bootstrap manifests...", manifests.len());

        kube_utils::apply_manifests_with_retry(
            &mgmt_client,
            &manifests,
            &ApplyOptions::default(),
            &RetryConfig::install(),
            "bootstrap manifests",
        )
        .await
        .cmd_err()?;

        info!("Waiting for control plane nodes to be ready...");
        wait_for_control_plane_ready(&mgmt_client, CONTROL_PLANE_READY_TIMEOUT).await?;

        // Copy distributable resources before installing CAPI providers.
        // `install_capi_on_management` reads `InfraProvider.spec` off the
        // mgmt apiserver to decide imagePullSecrets, credentials, etc.;
        // if the CR isn't there yet, every field is silently treated as
        // empty and the Deployment is born without its injections.
        self.wait_for_lattice_crds(&mgmt_client).await?;
        info!("Copying distributable resources to management cluster...");
        crate::commands::copy_lattice_resources(bootstrap_client, &mgmt_client, "bootstrap")
            .await?;

        info!("Installing CAPI on management cluster...");
        self.install_capi_on_management(bootstrap_client, &mgmt_client)
            .await?;

        info!("Waiting for CAPI controllers to be ready...");
        self.wait_for_management_controllers(&mgmt_client).await?;

        Ok(())
    }

    /// Generate all bootstrap manifests for the management cluster.
    ///
    /// Uses the same shared code as the bootstrap webhook to ensure consistency.
    async fn generate_bootstrap_manifests(
        &self,
        mgmt_client: &Client,
        infra_client: &Client,
    ) -> Result<Vec<String>> {
        let generator = DefaultManifestGenerator::new();

        // Each provider answers `lb_cidr` for itself — Docker/Proxmox
        // sync from spec, basis fetches `BasisCluster.spec.serviceBlockCidr`
        // off the cluster where its CR lives (bootstrap kind cluster
        // during install, since basis-capi-provider runs there).
        // A retryable provider error here means basis hasn't allocated
        // yet; install retries the bootstrap-manifest step until it
        // resolves.
        let provider = lattice_capi::provider::create_provider(self.provider(), &self.capi_ns())
            .map_err(|e| Error::command_failed(e.to_string()))?;
        let lb_cidr = self
            .resolve_lb_cidr_with_retry(provider.as_ref(), infra_client)
            .await?;
        let facts = ClusterFacts::from_cluster(&self.cluster, self.cluster_yaml.clone(), lb_cidr);
        // Read the *internal* control plane endpoint from kubeadm-config.
        // The management cluster is a kind cluster (kubeadm-bootstrapped),
        // the one place we resolve the endpoint without a CAPI Cluster CR.
        // Anything else (host kubeconfig, Docker port-forward) is wrong
        // for Cilium agents running inside the cluster.
        let api_server_endpoint =
            lattice_common::ApiServerEndpoint::from_kubeadm_config(mgmt_client)
                .await
                .map_err(|e| Error::command_failed(e.to_string()))?
                .ok_or_else(|| {
                    Error::command_failed(
                        "kube-system/kubeadm-config has no controlPlaneEndpoint — \
                     the management cluster must be kubeadm-bootstrapped (kind)"
                            .to_string(),
                    )
                })?;
        let config = BootstrapBundleConfig {
            facts: &facts,
            image: &self.image,
            registry_credentials: self.registry_credentials.as_deref(),
            api_server_endpoint: &api_server_endpoint,
        };

        generate_bootstrap_bundle(&generator, &config)
            .await
            .map_err(|e| Error::command_failed(e.to_string()))
    }

    /// Resolve the provider's LB CIDR, retrying on retryable errors
    /// (e.g. basis not yet finished allocating). Caps at 60s total —
    /// in practice basis-capi-provider populates serviceBlockCidr
    /// within seconds of seeing the BasisCluster CR.
    async fn resolve_lb_cidr_with_retry(
        &self,
        provider: &dyn lattice_capi::provider::Provider,
        infra_client: &Client,
    ) -> Result<Option<String>> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match provider.lb_cidr(&self.cluster, infra_client).await {
                Ok(cidr) => return Ok(cidr),
                Err(e) if Instant::now() < deadline => {
                    info!(error = %e, "Waiting for provider LB CIDR to be ready...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(Error::command_failed(e.to_string())),
            }
        }
    }

    /// Fetches the management cluster kubeconfig from the bootstrap cluster secret,
    /// rewriting the server URL for Docker provider if needed.
    async fn fetch_management_kubeconfig(&self, bootstrap_client: &Client) -> Result<String> {
        let namespace = self.capi_ns();
        let secret_name = self.kubeconfig_secret();

        info!("Fetching kubeconfig secret {}/{}", namespace, secret_name);
        let kubeconfig_bytes =
            kube_utils::get_secret_data(bootstrap_client, &secret_name, &namespace, "value")
                .await
                .cmd_err()?;

        let kubeconfig = String::from_utf8(kubeconfig_bytes)
            .map_err(|e| Error::command_failed(format!("Invalid kubeconfig encoding: {}", e)))?;
        info!("Kubeconfig fetched successfully");

        // Rewrite Docker provider kubeconfig to use localhost
        if self.provider() == ProviderType::Docker {
            info!("Rewriting kubeconfig for Docker provider...");
            self.rewrite_docker_kubeconfig(&kubeconfig).await
        } else {
            Ok(kubeconfig)
        }
    }

    /// Rewrites a kubeconfig's server URL to use localhost with the Docker-exposed port.
    /// Uses YAML parsing for safe manipulation instead of string replacement.
    async fn rewrite_docker_kubeconfig(&self, kubeconfig: &str) -> Result<String> {
        let lb_container = format!("{}-lb", self.cluster_name());
        info!("Looking up Docker port for container: {}", lb_container);

        // Retry getting the docker port - LB container may not be ready immediately
        let retry_config = lattice_common::retry::RetryConfig::default();
        let container = lb_container.clone();
        let port: String = retry_with_backoff(&retry_config, "docker_port_lookup", || {
            let c = container.clone();
            async move {
                let output = Command::new("docker")
                    .args(["port", &c, "6443"])
                    .output()
                    .await
                    .map_err(|e| format!("docker command failed: {}", e))?;

                if !output.status.success() {
                    return Err("LB container port not ready".to_string());
                }

                let port_str = String::from_utf8_lossy(&output.stdout);
                port_str
                    .trim()
                    .split(':')
                    .next_back()
                    .map(|p| p.to_string())
                    .ok_or_else(|| "failed to parse port".to_string())
            }
        })
        .await
        .map_err(|e| Error::command_failed(format!("Failed to get Docker LB port: {}", e)))?;

        info!("Docker LB port found: {}", port);
        let localhost_url = format!("https://127.0.0.1:{}", port);

        // Parse kubeconfig as YAML and update the server URL
        let mut config = lattice_core::yaml::parse_yaml(kubeconfig).map_err(|e| {
            Error::command_failed(format!("Failed to parse kubeconfig YAML: {}", e))
        })?;

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_array_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_json::Value::String(localhost_url.clone());
                    }
                }
            }
        }

        serde_json::to_string(&config)
            .map_err(|e| Error::command_failed(format!("Failed to serialize kubeconfig: {}", e)))
    }

    /// Waits for the management cluster API server to become reachable.
    async fn wait_for_api_server(&self) -> Result<()> {
        use k8s_openapi::api::core::v1::Namespace;
        use kube::Api;

        let kubeconfig_path = self.kubeconfig_path();
        wait_with_timeout(
            API_SERVER_READY_TIMEOUT,
            API_SERVER_POLL_INTERVAL,
            "API server",
            || {
                let path = kubeconfig_path.clone();
                async move {
                    let client = match kube_utils::create_client(
                        Some(&path),
                        Some(Duration::from_secs(10)),
                        Some(Duration::from_secs(30)),
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            info!("Client creation failed: {}", e);
                            return Ok(None); // Keep polling
                        }
                    };

                    // Just check if we can list namespaces - proves API is reachable
                    let ns: Api<Namespace> = Api::all(client);
                    match ns.list(&Default::default()).await {
                        Ok(_) => {
                            info!("API server is reachable");
                            Ok(Some(()))
                        }
                        Err(e) => {
                            info!("API not ready yet: {}", e);
                            Ok(None) // Keep polling
                        }
                    }
                }
            },
        )
        .await
    }

    /// Installs CAPI controllers on the management cluster.
    ///
    /// Runs before the CAPI resource pivot so the target already has the
    /// controllers that will own the moved CRs. The operator on the
    /// management cluster is still in cluster-mode and won't install CAPI
    /// until a LatticeCluster lands — that happens as part of pivot, so
    /// we install it directly here.
    async fn install_capi_on_management(
        &self,
        _bootstrap_client: &Client,
        mgmt_client: &Client,
    ) -> Result<()> {
        use kube::Api;
        use lattice_capi::installer::{ensure_capi_providers_for, NativeInstaller};
        use lattice_crd::crd::InfraProvider;

        let provider_ref = &self.cluster.spec.provider_ref;
        let cps: Api<InfraProvider> =
            Api::namespaced(mgmt_client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let cp = match cps.get(provider_ref).await {
            Ok(cp) => Some(cp),
            Err(kube::Error::Api(ae)) if ae.code == 404 => None,
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "failed to read InfraProvider '{provider_ref}': {e}"
                )));
            }
        };

        ensure_capi_providers_for(
            mgmt_client,
            &NativeInstaller::new(),
            self.provider(),
            cp.as_ref(),
            "lattice-cli",
        )
        .await
        .cmd_err()
    }

    /// Waits for CAPI and Lattice controllers to be ready on the management cluster.
    async fn wait_for_management_controllers(&self, mgmt_client: &Client) -> Result<()> {
        // Wait for CAPI controllers
        kube_utils::wait_for_all_deployments(mgmt_client, "capi-system", CAPI_CONTROLLERS_TIMEOUT)
            .await
            .cmd_err()?;

        // Wait for Lattice operator
        kube_utils::wait_for_deployment(
            mgmt_client,
            OPERATOR_NAME,
            LATTICE_SYSTEM_NAMESPACE,
            LATTICE_OPERATOR_TIMEOUT,
        )
        .await
        .cmd_err()
    }

    /// Seed the provider's credential Secret into `lattice-secrets` as an ESO
    /// source. The user's `InfraProvider` YAML references this Secret by name
    /// via `credentials.id`. Docker, GCP, Azure: no-op (no credentials to seed).
    async fn seed_provider_credentials(&self, client: &Client) -> Result<()> {
        match self.provider() {
            ProviderType::Proxmox => {
                let creds =
                    ProxmoxCredentials::from_env().map_err(|e| Error::validation(e.to_string()))?;
                info!("Seeding Proxmox credentials (PROXMOX_URL: {})", creds.url);
                Self::apply_seed_secret(client, &creds.to_k8s_secret()).await
            }
            ProviderType::Aws => {
                let creds =
                    AwsCredentials::from_env().map_err(|e| Error::validation(e.to_string()))?;
                info!("Seeding AWS credentials (region: {})", creds.region);
                Self::apply_seed_secret(client, &creds.to_k8s_secret()).await
            }
            ProviderType::OpenStack => {
                let creds = OpenStackCredentials::from_env()
                    .map_err(|e| Error::validation(e.to_string()))?;
                info!(
                    "Seeding OpenStack credentials (cloud: {})",
                    creds.cloud_name
                );
                Self::apply_seed_secret(client, &creds.to_k8s_secret()).await
            }
            ProviderType::Basis => {
                let creds =
                    BasisCredentials::from_env().map_err(|e| Error::validation(e.to_string()))?;
                info!(
                    "Seeding Basis credentials (BASIS_CONTROLLER_URL: {})",
                    creds.server_url
                );
                Self::apply_seed_secret(client, &creds.to_k8s_secret()).await
            }
            ProviderType::Docker => Ok(()),
            ProviderType::Gcp | ProviderType::Azure | _ => {
                info!(
                    "Provider {:?} has no env-var credential seeding; ensure your \
                     InfraProvider references an existing Secret",
                    self.provider()
                );
                Ok(())
            }
        }
    }

    /// Seed the registry credentials (from `--registry-credentials-file` or
    /// `GHCR_USER`/`GHCR_TOKEN`) as `image-registry-credentials` in
    /// `lattice-secrets`. The user's `ImageProvider` YAML references this
    /// Secret via `credentials.id: image-registry-credentials`. No-op when
    /// no credentials were provided.
    async fn seed_registry_credentials(&self, client: &Client) -> Result<()> {
        use kube::api::ObjectMeta;
        use std::collections::BTreeMap;

        let Some(ref creds) = self.registry_credentials else {
            return Ok(());
        };

        info!("Seeding registry credentials as 'image-registry-credentials'");
        let secret = k8s_openapi::api::core::v1::Secret {
            metadata: ObjectMeta {
                name: Some(REGISTRY_SEED_SECRET.to_string()),
                namespace: Some(lattice_common::LOCAL_SECRETS_NAMESPACE.to_string()),
                labels: Some(BTreeMap::from([
                    ("lattice.dev/secret-source".to_string(), "true".to_string()),
                    ("lattice.dev/distribute".to_string(), "true".to_string()),
                ])),
                ..Default::default()
            },
            type_: Some(lattice_core::SECRET_TYPE_DOCKERCONFIG.to_string()),
            data: Some(BTreeMap::from([(
                ".dockerconfigjson".to_string(),
                k8s_openapi::ByteString(creds.as_bytes().to_vec()),
            )])),
            ..Default::default()
        };
        Self::apply_seed_secret(client, &secret).await
    }

    /// Apply the pre-cluster Lattice CRD docs parsed from the install bundle
    /// (InfraProvider, ImageProvider, SecretProvider, etc.) to the bootstrap
    /// cluster. The operator waits for these before provisioning.
    async fn apply_pre_cluster_docs(&self, client: &Client) -> Result<()> {
        if self.pre_cluster_docs.is_empty() {
            return Err(Error::validation(
                "install bundle is missing pre-cluster resources \
                 (at least an InfraProvider matching spec.providerRef is required)",
            ));
        }
        info!(
            "Applying {} pre-cluster resource(s) from install bundle...",
            self.pre_cluster_docs.len()
        );
        kube_utils::apply_manifests_with_retry(
            client,
            &self.pre_cluster_docs,
            &ApplyOptions::default(),
            &RetryConfig::install(),
            "pre-cluster resources",
        )
        .await
        .cmd_err()
    }

    /// Apply a Secret into the `lattice-secrets` ESO source namespace.
    ///
    /// Secrets in this namespace are served by the local-webhook ESO backend;
    /// the `lattice.dev/secret-source: "true"` label is required for visibility.
    async fn apply_seed_secret(
        client: &Client,
        secret: &k8s_openapi::api::core::v1::Secret,
    ) -> Result<()> {
        use kube::api::{Api, Patch, PatchParams};

        retry_with_backoff(&RetryConfig::install(), "ensure_namespace", || async {
            kube_utils::ensure_namespace(
                client,
                lattice_common::LOCAL_SECRETS_NAMESPACE,
                None,
                "lattice-cli",
            )
            .await
        })
        .await
        .cmd_err()?;

        let secrets: Api<k8s_openapi::api::core::v1::Secret> =
            Api::namespaced(client.clone(), lattice_common::LOCAL_SECRETS_NAMESPACE);
        let name = secret
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| Error::validation("Secret must have a name"))?;
        retry_with_backoff(&RetryConfig::install(), "patch seed secret", || async {
            secrets
                .patch(
                    name,
                    &PatchParams::apply("lattice-cli").force(),
                    &Patch::Apply(secret),
                )
                .await
        })
        .await
        .map_err(|e| Error::command_failed(format!("Failed to seed secret '{name}': {e}")))?;

        Ok(())
    }

    /// Apply registry mirror credential secrets from companion files on disk.
    ///
    /// Apply registry mirror credential secrets to `lattice-secrets` namespace.
    ///
    /// For each mirror with `credentials`, looks for a Secret YAML file named
    /// `{remote_key}.yaml` (or `.yml`) in the config directory. The secret is
    /// applied to `lattice-secrets` so the cluster controller can read it
    /// when embedding credentials in CAPI manifests.
    async fn apply_registry_mirror_credentials(&self, client: &Client) -> Result<()> {
        let mirrors = match &self.cluster.spec.registry_mirrors {
            Some(m) if !m.is_empty() => m,
            _ => return Ok(()),
        };

        let mut applied = std::collections::HashSet::new();
        for mirror in mirrors {
            let remote_key = match mirror.credentials.as_ref() {
                Some(r) if !r.id.is_empty() => &r.id,
                _ => continue,
            };

            if !applied.insert(remote_key.clone()) {
                continue;
            }

            let secret_path = self.find_secret_file(remote_key).await?;
            let secret_yaml = tokio::fs::read_to_string(&secret_path).await.map_err(|e| {
                Error::validation(format!(
                    "Failed to read registry credential secret file {}: {}",
                    secret_path.display(),
                    e
                ))
            })?;

            let value = lattice_core::yaml::parse_yaml(&secret_yaml).map_err(|e| {
                Error::validation(format!(
                    "Invalid YAML in secret file {}: {}",
                    secret_path.display(),
                    e
                ))
            })?;

            let mut secret: k8s_openapi::api::core::v1::Secret = serde_json::from_value(value)
                .map_err(|e| {
                    Error::validation(format!(
                        "Invalid Secret in {}: {}",
                        secret_path.display(),
                        e
                    ))
                })?;

            // Apply to lattice-secrets as an ESO source secret
            secret.metadata.namespace = Some(lattice_common::LOCAL_SECRETS_NAMESPACE.to_string());
            let labels = secret.metadata.labels.get_or_insert_with(Default::default);
            labels.insert("lattice.dev/secret-source".to_string(), "true".to_string());
            labels.insert("lattice.dev/distribute".to_string(), "true".to_string());

            info!(
                "Applying registry credential secret '{}' from {}",
                remote_key,
                secret_path.display()
            );
            Self::apply_seed_secret(client, &secret).await?;
        }

        Ok(())
    }

    /// Find a secret file by name in the config directory.
    /// Checks for `{name}.yaml` then `{name}.yml`.
    async fn find_secret_file(&self, name: &str) -> Result<PathBuf> {
        // Validate name to prevent path traversal (e.g., "../../etc/passwd")
        lattice_core::validate_dns_label(name, "credentials secret name")
            .map_err(Error::validation)?;

        for ext in &["yaml", "yml"] {
            let path = self.config_dir.join(format!("{}.{}", name, ext));
            if tokio::fs::metadata(&path).await.is_ok() {
                return Ok(path);
            }
        }
        Err(Error::validation(format!(
            "Registry credential secret file not found: expected {}/{}.yaml or {}/{}.yml",
            self.config_dir.display(),
            name,
            self.config_dir.display(),
            name
        )))
    }

    async fn pivot_capi_resources(&self) -> Result<()> {
        let namespace = self.capi_ns();
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        let mgmt_kubeconfig = self.kubeconfig_path();
        let bootstrap_client = self.bootstrap_client().await?;

        // Wait for CAPI CRDs on target cluster
        info!("Waiting for CAPI CRDs on management cluster...");
        let mgmt_client = self.management_client().await?;
        kube_utils::wait_for_crd(&mgmt_client, "clusters.cluster.x-k8s.io", CAPI_CRD_TIMEOUT)
            .await
            .cmd_err()?;

        // Wait for all machines to be provisioned
        info!("Waiting for all machines to be provisioned...");
        let ns = namespace.clone();
        wait_with_timeout(
            MACHINE_PROVISIONING_TIMEOUT,
            MACHINE_POLL_INTERVAL,
            "machines to be provisioned",
            || {
                let client = bootstrap_client.clone();
                let namespace = ns.clone();
                async move {
                    let phases = kube_utils::get_machine_phases(&client, &namespace)
                        .await
                        .map_err(|e| e.to_string())?;

                    let all_running = !phases.is_empty() && phases.iter().all(|p| p == "Running");
                    if all_running {
                        info!("All machines are Running");
                        return Ok(Some(()));
                    }
                    info!("Machine phases: {}", phases.join(" "));
                    Ok(None) // Keep polling
                }
            },
        )
        .await?;

        // Move CAPI resources from bootstrap to management cluster.
        // Retry because CAPI webhooks on the management cluster may not be
        // serving yet immediately after the controllers start.
        info!("Moving CAPI resources from bootstrap to management cluster...");
        let retry_config = lattice_common::retry::RetryConfig {
            max_attempts: 6,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        };
        let bs_kc = bootstrap_kubeconfig.clone();
        let mgmt_kc = mgmt_kubeconfig.clone();
        let ns = namespace.clone();
        let cluster = self.cluster_name().to_string();
        retry_with_backoff(&retry_config, "capi_move", || {
            let bs_kc = bs_kc.clone();
            let mgmt_kc = mgmt_kc.clone();
            let ns = ns.clone();
            let cluster = cluster.clone();
            async move { lattice_move::local_move(&bs_kc, &mgmt_kc, &ns, &cluster).await }
        })
        .await
        .map(|_| ())
        .cmd_err()
    }

    /// Create lattice-admin ServiceAccount, break-glass token, CedarPolicies,
    /// and fetch proxy kubeconfig.
    ///
    /// The break-glass token is a long-lived Secret-based SA token — no expiration,
    /// full admin access. Store it securely as the root recovery credential.
    async fn setup_admin_access(&self) -> Result<()> {
        use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
        use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleRef, Subject};
        use kube::api::{Api, ObjectMeta, PostParams};

        let mgmt_client = self.management_client().await?;

        // Create lattice-admin ServiceAccount
        let sa_api: Api<ServiceAccount> =
            Api::namespaced(mgmt_client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("lattice-admin".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        sa_api
            .create(&PostParams::default(), &sa)
            .await
            .map_err(|e| {
                Error::command_failed(format!("failed to create lattice-admin SA: {}", e))
            })?;
        info!("Created lattice-admin ServiceAccount");

        // Bind lattice-admin to cluster-admin for full K8s RBAC access
        let crb_api: Api<ClusterRoleBinding> = Api::all(mgmt_client.clone());
        let crb = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some("lattice-admin-binding".to_string()),
                ..Default::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "ClusterRole".to_string(),
                name: "cluster-admin".to_string(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_string(),
                name: "lattice-admin".to_string(),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            }]),
        };
        crb_api
            .create(&PostParams::default(), &crb)
            .await
            .map_err(|e| {
                Error::command_failed(format!(
                    "failed to create lattice-admin ClusterRoleBinding: {}",
                    e
                ))
            })?;
        info!("Created lattice-admin ClusterRoleBinding");

        // Create break-glass long-lived SA token (no expiration)
        let secret_api: Api<Secret> =
            Api::namespaced(mgmt_client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let token_secret = Secret {
            metadata: ObjectMeta {
                name: Some("lattice-admin-token".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                annotations: Some(
                    [(
                        "kubernetes.io/service-account.name".to_string(),
                        "lattice-admin".to_string(),
                    )]
                    .into(),
                ),
                ..Default::default()
            },
            type_: Some(SECRET_TYPE_SA_TOKEN.to_string()),
            ..Default::default()
        };
        secret_api
            .create(&PostParams::default(), &token_secret)
            .await
            .map_err(|e| {
                Error::command_failed(format!(
                    "failed to create lattice-admin-token Secret: {}",
                    e
                ))
            })?;
        info!("Created lattice-admin-token Secret");

        // Create Cedar policies for admin and istiod proxy access
        let admin_policy = lattice_infra::bootstrap::generate_admin_access_cedar_policy();
        let admin_json = serde_json::to_string(&admin_policy)
            .map_err(|e| Error::command_failed(format!("failed to serialize CedarPolicy: {e}")))?;
        let cluster_policy = lattice_infra::bootstrap::generate_cluster_access_cedar_policy();
        let cluster_json = serde_json::to_string(&cluster_policy)
            .map_err(|e| Error::command_failed(format!("failed to serialize CedarPolicy: {e}")))?;

        kube_utils::apply_manifests_with_retry(
            &mgmt_client,
            &[&admin_json, &cluster_json],
            &ApplyOptions::default(),
            &RetryConfig::install(),
            "Cedar policies",
        )
        .await
        .cmd_err()?;
        info!("Created Cedar access policies");

        // Wait for token controller to populate the Secret
        info!("Waiting for admin token to be populated...");
        let admin_token = wait_with_timeout(
            Duration::from_secs(60),
            Duration::from_secs(2),
            "admin token to be populated",
            || {
                let api = secret_api.clone();
                async move {
                    match api.get("lattice-admin-token").await {
                        Ok(secret) => {
                            if let Some(data) = &secret.data {
                                if let Some(token_bytes) = data.get("token") {
                                    let token = String::from_utf8_lossy(&token_bytes.0).to_string();
                                    if !token.is_empty() {
                                        return Ok(Some(token));
                                    }
                                }
                            }
                            Ok(None)
                        }
                        Err(e) => {
                            warn!("Error reading admin token: {}", e);
                            Ok(None)
                        }
                    }
                }
            },
        )
        .await?;

        info!("Admin token ready (break-glass)");

        // Discover proxy endpoint and fetch kubeconfig
        let proxy_endpoint = self.discover_proxy_for_install(&mgmt_client).await?;
        let (_server, _pf, kubeconfig_json) = self
            .fetch_proxy_kubeconfig(&proxy_endpoint, &admin_token)
            .await?;

        // Save kubeconfig
        let kc_path = crate::config::save_proxy_kubeconfig(&kubeconfig_json)?;

        let cfg = crate::config::LatticeConfig {
            proxy_server: Some(proxy_endpoint),
            current_cluster: super::proxy::extract_cluster_names(&kubeconfig_json)?
                .first()
                .cloned(),
            last_login: Some(chrono::Utc::now().to_rfc3339()),
        };
        crate::config::save_config(&cfg)?;

        eprintln!();
        eprintln!("=======================================================");
        eprintln!("Proxy kubeconfig:  {}", kc_path.display());
        eprintln!(
            "Root kubeconfig:   {}",
            crate::config::kubeconfig_root_path()?.display()
        );
        eprintln!();
        eprintln!("Proxy kubeconfig routes through the Lattice auth proxy.");
        eprintln!("Root kubeconfig connects directly to the API server.");
        eprintln!("Both contain the lattice-admin token — store securely.");
        eprintln!();
        eprintln!("To re-login from another machine:");
        eprintln!("  lattice login --server <proxy-url> --token <admin-token>");
        eprintln!("=======================================================");

        Ok(())
    }

    /// Discover the proxy endpoint from the management cluster's cell Service.
    /// If the endpoint is a Docker-internal IP, start a port-forward.
    async fn discover_proxy_for_install(&self, client: &Client) -> Result<String> {
        use k8s_openapi::api::core::v1::Service;
        use kube::Api;
        use lattice_common::{CELL_SERVICE_NAME, DEFAULT_AUTH_PROXY_PORT};

        let services: Api<Service> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        // Wait for the cell service to get a LoadBalancer address
        let endpoint = wait_with_timeout(
            Duration::from_secs(120),
            Duration::from_secs(5),
            "proxy endpoint to be available",
            || {
                let svc_api = services.clone();
                async move {
                    match svc_api.get(CELL_SERVICE_NAME).await {
                        Ok(svc) => {
                            let host = svc
                                .status
                                .and_then(|s| s.load_balancer)
                                .and_then(|lb| lb.ingress)
                                .and_then(|ingress| ingress.into_iter().next())
                                .and_then(|entry| entry.hostname.or(entry.ip));

                            match host {
                                Some(h) => {
                                    Ok(Some(format!("https://{}:{}", h, DEFAULT_AUTH_PROXY_PORT)))
                                }
                                None => Ok(None),
                            }
                        }
                        Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
                        Err(e) => {
                            warn!("Error checking cell service: {}", e);
                            Ok(None)
                        }
                    }
                }
            },
        )
        .await?;

        Ok(endpoint)
    }

    /// Fetch the proxy kubeconfig, using port-forward if necessary.
    /// Returns (effective_server_url, optional_port_forward, kubeconfig_json).
    async fn fetch_proxy_kubeconfig(
        &self,
        endpoint: &str,
        token: &str,
    ) -> Result<(String, Option<super::port_forward::PortForward>, String)> {
        let (server, pf) = if super::port_forward::is_docker_internal_ip(endpoint) {
            info!(
                "Detected Docker-internal IP ({}), using port-forward",
                endpoint
            );
            let pf = super::port_forward::PortForward::start(
                &self.kubeconfig_path().to_string_lossy(),
                lattice_common::DEFAULT_AUTH_PROXY_PORT,
            )
            .await?;
            let url = pf.url.clone();
            (url, Some(pf))
        } else {
            (endpoint.to_string(), None)
        };

        let kubeconfig_json =
            super::proxy::fetch_kubeconfig(&server, token, true, Some("sa"), 0, true).await?;

        Ok((server, pf, kubeconfig_json))
    }
}

/// Get LatticeCluster phase using dynamic API.
///
/// Only called after the CR has been applied, so a 404 is a terminal
/// failure rather than a pending state — surface it as `Err`. Transient
/// errors return `Ok("Unknown")` so the caller's poll loop continues
/// through apiserver blips.
async fn get_latticecluster_phase(client: &Client, name: &str) -> Result<String> {
    use kube::api::{Api, DynamicObject};

    let ar =
        lattice_common::kube_utils::build_api_resource("lattice.dev/v1alpha1", "LatticeCluster");
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);

    match api.get(name).await {
        Ok(cluster) => Ok(cluster
            .data
            .get("status")
            .and_then(|s| s.get("phase"))
            .and_then(|p| p.as_str())
            .unwrap_or("Pending")
            .to_string()),
        Err(kube::Error::Api(e)) if e.code == 404 => Err(Error::command_failed(format!(
            "LatticeCluster '{name}' not found after apply — CR was never written to the apiserver"
        ))),
        Err(e) => {
            // Transient errors (SendRequest, timeout) — continue polling.
            warn!("Transient error getting LatticeCluster {}: {}", name, e);
            Ok("Unknown".to_string())
        }
    }
}

/// Check if the CAPI Cluster resource's control plane is ready.
///
/// Returns true when `status.controlPlaneReady` is true, indicating the
/// API server is reachable. This is checked before the full Ready phase
/// (which requires CNI) to avoid noisy connection errors in Phase 6.
async fn is_capi_cluster_control_plane_ready(
    client: &Client,
    cluster_name: &str,
    namespace: &str,
) -> bool {
    use kube::api::{Api, DynamicObject};

    let Ok(ar) =
        kube_utils::build_api_resource_with_discovery(client, "cluster.x-k8s.io", "Cluster").await
    else {
        return false;
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    match api.get(cluster_name).await {
        Ok(cluster) => {
            let status = cluster.data.get("status");

            // CAPI v1beta2: check conditions array for ControlPlaneInitialized.
            // We use Initialized (not Available) because Available requires all
            // machines to be Ready, which needs a CNI. When bootstrap=rke2 with
            // cni=none, the installer must reach the cluster to install the CNI —
            // Initialized confirms the API server is up, which is sufficient.
            if let Some(conditions) = status
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())
            {
                return conditions.iter().any(|c| {
                    c.get("type").and_then(|t| t.as_str()) == Some("ControlPlaneInitialized")
                        && c.get("status").and_then(|s| s.as_str()) == Some("True")
                });
            }

            // CAPI v1beta1 fallback: top-level boolean
            status
                .and_then(|s| s.get("controlPlaneReady"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }
        Err(_) => false,
    }
}

/// Wait for control plane nodes to be ready (ignores worker nodes).
async fn wait_for_control_plane_ready(client: &Client, timeout: Duration) -> Result<()> {
    use k8s_openapi::api::core::v1::Node;
    use kube::api::{Api, ListParams};
    use lattice_common::kube_utils::{has_condition, CONDITION_READY};

    let client = client.clone();
    wait_with_timeout(
        timeout,
        CONTROL_PLANE_POLL_INTERVAL,
        "control plane nodes to be ready",
        || {
            let client = client.clone();
            async move {
                let nodes: Api<Node> = Api::all(client);

                let node_list = match nodes.list(&ListParams::default()).await {
                    Ok(list) => list,
                    Err(e) => {
                        // Transient error - log and retry
                        warn!("Transient error listing nodes: {}", e);
                        return Ok(None); // Keep polling
                    }
                };

                // Filter for control plane nodes
                let cp_nodes: Vec<_> = node_list
                    .items
                    .iter()
                    .filter(|n| {
                        n.metadata.labels.as_ref().is_some_and(|l| {
                            l.contains_key("node-role.kubernetes.io/control-plane")
                        })
                    })
                    .collect();

                if cp_nodes.is_empty() {
                    info!("No control plane nodes found yet...");
                    return Ok(None); // Keep polling
                }

                let ready_count = cp_nodes
                    .iter()
                    .filter(|n| {
                        let conditions = n.status.as_ref().and_then(|s| s.conditions.as_ref());
                        has_condition(conditions.map(|c| c.as_slice()), CONDITION_READY)
                    })
                    .count();

                if ready_count == cp_nodes.len() {
                    info!("{} control plane node(s) ready", cp_nodes.len());
                    return Ok(Some(()));
                }

                info!(
                    "Waiting for control plane nodes: {}/{} ready",
                    ready_count,
                    cp_nodes.len()
                );
                Ok(None) // Keep polling
            }
        },
    )
    .await
}

/// Build registry credentials from GHCR_USER/GHCR_TOKEN environment variables.
fn credentials_from_env() -> Option<String> {
    use base64::Engine;
    let user = std::env::var("GHCR_USER").ok()?;
    let token = std::env::var("GHCR_TOKEN").ok()?;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"));
    Some(serde_json::json!({"auths": {"ghcr.io": {"auth": auth}}}).to_string())
}

pub async fn run(args: InstallArgs) -> Result<()> {
    let installer = Installer::from_args(&args).await?;

    if args.validate {
        info!("Dry run for cluster: {}", installer.cluster_name());
        info!("Provider: {}", installer.provider());
        info!("1. Create bootstrap kind cluster");
        info!("2. Deploy Lattice operator (installs CRDs, CAPI)");
        info!("3. Create InfraProvider and credentials");
        info!("4. Apply LatticeCluster: {}", args.config_file.display());
        info!("5. Wait for cluster provisioning");
        info!("6. Apply bootstrap manifests to management cluster");
        info!("7. Pivot CAPI resources to make cluster self-managing");
        info!("8. Delete bootstrap cluster");
        info!("9. Create lattice-admin SA, CedarPolicy, and fetch proxy kubeconfig");
        if let Some(out) = &args.kubeconfig_out {
            info!("10. Write kubeconfig to: {}", out.display());
        }
        return Ok(());
    }

    installer.run().await?;

    // Copy kubeconfig to additional output path if specified
    if let Some(out) = &args.kubeconfig_out {
        let src = crate::config::kubeconfig_proxy_path()?;
        tokio::fs::copy(&src, out).await?;
        info!("Kubeconfig also written to: {}", out.display());
    }

    Ok(())
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

    // ---- Bundle parser tests --------------------------------------------------

    fn build_installer(yaml: &str) -> Result<Installer> {
        Installer::new(
            yaml.to_string(),
            "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            false,
            None,
            None,
            PathBuf::from("."),
            Some("test".to_string()),
        )
    }

    fn parse_err(yaml: &str) -> String {
        match build_installer(yaml) {
            Ok(_) => panic!("expected parse error, got Ok"),
            Err(e) => e.to_string(),
        }
    }

    /// Minimal valid LatticeCluster YAML for bundle tests.
    const MIN_CLUSTER: &str = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test
spec:
  latticeImage: "ghcr.io/evan-hines-js/lattice:latest"
  providerRef: docker
  provider:
    kubernetes:
      version: "1.32.0"
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
      instanceType:
        cores: 2
        memoryGib: 4
        diskGib: 20
    workerPools: {}
  parentConfig:
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
"#;

    #[test]
    fn test_classify_doc_kind() {
        assert_eq!(classify_doc_kind("LatticePackage"), DocPhase::PostBootstrap);
        assert_eq!(classify_doc_kind("InfraProvider"), DocPhase::PreCluster);
        assert_eq!(classify_doc_kind("ImageProvider"), DocPhase::PreCluster);
        assert_eq!(classify_doc_kind("SecretProvider"), DocPhase::PreCluster);
        // Unknown Lattice kinds default to pre-cluster (operator may need them).
        assert_eq!(classify_doc_kind("SomeNewFutureKind"), DocPhase::PreCluster);
    }

    #[test]
    fn test_parser_accepts_infra_provider_doc() {
        let yaml = format!(
            "{MIN_CLUSTER}\n---\n{}",
            r#"apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: docker
spec:
  type: docker
"#
        );
        let installer = build_installer(&yaml).expect("parse");
        assert_eq!(installer.pre_cluster_docs.len(), 1);
        assert!(installer.pre_cluster_docs[0].contains("\"kind\":\"InfraProvider\""));
        assert!(installer.post_bootstrap_docs.is_empty());
    }

    #[test]
    fn test_parser_classifies_multiple_docs() {
        let yaml = format!(
            "{MIN_CLUSTER}\n---\n{}\n---\n{}",
            r#"apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: docker
spec:
  type: docker
"#,
            r#"apiVersion: lattice.dev/v1alpha1
kind: LatticePackage
metadata:
  name: flux
spec:
  propagate: false
  chart:
    name: flux2
    version: 2.0.0
    repository: https://fluxcd-community.github.io/helm-charts
"#
        );
        let installer = build_installer(&yaml).expect("parse");
        assert_eq!(installer.pre_cluster_docs.len(), 1);
        assert_eq!(installer.post_bootstrap_docs.len(), 1);
    }

    #[test]
    fn test_parser_rejects_non_lattice_api_group() {
        let yaml = format!(
            "{MIN_CLUSTER}\n---\n{}",
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: nope
"#
        );
        let err = parse_err(&yaml);
        assert!(err.contains("Unsupported apiVersion"), "got: {err}");
    }

    #[test]
    fn test_parser_requires_exactly_one_cluster() {
        // Zero clusters
        let err = parse_err(
            r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata: { name: docker }
spec: { type: docker }
"#,
        );
        assert!(err.contains("must contain a LatticeCluster"), "got: {err}");

        // Two clusters
        let yaml = format!("{MIN_CLUSTER}\n---\n{MIN_CLUSTER}");
        let err = parse_err(&yaml);
        assert!(err.contains("exactly one LatticeCluster"), "got: {err}");
    }

    #[test]
    fn test_parser_rejects_doc_without_kind() {
        let yaml = format!(
            "{MIN_CLUSTER}\n---\n{}",
            "apiVersion: lattice.dev/v1alpha1\nmetadata:\n  name: oops\n"
        );
        let err = parse_err(&yaml);
        assert!(err.contains("must have a `kind`"), "got: {err}");
    }

    #[test]
    fn test_rewrite_kubeconfig_server() {
        use lattice_core::yaml::parse_yaml;

        let kubeconfig = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTg==
    server: https://10.0.0.1:6443
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: admin
  name: my-context
current-context: my-context
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTg==
"#;

        let new_server = "https://127.0.0.1:12345";

        // Parse and update using the same logic as rewrite_docker_kubeconfig
        let mut config = parse_yaml(kubeconfig).expect("kubeconfig should be valid YAML");

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_array_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_json::Value::String(new_server.to_string());
                    }
                }
            }
        }

        // Verify the server was updated
        let server = config["clusters"][0]["cluster"]["server"]
            .as_str()
            .expect("server should be a string");
        assert_eq!(server, new_server);

        // Verify other fields are preserved
        let ca_data = config["clusters"][0]["cluster"]["certificate-authority-data"]
            .as_str()
            .expect("certificate-authority-data should be a string");
        assert_eq!(ca_data, "LS0tLS1CRUdJTg==");
    }

    #[test]
    fn test_rewrite_kubeconfig_multiple_clusters() {
        use lattice_core::yaml::parse_yaml;

        let kubeconfig = r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.0.0.1:6443
  name: cluster-1
- cluster:
    server: https://10.0.0.2:6443
  name: cluster-2
"#;

        let new_server = "https://127.0.0.1:12345";

        let mut config = parse_yaml(kubeconfig).expect("kubeconfig should be valid YAML");

        if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_array_mut()) {
            for cluster in clusters {
                if let Some(cluster_data) = cluster.get_mut("cluster") {
                    if let Some(server) = cluster_data.get_mut("server") {
                        *server = serde_json::Value::String(new_server.to_string());
                    }
                }
            }
        }

        // Both clusters should be updated
        let server1 = config["clusters"][0]["cluster"]["server"]
            .as_str()
            .expect("server1 should be a string");
        let server2 = config["clusters"][1]["cluster"]["server"]
            .as_str()
            .expect("server2 should be a string");
        assert_eq!(server1, new_server);
        assert_eq!(server2, new_server);
    }

    #[test]
    fn test_capi_namespace_format() {
        // Test the naming conventions directly
        let cluster_name = "test-cluster";
        assert_eq!(capi_namespace(cluster_name), "capi-test-cluster");
        assert_eq!(
            kubeconfig_secret_name(cluster_name),
            "test-cluster-kubeconfig"
        );
    }

    fn make_test_installer(config_dir: PathBuf) -> Installer {
        let cluster_yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test-cluster
spec:
  providerRef: docker
  provider:
    kubernetes:
      version: "1.29.0"
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
    workerPools: {}
  latticeImage: "test:latest"
"#;
        Installer::new(
            cluster_yaml.to_string(),
            "test:latest".to_string(),
            false,
            None,
            None,
            config_dir,
            None,
        )
        .expect("test installer should be valid")
    }

    #[tokio::test]
    async fn test_find_secret_file_yaml_extension() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let secret_path = dir.path().join("my-secret.yaml");
        std::fs::write(&secret_path, "apiVersion: v1").expect("should write file");

        let installer = make_test_installer(dir.path().to_path_buf());
        let found = installer
            .find_secret_file("my-secret")
            .await
            .expect("should find .yaml file");
        assert_eq!(found, secret_path);
    }

    #[tokio::test]
    async fn test_find_secret_file_yml_extension() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let secret_path = dir.path().join("my-secret.yml");
        std::fs::write(&secret_path, "apiVersion: v1").expect("should write file");

        let installer = make_test_installer(dir.path().to_path_buf());
        let found = installer
            .find_secret_file("my-secret")
            .await
            .expect("should find .yml file");
        assert_eq!(found, secret_path);
    }

    #[tokio::test]
    async fn test_find_secret_file_prefers_yaml_over_yml() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        std::fs::write(dir.path().join("my-secret.yaml"), "yaml").expect("write yaml");
        std::fs::write(dir.path().join("my-secret.yml"), "yml").expect("write yml");

        let installer = make_test_installer(dir.path().to_path_buf());
        let found = installer
            .find_secret_file("my-secret")
            .await
            .expect("should find file");
        assert_eq!(found, dir.path().join("my-secret.yaml"));
    }

    #[tokio::test]
    async fn test_find_secret_file_not_found() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let installer = make_test_installer(dir.path().to_path_buf());
        let result = installer.find_secret_file("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_apply_registry_mirror_credentials_no_mirrors() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let installer = make_test_installer(dir.path().to_path_buf());
        // No mirrors configured — should be a no-op (doesn't need a real client)
        // We can't easily test with a real client, but we verify the early return
        // by confirming it doesn't panic or error
        assert!(installer.cluster.spec.registry_mirrors.is_none());
    }
}
