//! LatticeCluster controller implementation
//!
//! This module implements the reconciliation logic for LatticeCluster resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use crate::capi::{
    ensure_capi_installed_with, CapiDetector, CapiInstaller,
};
use crate::crd::{
    ClusterCondition, ClusterPhase, ConditionStatus, LatticeCluster, LatticeClusterStatus,
    ProviderType,
};
use crate::provider::{CAPIManifest, DockerProvider, Provider};
use crate::Error;

/// Trait abstracting Kubernetes client operations for LatticeCluster
///
/// This trait allows mocking the Kubernetes client in tests while using
/// the real client in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait KubeClient: Send + Sync {
    /// Patch the status of a LatticeCluster
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the cluster to update
    /// * `status` - New status to apply
    async fn patch_status(&self, name: &str, status: &LatticeClusterStatus) -> Result<(), Error>;
}

/// Trait for cluster bootstrap registration
///
/// This trait allows the controller to register clusters for bootstrap
/// and obtain tokens for kubeadm postKubeadmCommands.
#[cfg_attr(test, automock)]
pub trait ClusterBootstrap: Send + Sync {
    /// Register a cluster for bootstrap and return a one-time token
    ///
    /// # Arguments
    ///
    /// * `cluster_id` - Unique cluster identifier
    /// * `cell_endpoint` - gRPC endpoint for the parent cell
    /// * `ca_certificate` - CA certificate PEM for the parent cell
    ///
    /// # Returns
    ///
    /// A one-time bootstrap token
    fn register_cluster(
        &self,
        cluster_id: String,
        cell_endpoint: String,
        ca_certificate: String,
    ) -> String;

    /// Check if a cluster is already registered
    fn is_cluster_registered(&self, cluster_id: &str) -> bool;

    /// Get the cell endpoint for the parent cluster
    fn cell_endpoint(&self) -> &str;

    /// Get the CA certificate PEM
    fn ca_cert_pem(&self) -> &str;
}

/// Trait abstracting CAPI resource operations
///
/// This trait allows mocking CAPI operations in tests while using the
/// real Kubernetes client for applying manifests in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CAPIClient: Send + Sync {
    /// Apply CAPI manifests to provision cluster infrastructure
    ///
    /// # Arguments
    ///
    /// * `manifests` - List of CAPI manifests to apply
    /// * `namespace` - Namespace to apply manifests in
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error>;

    /// Check if CAPI infrastructure is ready for a cluster
    ///
    /// # Arguments
    ///
    /// * `cluster_name` - Name of the cluster to check
    /// * `namespace` - Namespace where CAPI resources exist
    ///
    /// # Returns
    ///
    /// True if infrastructure is ready, false otherwise
    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<bool, Error>;
}

/// Real bootstrap implementation wrapping BootstrapState
pub struct RealClusterBootstrap<G: crate::bootstrap::ManifestGenerator> {
    state: Arc<crate::bootstrap::BootstrapState<G>>,
    cell_endpoint: String,
}

impl<G: crate::bootstrap::ManifestGenerator> RealClusterBootstrap<G> {
    /// Create a new RealClusterBootstrap wrapping the given BootstrapState
    pub fn new(state: Arc<crate::bootstrap::BootstrapState<G>>, cell_endpoint: String) -> Self {
        Self {
            state,
            cell_endpoint,
        }
    }
}

impl<G: crate::bootstrap::ManifestGenerator + 'static> ClusterBootstrap for RealClusterBootstrap<G> {
    fn register_cluster(
        &self,
        cluster_id: String,
        cell_endpoint: String,
        ca_certificate: String,
    ) -> String {
        let token = self
            .state
            .register_cluster(cluster_id, cell_endpoint, ca_certificate);
        token.as_str().to_string()
    }

    fn is_cluster_registered(&self, cluster_id: &str) -> bool {
        self.state.is_cluster_registered(cluster_id)
    }

    fn cell_endpoint(&self) -> &str {
        &self.cell_endpoint
    }

    fn ca_cert_pem(&self) -> &str {
        self.state.ca_cert_pem()
    }
}

/// Real Kubernetes client implementation
pub struct RealKubeClient {
    client: Client,
}

impl RealKubeClient {
    /// Create a new RealKubeClient wrapping the given kube Client
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl KubeClient for RealKubeClient {
    async fn patch_status(&self, name: &str, status: &LatticeClusterStatus) -> Result<(), Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());

        let status_patch = serde_json::json!({
            "status": status
        });

        api.patch_status(
            name,
            &PatchParams::apply("lattice-controller"),
            &Patch::Merge(&status_patch),
        )
        .await?;

        Ok(())
    }
}

/// Real CAPI client implementation using DynamicObject for untyped resources
pub struct RealCAPIClient {
    client: Client,
}

impl RealCAPIClient {
    /// Create a new RealCAPIClient
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CAPIClient for RealCAPIClient {
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;
        use kube::discovery::ApiResource;

        for manifest in manifests {
            // Parse API version and kind to create ApiResource
            let (group, version) = parse_api_version(&manifest.api_version);

            let ar = ApiResource {
                group: group.to_string(),
                version: version.to_string(),
                api_version: manifest.api_version.clone(),
                kind: manifest.kind.clone(),
                plural: pluralize_kind(&manifest.kind),
            };

            // Create dynamic object from manifest
            let obj: DynamicObject = serde_json::from_value(serde_json::json!({
                "apiVersion": manifest.api_version,
                "kind": manifest.kind,
                "metadata": {
                    "name": manifest.metadata.name,
                    "namespace": namespace,
                    "labels": manifest.metadata.labels,
                },
                "spec": manifest.spec,
            }))
            .map_err(|e| Error::serialization(e.to_string()))?;

            // Apply using server-side apply
            let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);
            api.patch(
                &manifest.metadata.name,
                &PatchParams::apply("lattice-controller").force(),
                &Patch::Apply(&obj),
            )
            .await?;

            info!(
                kind = %manifest.kind,
                name = %manifest.metadata.name,
                namespace = %namespace,
                "Applied CAPI manifest"
            );
        }

        Ok(())
    }

    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<bool, Error> {
        use kube::api::DynamicObject;
        use kube::discovery::ApiResource;

        // Check if the CAPI Cluster resource has Ready condition
        let ar = ApiResource {
            group: "cluster.x-k8s.io".to_string(),
            version: "v1beta1".to_string(),
            api_version: "cluster.x-k8s.io/v1beta1".to_string(),
            kind: "Cluster".to_string(),
            plural: "clusters".to_string(),
        };

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        match api.get(cluster_name).await {
            Ok(cluster) => {
                // Check status.phase == "Provisioned" or status.conditions contains Ready=True
                if let Some(status) = cluster.data.get("status") {
                    if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                        if phase == "Provisioned" {
                            return Ok(true);
                        }
                    }
                    // Also check conditions
                    if let Some(conditions) = status.get("conditions").and_then(|c| c.as_array()) {
                        for condition in conditions {
                            if condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                                && condition.get("status").and_then(|s| s.as_str()) == Some("True")
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Cluster doesn't exist yet
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Parse API version into group and version components
fn parse_api_version(api_version: &str) -> (&str, &str) {
    if let Some(idx) = api_version.rfind('/') {
        (&api_version[..idx], &api_version[idx + 1..])
    } else {
        // Core API (e.g., "v1")
        ("", api_version)
    }
}

/// Convert a Kind to its plural form (simplified)
fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();
    // Handle common CAPI kinds
    match lower.as_str() {
        "cluster" => "clusters".to_string(),
        "machine" => "machines".to_string(),
        "machinedeployment" => "machinedeployments".to_string(),
        "machineset" => "machinesets".to_string(),
        "kubeadmcontrolplane" => "kubeadmcontrolplanes".to_string(),
        "kubeadmconfigtemplate" => "kubeadmconfigtemplates".to_string(),
        "dockercluster" => "dockerclusters".to_string(),
        "dockermachine" => "dockermachines".to_string(),
        "dockermachinetemplate" => "dockermachinetemplates".to_string(),
        _ => format!("{}s", lower),
    }
}

/// Controller context containing shared state and clients
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients).
pub struct Context {
    /// Kubernetes client for API operations (trait object for testability)
    pub kube: Arc<dyn KubeClient>,
    /// CAPI client for applying manifests
    pub capi: Arc<dyn CAPIClient>,
    /// CAPI detector for checking installation status
    pub capi_detector: Arc<dyn CapiDetector>,
    /// CAPI installer for installing CAPI and providers
    pub capi_installer: Arc<dyn CapiInstaller>,
    /// Default namespace for CAPI resources
    pub capi_namespace: String,
    /// Bootstrap registration for workload clusters (None for cells)
    pub bootstrap: Option<Arc<dyn ClusterBootstrap>>,
}

impl Context {
    /// Create a new controller context with the given Kubernetes client
    pub fn new(client: Client) -> Self {
        use crate::capi::{ClusterctlInstaller, KubeCapiDetector};
        Self {
            kube: Arc::new(RealKubeClient::new(client.clone())),
            capi: Arc::new(RealCAPIClient::new(client.clone())),
            capi_detector: Arc::new(KubeCapiDetector::new(client.clone())),
            capi_installer: Arc::new(ClusterctlInstaller::new()),
            capi_namespace: "default".to_string(),
            bootstrap: None,
        }
    }

    /// Create a new controller context with a custom CAPI namespace
    pub fn with_namespace(client: Client, namespace: &str) -> Self {
        use crate::capi::{ClusterctlInstaller, KubeCapiDetector};
        Self {
            kube: Arc::new(RealKubeClient::new(client.clone())),
            capi: Arc::new(RealCAPIClient::new(client.clone())),
            capi_detector: Arc::new(KubeCapiDetector::new(client.clone())),
            capi_installer: Arc::new(ClusterctlInstaller::new()),
            capi_namespace: namespace.to_string(),
            bootstrap: None,
        }
    }

    /// Create a new controller context with bootstrap support
    ///
    /// Use this for cells that provision workload clusters.
    pub fn with_bootstrap(client: Client, bootstrap: Arc<dyn ClusterBootstrap>) -> Self {
        use crate::capi::{ClusterctlInstaller, KubeCapiDetector};
        Self {
            kube: Arc::new(RealKubeClient::new(client.clone())),
            capi: Arc::new(RealCAPIClient::new(client.clone())),
            capi_detector: Arc::new(KubeCapiDetector::new(client.clone())),
            capi_installer: Arc::new(ClusterctlInstaller::new()),
            capi_namespace: "default".to_string(),
            bootstrap: Some(bootstrap),
        }
    }

    /// Create a new controller context with custom client implementations
    ///
    /// This is primarily used for testing with mock clients.
    pub fn with_clients(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_detector: Arc<dyn CapiDetector>,
        capi_installer: Arc<dyn CapiInstaller>,
        namespace: &str,
    ) -> Self {
        Self {
            kube,
            capi,
            capi_detector,
            capi_installer,
            capi_namespace: namespace.to_string(),
            bootstrap: None,
        }
    }

    /// Create a new controller context with custom implementations and bootstrap
    ///
    /// This is primarily used for testing with mock clients.
    pub fn with_clients_and_bootstrap(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_detector: Arc<dyn CapiDetector>,
        capi_installer: Arc<dyn CapiInstaller>,
        bootstrap: Arc<dyn ClusterBootstrap>,
        namespace: &str,
    ) -> Self {
        Self {
            kube,
            capi,
            capi_detector,
            capi_installer,
            capi_namespace: namespace.to_string(),
            bootstrap: Some(bootstrap),
        }
    }
}

/// Reconcile a LatticeCluster resource
///
/// This function implements the main reconciliation loop for LatticeCluster.
/// It observes the current state, determines the desired state, and makes
/// incremental changes to converge on the desired state.
///
/// # Arguments
///
/// * `cluster` - The LatticeCluster resource to reconcile
/// * `ctx` - Shared controller context
///
/// # Returns
///
/// Returns an `Action` indicating when to requeue the resource, or an error
/// if reconciliation failed.
#[instrument(skip(cluster, ctx), fields(cluster = %cluster.name_any()))]
pub async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = cluster.name_any();
    info!("reconciling cluster");

    // Validate the cluster spec
    if let Err(e) = cluster.spec.validate() {
        warn!(error = %e, "cluster validation failed");
        update_status_failed(&cluster, &ctx, &e.to_string()).await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ClusterPhase::Pending);

    debug!(?current_phase, "current cluster phase");

    // State machine: transition based on current phase
    match current_phase {
        ClusterPhase::Pending => {
            // Ensure CAPI is installed before provisioning
            info!("ensuring CAPI is installed for provider");
            ensure_capi_installed_with(
                ctx.capi_detector.as_ref(),
                ctx.capi_installer.as_ref(),
                &cluster.spec.provider.type_,
            )
            .await?;

            // Generate and apply CAPI manifests, then transition to Provisioning
            info!("generating CAPI manifests for cluster");

            // Get the appropriate provider based on cluster spec
            let manifests = generate_capi_manifests(&cluster, &ctx).await?;

            // Apply CAPI manifests
            info!(count = manifests.len(), "applying CAPI manifests");
            ctx.capi.apply_manifests(&manifests, &ctx.capi_namespace).await?;

            // Update status to Provisioning
            info!("transitioning to Provisioning phase");
            update_status_provisioning(&cluster, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Provisioning => {
            // Check if CAPI infrastructure is ready
            debug!("checking infrastructure status");

            let is_ready = ctx.capi.is_infrastructure_ready(&name, &ctx.capi_namespace).await?;

            if is_ready {
                // Infrastructure is ready, transition to Pivoting
                info!("infrastructure ready, transitioning to Pivoting phase");
                update_status_pivoting(&cluster, &ctx).await?;
                Ok(Action::requeue(Duration::from_secs(5)))
            } else {
                // Still provisioning, requeue
                debug!("infrastructure not ready yet");
                Ok(Action::requeue(Duration::from_secs(30)))
            }
        }
        ClusterPhase::Pivoting => {
            // TODO: Check pivot status and transition to Ready when complete
            // For now, this would be handled by the agent sending pivot_complete
            debug!("cluster is pivoting");
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        ClusterPhase::Ready => {
            // Cluster is ready, check for drift
            debug!("cluster is ready");
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ClusterPhase::Failed => {
            // Failed state requires manual intervention
            warn!("cluster is in Failed state, awaiting spec change");
            Ok(Action::await_change())
        }
    }
}

/// Generate CAPI manifests for a cluster based on its provider type
async fn generate_capi_manifests(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Vec<CAPIManifest>, Error> {
    use crate::provider::BootstrapInfo;

    // Build bootstrap info from context if this is a workload cluster
    let bootstrap = if let Some(ref bootstrap_ctx) = ctx.bootstrap {
        let name = cluster.metadata.name.as_deref().unwrap_or("unknown");
        let ca_cert = bootstrap_ctx.ca_cert_pem().to_string();
        let cell_endpoint = bootstrap_ctx.cell_endpoint().to_string();
        let bootstrap_endpoint = format!("https://{}", cell_endpoint); // HTTPS with CA cert verification

        // Register cluster and get token
        let token = bootstrap_ctx.register_cluster(
            name.to_string(),
            cell_endpoint.clone(),
            ca_cert.clone(),
        );

        BootstrapInfo::new(bootstrap_endpoint, token, cell_endpoint, ca_cert)
    } else {
        // No bootstrap context - this is likely a management cluster
        BootstrapInfo::default()
    };

    match cluster.spec.provider.type_ {
        ProviderType::Docker => {
            let provider = DockerProvider::new();
            provider.generate_capi_manifests(cluster, &bootstrap).await
        }
        ProviderType::Aws => {
            // TODO: Implement AWS provider
            Err(Error::Provider("AWS provider not yet implemented".to_string()))
        }
        ProviderType::Gcp => {
            // TODO: Implement GCP provider
            Err(Error::Provider("GCP provider not yet implemented".to_string()))
        }
        ProviderType::Azure => {
            // TODO: Implement Azure provider
            Err(Error::Provider("Azure provider not yet implemented".to_string()))
        }
    }
}

/// Error policy for the controller
///
/// This function is called when reconciliation fails. It determines
/// the requeue strategy using exponential backoff.
///
/// # Arguments
///
/// * `cluster` - The LatticeCluster that failed reconciliation
/// * `error` - The error that occurred
/// * `_ctx` - Shared controller context (unused but required by signature)
///
/// # Returns
///
/// Returns an `Action` to requeue the resource after a delay.
pub fn error_policy(cluster: Arc<LatticeCluster>, error: &Error, _ctx: Arc<Context>) -> Action {
    error!(
        ?error,
        cluster = %cluster.name_any(),
        "reconciliation failed"
    );

    // Exponential backoff: start at 5 seconds
    // In a full implementation, we would track retry count and increase delay
    Action::requeue(Duration::from_secs(5))
}

/// Update cluster status to Provisioning phase
async fn update_status_provisioning(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition = ClusterCondition::new(
        "Provisioning",
        ConditionStatus::True,
        "StartingProvisioning",
        "Cluster provisioning has started",
    );

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Provisioning)
        .message("Provisioning cluster infrastructure")
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    info!("updated status to Provisioning");
    Ok(())
}

/// Update cluster status to Pivoting phase
async fn update_status_pivoting(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition = ClusterCondition::new(
        "Pivoting",
        ConditionStatus::True,
        "StartingPivot",
        "Cluster pivot has started",
    );

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Pivoting)
        .message("Pivoting cluster to self-managed")
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    info!("updated status to Pivoting");
    Ok(())
}

/// Update cluster status to Failed phase
async fn update_status_failed(
    cluster: &LatticeCluster,
    ctx: &Context,
    message: &str,
) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition =
        ClusterCondition::new("Ready", ConditionStatus::False, "ValidationFailed", message);

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Failed)
        .message(message.to_string())
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    warn!(message, "updated status to Failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        CellSpec, KubernetesSpec, LatticeClusterSpec, NodeSpec, ProviderSpec, ProviderType,
        ServiceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    /// Create a sample LatticeCluster for testing
    fn sample_cluster(name: &str) -> LatticeCluster {
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
                        cert_sans: None,
                    },
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 2,
                },
                networking: None,
                cell: None,
                cell_ref: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    /// Create a sample cell (management cluster) for testing
    fn sample_cell(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.cell = Some(CellSpec {
            host: "172.18.255.1".to_string(),
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        });
        cluster
    }

    /// Create a cluster with a specific status phase
    fn cluster_with_phase(name: &str, phase: ClusterPhase) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.status = Some(LatticeClusterStatus::with_phase(phase));
        cluster
    }

    /// Create a cluster with invalid spec (zero control plane nodes)
    fn invalid_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.nodes.control_plane = 0;
        cluster
    }

    mod reconcile_logic {
        use super::*;

        #[test]
        fn test_validation_with_valid_cluster() {
            let cluster = sample_cluster("valid-cluster");
            assert!(cluster.spec.validate().is_ok());
        }

        #[test]
        fn test_validation_with_invalid_cluster() {
            let cluster = invalid_cluster("invalid-cluster");
            assert!(cluster.spec.validate().is_err());
        }

        #[test]
        fn test_cell_cluster_validation() {
            let cluster = sample_cell("mgmt");
            assert!(cluster.spec.validate().is_ok());
            assert!(cluster.spec.is_cell());
        }
    }

    mod status_helpers {
        use super::*;

        #[test]
        fn test_multiple_condition_types_are_preserved() {
            let provisioning = ClusterCondition::new(
                "Provisioning",
                ConditionStatus::True,
                "InProgress",
                "Infrastructure provisioning",
            );
            let ready = ClusterCondition::new(
                "Ready",
                ConditionStatus::False,
                "NotReady",
                "Waiting for infrastructure",
            );

            let status = LatticeClusterStatus::default()
                .condition(provisioning)
                .condition(ready);

            assert_eq!(status.conditions.len(), 2);
        }
    }

    /// Cluster Lifecycle State Machine Tests
    ///
    /// These tests verify the complete cluster lifecycle flow through the reconciler.
    /// Each test represents a story of what happens when a cluster is in a specific
    /// state and the controller reconciles it.
    ///
    /// Lifecycle: Pending -> Provisioning -> Pivoting -> Ready
    ///            (any state can transition to Failed on error)
    ///
    /// Test Philosophy:
    /// - Tests focus on OBSERVABLE OUTCOMES (Action returned, errors propagated)
    /// - We avoid verifying internal mock call parameters
    /// - Status capture allows verifying phase transitions without tight coupling
    mod cluster_lifecycle_flow {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use std::sync::{Arc as StdArc, Mutex};

        /// Captured status update for verification without coupling to mock internals.
        /// This allows us to verify "status was updated to Provisioning" without
        /// using withf() matchers that couple tests to implementation details.
        #[derive(Clone)]
        struct StatusCapture {
            updates: StdArc<Mutex<Vec<LatticeClusterStatus>>>,
        }

        impl StatusCapture {
            fn new() -> Self {
                Self {
                    updates: StdArc::new(Mutex::new(Vec::new())),
                }
            }

            fn record(&self, status: LatticeClusterStatus) {
                self.updates.lock().unwrap().push(status);
            }

            fn last_phase(&self) -> Option<ClusterPhase> {
                self.updates.lock().unwrap().last().map(|s| s.phase.clone())
            }

            fn was_updated(&self) -> bool {
                !self.updates.lock().unwrap().is_empty()
            }
        }

        // ===== Test Fixture Helpers =====
        // These create mock contexts that capture status updates for verification

        /// Creates mocks where CAPI is already installed (no installation needed)
        fn mock_capi_already_installed() -> (Arc<MockCapiDetector>, Arc<MockCapiInstaller>) {
            let mut detector = MockCapiDetector::new();
            // CAPI is already installed
            detector
                .expect_crd_exists()
                .returning(|_, _| Ok(true));
            let installer = MockCapiInstaller::new();
            (Arc::new(detector), Arc::new(installer))
        }

        /// Creates a context that captures status updates for later verification.
        /// Use this when you need to verify WHAT phase was set, not HOW it was set.
        fn mock_context_with_status_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    capture_clone.record(status.clone());
                    Ok(())
                });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let (detector, installer) = mock_capi_already_installed();

            (
                Arc::new(Context::with_clients(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    detector,
                    installer,
                    "default",
                )),
                capture,
            )
        }

        /// Creates a context for read-only scenarios where no status updates happen.
        fn mock_context_readonly() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Ok(false));
            let (detector, installer) = mock_capi_already_installed();
            Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
            ))
        }

        /// Creates a context where infrastructure reports ready.
        fn mock_context_infra_ready_with_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    capture_clone.record(status.clone());
                    Ok(())
                });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Ok(true));

            let (detector, installer) = mock_capi_already_installed();

            (
                Arc::new(Context::with_clients(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    detector,
                    installer,
                    "default",
                )),
                capture,
            )
        }

        // ===== Lifecycle Flow Tests =====

        /// Story: When a user creates a new LatticeCluster, the controller should
        /// generate CAPI manifests and transition the cluster to Provisioning phase.
        /// This kicks off the infrastructure provisioning process.
        #[tokio::test]
        async fn story_new_cluster_starts_provisioning() {
            let cluster = Arc::new(sample_cluster("new-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Verify observable outcomes:
            // 1. Status was updated to Provisioning phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            // 2. Quick requeue to check provisioning progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: A cluster explicitly in Pending phase should behave identically
        /// to a new cluster - both enter the provisioning pipeline.
        #[tokio::test]
        async fn story_pending_cluster_starts_provisioning() {
            let cluster = Arc::new(cluster_with_phase("pending-cluster", ClusterPhase::Pending));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: While infrastructure is being provisioned (VMs starting, etc.),
        /// the controller should keep checking until CAPI reports ready.
        #[tokio::test]
        async fn story_provisioning_cluster_waits_for_infrastructure() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Observable outcome: longer requeue interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: Once infrastructure is ready, the cluster transitions to Pivoting
        /// phase where CAPI resources are moved into the cluster for self-management.
        #[tokio::test]
        async fn story_ready_infrastructure_triggers_pivot() {
            let cluster = Arc::new(cluster_with_phase(
                "ready-infra-cluster",
                ClusterPhase::Provisioning,
            ));
            let (ctx, capture) = mock_context_infra_ready_with_capture();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Verify transition to Pivoting phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Pivoting));
            // Quick requeue to monitor pivot progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: During the pivot phase, the controller monitors the agent's
        /// progress importing CAPI resources into the workload cluster.
        #[tokio::test]
        async fn story_pivoting_cluster_monitors_progress() {
            let cluster = Arc::new(cluster_with_phase("pivoting-cluster", ClusterPhase::Pivoting));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Moderate requeue interval during pivot
            assert_eq!(action, Action::requeue(Duration::from_secs(10)));
        }

        /// Story: Once a cluster is fully self-managing, the controller only needs
        /// periodic drift detection to ensure the cluster matches its spec.
        #[tokio::test]
        async fn story_ready_cluster_performs_drift_detection() {
            let cluster = Arc::new(cluster_with_phase("ready-cluster", ClusterPhase::Ready));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Long requeue interval for healthy clusters
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
        }

        /// Story: A failed cluster requires human intervention to fix the spec.
        /// The controller waits for spec changes rather than retrying on a timer.
        #[tokio::test]
        async fn story_failed_cluster_awaits_human_intervention() {
            let cluster = Arc::new(cluster_with_phase("failed-cluster", ClusterPhase::Failed));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Wait for spec changes, don't retry on timer
            assert_eq!(action, Action::await_change());
        }

        /// Story: Invalid cluster specs (like zero control plane nodes) should
        /// immediately fail rather than attempting to provision bad infrastructure.
        #[tokio::test]
        async fn story_invalid_spec_immediately_fails() {
            let cluster = Arc::new(invalid_cluster("invalid-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Verify transition to Failed phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Failed));
            // Wait for user to fix the spec
            assert_eq!(action, Action::await_change());
        }

        // ===== Error Propagation Tests =====

        /// Story: When the Kubernetes API is unavailable, errors should propagate
        /// so the controller can apply exponential backoff.
        #[tokio::test]
        async fn story_kube_api_errors_trigger_retry() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::Provider("connection refused".to_string())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let (detector, installer) = mock_capi_already_installed();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error propagates for retry
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("connection refused"));
        }

        /// Story: CAPI manifest application failures should propagate so the
        /// error policy can handle retries.
        #[tokio::test]
        async fn story_capi_failures_trigger_retry() {
            let cluster = Arc::new(sample_cluster("capi-error-cluster"));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_apply_manifests()
                .returning(|_, _| Err(Error::Provider("CAPI apply failed".to_string())));

            let (detector, installer) = mock_capi_already_installed();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error with context propagates
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("CAPI apply failed"));
        }
    }

    mod error_policy_tests {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use rstest::rstest;

        fn mock_context_no_updates() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ))
        }

        #[rstest]
        #[case::provider_error(Error::Provider("test error".to_string()))]
        #[case::validation_error(Error::Validation("invalid spec".to_string()))]
        #[case::pivot_error(Error::Pivot("pivot failed".to_string()))]
        fn test_error_policy_always_requeues_with_backoff(#[case] error: Error) {
            // error_policy should always requeue with 5s backoff regardless of error type
            let cluster = Arc::new(sample_cluster("test-cluster"));
            let ctx = mock_context_no_updates();

            let action = error_policy(cluster, &error, ctx);

            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }
    }

    /// Tests for status update error handling
    ///
    /// Note: The actual status content (phase, message, conditions) is tested
    /// through the reconcile flow tests which verify the complete behavior.
    /// These tests focus on error propagation which is a separate concern.
    mod status_error_handling {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        /// Story: When the Kubernetes API fails during status update, the error
        /// should propagate up so the controller can retry the reconciliation.
        #[tokio::test]
        async fn test_kube_api_failure_propagates_error() {
            let cluster = sample_cluster("test-cluster");

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::Provider("connection failed".to_string())));

            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            let ctx = Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            );

            let result = update_status_provisioning(&cluster, &ctx).await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("connection failed"));
        }
    }

    /// Tests for CAPI resource API handling
    ///
    /// These tests verify that we correctly parse Kubernetes API versions and
    /// generate resource plural names - essential for dynamically creating
    /// CAPI resources. While these are internal helpers, they're tested
    /// directly because the production code path (apply_manifests) requires
    /// a live Kubernetes cluster.
    mod capi_api_handling {
        use super::*;

        /// Story: When applying CAPI resources, we need to parse API versions like
        /// "cluster.x-k8s.io/v1beta1" into group and version for the DynamicObject API.
        #[test]
        fn test_grouped_api_versions_are_parsed_correctly() {
            let (group, version) = parse_api_version("cluster.x-k8s.io/v1beta1");
            assert_eq!(group, "cluster.x-k8s.io");
            assert_eq!(version, "v1beta1");
        }

        /// Story: Core Kubernetes resources use versions like "v1" without a group.
        #[test]
        fn test_core_api_versions_have_empty_group() {
            let (group, version) = parse_api_version("v1");
            assert_eq!(group, "");
            assert_eq!(version, "v1");
        }

        /// Story: The Kubernetes API requires plural resource names. We must correctly
        /// pluralize all CAPI resource kinds to construct valid API paths.
        #[test]
        fn test_all_capi_resource_kinds_are_pluralized_correctly() {
            // Core CAPI kinds
            assert_eq!(pluralize_kind("Cluster"), "clusters");
            assert_eq!(pluralize_kind("Machine"), "machines");
            assert_eq!(pluralize_kind("MachineSet"), "machinesets");
            assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");

            // Control plane kinds
            assert_eq!(pluralize_kind("KubeadmControlPlane"), "kubeadmcontrolplanes");
            assert_eq!(pluralize_kind("KubeadmConfigTemplate"), "kubeadmconfigtemplates");

            // Docker infrastructure kinds
            assert_eq!(pluralize_kind("DockerCluster"), "dockerclusters");
            assert_eq!(pluralize_kind("DockerMachine"), "dockermachines");
            assert_eq!(pluralize_kind("DockerMachineTemplate"), "dockermachinetemplates");
        }

        /// Story: Unknown resource kinds should fall back to simple 's' suffix pluralization.
        #[test]
        fn test_unknown_kinds_use_fallback_pluralization() {
            assert_eq!(pluralize_kind("CustomResource"), "customresources");
        }
    }

    mod generate_manifests_tests {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        fn cluster_with_provider(name: &str, provider_type: ProviderType) -> LatticeCluster {
            LatticeCluster {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: LatticeClusterSpec {
                    provider: ProviderSpec {
                        type_: provider_type,
                        kubernetes: KubernetesSpec {
                            version: "1.31.0".to_string(),
                            cert_sans: None,
                        },
                    },
                    nodes: NodeSpec {
                        control_plane: 1,
                        workers: 2,
                    },
                    networking: None,
                    cell: None,
                    cell_ref: None,
                    environment: None,
                    region: None,
                    workload: None,
                },
                status: None,
            }
        }

        fn mock_context() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ))
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_docker_provider() {
            let cluster = cluster_with_provider("docker-cluster", ProviderType::Docker);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.unwrap();
            // Docker provider should generate manifests
            assert!(!manifests.is_empty());
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_aws_provider_not_implemented() {
            let cluster = cluster_with_provider("aws-cluster", ProviderType::Aws);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("AWS provider not yet implemented"));
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_gcp_provider_not_implemented() {
            let cluster = cluster_with_provider("gcp-cluster", ProviderType::Gcp);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("GCP provider not yet implemented"));
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_azure_provider_not_implemented() {
            let cluster = cluster_with_provider("azure-cluster", ProviderType::Azure);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Azure provider not yet implemented"));
        }
    }

    /// Workload Cluster Bootstrap Flow Tests
    ///
    /// These tests verify that when a workload cluster is provisioned with
    /// bootstrap context (parent cell information), the manifest generation
    /// correctly registers the cluster and includes bootstrap information
    /// in the generated CAPI manifests.
    mod workload_cluster_bootstrap_flow {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        /// A simple test implementation of ClusterBootstrap that doesn't use mockall
        /// because ClusterBootstrap returns &str which is tricky with mockall.
        struct TestClusterBootstrap {
            cell_endpoint: String,
            ca_cert: String,
            registered_clusters: std::sync::Mutex<Vec<String>>,
        }

        impl TestClusterBootstrap {
            fn new(cell_endpoint: &str, ca_cert: &str) -> Self {
                Self {
                    cell_endpoint: cell_endpoint.to_string(),
                    ca_cert: ca_cert.to_string(),
                    registered_clusters: std::sync::Mutex::new(Vec::new()),
                }
            }

            fn was_cluster_registered(&self, cluster_id: &str) -> bool {
                self.registered_clusters.lock().unwrap().contains(&cluster_id.to_string())
            }
        }

        impl ClusterBootstrap for TestClusterBootstrap {
            fn register_cluster(
                &self,
                cluster_id: String,
                _cell_endpoint: String,
                _ca_certificate: String,
            ) -> String {
                self.registered_clusters.lock().unwrap().push(cluster_id.clone());
                format!("bootstrap-token-for-{}", cluster_id)
            }

            fn is_cluster_registered(&self, cluster_id: &str) -> bool {
                self.registered_clusters.lock().unwrap().contains(&cluster_id.to_string())
            }

            fn cell_endpoint(&self) -> &str {
                &self.cell_endpoint
            }

            fn ca_cert_pem(&self) -> &str {
                &self.ca_cert
            }
        }

        /// Story: When provisioning a workload cluster, the controller should
        /// register the cluster with the bootstrap service and include the
        /// bootstrap token in the generated CAPI manifests so kubeadm can
        /// call back to get the agent and CNI manifests.
        #[tokio::test]
        async fn story_workload_cluster_registers_for_bootstrap() {
            let cluster = sample_cluster("workload-prod-001");

            // Create a test bootstrap service
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell.example.com:443",
                "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
            ));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Context::with_clients_and_bootstrap(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                bootstrap.clone(),
                "default",
            );

            // Generate manifests - this should trigger registration
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.unwrap();
            assert!(!manifests.is_empty());

            // Verify the cluster was registered
            assert!(bootstrap.was_cluster_registered("workload-prod-001"));
        }

        /// Story: The bootstrap context provides the parent cell's endpoint
        /// so workload clusters know where to connect after provisioning.
        #[tokio::test]
        async fn story_bootstrap_context_provides_cell_endpoint() {
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "mgmt.lattice.io:443",
                "FAKE_CA_CERT",
            ));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Context::with_clients_and_bootstrap(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                bootstrap,
                "capi-system",
            );

            // Verify bootstrap is present in context
            assert!(ctx.bootstrap.is_some());
            let bootstrap_ctx = ctx.bootstrap.as_ref().unwrap();
            assert_eq!(bootstrap_ctx.cell_endpoint(), "mgmt.lattice.io:443");
        }

        /// Story: The CA certificate is included so workload clusters can
        /// verify the parent cell's TLS certificate during bootstrap.
        #[tokio::test]
        async fn story_bootstrap_includes_ca_certificate() {
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell:443",
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            ));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Context::with_clients_and_bootstrap(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                bootstrap,
                "default",
            );

            let bootstrap_ctx = ctx.bootstrap.as_ref().unwrap();
            assert!(bootstrap_ctx.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        }

        /// Story: The bootstrap token returned by register_cluster is included
        /// in the generated CAPI manifests for kubeadm postKubeadmCommands.
        #[tokio::test]
        async fn story_bootstrap_token_included_in_manifests() {
            let cluster = sample_cluster("workload-with-token");

            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell.example.com:443",
                "-----BEGIN CERTIFICATE-----\nCA_CERT\n-----END CERTIFICATE-----",
            ));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Context::with_clients_and_bootstrap(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                bootstrap,
                "default",
            );

            let result = generate_capi_manifests(&cluster, &ctx).await;
            assert!(result.is_ok());

            let manifests = result.unwrap();
            // Find the KubeadmControlPlane manifest
            let kcp = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("Should have KubeadmControlPlane manifest");

            // The spec should contain postKubeadmCommands with the bootstrap token
            let spec = kcp.spec.as_ref().expect("KubeadmControlPlane should have spec");
            let kubeadm_config = spec.get("kubeadmConfigSpec").expect("Should have kubeadmConfigSpec");
            let post_commands = kubeadm_config.get("postKubeadmCommands");

            assert!(post_commands.is_some(), "Should have postKubeadmCommands");
            let commands_str = serde_json::to_string(post_commands.unwrap()).unwrap();
            assert!(commands_str.contains("bootstrap-token-for-workload-with-token"));
        }
    }

    /// API Version Parsing Tests
    ///
    /// These tests verify that Kubernetes API versions are correctly parsed
    /// into group and version components for dynamic resource creation.
    mod api_version_parsing {
        use super::*;

        /// Story: CAPI resources use grouped API versions like "cluster.x-k8s.io/v1beta1"
        /// which need to be split into group="cluster.x-k8s.io" and version="v1beta1"
        #[test]
        fn story_capi_api_versions_split_correctly() {
            let test_cases = vec![
                ("cluster.x-k8s.io/v1beta1", "cluster.x-k8s.io", "v1beta1"),
                ("infrastructure.cluster.x-k8s.io/v1beta1", "infrastructure.cluster.x-k8s.io", "v1beta1"),
                ("controlplane.cluster.x-k8s.io/v1beta1", "controlplane.cluster.x-k8s.io", "v1beta1"),
                ("bootstrap.cluster.x-k8s.io/v1beta1", "bootstrap.cluster.x-k8s.io", "v1beta1"),
            ];

            for (input, expected_group, expected_version) in test_cases {
                let (group, version) = parse_api_version(input);
                assert_eq!(group, expected_group, "group for {}", input);
                assert_eq!(version, expected_version, "version for {}", input);
            }
        }

        /// Story: Core Kubernetes resources use "v1" without a group prefix
        #[test]
        fn story_core_api_version_has_empty_group() {
            let (group, version) = parse_api_version("v1");
            assert_eq!(group, "");
            assert_eq!(version, "v1");
        }

        /// Story: Apps API group resources like Deployments
        #[test]
        fn story_apps_api_version_parses_correctly() {
            let (group, version) = parse_api_version("apps/v1");
            assert_eq!(group, "apps");
            assert_eq!(version, "v1");
        }
    }

    /// Resource Pluralization Tests
    ///
    /// The Kubernetes API requires plural resource names when constructing
    /// API paths. These tests verify all CAPI resource kinds are pluralized correctly.
    mod resource_pluralization {
        use super::*;

        /// Story: All standard CAPI resource kinds must pluralize correctly
        /// for the dynamic client to work with them.
        #[test]
        fn story_all_capi_kinds_have_correct_plurals() {
            // Core CAPI resources
            assert_eq!(pluralize_kind("Cluster"), "clusters");
            assert_eq!(pluralize_kind("Machine"), "machines");
            assert_eq!(pluralize_kind("MachineSet"), "machinesets");
            assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");

            // Control plane resources
            assert_eq!(pluralize_kind("KubeadmControlPlane"), "kubeadmcontrolplanes");
            assert_eq!(pluralize_kind("KubeadmConfigTemplate"), "kubeadmconfigtemplates");

            // Docker provider resources
            assert_eq!(pluralize_kind("DockerCluster"), "dockerclusters");
            assert_eq!(pluralize_kind("DockerMachine"), "dockermachines");
            assert_eq!(pluralize_kind("DockerMachineTemplate"), "dockermachinetemplates");
        }

        /// Story: Unknown resource kinds should use simple 's' suffix fallback
        /// so new resource types can still work without explicit mapping.
        #[test]
        fn story_unknown_kinds_use_fallback_pluralization() {
            assert_eq!(pluralize_kind("CustomCluster"), "customclusters");
            assert_eq!(pluralize_kind("MyResource"), "myresources");
            assert_eq!(pluralize_kind("SomeNewKind"), "somenewkinds");
        }

        /// Story: Pluralization is case-insensitive (Kubernetes convention)
        #[test]
        fn story_pluralization_is_case_insensitive() {
            assert_eq!(pluralize_kind("CLUSTER"), "clusters");
            assert_eq!(pluralize_kind("cluster"), "clusters");
            assert_eq!(pluralize_kind("Cluster"), "clusters");
        }
    }

    /// Infrastructure Ready Detection Tests
    ///
    /// These tests verify the controller correctly detects when CAPI
    /// infrastructure is ready based on the Cluster resource status.
    mod infrastructure_ready_detection {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        /// Story: When CAPI reports infrastructure NOT ready, the controller
        /// should continue polling with the Provisioning phase requeue interval.
        #[tokio::test]
        async fn story_not_ready_infrastructure_triggers_requeue() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure is NOT ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Ok(false));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Should requeue with longer interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: When CAPI reports infrastructure IS ready, the controller
        /// should transition to Pivoting phase.
        #[tokio::test]
        async fn story_ready_infrastructure_triggers_phase_transition() {
            use std::sync::{Arc as StdArc, Mutex};

            let cluster = Arc::new(cluster_with_phase(
                "ready-cluster",
                ClusterPhase::Provisioning,
            ));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> = StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    updates_clone.lock().unwrap().push(status.clone());
                    Ok(())
                });

            let mut capi_mock = MockCAPIClient::new();
            // Infrastructure IS ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Ok(true));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let action = reconcile(cluster, ctx).await.expect("reconcile should succeed");

            // Should transition to Pivoting and requeue quickly
            let recorded = updates.lock().unwrap();
            assert!(!recorded.is_empty());
            assert_eq!(recorded.last().unwrap().phase, ClusterPhase::Pivoting);
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: When CAPI infrastructure check fails, error should propagate
        /// for retry with backoff.
        #[tokio::test]
        async fn story_infrastructure_check_failure_propagates_error() {
            let cluster = Arc::new(cluster_with_phase(
                "error-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure check fails
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Err(Error::Provider("CAPI API unavailable".to_string())));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("CAPI API unavailable"));
        }
    }

    /// CAPI Installation Flow Tests
    ///
    /// These tests verify the controller correctly handles CAPI installation
    /// before attempting to provision a cluster.
    mod capi_installation_flow {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When CAPI is already installed, the controller proceeds
        /// directly to manifest generation without installing.
        #[tokio::test]
        async fn story_capi_already_installed_skips_installation() {
            let cluster = Arc::new(sample_cluster("ready-to-provision"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> = StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    updates_clone.lock().unwrap().push(status.clone());
                    Ok(())
                });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut detector = MockCapiDetector::new();
            // CAPI is already installed
            detector
                .expect_crd_exists()
                .returning(|_, _| Ok(true));

            // Installer should NOT be called
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
            // Should have transitioned to Provisioning
            let recorded = updates.lock().unwrap();
            assert!(!recorded.is_empty());
        }

        /// Story: When CAPI is not installed, the controller should install it
        /// before attempting to provision.
        #[tokio::test]
        async fn story_capi_not_installed_triggers_installation() {
            let cluster = Arc::new(sample_cluster("needs-capi"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> = StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    updates_clone.lock().unwrap().push(status.clone());
                    Ok(())
                });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut detector = MockCapiDetector::new();
            // CAPI is NOT installed initially
            detector
                .expect_crd_exists()
                .returning(|_, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            // Installer should be called
            installer
                .expect_install()
                .times(1)
                .returning(|_| Ok(()));

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
        }

        /// Story: When CAPI installation fails, the error should propagate
        /// for retry with exponential backoff.
        #[tokio::test]
        async fn story_capi_installation_failure_propagates_error() {
            let cluster = Arc::new(sample_cluster("install-fails"));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();

            let mut detector = MockCapiDetector::new();
            // CAPI is NOT installed
            detector
                .expect_crd_exists()
                .returning(|_, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            // Installation fails
            installer
                .expect_install()
                .returning(|_| Err(Error::CapiInstallation("clusterctl not found".to_string())));

            let ctx = Arc::new(Context::with_clients(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("clusterctl"));
        }
    }

    /// Status Update Content Tests
    ///
    /// These tests verify that status updates contain the correct phase,
    /// message, and conditions as the cluster progresses through its lifecycle.
    mod status_update_content {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When transitioning to Provisioning, the status should include
        /// a clear message and Provisioning condition for observability.
        #[tokio::test]
        async fn story_provisioning_status_has_correct_content() {
            let cluster = sample_cluster("new-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    *captured_clone.lock().unwrap() = Some(status.clone());
                    Ok(())
                });

            let ctx = Context::with_clients(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            update_status_provisioning(&cluster, &ctx).await.unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Provisioning);
            assert!(status.message.unwrap().contains("Provisioning"));
            assert!(!status.conditions.is_empty());

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Provisioning");
            assert_eq!(condition.status, ConditionStatus::True);
        }

        /// Story: When transitioning to Pivoting, the status should indicate
        /// that the cluster is being transitioned to self-management.
        #[tokio::test]
        async fn story_pivoting_status_has_correct_content() {
            let cluster = sample_cluster("pivoting-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    *captured_clone.lock().unwrap() = Some(status.clone());
                    Ok(())
                });

            let ctx = Context::with_clients(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            update_status_pivoting(&cluster, &ctx).await.unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Pivoting);
            assert!(status.message.unwrap().contains("Pivoting"));

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Pivoting");
            assert_eq!(condition.reason, "StartingPivot");
        }

        /// Story: When a cluster fails validation, the status should clearly
        /// indicate the failure reason so users can fix the configuration.
        #[tokio::test]
        async fn story_failed_status_includes_error_message() {
            let cluster = sample_cluster("invalid-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(move |_, status| {
                    *captured_clone.lock().unwrap() = Some(status.clone());
                    Ok(())
                });

            let ctx = Context::with_clients(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            let error_msg = "control plane count must be at least 1";
            update_status_failed(&cluster, &ctx, error_msg).await.unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Failed);
            assert_eq!(status.message.as_ref().unwrap(), error_msg);

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Ready");
            assert_eq!(condition.status, ConditionStatus::False);
            assert_eq!(condition.reason, "ValidationFailed");
            assert_eq!(condition.message, error_msg);
        }
    }

    /// Error Policy Behavior Tests
    ///
    /// These tests verify that the error policy correctly handles different
    /// types of errors and returns appropriate requeue actions.
    mod error_policy_behavior {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        fn mock_context_minimal() -> Arc<Context> {
            Arc::new(Context::with_clients(
                Arc::new(MockKubeClient::new()),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            ))
        }

        /// Story: All errors should result in a requeue with backoff,
        /// regardless of error type, to handle transient failures.
        #[test]
        fn story_all_error_types_trigger_requeue() {
            let cluster = Arc::new(sample_cluster("error-cluster"));
            let ctx = mock_context_minimal();

            let error_types = vec![
                Error::Provider("provider error".to_string()),
                Error::Validation("validation error".to_string()),
                Error::Pivot("pivot error".to_string()),
                Error::Serialization("serialization error".to_string()),
                Error::CapiInstallation("capi error".to_string()),
            ];

            for error in error_types {
                let action = error_policy(cluster.clone(), &error, ctx.clone());
                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "error type {:?} should trigger 5s requeue",
                    error
                );
            }
        }

        /// Story: Error policy should work correctly with clusters in any phase.
        #[test]
        fn story_error_policy_works_for_all_phases() {
            let ctx = mock_context_minimal();

            let phases = vec![
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Ready,
                ClusterPhase::Failed,
            ];

            for phase in phases {
                let cluster = Arc::new(cluster_with_phase("test", phase.clone()));
                let error = Error::Provider("test error".to_string());
                let action = error_policy(cluster, &error, ctx.clone());

                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "phase {:?} should trigger requeue",
                    phase
                );
            }
        }
    }
}
