//! CAPI (Cluster API) management
//!
//! Handles ensuring CAPI and infrastructure providers are installed before
//! attempting to provision clusters.

use std::process::Command;

use async_trait::async_trait;
use kube::api::DynamicObject;
use kube::discovery::ApiResource;
use kube::{Api, Client};
#[cfg(test)]
use mockall::automock;
use tracing::{info, warn};

use crate::crd::ProviderType;
use crate::Error;

/// CRD information for a CAPI infrastructure provider
pub struct ProviderCrdInfo {
    /// API group (e.g., "infrastructure.cluster.x-k8s.io")
    pub group: &'static str,
    /// Kind (e.g., "DockerCluster")
    pub kind: &'static str,
    /// Plural name (e.g., "dockerclusters")
    pub plural: &'static str,
}

/// Get the CRD info for detecting if a provider is installed
pub fn provider_crd_info(provider: &ProviderType) -> ProviderCrdInfo {
    match provider {
        ProviderType::Docker => ProviderCrdInfo {
            group: "infrastructure.cluster.x-k8s.io",
            kind: "DockerCluster",
            plural: "dockerclusters",
        },
        ProviderType::Aws => ProviderCrdInfo {
            group: "infrastructure.cluster.x-k8s.io",
            kind: "AWSCluster",
            plural: "awsclusters",
        },
        ProviderType::Gcp => ProviderCrdInfo {
            group: "infrastructure.cluster.x-k8s.io",
            kind: "GCPCluster",
            plural: "gcpclusters",
        },
        ProviderType::Azure => ProviderCrdInfo {
            group: "infrastructure.cluster.x-k8s.io",
            kind: "AzureCluster",
            plural: "azureclusters",
        },
    }
}

/// Get the clusterctl provider name for installation
pub fn clusterctl_provider_name(provider: &ProviderType) -> &'static str {
    match provider {
        ProviderType::Docker => "docker",
        ProviderType::Aws => "aws",
        ProviderType::Gcp => "gcp",
        ProviderType::Azure => "azure",
    }
}

/// Trait for detecting CAPI installation status
///
/// This trait abstracts Kubernetes API calls for testability.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiDetector: Send + Sync {
    /// Check if a CRD exists in the cluster
    async fn crd_exists(&self, group: &str, plural: &str) -> Result<bool, Error>;
}

/// Trait for installing CAPI and infrastructure providers
///
/// This trait abstracts clusterctl command execution for testability.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Install CAPI with the specified infrastructure provider
    async fn install(&self, provider: &str) -> Result<(), Error>;
}

/// Check if a specific infrastructure provider is installed
pub async fn is_provider_installed_with<D: CapiDetector + ?Sized>(
    detector: &D,
    provider: &ProviderType,
) -> Result<bool, Error> {
    let info = provider_crd_info(provider);
    detector.crd_exists(info.group, info.plural).await
}

/// Check if CAPI core is installed
pub async fn is_capi_installed_with<D: CapiDetector + ?Sized>(detector: &D) -> Result<bool, Error> {
    detector.crd_exists("cluster.x-k8s.io", "clusters").await
}

/// Ensure CAPI and the required provider are installed
///
/// If the provider is already installed, does nothing.
/// If not installed, installs CAPI with the specified provider.
pub async fn ensure_capi_installed_with<D: CapiDetector + ?Sized, I: CapiInstaller + ?Sized>(
    detector: &D,
    installer: &I,
    provider: &ProviderType,
) -> Result<(), Error> {
    // Check if provider is already installed
    if is_provider_installed_with(detector, provider).await? {
        return Ok(());
    }

    // Install CAPI with the provider
    let provider_name = clusterctl_provider_name(provider);
    installer.install(provider_name).await
}

// =============================================================================
// Real Implementations
// =============================================================================

/// CAPI detector that uses the Kubernetes API
pub struct KubeCapiDetector {
    client: Client,
}

impl KubeCapiDetector {
    /// Create a new detector with the given client
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CapiDetector for KubeCapiDetector {
    async fn crd_exists(&self, group: &str, plural: &str) -> Result<bool, Error> {
        let ar = ApiResource {
            group: group.to_string(),
            version: "v1beta1".to_string(),
            api_version: format!("{}/v1beta1", group),
            kind: String::new(), // Not needed for list
            plural: plural.to_string(),
        };

        let api: Api<DynamicObject> = Api::all_with(self.client.clone(), &ar);
        match api.list(&Default::default()).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
            Err(e) => Err(Error::Kube(e)),
        }
    }
}

/// CAPI installer that uses clusterctl
pub struct ClusterctlInstaller;

impl ClusterctlInstaller {
    /// Create a new installer
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClusterctlInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CapiInstaller for ClusterctlInstaller {
    async fn install(&self, provider: &str) -> Result<(), Error> {
        info!(provider, "Installing CAPI with infrastructure provider");

        let output = Command::new("clusterctl")
            .args(["init", "--infrastructure", provider])
            .output()
            .map_err(|e| Error::CapiInstallation(format!("failed to run clusterctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "already installed" is success
            if stderr.contains("already installed") || stderr.contains("already exists") {
                info!("CAPI already installed");
                return Ok(());
            }
            return Err(Error::CapiInstallation(format!(
                "clusterctl init failed: {}",
                stderr
            )));
        }

        info!("CAPI installed successfully");
        Ok(())
    }
}

/// Convenience function to ensure CAPI is installed using default implementations
pub async fn ensure_capi_installed(client: &Client, provider: &ProviderType) -> Result<(), Error> {
    let detector = KubeCapiDetector::new(client.clone());
    let installer = ClusterctlInstaller::new();

    if is_provider_installed_with(&detector, provider).await? {
        return Ok(());
    }

    if is_capi_installed_with(&detector).await? {
        warn!(
            provider = ?provider,
            "CAPI core is installed but infrastructure provider is missing"
        );
    }

    let provider_name = clusterctl_provider_name(provider);
    installer.install(provider_name).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::ProviderType;
    use mockall::predicate::*;

    // ==========================================================================
    // Story: CAPI Provider CRD Detection
    //
    // When the Lattice operator needs to provision clusters, it must first
    // verify that the appropriate CAPI infrastructure provider is installed.
    // Each cloud provider (Docker, AWS, GCP, Azure) has its own CRD that
    // must exist before cluster provisioning can proceed.
    // ==========================================================================

    /// When generating CAPI manifests for a Docker cluster, the operator
    /// should use the DockerCluster CRD from the infrastructure API group.
    #[test]
    fn when_provider_is_docker_the_crd_info_points_to_docker_cluster() {
        let info = provider_crd_info(&ProviderType::Docker);

        assert_eq!(
            info.group, "infrastructure.cluster.x-k8s.io",
            "Docker provider should use the standard infrastructure API group"
        );
        assert_eq!(
            info.kind, "DockerCluster",
            "Docker provider uses DockerCluster kind"
        );
        assert_eq!(
            info.plural, "dockerclusters",
            "Plural form must match Kubernetes conventions"
        );
    }

    /// When generating CAPI manifests for an AWS cluster, the operator
    /// should use the AWSCluster CRD for cloud infrastructure.
    #[test]
    fn when_provider_is_aws_the_crd_info_points_to_aws_cluster() {
        let info = provider_crd_info(&ProviderType::Aws);

        assert_eq!(info.group, "infrastructure.cluster.x-k8s.io");
        assert_eq!(info.kind, "AWSCluster");
        assert_eq!(info.plural, "awsclusters");
    }

    /// When generating CAPI manifests for a GCP cluster, the operator
    /// should use the GCPCluster CRD for Google Cloud infrastructure.
    #[test]
    fn when_provider_is_gcp_the_crd_info_points_to_gcp_cluster() {
        let info = provider_crd_info(&ProviderType::Gcp);

        assert_eq!(
            info.group, "infrastructure.cluster.x-k8s.io",
            "GCP provider should use the standard infrastructure API group"
        );
        assert_eq!(info.kind, "GCPCluster", "GCP provider uses GCPCluster kind");
        assert_eq!(info.plural, "gcpclusters");
    }

    /// When generating CAPI manifests for an Azure cluster, the operator
    /// should use the AzureCluster CRD for Microsoft Azure infrastructure.
    #[test]
    fn when_provider_is_azure_the_crd_info_points_to_azure_cluster() {
        let info = provider_crd_info(&ProviderType::Azure);

        assert_eq!(info.group, "infrastructure.cluster.x-k8s.io");
        assert_eq!(
            info.kind, "AzureCluster",
            "Azure provider uses AzureCluster kind"
        );
        assert_eq!(info.plural, "azureclusters");
    }

    /// When the operator needs to install CAPI providers via clusterctl,
    /// it should map provider types to their clusterctl-recognized names.
    #[test]
    fn when_installing_providers_clusterctl_names_are_lowercase() {
        // clusterctl uses lowercase provider names for the --infrastructure flag
        assert_eq!(
            clusterctl_provider_name(&ProviderType::Docker),
            "docker",
            "Docker provider name for clusterctl"
        );
        assert_eq!(
            clusterctl_provider_name(&ProviderType::Aws),
            "aws",
            "AWS provider name for clusterctl"
        );
        assert_eq!(
            clusterctl_provider_name(&ProviderType::Gcp),
            "gcp",
            "GCP provider name for clusterctl"
        );
        assert_eq!(
            clusterctl_provider_name(&ProviderType::Azure),
            "azure",
            "Azure provider name for clusterctl"
        );
    }

    // ==========================================================================
    // Story: CAPI Detection Before Cluster Provisioning
    //
    // Before provisioning a cluster, the operator must detect whether CAPI
    // and the required infrastructure provider are already installed.
    // This prevents unnecessary reinstallation and allows for idempotent
    // reconciliation.
    // ==========================================================================

    /// When the Docker infrastructure provider CRD exists in the cluster,
    /// the detector should report that the provider is installed.
    #[tokio::test]
    async fn when_docker_crd_exists_provider_is_detected_as_installed() {
        let mut mock = MockCapiDetector::new();
        mock.expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("dockerclusters"))
            .returning(|_, _| Ok(true));

        let result = is_provider_installed_with(&mock, &ProviderType::Docker).await;

        assert!(
            result.unwrap(),
            "Provider should be detected as installed when CRD exists"
        );
    }

    /// When the Docker infrastructure provider CRD is missing,
    /// the detector should report that the provider is not installed.
    #[tokio::test]
    async fn when_docker_crd_is_missing_provider_is_not_installed() {
        let mut mock = MockCapiDetector::new();
        mock.expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("dockerclusters"))
            .returning(|_, _| Ok(false));

        let result = is_provider_installed_with(&mock, &ProviderType::Docker).await;

        assert!(
            !result.unwrap(),
            "Provider should not be detected when CRD is missing"
        );
    }

    /// When checking if CAPI core is installed, the detector should look
    /// for the Cluster CRD from the core cluster.x-k8s.io API group.
    #[tokio::test]
    async fn when_cluster_crd_exists_capi_core_is_installed() {
        let mut mock = MockCapiDetector::new();
        mock.expect_crd_exists()
            .with(eq("cluster.x-k8s.io"), eq("clusters"))
            .returning(|_, _| Ok(true));

        let result = is_capi_installed_with(&mock).await;

        assert!(
            result.unwrap(),
            "CAPI core should be detected when Cluster CRD exists"
        );
    }

    /// When the Cluster CRD is missing, CAPI core is not installed.
    #[tokio::test]
    async fn when_cluster_crd_is_missing_capi_core_is_not_installed() {
        let mut mock = MockCapiDetector::new();
        mock.expect_crd_exists()
            .with(eq("cluster.x-k8s.io"), eq("clusters"))
            .returning(|_, _| Ok(false));

        let result = is_capi_installed_with(&mock).await;

        assert!(
            !result.unwrap(),
            "CAPI core should not be detected when Cluster CRD is missing"
        );
    }

    /// When the detector encounters an error checking for CRDs,
    /// the error should propagate to the caller.
    #[tokio::test]
    async fn when_detection_fails_error_propagates_to_caller() {
        let mut mock = MockCapiDetector::new();
        mock.expect_crd_exists()
            .returning(|_, _| Err(Error::CapiInstallation("connection refused".to_string())));

        let result = is_provider_installed_with(&mock, &ProviderType::Docker).await;

        assert!(
            result.is_err(),
            "Detection errors should propagate to caller"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("connection refused"),
            "Error message should be preserved"
        );
    }

    // ==========================================================================
    // Story: CAPI Installation During Cluster Provisioning
    //
    // When a cluster is being provisioned and CAPI/provider is not installed,
    // the operator should automatically install them. This ensures a smooth
    // user experience where users don't need to manually install CAPI.
    // ==========================================================================

    /// When the Docker provider is already installed, ensure_capi should
    /// skip installation and return success without calling the installer.
    #[tokio::test]
    async fn when_provider_already_installed_skip_installation() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("dockerclusters"))
            .returning(|_, _| Ok(true));

        // CRITICAL: installer should NOT be called
        installer.expect_install().never();

        let result =
            ensure_capi_installed_with(&detector, &installer, &ProviderType::Docker).await;

        assert!(result.is_ok(), "Should succeed without installing");
    }

    /// When the Docker provider is not installed, ensure_capi should
    /// call the installer with the correct provider name.
    #[tokio::test]
    async fn when_provider_missing_install_with_correct_name() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("dockerclusters"))
            .returning(|_, _| Ok(false));

        installer
            .expect_install()
            .with(eq("docker"))
            .times(1)
            .returning(|_| Ok(()));

        let result =
            ensure_capi_installed_with(&detector, &installer, &ProviderType::Docker).await;

        assert!(result.is_ok(), "Installation should succeed");
    }

    /// When the AWS provider is not installed, ensure_capi should
    /// install with the "aws" provider name.
    #[tokio::test]
    async fn when_aws_provider_missing_install_with_aws_name() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("awsclusters"))
            .returning(|_, _| Ok(false));

        installer
            .expect_install()
            .with(eq("aws"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&detector, &installer, &ProviderType::Aws).await;

        assert!(result.is_ok());
    }

    /// When the GCP provider is not installed, ensure_capi should
    /// install with the "gcp" provider name.
    #[tokio::test]
    async fn when_gcp_provider_missing_install_with_gcp_name() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("gcpclusters"))
            .returning(|_, _| Ok(false));

        installer
            .expect_install()
            .with(eq("gcp"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&detector, &installer, &ProviderType::Gcp).await;

        assert!(result.is_ok());
    }

    /// When the Azure provider is not installed, ensure_capi should
    /// install with the "azure" provider name.
    #[tokio::test]
    async fn when_azure_provider_missing_install_with_azure_name() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("azureclusters"))
            .returning(|_, _| Ok(false));

        installer
            .expect_install()
            .with(eq("azure"))
            .times(1)
            .returning(|_| Ok(()));

        let result = ensure_capi_installed_with(&detector, &installer, &ProviderType::Azure).await;

        assert!(result.is_ok());
    }

    /// When installation fails, the error should propagate to the caller
    /// with context about what went wrong.
    #[tokio::test]
    async fn when_installation_fails_error_propagates() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .with(eq("infrastructure.cluster.x-k8s.io"), eq("dockerclusters"))
            .returning(|_, _| Ok(false));

        installer.expect_install().with(eq("docker")).returning(|_| {
            Err(Error::CapiInstallation(
                "clusterctl init failed: timeout".to_string(),
            ))
        });

        let result =
            ensure_capi_installed_with(&detector, &installer, &ProviderType::Docker).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("timeout"),
            "Error should contain failure reason"
        );
    }

    /// When detection fails during ensure_capi, the error should
    /// propagate before any installation is attempted.
    #[tokio::test]
    async fn when_detection_fails_during_ensure_no_installation_attempted() {
        let mut detector = MockCapiDetector::new();
        let mut installer = MockCapiInstaller::new();

        detector
            .expect_crd_exists()
            .returning(|_, _| Err(Error::CapiInstallation("API server unavailable".to_string())));

        // CRITICAL: installer should NOT be called when detection fails
        installer.expect_install().never();

        let result =
            ensure_capi_installed_with(&detector, &installer, &ProviderType::Docker).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unavailable"));
    }

    // ==========================================================================
    // Story: ClusterctlInstaller Construction
    //
    // The ClusterctlInstaller is a lightweight wrapper around the clusterctl
    // CLI tool. It should be easy to construct and should implement Default
    // for convenience in production code.
    // ==========================================================================

    /// When creating a ClusterctlInstaller, both new() and Default should
    /// produce equivalent instances that can be used for CAPI installation.
    #[test]
    fn clusterctl_installer_can_be_constructed_via_new_or_default() {
        let _via_new = ClusterctlInstaller::new();
        let _via_default: ClusterctlInstaller = Default::default();

        // Both should compile and create valid instances
        // The installer is a unit struct, so equality isn't meaningful,
        // but construction should succeed
    }

    // ==========================================================================
    // Story: Provider CRD Info for All Providers
    //
    // Each provider type must map to consistent CRD information that follows
    // Kubernetes naming conventions and the CAPI infrastructure API group.
    // ==========================================================================

    /// All providers should use the same infrastructure API group but have
    /// unique kind and plural names that follow Kubernetes conventions.
    #[test]
    fn all_providers_share_same_api_group_with_unique_kinds() {
        let providers = [
            ProviderType::Docker,
            ProviderType::Aws,
            ProviderType::Gcp,
            ProviderType::Azure,
        ];

        let expected_group = "infrastructure.cluster.x-k8s.io";

        for provider in &providers {
            let info = provider_crd_info(provider);

            assert_eq!(
                info.group, expected_group,
                "{:?} should use the infrastructure API group",
                provider
            );

            // Kind should end with "Cluster"
            assert!(
                info.kind.ends_with("Cluster"),
                "{:?} kind '{}' should end with 'Cluster'",
                provider,
                info.kind
            );

            // Plural should end with "clusters" and be lowercase
            assert!(
                info.plural.ends_with("clusters"),
                "{:?} plural '{}' should end with 'clusters'",
                provider,
                info.plural
            );
            assert_eq!(
                info.plural,
                info.plural.to_lowercase(),
                "{:?} plural should be lowercase",
                provider
            );
        }
    }

    /// Provider CRD info should be consistent for the same provider type.
    /// This ensures idempotent behavior in reconciliation.
    #[test]
    fn provider_crd_info_is_consistent_for_same_provider() {
        // Multiple calls should return the same info
        let info1 = provider_crd_info(&ProviderType::Docker);
        let info2 = provider_crd_info(&ProviderType::Docker);

        assert_eq!(info1.group, info2.group);
        assert_eq!(info1.kind, info2.kind);
        assert_eq!(info1.plural, info2.plural);
    }
}
