//! Infrastructure installation utilities
//!
//! Provides functions for installing infrastructure components like Istio, Cilium, and CAPI.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{
    apply_manifests_with_discovery, ApplyOptions, ParentConfig, LATTICE_SYSTEM_NAMESPACE,
};

use lattice_capi::installer::{
    copy_credentials_to_provider_namespace, CapiInstaller, CapiProviderConfig,
};
use lattice_common::crd::{CloudProvider, LatticeCluster, ProviderType};
use lattice_infra::bootstrap::{self, InfrastructureConfig};

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Apply manifests with infinite retry and exponential backoff.
///
/// During startup, the API server's discovery endpoint returns 503 while
/// aggregated APIServices (e.g., KEDA metrics) initialize. The operator
/// cannot proceed without infrastructure, so we retry forever.
async fn apply_manifests_with_retry(
    client: &Client,
    manifests: &[String],
    context: &str,
) -> anyhow::Result<()> {
    let config = RetryConfig {
        initial_delay: Duration::from_secs(2),
        ..RetryConfig::infinite()
    };

    retry_with_backoff(&config, context, || {
        let client = client.clone();
        async move { apply_manifests_with_discovery(&client, manifests, &ApplyOptions::default()).await }
    })
    .await
    .map_err(Into::into)
}

/// Reconcile Service-mode infrastructure (Istio, Gateway API, ESO, Cilium policies)
///
/// Reads config from env vars instead of LatticeCluster CRD, so it can run
/// independently in Service mode without requiring a LatticeCluster to exist.
pub async fn ensure_service_infrastructure(client: &Client) -> anyhow::Result<()> {
    let cluster_name = std::env::var("LATTICE_CLUSTER_NAME").unwrap_or_else(|_| "default".into());
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(
        cluster = %cluster_name,
        is_bootstrap,
        "Applying Service mode infrastructure..."
    );

    let config = InfrastructureConfig {
        cluster_name,
        skip_service_mesh: false,
        skip_cilium_policies: is_bootstrap,
        ..Default::default()
    };

    let manifests = bootstrap::generate_core(&config)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate service infrastructure: {}", e))?;
    tracing::info!(count = manifests.len(), "applying service infrastructure");
    apply_manifests_with_retry(client, &manifests, "service infrastructure").await?;

    tracing::info!("Service infrastructure installation complete");
    Ok(())
}

/// Reconcile Cluster-mode infrastructure (CAPI, operator network policies)
///
/// Reads provider/bootstrap from LatticeCluster CRD (the source of truth).
/// Infrastructure is NOT included in the bootstrap bundle (to reduce network
/// pressure from simultaneous image pulls on new nodes). The operator installs
/// everything once it's running. Server-side apply handles idempotency.
pub async fn ensure_cluster_infrastructure(
    client: &Client,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(
        is_bootstrap_cluster = is_bootstrap,
        "Applying infrastructure manifests (server-side apply)..."
    );

    if is_bootstrap {
        // Bootstrap cluster (KIND): Skip Cilium policies, use "bootstrap" as cluster name
        // This is a temporary cluster that doesn't need full self-management infra
        let config = InfrastructureConfig {
            cluster_name: "bootstrap".to_string(),
            skip_cilium_policies: true,
            skip_service_mesh: true,
            monitoring: false,
            backups: false,
            external_secrets: false,
            ..Default::default()
        };
        let manifests = bootstrap::generate_core(&config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate core infrastructure: {}", e))?;
        tracing::info!(count = manifests.len(), "applying core infrastructure");
        apply_manifests_with_retry(client, &manifests, "core infrastructure").await?;

        tracing::info!("Installing CAPI on bootstrap cluster...");
        ensure_capi_on_bootstrap(client, installer).await?;
    } else {
        // Workload cluster: Read provider/bootstrap from LatticeCluster CRD
        // This is the source of truth - same values used by bootstrap webhook
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        let list = clusters.list(&ListParams::default()).await?;

        let cluster = list.items.first().ok_or_else(|| {
            anyhow::anyhow!(
                "no LatticeCluster found - workload clusters must have a LatticeCluster CRD \
                 (pivoted from parent). This indicates a failed or incomplete pivot."
            )
        })?;

        let mut config = InfrastructureConfig::from(cluster);

        // Read parent config if it exists (indicates we have an upstream parent cell)
        if let Ok(Some(parent)) = ParentConfig::read(client).await {
            config.parent_host = Some(parent.endpoint.host);
            config.parent_grpc_port = parent.endpoint.grpc_port;
        }

        tracing::info!(
            provider = ?config.provider,
            bootstrap = ?config.bootstrap,
            cluster = %config.cluster_name,
            parent_host = ?config.parent_host,
            "read config from LatticeCluster CRD"
        );

        let manifests = bootstrap::generate_core(&config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate infrastructure manifests: {}", e))?;
        tracing::info!(count = manifests.len(), "applying infrastructure manifests");
        apply_manifests_with_retry(client, &manifests, "full infrastructure").await?;

        // Install CAPI providers so this cluster can self-manage.
        // Pivot moves CAPI *resources* but not the provider controllers.
        let provider_type = cluster.spec.provider.provider_type();
        let cloud_providers: Api<CloudProvider> =
            Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let cp = cloud_providers.get(&cluster.spec.provider_ref).await.ok();
        ensure_capi(client, provider_type, cp.as_ref(), installer).await?;
    }

    tracing::info!("Infrastructure installation complete");
    Ok(())
}

/// Install CAPI on the bootstrap cluster.
///
/// The bootstrap cluster needs CAPI installed BEFORE a LatticeCluster is created.
/// Uses LATTICE_PROVIDER env var to determine which infrastructure provider to install.
///
/// NOTE: CloudProvider is created by the install command AFTER the operator starts,
/// so this function waits for it to exist before proceeding.
async fn ensure_capi_on_bootstrap(
    client: &Client,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    let provider_str = std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());
    let provider_ref =
        std::env::var("LATTICE_PROVIDER_REF").unwrap_or_else(|_| provider_str.clone());

    let infrastructure: ProviderType = provider_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid LATTICE_PROVIDER '{}': {}", provider_str, e))?;

    // Wait for CloudProvider to be created by install command
    let cloud_providers: Api<CloudProvider> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    tracing::info!(provider_ref = %provider_ref, "Waiting for CloudProvider...");
    let cp = wait_for_resource(
        &format!("CloudProvider '{}'", provider_ref),
        DEFAULT_RESOURCE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        || {
            let cloud_providers = cloud_providers.clone();
            let provider_ref = provider_ref.clone();
            async move {
                match cloud_providers.get(&provider_ref).await {
                    Ok(cp) => Ok(Some(cp)),
                    Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
                    Err(e) => Err(format!("API error: {}", e)),
                }
            }
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    tracing::info!(provider_ref = %provider_ref, "CloudProvider found");

    ensure_capi(client, infrastructure, Some(&cp), installer).await
}

/// Install CAPI providers with optional credential copying.
///
/// Shared by both bootstrap and self-managed cluster paths.
/// The caller is responsible for resolving the CloudProvider (blocking wait on
/// bootstrap, best-effort lookup on self-managed clusters).
async fn ensure_capi(
    client: &Client,
    provider_type: ProviderType,
    cloud_provider: Option<&CloudProvider>,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    tracing::info!(infrastructure = ?provider_type, "Installing CAPI providers");

    if let Some(cp) = cloud_provider {
        if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
            copy_credentials_to_provider_namespace(client, provider_type, secret_ref)
                .await
                .map_err(|e| anyhow::anyhow!("failed to copy provider credentials: {}", e))?;
        }
    }

    let config = CapiProviderConfig::new(provider_type)
        .map_err(|e| anyhow::anyhow!("failed to create CAPI config: {}", e))?;
    installer
        .ensure(&config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = ?provider_type, "CAPI providers installed successfully");
    Ok(())
}
