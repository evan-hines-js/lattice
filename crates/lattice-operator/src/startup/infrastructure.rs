//! Infrastructure installation at operator startup.
//!
//! Two stages:
//! - [`ensure_capi_infrastructure`] — blocking: installs CAPI (and its
//!   prereqs: cert-manager, ESO, local-webhook ClusterSecretStore). Must
//!   complete before the rest of the operator starts.
//! - [`spawn_general_infrastructure`] — background: applies the bootstrap
//!   manifests (Gateway API CRDs, operator mesh enrollment, cluster-access
//!   Cedar policy). Runs on a separate task; controllers don't wait on it.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::SharedConfig;
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use lattice_capi::installer::{ensure_capi_providers_for, CapiInstaller};
use lattice_crd::crd::{InfraProvider, LatticeCluster};
use lattice_infra::bootstrap;

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Install critical infrastructure (cert-manager + CAPI) that must complete
/// before controllers start.
///
/// cert-manager is applied as phase 0 of the phased infrastructure system
/// with its health gate (all deployments in cert-manager namespace ready).
/// CAPI providers are then installed via the native CAPI installer.
pub async fn ensure_capi_infrastructure(
    client: &Client,
    capi_installer: Option<&dyn CapiInstaller>,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    if config.is_bootstrap_cluster {
        if let Some(installer) = capi_installer {
            ensure_capi_on_bootstrap(client, installer, config).await?;
        }
    } else {
        let cluster = find_lattice_cluster(client, capi_installer.is_some()).await?;

        if let (Some(installer), Some(c)) = (capi_installer, &cluster) {
            let provider_type = c.spec.provider.provider_type();
            let cloud_providers: Api<InfraProvider> =
                Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
            let cp = cloud_providers.get(&c.spec.provider_ref).await.ok();
            ensure_capi_providers_for(
                client,
                installer,
                provider_type,
                cp.as_ref(),
                "lattice-operator",
            )
            .await
            .map_err(|e| anyhow::anyhow!("CAPI installation failed: {e}"))?;
        }
    }

    Ok(())
}

/// Install general infrastructure (Istio, ESO, VictoriaMetrics, etc.) in the
/// background. These components need workers to schedule, so they retry until
/// workers are available. Runs as a background task — does not block startup.
///
/// `cluster_mode` indicates whether a LatticeCluster CRD is expected (true for
/// cluster/all modes where CAPI was installed).
pub fn spawn_general_infrastructure(
    client: Client,
    cluster_mode: bool,
    config: SharedConfig,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move { ensure_general_infrastructure(&client, cluster_mode, &config).await })
}

/// Delay before starting background infrastructure to avoid competing with
/// controller startup for API server resources. Controllers need watches
/// established quickly; infrastructure manifests can wait.
const INFRA_STAGGER_DELAY: Duration = Duration::from_secs(5);

/// Apply bootstrap manifests (Gateway API CRDs + operator mesh enrollment +
/// cluster-access Cedar policy).
///
/// Bootstrap clusters have no mesh and skip everything. Non-bootstrap clusters
/// that opted out of services (`LatticeCluster.spec.services = false`) also
/// skip. Everyone else applies the full set.
async fn ensure_general_infrastructure(
    client: &Client,
    cluster_mode: bool,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    // Stagger to avoid competing with controller watch setup for API server capacity.
    // Controllers are starting concurrently and need to establish ~16 watches.
    tokio::time::sleep(INFRA_STAGGER_DELAY).await;

    let skip_mesh = resolve_skip_mesh(client, cluster_mode, config).await;
    tracing::info!(skip_mesh, "applying bootstrap manifests");

    let manifests = bootstrap::bootstrap_manifests(skip_mesh)
        .map_err(|e| anyhow::anyhow!("failed to generate bootstrap manifests: {e}"))?;
    if manifests.is_empty() {
        return Ok(());
    }

    lattice_common::apply_manifests(
        client,
        &manifests,
        &lattice_common::ApplyOptions::default(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to apply bootstrap manifests: {e}"))?;

    Ok(())
}

/// Decide whether this boot should skip mesh-related bootstrap manifests.
///
/// Bootstrap clusters never have mesh. Otherwise we look for a LatticeCluster
/// and honor `spec.services`; if there's no cluster yet (pre-pivot race), we
/// default to keeping mesh on since that's the steady state.
async fn resolve_skip_mesh(
    client: &Client,
    cluster_mode: bool,
    config: &SharedConfig,
) -> bool {
    if config.is_bootstrap_cluster {
        return true;
    }
    match find_lattice_cluster(client, cluster_mode).await {
        Ok(Some(c)) => !c.spec.services,
        _ => false,
    }
}

/// Find the LatticeCluster instance.
///
/// When `required` is true (cluster/all mode), retries forever with
/// exponential backoff until the API server registers the CRD and an
/// instance appears (the CRD definition may have just been applied).
/// When `required` is false (service-only mode), returns `None` immediately
/// if no instance exists.
async fn find_lattice_cluster(
    client: &Client,
    required: bool,
) -> anyhow::Result<Option<LatticeCluster>> {
    let clusters: Api<LatticeCluster> = Api::all(client.clone());

    if !required {
        return Ok(clusters
            .list(&ListParams::default())
            .await
            .ok()
            .and_then(|list| list.items.into_iter().next()));
    }

    // Cluster/all mode: the LatticeCluster must exist (pivoted from parent).
    // Retry forever — the API server may still be registering the CRD schema.
    let retry = RetryConfig {
        initial_delay: Duration::from_secs(1),
        ..RetryConfig::default()
    };
    retry_with_backoff(&retry, "find LatticeCluster", || {
        let clusters = clusters.clone();
        async move {
            match clusters.list(&ListParams::default()).await {
                Ok(list) => match list.items.into_iter().next() {
                    Some(c) => Ok(c),
                    None => Err(String::from("no LatticeCluster instance found yet")),
                },
                Err(e) => Err(format!("API error: {e}")),
            }
        }
    })
    .await
    .map(Some)
    .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Install CAPI on the bootstrap cluster.
///
/// Bootstrap sequence:
/// - Wait for InfraProvider (created by `lattice install`)
/// - cert-manager (ESO and CAPI depend on it)
/// - ESO + local webhook ClusterSecretStore (InfraProvider credentials flow through ESO)
/// - Wait for ESO to sync the InfraProvider's credentials secret
/// - CAPI providers (reads the ESO-synced credentials)
async fn ensure_capi_on_bootstrap(
    client: &Client,
    installer: &dyn CapiInstaller,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    let provider_ref = config.provider_ref.clone();
    let infrastructure = config.provider;

    let cloud_providers: Api<InfraProvider> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    tracing::info!(provider_ref = %provider_ref, "Waiting for InfraProvider...");
    let cp = wait_for_resource(
        &format!("InfraProvider '{}'", provider_ref),
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

    ensure_capi_providers_for(
        client,
        installer,
        infrastructure,
        Some(&cp),
        "lattice-operator",
    )
    .await
    .map_err(|e| anyhow::anyhow!("CAPI installation failed: {e}"))
}
