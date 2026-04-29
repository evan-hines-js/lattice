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
        let cluster = find_lattice_cluster(client, config, capi_installer.is_some()).await?;

        if let (Some(installer), Some(c)) = (capi_installer, &cluster) {
            let provider_type = c.spec.provider.provider_type();
            let provider_ref = c.spec.provider_ref.clone();
            let cloud_providers: Api<InfraProvider> =
                Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

            // Wait for the InfraProvider to arrive from the parent via the
            // distribute-label sync. Tolerating a 404 here (which the old
            // `.ok()` did) meant the CAPI provider Deployment got applied
            // without imagePullSecrets / credentials injected — whatever
            // the InfraProvider.spec carries is needed at apply time and
            // never backfilled later.
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
                provider_type,
                Some(&cp),
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

    lattice_common::apply_manifests_with_retry(
        client,
        &manifests,
        &lattice_common::ApplyOptions::default(),
        &RetryConfig::install(),
        "operator bootstrap manifests",
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
async fn resolve_skip_mesh(client: &Client, cluster_mode: bool, config: &SharedConfig) -> bool {
    if config.is_bootstrap_cluster {
        return true;
    }
    match find_lattice_cluster(client, config, cluster_mode).await {
        Ok(Some(c)) => !c.spec.services,
        _ => false,
    }
}

/// Find the local LatticeCluster instance by name.
///
/// Looks up `LATTICE_CLUSTER_NAME` rather than picking the first
/// LatticeCluster the apiserver returns: a cell that hosts sibling
/// LatticeCluster CRs (e.g. an edge cluster also tracking its
/// children) lists more than one, and `.list().next()` would silently
/// pick whichever sorts first — feeding the wrong `status.endpoint`
/// into Cilium and breaking worker-pod auth.
///
/// When `required` is true (cluster/all mode), retries forever with
/// exponential backoff until the API server registers the CRD and the
/// named instance appears (the CRD definition may have just been
/// applied). When `required` is false, returns `None` immediately if
/// the named CR doesn't exist.
async fn find_lattice_cluster(
    client: &Client,
    config: &SharedConfig,
    required: bool,
) -> anyhow::Result<Option<LatticeCluster>> {
    let cluster_name = config.cluster_name.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "LATTICE_CLUSTER_NAME must be set on non-bootstrap clusters \
             so the operator looks up its own LatticeCluster CR by name"
        )
    })?;
    let clusters: Api<LatticeCluster> = Api::all(client.clone());

    if !required {
        return Ok(clusters.get_opt(cluster_name).await.ok().flatten());
    }

    // Cluster/all mode: the LatticeCluster must exist (pivoted from parent).
    // Retry forever — the API server may still be registering the CRD schema.
    let retry = RetryConfig {
        initial_delay: Duration::from_secs(1),
        ..RetryConfig::default()
    };
    let cluster_name = cluster_name.to_string();
    retry_with_backoff(&retry, "find LatticeCluster", || {
        let clusters = clusters.clone();
        let cluster_name = cluster_name.clone();
        async move {
            match clusters.get_opt(&cluster_name).await {
                Ok(Some(c)) => Ok(c),
                Ok(None) => Err(format!("LatticeCluster '{cluster_name}' not found yet")),
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
