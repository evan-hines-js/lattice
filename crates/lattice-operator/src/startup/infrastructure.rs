//! Infrastructure installation utilities
//!
//! Provides functions for installing infrastructure components like Istio, Cilium, and CAPI.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use crate::capi::{ensure_capi_installed, CapiProviderConfig, ClusterctlInstaller};
use crate::crd::{BootstrapProvider, CloudProvider, LatticeCluster, ProviderType};
use crate::infra::bootstrap::{self, InfrastructureConfig};

use super::manifests::apply_manifests;

/// Reconcile infrastructure components
///
/// Ensures all infrastructure is installed. Server-side apply handles idempotency.
/// This runs on every controller startup, applying the latest manifests.
///
/// IMPORTANT: Uses the SAME generate_all() function as the bootstrap webhook.
/// This guarantees upgrades work by changing Lattice version - on restart,
/// the operator re-applies identical infrastructure manifests.
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `cedar_enabled` - Enable Cedar ExtAuth integration with Istio
pub async fn ensure_infrastructure(client: &Client, cedar_enabled: bool) -> anyhow::Result<()> {
    let is_bootstrap_cluster = std::env::var("LATTICE_ROOT_INSTALL").is_ok()
        || std::env::var("LATTICE_BOOTSTRAP_CLUSTER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

    tracing::info!(
        is_bootstrap_cluster,
        cedar_enabled,
        "Applying infrastructure manifests (server-side apply)..."
    );

    if is_bootstrap_cluster {
        // Bootstrap cluster (KIND): Use generate_core() + clusterctl init
        // This is a temporary cluster that doesn't need full self-management infra
        // Use "bootstrap" as the cluster name for the trust domain
        let manifests = bootstrap::generate_core("bootstrap", true, cedar_enabled).await;
        tracing::info!(count = manifests.len(), "applying core infrastructure");
        apply_manifests(client, &manifests).await?;

        tracing::info!("Installing CAPI on bootstrap cluster...");
        ensure_capi_on_bootstrap(client).await?;
    } else {
        // Workload cluster: Read provider/bootstrap from LatticeCluster CRD
        // This is the source of truth - same values used by bootstrap webhook
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        let list = clusters.list(&ListParams::default()).await?;

        let (provider, bootstrap, cluster_name) = if let Some(cluster) = list.items.first() {
            let p = cluster.spec.provider.provider_type();
            let b = cluster.spec.provider.kubernetes.bootstrap.clone();
            let name = cluster
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| "default".to_string());
            tracing::info!(provider = ?p, bootstrap = ?b, cluster = %name, "read config from LatticeCluster CRD");
            (p, b, name)
        } else {
            // No LatticeCluster yet - use defaults (shouldn't happen on real clusters)
            tracing::warn!("no LatticeCluster found, using defaults");
            (
                ProviderType::Docker,
                BootstrapProvider::Kubeadm,
                "default".to_string(),
            )
        };

        let config = InfrastructureConfig {
            provider,
            bootstrap,
            cluster_name,
            skip_cilium_policies: false,
            cedar_enabled,
        };

        let manifests = bootstrap::generate_all(&config).await;
        tracing::info!(
            count = manifests.len(),
            "applying all infrastructure (same as bootstrap webhook)"
        );
        apply_manifests(client, &manifests).await?;
    }

    tracing::info!("Infrastructure installation complete");
    Ok(())
}

/// Install CAPI on the bootstrap cluster.
///
/// The bootstrap cluster needs CAPI installed BEFORE a LatticeCluster is created,
/// because the installer waits for CAPI CRDs to be available. Without this, the
/// installer hangs in Phase 2 waiting for CRDs that would only be installed when
/// a LatticeCluster is reconciled (Phase 3).
///
/// Uses LATTICE_PROVIDER env var to determine which infrastructure provider to install.
/// Reads CloudProvider CRD (created by install command) for credentials.
///
/// NOTE: CloudProvider is created by the install command AFTER the operator starts,
/// so this function waits for it to exist before proceeding.
async fn ensure_capi_on_bootstrap(client: &Client) -> anyhow::Result<()> {
    let provider_str = std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());
    let provider_ref =
        std::env::var("LATTICE_PROVIDER_REF").unwrap_or_else(|_| provider_str.clone());

    let infrastructure = match provider_str.to_lowercase().as_str() {
        "docker" => ProviderType::Docker,
        "proxmox" => ProviderType::Proxmox,
        "openstack" => ProviderType::OpenStack,
        "aws" => ProviderType::Aws,
        "gcp" => ProviderType::Gcp,
        "azure" => ProviderType::Azure,
        other => return Err(anyhow::anyhow!("unknown LATTICE_PROVIDER: {}", other)),
    };

    tracing::info!(infrastructure = %provider_str, "Installing CAPI providers for bootstrap cluster");

    // Wait for CloudProvider to be created by install command
    let cloud_providers: Api<CloudProvider> = Api::namespaced(client.clone(), "lattice-system");
    tracing::info!(provider_ref = %provider_ref, "Waiting for CloudProvider...");
    let cp = loop {
        match cloud_providers.get(&provider_ref).await {
            Ok(cp) => break cp,
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::debug!(provider_ref = %provider_ref, "CloudProvider not found, waiting...");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to get CloudProvider '{}': {}",
                    provider_ref,
                    e
                ));
            }
        }
    };
    tracing::info!(provider_ref = %provider_ref, "CloudProvider found");

    // Copy credentials to CAPI provider namespace if present
    if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
        crate::capi::copy_credentials_to_provider_namespace(client, infrastructure, secret_ref)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to copy provider credentials: {}", e))?;
    }

    let config = CapiProviderConfig::new(infrastructure)
        .map_err(|e| anyhow::anyhow!("Failed to create CAPI config: {}", e))?;
    ensure_capi_installed(&ClusterctlInstaller::new(), &config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = %provider_str, "CAPI providers installed successfully");
    Ok(())
}
