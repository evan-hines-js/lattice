//! Cell service utilities
//!
//! Provides functions for managing the cell LoadBalancer service that children connect to.

use k8s_openapi::api::core::v1::Service;
use kube::api::{Api, PostParams};
use kube::Client;

use lattice_common::kube_utils::{build_cell_internal_service, build_cell_service};
use lattice_common::{CELL_INTERNAL_SERVICE_NAME, CELL_SERVICE_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use lattice_crd::crd::{LatticeCluster, ProviderType};

use super::polling::{
    wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT, LOAD_BALANCER_POLL_INTERVAL,
};

/// Ensure both cell Services exist: the externally-typed one for
/// bootstrap/gRPC/auth-proxy and the in-cluster ClusterIP for the
/// CAPI proxy.
///
/// `service_type` is the user-configured `parent_config.service.type`
/// from the LatticeCluster. The internal proxy Service is always
/// ClusterIP regardless.
pub async fn ensure_cell_service_exists(
    client: &Client,
    bootstrap_port: u16,
    grpc_port: u16,
    proxy_port: u16,
    service_type: &str,
    provider_type: ProviderType,
) -> anyhow::Result<()> {
    let api: Api<Service> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    if api.get(CELL_SERVICE_NAME).await.is_err() {
        let service = build_cell_service(bootstrap_port, grpc_port, service_type, &provider_type);
        api.create(&PostParams::default(), &service).await?;
        tracing::info!(
            bootstrap_port,
            grpc_port,
            service_type,
            "Created {CELL_SERVICE_NAME} Service"
        );
    }

    if api.get(CELL_INTERNAL_SERVICE_NAME).await.is_err() {
        let internal = build_cell_internal_service(proxy_port);
        api.create(&PostParams::default(), &internal).await?;
        tracing::info!(
            proxy_port,
            "Created {CELL_INTERNAL_SERVICE_NAME} ClusterIP Service"
        );
    }

    Ok(())
}

/// Discover the cell service host from the LoadBalancer Service.
///
/// Returns:
/// - `Ok(Some(host))` - LoadBalancer has an assigned address
/// - `Ok(None)` - Service exists but no address yet (waiting for cloud provider)
/// - `Err(msg)` - API error (transient, should retry)
pub async fn discover_cell_host(client: &Client) -> Result<Option<String>, String> {
    let services: Api<Service> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let svc = services
        .get(CELL_SERVICE_NAME)
        .await
        .map_err(|e| format!("failed to get {CELL_SERVICE_NAME} Service: {e}"))?;

    let Some(status) = svc.status else {
        return Ok(None);
    };
    let Some(lb) = status.load_balancer else {
        return Ok(None);
    };
    let Some(ingress) = lb.ingress else {
        return Ok(None);
    };
    let Some(first) = ingress.first() else {
        return Ok(None);
    };

    // Prefer hostname (AWS NLB) over IP
    Ok(first.hostname.clone().or_else(|| first.ip.clone()))
}

/// Get extra SANs for cell server TLS certificate.
///
/// If this cluster provisions children (has parent_config), creates the cell
/// LoadBalancer Service and waits for an external address. Returns the address
/// to include in TLS SANs so children can connect via HTTPS.
pub async fn get_cell_server_sans(
    client: &Client,
    cluster_name: &Option<String>,
    is_bootstrap_cluster: bool,
) -> Vec<String> {
    if is_bootstrap_cluster {
        tracing::info!("Bootstrap cluster, using default SANs");
        return vec![];
    }

    let Some(ref name) = cluster_name else {
        return vec![];
    };

    // Wait for our LatticeCluster to exist
    tracing::info!(cluster = %name, "Waiting for LatticeCluster...");
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = match wait_for_resource(
        &format!("LatticeCluster '{}'", name),
        DEFAULT_RESOURCE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        || {
            let clusters = clusters.clone();
            let name = name.clone();
            async move {
                match clusters.get(&name).await {
                    Ok(c) => Ok(Some(c)),
                    Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
                    Err(e) => Err(format!("API error: {}", e)),
                }
            }
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to wait for LatticeCluster");
            return vec![];
        }
    };
    tracing::info!(cluster = %name, "LatticeCluster found");

    // If we don't provision children, no need for cell host in SANs
    let Some(ref parent_config) = cluster.spec.parent_config else {
        tracing::info!("No parent_config, cluster doesn't provision children");
        return vec![];
    };

    // Create the cell Services (external + internal proxy)
    let provider_type = cluster.spec.provider.provider_type();
    tracing::info!(?provider_type, "Creating cell Services...");
    if let Err(e) = ensure_cell_service_exists(
        client,
        parent_config.bootstrap_port,
        parent_config.grpc_port,
        parent_config.proxy_port,
        &parent_config.service.type_,
        provider_type,
    )
    .await
    {
        tracing::warn!(error = %e, "Failed to create cell Service");
    }

    // Wait for LoadBalancer to get external address
    tracing::info!("Waiting for cell LoadBalancer address...");
    match wait_for_resource(
        "cell LoadBalancer address",
        DEFAULT_RESOURCE_TIMEOUT,
        LOAD_BALANCER_POLL_INTERVAL,
        || async { discover_cell_host(client).await },
    )
    .await
    {
        Ok(host) => {
            tracing::info!(host = %host, "Cell host discovered, adding to TLS SANs");
            vec![host]
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to wait for cell LoadBalancer address");
            vec![]
        }
    }
}
