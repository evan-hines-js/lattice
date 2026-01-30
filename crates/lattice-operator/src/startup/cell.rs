//! Cell service utilities
//!
//! Provides functions for managing the cell LoadBalancer service that children connect to.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, PostParams};
use kube::Client;

use crate::crd::{LatticeCluster, ProviderType};

/// Ensure the cell LoadBalancer Service exists.
///
/// - Cloud providers: `load_balancer_ip` is None, cloud assigns address
/// - On-prem: `load_balancer_ip` is set from parent_config.host, Cilium L2 announces it
pub async fn ensure_cell_service_exists(
    client: &Client,
    load_balancer_ip: Option<String>,
    bootstrap_port: u16,
    grpc_port: u16,
    proxy_port: u16,
    provider_type: ProviderType,
) -> anyhow::Result<()> {
    let api: Api<Service> = Api::namespaced(client.clone(), "lattice-system");

    // Check if it already exists
    if api.get("lattice-cell").await.is_ok() {
        tracing::debug!("lattice-cell Service already exists");
        return Ok(());
    }

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lattice-operator".to_string());

    // Cloud-specific LoadBalancer annotations
    let annotations = provider_type.load_balancer_annotations();

    let service = Service {
        metadata: ObjectMeta {
            name: Some("lattice-cell".to_string()),
            namespace: Some("lattice-system".to_string()),
            labels: Some(labels.clone()),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("LoadBalancer".to_string()),
            selector: Some(labels),
            load_balancer_ip: load_balancer_ip.clone(),
            ports: Some(vec![
                ServicePort {
                    name: Some("bootstrap".to_string()),
                    port: bootstrap_port as i32,
                    target_port: Some(IntOrString::Int(bootstrap_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("grpc".to_string()),
                    port: grpc_port as i32,
                    target_port: Some(IntOrString::Int(grpc_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("proxy".to_string()),
                    port: proxy_port as i32,
                    target_port: Some(IntOrString::Int(proxy_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    api.create(&PostParams::default(), &service).await?;
    tracing::info!(
        load_balancer_ip = ?load_balancer_ip,
        bootstrap_port,
        grpc_port,
        proxy_port,
        "Created lattice-cell LoadBalancer Service"
    );

    Ok(())
}

/// Discover the cell service host from the LoadBalancer Service.
///
/// Returns:
/// - `Ok(Some(host))` - LoadBalancer has an assigned address
/// - `Ok(None)` - Service exists but no address yet (waiting for cloud provider)
/// - `Err(msg)` - API error (transient, should retry)
pub async fn discover_cell_host(client: &Client) -> Result<Option<String>, String> {
    let services: Api<Service> = Api::namespaced(client.clone(), "lattice-system");
    let svc = services
        .get("lattice-cell")
        .await
        .map_err(|e| format!("failed to get lattice-cell Service: {}", e))?;

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
    let cluster = loop {
        match clusters.get(name).await {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "LatticeCluster not found, retrying...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };
    tracing::info!(cluster = %name, "LatticeCluster found");

    // If we don't provision children, no need for cell host in SANs
    let Some(ref parent_config) = cluster.spec.parent_config else {
        tracing::info!("No parent_config, cluster doesn't provision children");
        return vec![];
    };

    // Create the cell LoadBalancer Service
    let provider_type = cluster.spec.provider.provider_type();
    tracing::info!(?provider_type, "Creating cell LoadBalancer Service...");
    if let Err(e) = ensure_cell_service_exists(
        client,
        parent_config.host.clone(),
        parent_config.bootstrap_port,
        parent_config.grpc_port,
        parent_config.proxy_port,
        provider_type,
    )
    .await
    {
        tracing::warn!(error = %e, "Failed to create cell Service");
    }

    // Wait for LoadBalancer to get external address
    tracing::info!("Waiting for cell LoadBalancer address...");
    loop {
        match discover_cell_host(client).await {
            Ok(Some(host)) => {
                tracing::info!(host = %host, "Cell host discovered, adding to TLS SANs");
                return vec![host];
            }
            Ok(None) => {
                // Not yet assigned, keep waiting
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to discover cell host, retrying...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
