//! Infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests. Used by:
//! - Bootstrap webhook: pre-installs everything in parallel with operator
//! - Operator startup: re-applies (idempotent via server-side apply)
//!
//! Server-side apply handles idempotency - no need to check if installed.

pub mod cilium;
pub mod eso;
pub mod istio;

use tracing::{debug, info};

use lattice_common::crd::{BootstrapProvider, ProviderType};

// Re-export submodule types
pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use istio::{IstioConfig, IstioReconciler};

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Cluster name for trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
}

/// Generate core infrastructure manifests (Istio, Gateway API)
///
/// Used by both operator startup and full cluster bootstrap.
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
///
/// # Arguments
/// * `cluster_name` - Cluster name for trust domain (lattice.{cluster}.local)
/// * `skip_cilium_policies` - Skip Cilium policies (true for kind/bootstrap clusters)
pub async fn generate_core(
    cluster_name: &str,
    skip_cilium_policies: bool,
) -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();

    // Istio ambient
    manifests.extend(generate_istio(cluster_name, skip_cilium_policies).await?);

    // Gateway API CRDs (required for Istio Gateway and waypoints)
    let gw_api = generate_gateway_api_crds()?;
    debug!(count = gw_api.len(), "generated Gateway API CRDs");
    manifests.extend(gw_api);

    // External Secrets Operator (for Vault integration)
    manifests.extend(eso::generate_eso().await?);

    Ok(manifests)
}

/// Generate ALL infrastructure manifests for a self-managing cluster
///
/// Includes core infrastructure (Istio, Gateway API).
/// NOTE: cert-manager and CAPI providers are installed via `clusterctl init`,
/// which manages their lifecycle (including upgrades).
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm execution.
pub async fn generate_all(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    // Core infrastructure (Istio, Gateway API)
    // cert-manager and CAPI are installed via clusterctl init
    let manifests = generate_core(&config.cluster_name, config.skip_cilium_policies).await?;

    info!(
        total = manifests.len(),
        "generated infrastructure manifests"
    );
    Ok(manifests)
}

/// Generate Istio manifests
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution.
///
/// # Arguments
/// * `cluster_name` - Cluster name for trust domain (lattice.{cluster}.local)
/// * `skip_cilium_policies` - Skip Cilium policies (true for kind/bootstrap clusters)
pub async fn generate_istio(
    cluster_name: &str,
    skip_cilium_policies: bool,
) -> Result<Vec<String>, String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = IstioReconciler::new(cluster_name);
    let istio = reconciler.manifests().await?;
    manifests.extend(istio.iter().cloned());

    // Istio policies - serialize typed structs to JSON
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_peer_authentication())
            .expect("PeerAuthentication serialization"),
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_default_deny())
            .expect("AuthorizationPolicy serialization"),
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_waypoint_default_deny())
            .expect("AuthorizationPolicy serialization"),
    );
    manifests.push(
        serde_json::to_string_pretty(&IstioReconciler::generate_operator_allow_policy())
            .expect("AuthorizationPolicy serialization"),
    );

    // Cilium policies (skip on kind/bootstrap clusters) - serialize typed structs to JSON
    if !skip_cilium_policies {
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_ztunnel_allowlist())
                .expect("CiliumClusterwideNetworkPolicy serialization"),
        );
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_default_deny())
                .expect("CiliumClusterwideNetworkPolicy serialization"),
        );
        manifests.push(
            serde_json::to_string_pretty(&cilium::generate_waypoint_egress_policy())
                .expect("CiliumClusterwideNetworkPolicy serialization"),
        );
    }

    Ok(manifests)
}

/// Generate Gateway API CRDs
pub fn generate_gateway_api_crds() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let version = option_env!("GATEWAY_API_VERSION").unwrap_or("1.2.1");
    let crds_path = format!("{}/gateway-api-crds-v{}.yaml", charts_dir, version);

    let content =
        std::fs::read_to_string(&crds_path).map_err(|e| format!("read {}: {}", crds_path, e))?;

    Ok(split_yaml_documents(&content))
}

// Helpers

/// Get charts directory from environment or use default
pub fn charts_dir() -> String {
    std::env::var("LATTICE_CHARTS_DIR").unwrap_or_else(|_| {
        option_env!("LATTICE_CHARTS_DIR")
            .unwrap_or("/charts")
            .to_string()
    })
}

pub(crate) fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Split a multi-document YAML string into individual documents.
///
/// Only used for parsing external YAML sources (helm output, CRD files).
/// Filters out empty documents and comment-only blocks.
/// Normalizes output to always have `---` prefix for kubectl apply compatibility.
///
/// Note: JSON policies from our typed generators are added directly to manifest
/// lists and never go through this function.
pub fn split_yaml_documents(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|doc| doc.trim())
        .filter(|doc| !doc.is_empty() && doc.contains("kind:"))
        .map(|doc| {
            if doc.starts_with("---") {
                doc.to_string()
            } else {
                format!("---\n{}", doc)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_yaml_documents() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_namespace_yaml() {
        let ns = namespace_yaml("test");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: test"));
    }
}
