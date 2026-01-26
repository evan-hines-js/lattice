//! Resource distribution for child clusters (cell-side)
//!
//! This module handles fetching resources from the parent cluster
//! to distribute to child clusters.

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::Client;
use thiserror::Error;
use tracing::debug;

use lattice_common::crd::{CloudProvider, SecretsProvider};
pub use lattice_common::DistributableResources;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Error type for resource distribution
#[derive(Debug, Error)]
pub enum ResourceError {
    /// Internal error during resource fetching
    #[error("internal error: {0}")]
    Internal(String),
}

/// Fetch all resources to distribute to child clusters.
pub async fn fetch_distributable_resources(
    client: &Client,
) -> Result<DistributableResources, ResourceError> {
    use std::collections::HashSet;

    let lp = ListParams::default();
    let mut secret_names: HashSet<String> = HashSet::new();

    // Fetch CloudProvider CRDs
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let cp_list = cp_api
        .list(&lp)
        .await
        .map_err(|e| ResourceError::Internal(format!("failed to list CloudProviders: {}", e)))?;

    let mut cloud_providers = Vec::new();
    for cp in &cp_list.items {
        let yaml = serialize_for_distribution(cp)?;
        cloud_providers.push(yaml);
        if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
            secret_names.insert(secret_ref.name.clone());
        }
    }

    // Fetch SecretsProvider CRDs
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let sp_list = sp_api
        .list(&lp)
        .await
        .map_err(|e| ResourceError::Internal(format!("failed to list SecretsProviders: {}", e)))?;

    let mut secrets_providers = Vec::new();
    for sp in &sp_list.items {
        let yaml = serialize_for_distribution(sp)?;
        secrets_providers.push(yaml);
        if let Some(ref secret_ref) = sp.spec.credentials_secret_ref {
            secret_names.insert(secret_ref.name.clone());
        }
    }

    // Fetch referenced secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets = Vec::new();
    for name in &secret_names {
        match secret_api.get(name).await {
            Ok(secret) => {
                let yaml = serialize_for_distribution(&secret)?;
                secrets.push(yaml);
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                debug!(secret = %name, "Referenced secret not found, skipping");
            }
            Err(e) => {
                return Err(ResourceError::Internal(format!(
                    "failed to get secret {}: {}",
                    name, e
                )));
            }
        }
    }

    debug!(
        cloud_providers = cloud_providers.len(),
        secrets_providers = secrets_providers.len(),
        secrets = secrets.len(),
        "fetched distributable resources"
    );

    Ok(DistributableResources {
        cloud_providers,
        secrets_providers,
        secrets,
    })
}

/// Serialize a Kubernetes resource for distribution, stripping cluster-specific metadata
fn serialize_for_distribution<T: serde::Serialize + Clone + kube::ResourceExt>(
    resource: &T,
) -> Result<Vec<u8>, ResourceError> {
    let mut clean = resource.clone();
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    serde_yaml::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| ResourceError::Internal(format!("failed to serialize resource: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distributable_resources_is_empty() {
        let empty = DistributableResources::default();
        assert!(empty.is_empty());

        let with_cp = DistributableResources {
            cloud_providers: vec![vec![1, 2, 3]],
            ..Default::default()
        };
        assert!(!with_cp.is_empty());
    }
}
