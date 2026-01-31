//! Resource distribution for child clusters (cell-side)
//!
//! This module handles fetching resources from the parent cluster
//! to distribute to child clusters. Resources are prefixed with the
//! origin cluster name for inherited policies/providers.

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::{Client, Resource};
use thiserror::Error;
use tracing::debug;

use lattice_common::crd::{CedarPolicy, CloudProvider, OIDCProvider, SecretsProvider};
pub use lattice_common::DistributableResources;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Label indicating which cluster originally created this resource
pub const ORIGIN_CLUSTER_LABEL: &str = "lattice.dev/origin-cluster";
/// Label indicating the original name before prefixing
pub const ORIGINAL_NAME_LABEL: &str = "lattice.dev/original-name";
/// Label indicating this resource was inherited from a parent
pub const INHERITED_LABEL: &str = "lattice.dev/inherited";

/// Error type for resource distribution
#[derive(Debug, Error)]
pub enum ResourceError {
    /// Internal error during resource fetching
    #[error("internal error: {0}")]
    Internal(String),
}

/// Fetch all resources to distribute to child clusters.
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `cluster_name` - Name of the current cluster (used for prefixing inherited resources)
pub async fn fetch_distributable_resources(
    client: &Client,
    cluster_name: &str,
) -> Result<DistributableResources, ResourceError> {
    use std::collections::HashSet;

    let lp = ListParams::default();
    let mut secret_names: HashSet<String> = HashSet::new();

    // Fetch CloudProvider CRDs
    // Handle 404 gracefully - CRD may not be installed on bootstrap clusters
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut cloud_providers = Vec::new();
    match cp_api.list(&lp).await {
        Ok(cp_list) => {
            for cp in &cp_list.items {
                let json = serialize_for_distribution(cp)?;
                cloud_providers.push(json);
                if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
                    secret_names.insert(secret_ref.name.clone());
                }
            }
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!("CloudProvider CRD not installed, skipping");
        }
        Err(e) => {
            return Err(ResourceError::Internal(format!(
                "failed to list CloudProviders: {}",
                e
            )));
        }
    }

    // Fetch SecretsProvider CRDs
    // Handle 404 gracefully - CRD may not be installed on bootstrap clusters
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets_providers = Vec::new();
    match sp_api.list(&lp).await {
        Ok(sp_list) => {
            for sp in &sp_list.items {
                let json = serialize_for_distribution(sp)?;
                secrets_providers.push(json);
                if let Some(ref secret_ref) = sp.spec.credentials_secret_ref {
                    secret_names.insert(secret_ref.name.clone());
                }
            }
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!("SecretsProvider CRD not installed, skipping");
        }
        Err(e) => {
            return Err(ResourceError::Internal(format!(
                "failed to list SecretsProviders: {}",
                e
            )));
        }
    }

    // Fetch CedarPolicy CRDs (skip disabled or non-propagating)
    // Handle 404 gracefully - CRD may not be installed on bootstrap clusters
    let cedar_api: Api<CedarPolicy> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut cedar_policies = Vec::new();
    match cedar_api.list(&lp).await {
        Ok(cedar_list) => {
            for policy in &cedar_list.items {
                if !policy.spec.enabled || !policy.spec.propagate {
                    continue;
                }
                let json = serialize_policy_for_distribution(policy, cluster_name)?;
                cedar_policies.push(json);
            }
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!("CedarPolicy CRD not installed, skipping");
        }
        Err(e) => {
            return Err(ResourceError::Internal(format!(
                "failed to list CedarPolicies: {}",
                e
            )));
        }
    }

    // Fetch OIDCProvider CRDs (skip non-propagating)
    // Handle 404 gracefully - CRD may not be installed on bootstrap clusters
    let oidc_api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut oidc_providers = Vec::new();
    match oidc_api.list(&lp).await {
        Ok(oidc_list) => {
            for provider in &oidc_list.items {
                if !provider.spec.propagate {
                    continue;
                }
                let json = serialize_provider_for_distribution(provider, cluster_name)?;
                oidc_providers.push(json);
                // Collect client_secret reference if present
                if let Some(ref secret_ref) = provider.spec.client_secret {
                    secret_names.insert(secret_ref.name.clone());
                }
            }
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!("OIDCProvider CRD not installed, skipping");
        }
        Err(e) => {
            return Err(ResourceError::Internal(format!(
                "failed to list OIDCProviders: {}",
                e
            )));
        }
    }

    // Fetch referenced secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mut secrets = Vec::new();
    for name in &secret_names {
        match secret_api.get(name).await {
            Ok(secret) => {
                let json = serialize_for_distribution(&secret)?;
                secrets.push(json);
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
        cedar_policies = cedar_policies.len(),
        oidc_providers = oidc_providers.len(),
        secrets = secrets.len(),
        "fetched distributable resources"
    );

    Ok(DistributableResources {
        cloud_providers,
        secrets_providers,
        secrets,
        cedar_policies,
        oidc_providers,
    })
}

/// Serialize a Kubernetes resource for distribution, stripping cluster-specific metadata
fn serialize_for_distribution<T: serde::Serialize + Clone + kube::ResourceExt>(
    resource: &T,
) -> Result<Vec<u8>, ResourceError> {
    let mut clean = resource.clone();
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    serde_json::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| ResourceError::Internal(format!("failed to serialize resource: {}", e)))
}

/// Serialize a CedarPolicy for distribution with origin cluster prefix and labels
fn serialize_policy_for_distribution(
    policy: &CedarPolicy,
    cluster_name: &str,
) -> Result<Vec<u8>, ResourceError> {
    let mut clean = policy.clone();
    let original_name = clean.metadata.name.clone().unwrap_or_default();

    // Prefix name with origin cluster: "global-root--admin-access"
    let prefixed_name = format!("{}--{}", cluster_name, original_name);
    clean.metadata.name = Some(prefixed_name);

    // Strip cluster-specific metadata
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    // Add origin labels
    let labels = clean.metadata.labels.get_or_insert_with(Default::default);
    labels.insert(ORIGIN_CLUSTER_LABEL.to_string(), cluster_name.to_string());
    labels.insert(ORIGINAL_NAME_LABEL.to_string(), original_name);
    labels.insert(INHERITED_LABEL.to_string(), "true".to_string());

    serde_json::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| ResourceError::Internal(format!("failed to serialize CedarPolicy: {}", e)))
}

/// Serialize an OIDCProvider for distribution with origin cluster prefix and labels
fn serialize_provider_for_distribution(
    provider: &OIDCProvider,
    cluster_name: &str,
) -> Result<Vec<u8>, ResourceError> {
    let mut clean = provider.clone();
    let original_name = clean.metadata.name.clone().unwrap_or_default();

    // Prefix name with origin cluster: "global-root--corporate-idp"
    let prefixed_name = format!("{}--{}", cluster_name, original_name);
    clean.metadata.name = Some(prefixed_name);

    // Strip cluster-specific metadata
    lattice_common::kube_utils::strip_export_metadata(clean.meta_mut());

    // Add origin labels
    let labels = clean.metadata.labels.get_or_insert_with(Default::default);
    labels.insert(ORIGIN_CLUSTER_LABEL.to_string(), cluster_name.to_string());
    labels.insert(ORIGINAL_NAME_LABEL.to_string(), original_name);
    labels.insert(INHERITED_LABEL.to_string(), "true".to_string());

    serde_json::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| ResourceError::Internal(format!("failed to serialize OIDCProvider: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{CloudProviderSpec, CloudProviderType, SecretRef};
    use lattice_common::CAPA_NAMESPACE;

    // =========================================================================
    // serialize_for_distribution Tests
    // =========================================================================

    fn sample_cloud_provider() -> CloudProvider {
        let mut cp = CloudProvider::new(
            "test-provider",
            CloudProviderSpec {
                provider_type: CloudProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );
        // Add metadata that should be stripped
        cp.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        cp.metadata.uid = Some("test-uid-12345".to_string());
        cp.metadata.resource_version = Some("123456".to_string());
        cp.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .into(),
            ));
        cp
    }

    #[test]
    fn test_serialize_for_distribution_produces_json() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp);
        assert!(result.is_ok());

        let json = String::from_utf8(result.unwrap()).unwrap();
        assert!(json.contains("test-provider"));
        // CloudProviderType uses rename_all = "lowercase", so Docker -> docker
        assert!(json.contains("docker"));
    }

    #[test]
    fn test_serialize_for_distribution_strips_uid() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // UID should be stripped
        assert!(!json.contains("test-uid-12345"));
    }

    #[test]
    fn test_serialize_for_distribution_strips_resource_version() {
        let cp = sample_cloud_provider();
        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // resourceVersion should be stripped
        assert!(!json.contains("resourceVersion"));
    }

    #[test]
    fn test_serialize_for_distribution_with_credentials_ref() {
        let mut cp = sample_cloud_provider();
        cp.spec.credentials_secret_ref = Some(SecretRef {
            name: "my-secret".to_string(),
            namespace: CAPA_NAMESPACE.to_string(),
        });

        let result = serialize_for_distribution(&cp).unwrap();
        let json = String::from_utf8(result).unwrap();

        // Credentials ref should be preserved
        assert!(json.contains("my-secret"));
        assert!(json.contains(CAPA_NAMESPACE));
    }

    #[test]
    fn test_serialize_for_distribution_with_secret() {
        use k8s_openapi::api::core::v1::Secret;
        use std::collections::BTreeMap;

        let mut secret = Secret::default();
        secret.metadata.name = Some("test-secret".to_string());
        secret.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        secret.metadata.uid = Some("secret-uid".to_string());
        secret.metadata.resource_version = Some("999".to_string());

        let mut data = BTreeMap::new();
        data.insert(
            "key".to_string(),
            k8s_openapi::ByteString("value".as_bytes().to_vec()),
        );
        secret.data = Some(data);

        let result = serialize_for_distribution(&secret).unwrap();
        let json = String::from_utf8(result).unwrap();

        // Name should be preserved
        assert!(json.contains("test-secret"));
        // UID and resourceVersion should be stripped
        assert!(!json.contains("secret-uid"));
    }

    // =========================================================================
    // ResourceError Tests
    // =========================================================================

    #[test]
    fn test_resource_error_internal() {
        let err = ResourceError::Internal("test error".to_string());
        assert!(err.to_string().contains("internal error"));
        assert!(err.to_string().contains("test error"));
    }

    // =========================================================================
    // DistributableResources Tests (re-exports from lattice_common)
    // =========================================================================

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

    #[test]
    fn test_distributable_resources_with_secrets_providers() {
        let resources = DistributableResources {
            secrets_providers: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_secrets() {
        let resources = DistributableResources {
            secrets: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_cedar_policies() {
        let resources = DistributableResources {
            cedar_policies: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    #[test]
    fn test_distributable_resources_with_oidc_providers() {
        let resources = DistributableResources {
            oidc_providers: vec![vec![1]],
            ..Default::default()
        };
        assert!(!resources.is_empty());
    }

    // =========================================================================
    // CedarPolicy Serialization Tests
    // =========================================================================

    fn sample_cedar_policy() -> CedarPolicy {
        use lattice_common::crd::CedarPolicySpec;

        let mut policy = CedarPolicy::new(
            "admin-access",
            CedarPolicySpec {
                description: Some("Allow admins".to_string()),
                policies: "permit(principal, action, resource);".to_string(),
                priority: 0,
                enabled: true,
                propagate: true,
            },
        );
        policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        policy.metadata.uid = Some("policy-uid-12345".to_string());
        policy
    }

    #[test]
    fn test_serialize_policy_for_distribution_prefixes_name() {
        let policy = sample_cedar_policy();
        let result = serialize_policy_for_distribution(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // Name should be prefixed with cluster name
        assert!(json.contains("global-root--admin-access"));
        // Original name should not be the resource name
        assert!(!json.contains(r#""name":"admin-access""#));
    }

    #[test]
    fn test_serialize_policy_for_distribution_adds_origin_labels() {
        let policy = sample_cedar_policy();
        let result = serialize_policy_for_distribution(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // Should have origin labels
        assert!(json.contains(ORIGIN_CLUSTER_LABEL));
        assert!(json.contains("global-root"));
        assert!(json.contains(ORIGINAL_NAME_LABEL));
        assert!(json.contains(INHERITED_LABEL));
        assert!(json.contains("\"true\""));
    }

    #[test]
    fn test_serialize_policy_for_distribution_strips_metadata() {
        let policy = sample_cedar_policy();
        let result = serialize_policy_for_distribution(&policy, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // UID should be stripped
        assert!(!json.contains("policy-uid-12345"));
    }

    // =========================================================================
    // OIDCProvider Serialization Tests
    // =========================================================================

    fn sample_oidc_provider() -> OIDCProvider {
        use lattice_common::crd::OIDCProviderSpec;

        let mut provider = OIDCProvider::new(
            "corporate-idp",
            OIDCProviderSpec {
                issuer_url: "https://idp.example.com".to_string(),
                client_id: "lattice".to_string(),
                client_secret: None,
                username_claim: "sub".to_string(),
                groups_claim: "groups".to_string(),
                username_prefix: None,
                groups_prefix: None,
                audiences: vec![],
                required_claims: vec![],
                ca_bundle: None,
                jwks_refresh_interval_seconds: 3600,
                propagate: true,
                allow_child_override: false,
            },
        );
        provider.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        provider.metadata.uid = Some("provider-uid-12345".to_string());
        provider
    }

    #[test]
    fn test_serialize_provider_for_distribution_prefixes_name() {
        let provider = sample_oidc_provider();
        let result = serialize_provider_for_distribution(&provider, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // Name should be prefixed with cluster name
        assert!(json.contains("global-root--corporate-idp"));
    }

    #[test]
    fn test_serialize_provider_for_distribution_adds_origin_labels() {
        let provider = sample_oidc_provider();
        let result = serialize_provider_for_distribution(&provider, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // Should have origin labels
        assert!(json.contains(ORIGIN_CLUSTER_LABEL));
        assert!(json.contains(ORIGINAL_NAME_LABEL));
        assert!(json.contains(INHERITED_LABEL));
    }

    #[test]
    fn test_serialize_provider_for_distribution_strips_metadata() {
        let provider = sample_oidc_provider();
        let result = serialize_provider_for_distribution(&provider, "global-root").unwrap();
        let json = String::from_utf8(result).unwrap();

        // UID should be stripped
        assert!(!json.contains("provider-uid-12345"));
    }
}
