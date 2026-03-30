//! Shared credential reconciliation for provider CRDs.
//!
//! Extracts the ESO credential flow from InfraProvider into a reusable utility
//! that any provider controller (InfraProvider, DNSProvider, CertIssuer) can call.

use std::collections::BTreeMap;

use tracing::debug;

use lattice_common::crd::workload::resources::ResourceSpec;
use lattice_common::template::extract_secret_refs;
use lattice_common::ReconcileError;

use crate::eso::{apply_external_secret, build_external_secret, build_templated_external_secret};

/// Configuration for reconciling provider credentials via ESO.
pub struct ProviderCredentialConfig<'a> {
    /// Name of the provider resource (used to derive the secret name).
    pub provider_name: &'a str,
    /// The ESO-managed credential source (ResourceSpec with type: secret).
    pub credentials: &'a ResourceSpec,
    /// Optional template data for shaping credentials using `${secret.*}` syntax.
    pub credential_data: Option<&'a BTreeMap<String, String>>,
    /// Namespace where the ESO ExternalSecret (and resulting K8s Secret) should live.
    pub target_namespace: &'a str,
    /// Field manager for server-side apply.
    pub field_manager: &'a str,
}

/// Reconcile ESO credentials for a provider.
///
/// Creates an ExternalSecret that syncs credentials from a ClusterSecretStore
/// into a K8s Secret in the target namespace. Supports both simple (all keys)
/// and templated (`${secret.*}`) modes.
///
/// Returns the name of the K8s Secret that ESO will sync.
pub async fn reconcile_credentials(
    client: &kube::Client,
    config: &ProviderCredentialConfig<'_>,
) -> Result<String, ReconcileError> {
    let params = config.credentials.params.as_secret().ok_or_else(|| {
        ReconcileError::Validation(
            "credentials must have type: secret with params.provider".into(),
        )
    })?;

    let remote_key = config.credentials.secret_remote_key().ok_or_else(|| {
        ReconcileError::Validation("credentials: missing 'id' field (remote key)".into())
    })?;

    let secret_name = format!("{}-credentials", config.provider_name);

    let es = if let Some(data) = config.credential_data {
        let mut template_data = BTreeMap::new();
        let mut all_refs = Vec::new();
        for (key, value) in data {
            let (rendered, refs) = extract_secret_refs(value, false);
            template_data.insert(key.clone(), rendered);
            all_refs.extend(refs);
        }
        build_templated_external_secret(
            &secret_name,
            config.target_namespace,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            template_data,
            &all_refs,
        )
        .map_err(ReconcileError::Validation)?
    } else {
        build_external_secret(
            &secret_name,
            config.target_namespace,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            None,
        )
    };

    apply_external_secret(client, &es, config.field_manager).await?;

    debug!(
        provider = %config.provider_name,
        namespace = %config.target_namespace,
        secret = %secret_name,
        "ESO ExternalSecret applied for provider credentials"
    );

    Ok(secret_name)
}


#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{ResourceParams, ResourceType, SecretParams};

    fn sample_credentials() -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("infrastructure/aws/prod".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: "vault-prod".to_string(),
                keys: Some(vec![
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn config_builds_simple_external_secret() {
        let creds = sample_credentials();
        let config = ProviderCredentialConfig {
            provider_name: "aws-prod",
            credentials: &creds,
            credential_data: None,
            target_namespace: "lattice-system",
            field_manager: "test",
        };

        let params = config.credentials.params.as_secret().unwrap();
        let remote_key = config.credentials.secret_remote_key().unwrap();
        let secret_name = format!("{}-credentials", config.provider_name);

        let es = build_external_secret(
            &secret_name,
            config.target_namespace,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            None,
        );

        assert_eq!(es.metadata.name, "aws-prod-credentials");
        assert_eq!(es.metadata.namespace, "lattice-system");
        assert_eq!(es.spec.secret_store_ref.name, "vault-prod");
        assert_eq!(es.spec.data.len(), 2);
    }

    #[test]
    fn config_builds_templated_external_secret() {
        let creds = ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("infra/openstack/creds".to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: "vault-prod".to_string(),
                keys: Some(vec![
                    "username".to_string(),
                    "password".to_string(),
                    "auth_url".to_string(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut credential_data = BTreeMap::new();
        credential_data.insert(
            "clouds.yaml".to_string(),
            "auth:\n  username: \"${secret.credentials.username}\"\n  password: \"${secret.credentials.password}\"".to_string(),
        );

        let config = ProviderCredentialConfig {
            provider_name: "openstack-prod",
            credentials: &creds,
            credential_data: Some(&credential_data),
            target_namespace: "lattice-system",
            field_manager: "test",
        };

        let params = config.credentials.params.as_secret().unwrap();
        let remote_key = config.credentials.secret_remote_key().unwrap();
        let secret_name = format!("{}-credentials", config.provider_name);

        let mut template_data = BTreeMap::new();
        let mut all_refs = Vec::new();
        for (key, value) in credential_data.iter() {
            let (rendered, refs) = extract_secret_refs(value, false);
            template_data.insert(key.clone(), rendered);
            all_refs.extend(refs);
        }

        let es = build_templated_external_secret(
            &secret_name,
            config.target_namespace,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            template_data,
            &all_refs,
        )
        .unwrap();

        assert_eq!(es.metadata.name, "openstack-prod-credentials");
        assert!(es.spec.target.template.is_some());
        let template = es.spec.target.template.as_ref().unwrap();
        assert!(template.data.contains_key("clouds.yaml"));
    }
}
