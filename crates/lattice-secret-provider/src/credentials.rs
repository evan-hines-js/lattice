//! Shared credential reconciliation for provider CRDs.
//!
//! Extracts the ESO credential flow from InfraProvider into a reusable utility
//! that any provider controller (InfraProvider, DNSProvider, CertIssuer) can call.

use std::collections::BTreeMap;

use tracing::debug;

use kube::{Api, ResourceExt};

use lattice_common::ReconcileError;
use lattice_crd::crd::{CredentialSpec, ImageProvider, InfraProvider};
use lattice_render::extract_secret_refs;

use crate::eso::{apply_external_secret, build_external_secret, build_templated_external_secret};

/// Configuration for reconciling provider credentials via ESO.
pub struct ProviderCredentialConfig<'a> {
    /// Name of the provider resource (used to derive the secret name).
    pub provider_name: &'a str,
    /// ESO-managed credential source.
    pub credentials: &'a CredentialSpec,
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
    let creds = config.credentials;
    creds
        .validate()
        .map_err(|e| ReconcileError::Validation(e.to_string()))?;

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
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
            template_data,
            &all_refs,
        )
        .map_err(ReconcileError::Validation)?
    } else {
        build_external_secret(
            &secret_name,
            config.target_namespace,
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
            creds.refresh_interval.clone(),
        )
    };

    // Set the K8s Secret type if specified (e.g., dockerconfigjson for imagePullSecrets)
    let mut es = es;
    if let Some(ref secret_type) = creds.secret_type {
        let template =
            es.spec
                .target
                .template
                .get_or_insert_with(|| crate::eso::ExternalSecretTemplate {
                    engine_version: "v2".to_string(),
                    type_: None,
                    data: std::collections::BTreeMap::new(),
                });
        template.type_ = Some(secret_type.clone());
    }

    apply_external_secret(client, &es, config.field_manager).await?;

    debug!(
        provider = %config.provider_name,
        namespace = %config.target_namespace,
        secret = %secret_name,
        "ESO ExternalSecret applied for provider credentials"
    );

    Ok(secret_name)
}

/// Ensure credentials exist in a target namespace via ESO.
///
/// Creates the namespace if needed, applies an ExternalSecret, and watches
/// for ESO to sync the resulting K8s Secret. Single entry point for
/// "I need these credentials to exist in this namespace."
pub async fn ensure_credentials(
    client: &kube::Client,
    provider_name: &str,
    credentials: &CredentialSpec,
    credential_data: Option<&BTreeMap<String, String>>,
    target_namespace: &str,
    field_manager: &str,
) -> Result<String, ReconcileError> {
    lattice_common::kube_utils::ensure_namespace(client, target_namespace, None, field_manager)
        .await
        .map_err(|e| {
            ReconcileError::Internal(format!(
                "failed to ensure namespace '{target_namespace}': {e}"
            ))
        })?;

    let secret_name = reconcile_credentials(
        client,
        &ProviderCredentialConfig {
            provider_name,
            credentials,
            credential_data,
            target_namespace,
            field_manager,
        },
    )
    .await?;

    lattice_common::kube_utils::wait_for_secret(
        client,
        &secret_name,
        target_namespace,
        std::time::Duration::from_secs(120),
    )
    .await
    .map_err(|e| ReconcileError::Internal(e.to_string()))?;

    Ok(secret_name)
}

/// Materialize `InfraProvider.imagePullSecrets` directly in the CAPI provider
/// namespace via ESO.
///
/// For each entry, reads the matching `ImageProvider` from the InfraProvider's
/// namespace and applies an `ExternalSecret` into `target_namespace` forced to
/// `kubernetes.io/dockerconfigjson`. Returns the synced Secret names — callers
/// set these as `imagePullSecrets` on the provider Deployment.
pub async fn ensure_capi_image_pull_secrets(
    client: &kube::Client,
    cp: &InfraProvider,
    target_namespace: &str,
    field_manager: &str,
) -> Result<Vec<String>, ReconcileError> {
    if cp.spec.image_pull_secrets.is_empty() {
        return Ok(Vec::new());
    }

    let cp_ns = cp
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| ReconcileError::Validation("InfraProvider missing namespace".into()))?;
    let image_providers: Api<ImageProvider> = Api::namespaced(client.clone(), cp_ns);

    let mut names = Vec::with_capacity(cp.spec.image_pull_secrets.len());
    for pull in &cp.spec.image_pull_secrets {
        let ip = image_providers.get(&pull.name).await.map_err(|e| {
            ReconcileError::Validation(format!(
                "InfraProvider {}/{} references ImageProvider '{}' in {}: {}",
                cp_ns,
                cp.name_any(),
                pull.name,
                cp_ns,
                e
            ))
        })?;

        let credentials = ip.spec.credentials.as_ref().ok_or_else(|| {
            ReconcileError::Validation(format!(
                "ImageProvider '{}' has no credentials — cannot materialize pull secret in {}",
                pull.name, target_namespace
            ))
        })?;

        // Force dockerconfigjson so kubelet accepts the synced Secret as an
        // imagePullSecret (mirrors the ImageProvider controller's behavior).
        let mut creds = credentials.clone();
        if creds.secret_type.is_none() {
            creds.secret_type = Some(lattice_core::SECRET_TYPE_DOCKERCONFIG.to_string());
        }

        let secret_name = ensure_credentials(
            client,
            &ip.name_any(),
            &creds,
            ip.spec.credential_data.as_ref(),
            target_namespace,
            field_manager,
        )
        .await?;
        names.push(secret_name);
    }

    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_credentials() -> CredentialSpec {
        CredentialSpec {
            id: "infrastructure/aws/prod".to_string(),
            provider: "vault-prod".to_string(),
            keys: Some(vec![
                "AWS_ACCESS_KEY_ID".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string(),
            ]),
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

        let secret_name = format!("{}-credentials", config.provider_name);

        let es = build_external_secret(
            &secret_name,
            config.target_namespace,
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
            None,
        );

        assert_eq!(es.metadata.name, "aws-prod-credentials");
        assert_eq!(es.metadata.namespace, "lattice-system");
        assert_eq!(es.spec.secret_store_ref.name, "vault-prod");
        assert_eq!(es.spec.data.len(), 2);
    }

    #[test]
    fn config_builds_templated_external_secret() {
        let creds = CredentialSpec {
            id: "infra/openstack/creds".to_string(),
            provider: "vault-prod".to_string(),
            keys: Some(vec![
                "username".to_string(),
                "password".to_string(),
                "auth_url".to_string(),
            ]),
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
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
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
