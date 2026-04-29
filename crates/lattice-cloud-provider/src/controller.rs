//! InfraProvider reconciliation controller
//!
//! Watches InfraProvider CRDs and validates credentials configuration.
//! Consumers (cluster provisioners) create ESO ExternalSecrets in their
//! target namespaces — this controller only validates the spec.
//!
//! Docker providers require no credentials. All others require the
//! `credentials` field (ESO CredentialSpec), optionally with `credentialData`
//! templates for complex credential shapes.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::status_check;
use lattice_common::{ControllerContext, ReconcileError, REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS};
use lattice_crd::crd::{InfraProvider, InfraProviderPhase, InfraProviderStatus, InfraProviderType};

const FIELD_MANAGER: &str = "lattice-cloud-provider-controller";

/// Reconcile a InfraProvider
///
/// Reconciles credentials (ESO or manual) and updates status.
/// Skips work when the spec hasn't changed (generation matches) and already Ready.
pub async fn reconcile(
    cp: Arc<InfraProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = cp.name_any();
    let client = &ctx.client;
    let generation = cp.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("InfraProvider missing metadata.generation".into())
    })?;

    // Skip work if spec unchanged and already Ready
    if status_check::is_status_unchanged(
        cp.status.as_ref(),
        &InfraProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(cloud_provider = %name, provider_type = ?cp.spec.provider_type, "Reconciling InfraProvider");

    let (phase, message, requeue_secs) = if let Err(e) = cp.spec.validate() {
        let msg = e.to_string();
        warn!(cloud_provider = %name, error = %msg, "Validation failed");
        (InfraProviderPhase::Failed, msg, REQUEUE_ERROR_SECS)
    } else {
        match validate_credentials(&cp) {
            Ok(()) => {
                info!(cloud_provider = %name, "Credentials validated successfully");
                (
                    InfraProviderPhase::Ready,
                    "Credentials reconciled successfully".to_string(),
                    REQUEUE_SUCCESS_SECS,
                )
            }
            Err(e) => {
                warn!(cloud_provider = %name, error = %e, "Credential reconciliation failed");
                (
                    InfraProviderPhase::Failed,
                    e.to_string(),
                    REQUEUE_ERROR_SECS,
                )
            }
        }
    };
    status_check::patch_phase_status::<InfraProvider, InfraProviderStatus>(
        client,
        &cp,
        cp.status.as_ref(),
        phase,
        Some(message),
        Some(generation),
        FIELD_MANAGER,
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(requeue_secs)))
}

/// Validate credentials for the cloud provider.
///
/// Docker providers require no credentials. All others require the
/// `credentials` field (ESO CredentialSpec). ExternalSecrets are created
/// by consumers in their target namespaces, not by this controller.
fn validate_credentials(cp: &InfraProvider) -> Result<(), ReconcileError> {
    if cp.spec.credential_data.is_some() && cp.spec.credentials.is_none() {
        return Err(ReconcileError::Validation(
            "credentialData requires credentials to be set".into(),
        ));
    }

    match cp.spec.provider_type {
        InfraProviderType::Docker => {
            debug!(cloud_provider = %cp.name_any(), "Docker provider requires no credentials");
            Ok(())
        }
        provider_type => {
            if cp.spec.credentials.is_some() {
                Ok(())
            } else {
                Err(ReconcileError::Validation(format!(
                    "{:?} provider requires credentials",
                    provider_type
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use lattice_core::LATTICE_SYSTEM_NAMESPACE;
    use lattice_crd::crd::{CredentialSpec, InfraProviderSpec};
    use lattice_render::extract_secret_refs;
    use lattice_secret_provider::eso::{build_external_secret, build_templated_external_secret};
    use std::collections::BTreeMap;

    fn sample_provider(provider_type: InfraProviderType) -> InfraProvider {
        let (name, region) = match provider_type {
            InfraProviderType::Docker => ("docker", None),
            InfraProviderType::AWS => ("aws-prod", Some("us-east-1")),
            InfraProviderType::Proxmox => ("proxmox-homelab", None),
            InfraProviderType::OpenStack => ("openstack-prod", Some("RegionOne")),
            _ => ("unknown", None),
        };

        let credentials = if provider_type == InfraProviderType::Docker {
            None
        } else {
            Some(CredentialSpec::test(
                &format!("infra/{name}"),
                "lattice-local",
            ))
        };

        InfraProvider::new(
            name,
            InfraProviderSpec {
                provider_type,
                region: region.map(String::from),
                credentials,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn docker_no_credentials() {
        let cp = sample_provider(InfraProviderType::Docker);
        assert_eq!(cp.spec.provider_type, InfraProviderType::Docker);
        assert!(cp.spec.credentials.is_none());
        assert!(cp.credential_secret_name().is_none());
    }

    #[tokio::test]
    async fn eso_credentials_resolve() {
        let cp = sample_provider(InfraProviderType::AWS);
        assert!(cp.spec.credentials.is_some());
        let name = cp.credential_secret_name().unwrap();
        assert_eq!(name, "aws-prod-credentials");
    }

    #[tokio::test]
    async fn credential_data_without_credentials_is_invalid() {
        let mut data = BTreeMap::new();
        data.insert("key".to_string(), "value".to_string());

        let cp = InfraProvider::new(
            "test",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: None,
                credential_data: Some(data),
                aws: None,
                proxmox: None,
                openstack: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        );

        assert!(cp.spec.credential_data.is_some() && cp.spec.credentials.is_none());
    }

    #[tokio::test]
    async fn simple_mode_builds_external_secret() {
        let cp = sample_provider(InfraProviderType::AWS);

        let creds = cp.spec.credentials.as_ref().unwrap();
        let secret_name = format!("{}-credentials", cp.name_any());

        let es = build_external_secret(
            &secret_name,
            LATTICE_SYSTEM_NAMESPACE,
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
            None,
        );

        assert_eq!(es.metadata.name, "aws-prod-credentials");
        assert_eq!(es.metadata.namespace, LATTICE_SYSTEM_NAMESPACE);
        assert_eq!(es.spec.secret_store_ref.name, "lattice-local");
    }

    #[tokio::test]
    async fn templated_mode_builds_external_secret() {
        let mut credential_data = BTreeMap::new();
        credential_data.insert(
            "clouds.yaml".to_string(),
            "auth:\n  username: \"${secret.credentials.username}\"\n  password: \"${secret.credentials.password}\"".to_string(),
        );

        let cp = InfraProvider::new(
            "openstack-test",
            InfraProviderSpec {
                provider_type: InfraProviderType::OpenStack,
                region: None,
                credentials: Some(CredentialSpec {
                    id: "infrastructure/openstack/creds".to_string(),
                    provider: "vault-prod".to_string(),
                    keys: Some(vec![
                        "username".to_string(),
                        "password".to_string(),
                        "auth_url".to_string(),
                    ]),
                    ..Default::default()
                }),
                credential_data: Some(credential_data.clone()),
                aws: None,
                proxmox: None,
                openstack: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        );

        let creds = cp.spec.credentials.as_ref().unwrap();
        let secret_name = format!("{}-credentials", cp.name_any());

        let mut template_data = BTreeMap::new();
        let mut all_refs = Vec::new();
        for (key, value) in &credential_data {
            let (rendered, refs) = extract_secret_refs(value, false);
            template_data.insert(key.clone(), rendered);
            all_refs.extend(refs);
        }

        let es = build_templated_external_secret(
            &secret_name,
            LATTICE_SYSTEM_NAMESPACE,
            &creds.provider,
            &creds.id,
            creds.keys.as_deref(),
            template_data,
            &all_refs,
        )
        .unwrap();

        assert_eq!(es.metadata.name, "openstack-test-credentials");
        assert!(es.spec.target.template.is_some());
        let template = es.spec.target.template.as_ref().unwrap();
        assert!(template.data.contains_key("clouds.yaml"));
        assert!(template.data["clouds.yaml"].contains("{{ .credentials_username }}"));
        assert_eq!(es.spec.data.len(), 2);
    }

    #[tokio::test]
    async fn missing_credentials_for_cloud_provider() {
        let cp = InfraProvider::new(
            "aws-no-creds",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        );

        assert!(cp.spec.credentials.is_none());
        assert!(cp.credential_secret_name().is_none());
    }

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        let mut cp = sample_provider(InfraProviderType::Docker);
        cp.status = Some(InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: None,
            last_validated: Some("2024-01-01T00:00:00Z".to_string()),
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            cp.status.as_ref(),
            &InfraProviderPhase::Ready,
            None,
            Some(1)
        ));
        assert!(!status_check::is_status_unchanged(
            cp.status.as_ref(),
            &InfraProviderPhase::Failed,
            None,
            Some(1)
        ));
    }

    #[tokio::test]
    async fn provider_with_namespace_uses_it() {
        let mut cp = sample_provider(InfraProviderType::Docker);
        cp.metadata = ObjectMeta {
            name: Some("test-provider".to_string()),
            namespace: Some("custom-namespace".to_string()),
            ..Default::default()
        };
        assert_eq!(cp.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn all_provider_types_covered() {
        for provider_type in [
            InfraProviderType::Docker,
            InfraProviderType::AWS,
            InfraProviderType::Proxmox,
            InfraProviderType::OpenStack,
        ] {
            let cp = sample_provider(provider_type);
            assert_eq!(cp.spec.provider_type, provider_type);
        }
    }
}
