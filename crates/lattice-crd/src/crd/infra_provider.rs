//! InfraProvider CRD for registering cloud accounts/credentials
//!
//! A InfraProvider represents a named cloud account that clusters can reference.

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::credential_secret_name;

/// InfraProvider defines a cloud account/region that clusters can be deployed to.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: InfraProvider
/// metadata:
///   name: aws-prod
/// spec:
///   type: AWS
///   region: us-east-1
///   credentials:
///     id: infrastructure/aws/prod
///     provider: lattice-local
///     keys: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]
///   aws:
///     vpcId: vpc-xxx
///     subnetIds: [subnet-a, subnet-b]
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "InfraProvider",
    namespaced,
    status = "InfraProviderStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Region","type":"string","jsonPath":".spec.region"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct InfraProviderSpec {
    /// Cloud provider type
    #[serde(rename = "type")]
    pub provider_type: InfraProviderType,

    /// Region/location for this provider
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// ESO-managed credential source. The controller creates an ExternalSecret
    /// that syncs credentials from a ClusterSecretStore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<super::types::CredentialSpec>,

    /// Template data for shaping credentials using `${secret.*}` syntax.
    /// Each key becomes a key in the resulting K8s Secret.
    /// Values can use `${secret.credentials.KEY}` to inject secret values.
    /// Only valid when `credentials` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<BTreeMap<String, String>>,

    /// AWS-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsProviderConfig>,

    /// Proxmox-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxProviderConfig>,

    /// Basis-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<BasisProviderConfig>,

    /// ImageProviders supplying registry credentials for the CAPI provider's
    /// own Deployment image. Each entry names an `ImageProvider` in the same
    /// namespace as this InfraProvider; at CAPI install time the operator
    /// creates an ExternalSecret in the CAPI provider namespace so ESO syncs
    /// the dockerconfigjson directly there, and wires it onto the provider
    /// Deployment's `imagePullSecrets`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<ImagePullSecretRef>,

    /// Labels for cluster selector matching
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Reference to an `ImageProvider` supplying image pull credentials.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImagePullSecretRef {
    /// Name of an ImageProvider resource in the same namespace as the
    /// InfraProvider.
    pub name: String,
}

/// Supported cloud provider types
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum InfraProviderType {
    /// Amazon Web Services
    AWS,
    /// Proxmox VE (on-premises)
    Proxmox,
    /// Docker/Kind (local development)
    Docker,
    /// Basis (minimal bare-metal VM scheduler)
    Basis,
}

impl std::fmt::Display for InfraProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AWS => write!(f, "AWS"),
            Self::Proxmox => write!(f, "Proxmox"),
            Self::Docker => write!(f, "Docker"),
            Self::Basis => write!(f, "Basis"),
        }
    }
}

/// AWS-specific provider configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AwsProviderConfig {
    /// Existing VPC ID (BYOI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,

    /// Existing subnet IDs (BYOI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_ids: Option<Vec<String>>,

    /// SSH key name for node access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_name: Option<String>,

    /// IAM role ARN for CAPA to assume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
}

/// Proxmox-specific provider configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxProviderConfig {
    /// Proxmox server URL
    pub server_url: String,

    /// Proxmox node name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,

    /// Storage pool for VM disks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
}

/// Basis-specific provider configuration.
///
/// Carries only the connection info needed to reach a Basis controller —
/// the controller owns scheduling, IP allocation, and VIP reservation
/// itself, so there's nothing else to configure at the account level.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BasisProviderConfig {
    /// gRPC endpoint of the Basis controller, e.g. `https://10.0.0.1:7443`.
    pub server_url: String,
}

/// InfraProvider status
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InfraProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: InfraProviderPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Last time credentials were validated
    #[serde(default)]
    pub last_validated: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// InfraProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum InfraProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Credentials validated, ready for use
    Ready,
    /// Credential validation failed
    Failed,
}

impl std::fmt::Display for InfraProviderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl InfraProviderSpec {
    /// Validate the spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        // Validate credentials if present
        if let Some(ref credentials) = self.credentials {
            credentials.validate()?;
        }

        // credentialData requires credentials
        if self.credential_data.is_some() && self.credentials.is_none() {
            return Err(crate::ValidationError::new(
                "credentialData requires credentials to be set",
            ));
        }

        // Provider-type-specific config validation
        match self.provider_type {
            InfraProviderType::AWS => {
                // AWS provider doesn't strictly require aws config (it's optional BYOI),
                // but does require credentials
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "AWS provider requires credentials",
                    ));
                }
            }
            InfraProviderType::Proxmox => {
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "Proxmox provider requires credentials",
                    ));
                }
                let proxmox = self.proxmox.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("proxmox config required when type is proxmox")
                })?;
                if proxmox.server_url.is_empty() {
                    return Err(crate::ValidationError::new(
                        "proxmox.serverUrl cannot be empty",
                    ));
                }
            }
            InfraProviderType::Docker => {
                // Docker providers require no credentials or provider-specific config
            }
            InfraProviderType::Basis => {
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "Basis provider requires credentials",
                    ));
                }
                let basis = self.basis.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("basis config required when type is basis")
                })?;
                if basis.server_url.is_empty() {
                    return Err(crate::ValidationError::new(
                        "basis.serverUrl cannot be empty",
                    ));
                }
            }
        }

        Ok(())
    }
}

impl InfraProvider {
    /// Returns the ESO-synced credential secret name (`{name}-credentials`).
    /// `None` if no credentials are configured (e.g., Docker provider).
    /// Callers create ExternalSecrets in whichever namespace they need.
    pub fn credential_secret_name(&self) -> Option<String> {
        self.spec
            .credentials
            .as_ref()
            .map(|_| credential_secret_name(&self.name_any()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CredentialSpec;

    #[test]
    fn aws_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: aws-prod
spec:
  type: aws
  region: us-east-1
  credentials:
    id: infra/aws/prod
    provider: lattice-local
  aws:
    vpcId: vpc-xxx
    subnetIds:
      - subnet-a
      - subnet-b
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, InfraProviderType::AWS);
        assert_eq!(provider.spec.region, Some("us-east-1".to_string()));
        assert!(provider.spec.credentials.is_some());
    }

    #[test]
    fn proxmox_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: proxmox-lab
spec:
  type: proxmox
  credentials:
    id: proxmox-creds
    provider: lattice-local
  proxmox:
    serverUrl: https://pve.local:8006
    node: pve1
    storage: local-lvm
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, InfraProviderType::Proxmox);
        assert!(provider.spec.credentials.is_some());
    }

    #[test]
    fn basis_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: homelab-basis
spec:
  type: basis
  credentials:
    id: basis-credentials
    provider: lattice-local
  basis:
    serverUrl: https://10.0.0.206:7443
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, InfraProviderType::Basis);
        assert_eq!(
            provider
                .spec
                .basis
                .as_ref()
                .expect("basis config")
                .server_url,
            "https://10.0.0.206:7443"
        );
    }

    #[test]
    fn k8s_secret_ref_with_credentials() {
        let cp = InfraProvider::new(
            "aws-prod",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: Some(CredentialSpec::test("infra/aws/prod", "vault-prod")),
                credential_data: None,
                aws: None,
                proxmox: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        );

        let name = cp.credential_secret_name().unwrap();
        assert_eq!(name, "aws-prod-credentials");
    }

    #[test]
    fn credential_secret_name_without_credentials() {
        let cp = InfraProvider::new(
            "docker",
            InfraProviderSpec {
                provider_type: InfraProviderType::Docker,
                region: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                basis: None,
                image_pull_secrets: Vec::new(),
                labels: Default::default(),
            },
        );

        assert!(cp.credential_secret_name().is_none());
    }

    #[test]
    fn image_pull_secrets_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: proxmox
spec:
  type: proxmox
  credentials:
    id: proxmox-creds
    provider: lattice-local
  proxmox:
    serverUrl: https://pve.local:8006
  imagePullSecrets:
    - name: ghcr-creds
    - name: quay-fallback
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        let pulls: Vec<&str> = provider
            .spec
            .image_pull_secrets
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(pulls, vec!["ghcr-creds", "quay-fallback"]);
    }

    #[test]
    fn image_pull_secrets_default_empty() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: docker
spec:
  type: docker
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.image_pull_secrets.is_empty());
    }

    #[test]
    fn credential_data_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: proxmox-prod
spec:
  type: proxmox
  credentials:
    id: infrastructure/proxmox/credentials
    provider: vault-prod
    keys:
      - username
      - password
  credentialData:
    creds.yaml: |
      username: "${secret.credentials.username}"
      password: "${secret.credentials.password}"
  proxmox:
    serverUrl: https://pve.local:8006
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");

        assert_eq!(provider.spec.provider_type, InfraProviderType::Proxmox);
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credential_data.is_some());

        let data = provider.spec.credential_data.as_ref().unwrap();
        assert!(data.contains_key("creds.yaml"));
        assert!(data["creds.yaml"].contains("${secret.credentials.username}"));

        let name = provider.credential_secret_name().unwrap();
        assert_eq!(name, "proxmox-prod-credentials");
    }
}
