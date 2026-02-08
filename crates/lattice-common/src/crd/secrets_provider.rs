//! SecretsProvider CRD for Vault integration
//!
//! A SecretsProvider represents a connection to HashiCorp Vault that can be
//! distributed to child clusters, creating ESO ClusterSecretStore automatically.

use std::collections::BTreeMap;

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::service::ResourceSpec;
use super::types::SecretRef;
use crate::LATTICE_SYSTEM_NAMESPACE;

/// SecretsProvider defines a Vault connection for ESO integration.
///
/// When distributed to child clusters, this creates the corresponding ESO
/// ClusterSecretStore automatically.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: SecretsProvider
/// metadata:
///   name: vault-prod
/// spec:
///   server: https://vault.example.com
///   path: secret/data/lattice
///   authMethod: kubernetes
///   kubernetesRole: lattice
///   credentialsSecretRef:
///     name: vault-token
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "SecretsProvider",
    namespaced,
    status = "SecretsProviderStatus",
    printcolumn = r#"{"name":"Backend","type":"string","jsonPath":".spec.backend"}"#,
    printcolumn = r#"{"name":"Server","type":"string","jsonPath":".spec.server"}"#,
    printcolumn = r#"{"name":"Auth","type":"string","jsonPath":".spec.authMethod"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SecretsProviderSpec {
    /// Backend type (default: vault)
    #[serde(default)]
    pub backend: SecretsBackend,

    /// Vault server URL (required for vault backend, ignored for local)
    pub server: String,

    /// Path prefix for secrets (e.g., "secret/data/lattice")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Authentication method
    #[serde(default)]
    pub auth_method: VaultAuthMethod,

    /// Reference to secret containing Vault credentials
    /// Required for token auth (contains VAULT_TOKEN)
    /// Optional for kubernetes auth (uses ServiceAccount)
    /// Mutually exclusive with `credentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,

    /// ESO-managed credential source. Fetched via the local webhook
    /// ClusterSecretStore. Mutually exclusive with `credentialsSecretRef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ResourceSpec>,

    /// Template data for shaping credentials using `${secret.*}` syntax.
    /// Only valid when `credentials` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<BTreeMap<String, String>>,

    /// Kubernetes auth mount path (default: "kubernetes")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_mount_path: Option<String>,

    /// Kubernetes auth role
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_role: Option<String>,

    /// AppRole auth mount path (default: "approle")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approle_mount_path: Option<String>,

    /// Vault namespace (enterprise feature)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// CA certificate for TLS verification (PEM format)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,
}

/// Backend type for secrets storage
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SecretsBackend {
    /// HashiCorp Vault backend (requires server, auth config)
    #[default]
    Vault,
    /// Local webhook backend (operator proxies K8s Secrets via HTTP)
    Local,
}

/// Vault authentication methods
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VaultAuthMethod {
    /// Token-based auth (credentialsSecretRef contains VAULT_TOKEN)
    #[default]
    Token,
    /// Kubernetes ServiceAccount auth
    Kubernetes,
    /// AppRole auth (credentialsSecretRef contains role_id and secret_id)
    AppRole,
}

/// SecretsProvider status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretsProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: SecretsProviderPhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last time connection was validated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated: Option<String>,
}

/// SecretsProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum SecretsProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Connection validated, ready for use
    Ready,
    /// Connection validation failed
    Failed,
}

impl SecretsProvider {
    /// Resolve the K8s Secret that contains provider credentials.
    ///
    /// - ESO mode (`credentials` set): returns a synthetic ref pointing to the
    ///   ESO-synced secret `{name}-credentials` in `lattice-system`.
    /// - Manual mode (`credentialsSecretRef` set): returns the user-provided ref.
    /// - Neither set: returns `None`.
    pub fn k8s_secret_ref(&self) -> Option<SecretRef> {
        if self.spec.credentials.is_some() {
            Some(SecretRef {
                name: format!("{}-credentials", self.name_any()),
                namespace: LATTICE_SYSTEM_NAMESPACE.to_string(),
            })
        } else {
            self.spec.credentials_secret_ref.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_token_auth_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  server: https://vault.example.com
  path: secret/data/lattice
  authMethod: token
  credentialsSecretRef:
    name: vault-token
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.server, "https://vault.example.com");
        assert_eq!(provider.spec.auth_method, VaultAuthMethod::Token);
    }

    #[test]
    fn vault_kubernetes_auth_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-k8s
spec:
  server: https://vault.example.com
  authMethod: kubernetes
  kubernetesRole: lattice
  kubernetesMountPath: kubernetes
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.auth_method, VaultAuthMethod::Kubernetes);
        assert_eq!(provider.spec.kubernetes_role, Some("lattice".to_string()));
    }

    #[test]
    fn backend_defaults_to_vault() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  server: https://vault.example.com
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.backend, SecretsBackend::Vault);
    }

    #[test]
    fn local_backend_parses() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: local-test
spec:
  backend: local
  server: ""
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.backend, SecretsBackend::Local);
        assert_eq!(provider.spec.server, "");
    }

    // =========================================================================
    // k8s_secret_ref() Tests
    // =========================================================================

    #[test]
    fn k8s_secret_ref_manual_mode() {
        let sp = SecretsProvider::new(
            "vault-prod",
            SecretsProviderSpec {
                backend: SecretsBackend::default(),
                server: "https://vault.example.com".to_string(),
                path: None,
                auth_method: VaultAuthMethod::Token,
                credentials_secret_ref: Some(SecretRef {
                    name: "my-token".to_string(),
                    namespace: "default".to_string(),
                }),
                credentials: None,
                credential_data: None,
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        );
        let secret_ref = sp.k8s_secret_ref().expect("should have secret ref");
        assert_eq!(secret_ref.name, "my-token");
        assert_eq!(secret_ref.namespace, "default");
    }

    #[test]
    fn k8s_secret_ref_eso_mode() {
        use crate::crd::ResourceType;

        let sp = SecretsProvider::new(
            "vault-prod",
            SecretsProviderSpec {
                backend: SecretsBackend::default(),
                server: "https://vault.example.com".to_string(),
                path: None,
                auth_method: VaultAuthMethod::Token,
                credentials_secret_ref: None,
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("vault/token".to_string()),
                    ..Default::default()
                }),
                credential_data: None,
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        );
        let secret_ref = sp.k8s_secret_ref().expect("should have secret ref");
        assert_eq!(secret_ref.name, "vault-prod-credentials");
        assert_eq!(secret_ref.namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[test]
    fn k8s_secret_ref_none() {
        let sp = SecretsProvider::new(
            "vault-k8s",
            SecretsProviderSpec {
                backend: SecretsBackend::default(),
                server: "https://vault.example.com".to_string(),
                path: None,
                auth_method: VaultAuthMethod::Kubernetes,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: None,
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        );
        assert!(sp.k8s_secret_ref().is_none());
    }

    #[test]
    fn credentials_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  server: https://vault.example.com
  authMethod: token
  credentials:
    type: secret
    id: vault/token
    params:
      provider: lattice-local
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credentials_secret_ref.is_none());
        let secret_ref = provider.k8s_secret_ref().expect("should have ref");
        assert_eq!(secret_ref.name, "vault-prod-credentials");
    }

    #[test]
    fn credential_data_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  server: https://vault.example.com
  authMethod: appRole
  credentials:
    type: secret
    id: vault/approle
    params:
      provider: lattice-local
      keys: [role_id, secret_id]
  credentialData:
    approle.json: '{"role_id": "${secret.credentials.role_id}"}'
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credential_data.is_some());
        let data = provider.spec.credential_data.unwrap();
        assert!(data.contains_key("approle.json"));
    }
}
