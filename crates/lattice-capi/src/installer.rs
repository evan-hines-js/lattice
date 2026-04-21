//! CAPI (Cluster API) provider management
//!
//! Handles installing and upgrading CAPI providers by reading pre-downloaded
//! YAML manifests, performing env var substitution, and applying them natively
//! via kube-rs. No external tools required.
//!
//! Always installs both kubeadm and RKE2 bootstrap/control-plane providers
//! to ensure move works between any clusters.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ListParams};
use kube::{Client as KubeClient, ResourceExt};
#[cfg(test)]
use mockall::automock;
use tracing::{debug, info, warn};

use lattice_common::credentials::{AwsCredentials, CredentialProvider};
use lattice_common::kube_utils::{self, ApplyOptions};
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{
    Error, AWS_CAPA_CREDENTIALS_SECRET, OPENSTACK_CREDENTIALS_SECRET, PROXMOX_CREDENTIALS_SECRET,
};
use lattice_core::system_namespaces::{
    CAPA_NAMESPACE, CAPI_BASIS_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE,
};
use lattice_crd::crd::{InfraProvider, ProviderType};

/// Timeout for waiting on cert-manager and provider deployments
const DEPLOYMENT_READY_TIMEOUT: Duration = Duration::from_secs(300);

// =============================================================================
// Provider path mapping
// =============================================================================

/// Map (provider_name, provider_type) to the directory name under /providers/
fn provider_dir_name(name: &str, provider_type: CapiProviderType) -> &'static str {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => "cluster-api",
        ("kubeadm", CapiProviderType::Bootstrap) => "bootstrap-kubeadm",
        ("kubeadm", CapiProviderType::ControlPlane) => "control-plane-kubeadm",
        ("rke2", CapiProviderType::Bootstrap) => "bootstrap-rke2",
        ("rke2", CapiProviderType::ControlPlane) => "control-plane-rke2",
        ("docker", CapiProviderType::Infrastructure) => "infrastructure-docker",
        ("proxmox", CapiProviderType::Infrastructure) => "infrastructure-proxmox",
        ("aws", CapiProviderType::Infrastructure) => "infrastructure-aws",
        ("openstack", CapiProviderType::Infrastructure) => "infrastructure-openstack",
        ("basis", CapiProviderType::Infrastructure) => "infrastructure-basis",
        ("in-cluster", _) => "ipam-in-cluster",
        _ => "unknown",
    }
}

/// Map (provider_name, provider_type) to the expected Kubernetes namespace
fn provider_namespace(name: &str, provider_type: CapiProviderType) -> Option<&'static str> {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => Some("capi-system"),
        ("kubeadm", CapiProviderType::Bootstrap) => Some("capi-kubeadm-bootstrap-system"),
        ("kubeadm", CapiProviderType::ControlPlane) => Some("capi-kubeadm-control-plane-system"),
        ("rke2", CapiProviderType::Bootstrap) => Some("rke2-bootstrap-system"),
        ("rke2", CapiProviderType::ControlPlane) => Some("rke2-control-plane-system"),
        ("docker", CapiProviderType::Infrastructure) => Some("capd-system"),
        ("proxmox", CapiProviderType::Infrastructure) => Some(CAPMOX_NAMESPACE),
        ("aws", CapiProviderType::Infrastructure) => Some(CAPA_NAMESPACE),
        ("openstack", CapiProviderType::Infrastructure) => Some(CAPO_NAMESPACE),
        ("basis", CapiProviderType::Infrastructure) => Some(CAPI_BASIS_NAMESPACE),
        ("in-cluster", _) => Some("capi-ipam-in-cluster-system"),
        _ => None,
    }
}

/// Map (provider_name, provider_type) to the component YAML filenames
fn provider_component_files(
    name: &str,
    provider_type: CapiProviderType,
) -> &'static [&'static str] {
    match (name, provider_type) {
        ("cluster-api", CapiProviderType::Core) => &["core-components.yaml"],
        ("kubeadm", CapiProviderType::Bootstrap) => &["bootstrap-components.yaml"],
        ("kubeadm", CapiProviderType::ControlPlane) => &["control-plane-components.yaml"],
        ("rke2", CapiProviderType::Bootstrap) => &["bootstrap-components.yaml"],
        ("rke2", CapiProviderType::ControlPlane) => &["control-plane-components.yaml"],
        ("docker", CapiProviderType::Infrastructure) => {
            &["infrastructure-components-development.yaml"]
        }
        ("proxmox", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("aws", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("openstack", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("basis", CapiProviderType::Infrastructure) => &["infrastructure-components.yaml"],
        ("in-cluster", _) => &["ipam-components.yaml"],
        _ => &[],
    }
}

// =============================================================================
// Env var substitution
// =============================================================================

/// Substitute `${VAR}` patterns in YAML, handling bash-style defaults.
///
/// Supported patterns (matching clusterctl behavior):
/// - `${VAR}` — replaced with value from `vars`, or left as-is if missing
/// - `${VAR:=default}` — replaced with value from `vars`, or `default` if missing
/// - `${VAR:-default}` — same as `:=`
/// - `${VAR="default"}` — replaced with value from `vars`, or `default` if missing
/// - `${VAR/#pattern/replacement}` — bash string substitution (resolved to value or empty)
fn substitute_vars(yaml: &str, vars: &[(String, String)]) -> String {
    let var_map: HashMap<&str, &str> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut result = String::with_capacity(yaml.len());
    let mut remaining = yaml;

    while let Some(start) = remaining.find("${") {
        result.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];

        if let Some(end) = after_start.find('}') {
            let expr = &after_start[..end];
            let replacement = resolve_var_expr(expr, &var_map);
            result.push_str(&replacement);
            remaining = &after_start[end + 1..];
        } else {
            // No closing brace — emit literal and advance past "${"
            result.push_str("${");
            remaining = after_start;
        }
    }
    result.push_str(remaining);
    result
}

/// Resolve a single variable expression (the content between `${` and `}`).
fn resolve_var_expr(expr: &str, vars: &HashMap<&str, &str>) -> String {
    // ${VAR/#pattern/replacement} — bash string substitution
    if let Some(slash_pos) = expr.find("/#") {
        let var_name = &expr[..slash_pos];
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_default();
    }

    // ${VAR:=default} or ${VAR:-default}
    if let Some(pos) = expr.find(":=").or_else(|| expr.find(":-")) {
        let var_name = &expr[..pos];
        let default = &expr[pos + 2..];
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string());
    }

    // ${VAR="default"} — strip surrounding quotes from default
    if let Some(pos) = expr.find('=') {
        let var_name = &expr[..pos];
        let default = expr[pos + 1..].trim_matches('"');
        return vars
            .get(var_name)
            .map(|s| s.to_string())
            .unwrap_or_else(|| default.to_string());
    }

    // ${VAR} — plain substitution, leave as-is if missing
    vars.get(expr)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("${{{}}}", expr))
}

// =============================================================================
// Credential helpers (free functions, testable without a struct)
// =============================================================================

/// Read a Kubernetes secret and return its data as string key-value pairs.
async fn read_secret(
    client: &KubeClient,
    namespace: &str,
    name: &str,
) -> Result<HashMap<String, String>, String> {
    use k8s_openapi::api::core::v1::Secret;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret = secrets
        .get(name)
        .await
        .map_err(|e| format!("Failed to get secret {}/{}: {}", namespace, name, e))?;

    let mut data = HashMap::new();
    if let Some(string_data) = secret.string_data {
        data.extend(string_data);
    }
    if let Some(secret_data) = secret.data {
        for (key, value) in secret_data {
            if let Ok(decoded) = String::from_utf8(value.0) {
                data.insert(key, decoded);
            }
        }
    }

    Ok(data)
}

/// Build provider-specific env vars for template substitution.
///
/// Reads credentials from pre-created secrets to substitute template
/// variables like `${PROXMOX_URL}` in provider manifests.
async fn get_provider_env_vars(
    client: &KubeClient,
    config: &CapiProviderConfig,
) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();
    let info = &config.infra_info;

    if let Some((namespace, secret_name)) = config.credentials_secret() {
        if let Ok(secret) = read_secret(client, namespace, secret_name).await {
            if config.infrastructure == ProviderType::Aws {
                match AwsCredentials::from_secret(&secret) {
                    Ok(creds) => {
                        env_vars.push((
                            "AWS_B64ENCODED_CREDENTIALS".to_string(),
                            creds.to_b64_encoded(),
                        ));
                        info!(provider = "aws", "Generated AWS_B64ENCODED_CREDENTIALS");
                    }
                    Err(e) => {
                        warn!(provider = "aws", error = %e, "Failed to load AWS credentials");
                    }
                }
            } else {
                for (secret_key, env_key) in info.credentials_env_map {
                    if let Some(value) = secret.get(*secret_key) {
                        env_vars.push((env_key.to_string(), value.clone()));
                    }
                }
                if !env_vars.is_empty() {
                    info!(
                        provider = info.name,
                        credentials_count = env_vars.len(),
                        "Loaded provider credentials"
                    );
                }
            }
        }
    }

    env_vars
}

// =============================================================================
// Version detection (free functions)
// =============================================================================

/// All known provider (name, type) pairs for discovery.
const KNOWN_PROVIDERS: &[(&str, CapiProviderType)] = &[
    ("cluster-api", CapiProviderType::Core),
    ("kubeadm", CapiProviderType::Bootstrap),
    ("kubeadm", CapiProviderType::ControlPlane),
    ("rke2", CapiProviderType::Bootstrap),
    ("rke2", CapiProviderType::ControlPlane),
    ("docker", CapiProviderType::Infrastructure),
    ("proxmox", CapiProviderType::Infrastructure),
    ("openstack", CapiProviderType::Infrastructure),
    ("aws", CapiProviderType::Infrastructure),
    ("basis", CapiProviderType::Infrastructure),
    ("in-cluster", CapiProviderType::Infrastructure),
];

/// Get installed CAPI providers by checking provider namespaces in parallel.
async fn get_installed_providers(client: &KubeClient) -> Vec<InstalledProvider> {
    let futures: Vec<_> = KNOWN_PROVIDERS
        .iter()
        .filter_map(|(name, provider_type)| {
            let namespace = provider_namespace(name, *provider_type)?;
            let client = client.clone();
            let name = *name;
            let provider_type = *provider_type;
            Some(async move {
                match get_provider_version(&client, namespace).await {
                    Ok(Some(version)) => Some(InstalledProvider {
                        name: name.to_string(),
                        provider_type,
                        version,
                        namespace: namespace.to_string(),
                    }),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(namespace = %namespace, error = %e, "Failed to check provider version");
                        None
                    }
                }
            })
        })
        .collect();

    let results = futures::future::join_all(futures).await;
    results.into_iter().flatten().collect()
}

/// Get provider version from deployment labels.
///
/// Returns `Ok(Some(version))` if found, `Ok(None)` if namespace doesn't exist.
async fn get_provider_version(
    client: &KubeClient,
    namespace: &str,
) -> Result<Option<String>, String> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    match namespaces.get(namespace).await {
        Ok(_) => {}
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(None),
        Err(e) => return Err(format!("failed to check namespace {}: {}", namespace, e)),
    }

    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let list = deployments
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("failed to list deployments in {}: {}", namespace, e))?;

    let Some(deployment) = list.items.first() else {
        return Ok(None);
    };
    let Some(labels) = deployment.metadata.labels.as_ref() else {
        return Ok(Some("unknown".to_string()));
    };

    if let Some(version) = labels.get("app.kubernetes.io/version") {
        if !version.is_empty() {
            return Ok(Some(version.clone()));
        }
    }

    // Fallback: RKE2 providers use a different label
    if let Some(version) = labels.get("cluster-api.cattle.io/version") {
        if !version.is_empty() {
            return Ok(Some(version.clone()));
        }
    }

    Ok(Some("unknown".to_string()))
}

/// Compute what actions are needed for each provider.
fn compute_provider_actions(
    installed: &[InstalledProvider],
    desired: &[DesiredProvider],
) -> HashMap<String, ProviderAction> {
    let mut actions = HashMap::new();

    let installed_map: HashMap<(String, CapiProviderType), &InstalledProvider> = installed
        .iter()
        .map(|p| ((p.name.clone(), p.provider_type), p))
        .collect();

    for desired_provider in desired {
        let key = (
            desired_provider.name.clone(),
            desired_provider.provider_type,
        );
        let action_key = format!(
            "{}:{:?}",
            desired_provider.name, desired_provider.provider_type
        );

        if let Some(installed_provider) = installed_map.get(&key) {
            if installed_provider.version == desired_provider.version
                || installed_provider.version == "unknown"
            {
                actions.insert(action_key, ProviderAction::Skip);
            } else {
                actions.insert(
                    action_key,
                    ProviderAction::Upgrade {
                        from: installed_provider.version.clone(),
                        to: desired_provider.version.clone(),
                    },
                );
            }
        } else {
            actions.insert(action_key, ProviderAction::Install);
        }
    }

    actions
}

// =============================================================================
// Credential copying
// =============================================================================

/// Copy credentials from InfraProvider's secret reference to the CAPI provider namespace.
///
/// Returns the CAPI infrastructure provider namespace for a given type.
/// `None` for Docker (no credentials needed).
pub fn infra_provider_namespace(provider: ProviderType) -> Option<&'static str> {
    match provider {
        ProviderType::Aws => Some(CAPA_NAMESPACE),
        ProviderType::Proxmox => Some(CAPMOX_NAMESPACE),
        ProviderType::OpenStack => Some(CAPO_NAMESPACE),
        ProviderType::Basis => Some(CAPI_BASIS_NAMESPACE),
        _ => None,
    }
}

/// Install every component CAPI depends on before `ensure_capi_providers_for`
/// can succeed: cert-manager (webhooks), ESO (ExternalSecret CRDs used for
/// provider credential sync), and the local-webhook `ClusterSecretStore`
/// (ESO's fallback backend when no external vault is configured).
///
/// Single entry point used by both the in-cluster operator startup and the
/// CLI uninstall flow — the uninstall kind cluster needs the same
/// prerequisites as a real bootstrap cluster because both end up calling
/// [`ensure_capi_providers_for`].
pub async fn ensure_capi_prereqs(client: &KubeClient) -> Result<(), Error> {
    let (cm, eso) = tokio::join!(
        lattice_cert_manager::install::install_blocking(client),
        lattice_eso::install::install_blocking(client),
    );
    cm.map_err(|e| Error::capi_installation(format!("cert-manager install failed: {e}")))?;
    eso.map_err(|e| Error::capi_installation(format!("ESO install failed: {e}")))?;

    lattice_secret_provider::controller::ensure_local_webhook_infrastructure(client)
        .await
        .map_err(|e| {
            Error::capi_installation(format!("local-webhook ClusterSecretStore failed: {e}"))
        })?;

    info!("cert-manager, ESO, and local-webhook ClusterSecretStore ready");
    Ok(())
}

/// Install CAPI providers for a given `ProviderType`, wiring the
/// `InfraProvider`'s ESO credentials and declared image pull secrets into the
/// CAPI provider namespace. This is the single entry point used by both the
/// CLI install path and the in-cluster operator startup — keeping them
/// identical is important because CAPI pods start failing quickly when
/// credentials or pull secrets are missing.
///
/// `cp` is optional: Docker clusters have no cloud provider, and the uninstall
/// bootstrap path installs CAPI into a fresh kind cluster before the
/// InfraProvider has been copied over.
pub async fn ensure_capi_providers_for(
    client: &KubeClient,
    installer: &dyn CapiInstaller,
    provider_type: ProviderType,
    cp: Option<&InfraProvider>,
    field_manager: &str,
) -> Result<(), Error> {
    tracing::info!(infrastructure = ?provider_type, "Installing CAPI providers");

    // cert-manager + ESO + local-webhook are unconditional prerequisites for
    // every CAPI install. Running them here means no caller can forget — each
    // install_blocking is idempotent (SSA re-apply) so calling this from an
    // operator that already ran prereqs in startup is cheap.
    ensure_capi_prereqs(client).await?;

    let target_ns = infra_provider_namespace(provider_type);
    let mut image_pull_secret_names: Vec<String> = Vec::new();

    if let Some(cp) = cp {
        if let (Some(credentials), Some(ns)) = (cp.spec.credentials.as_ref(), target_ns) {
            lattice_secret_provider::credentials::ensure_credentials(
                client,
                &cp.name_any(),
                credentials,
                cp.spec.credential_data.as_ref(),
                ns,
                field_manager,
            )
            .await
            .map_err(|e| {
                Error::capi_installation(format!("failed to sync credentials to {ns}: {e}"))
            })?;
        }

        if let Some(ns) = target_ns {
            image_pull_secret_names =
                lattice_secret_provider::credentials::ensure_capi_image_pull_secrets(
                    client,
                    cp,
                    ns,
                    field_manager,
                )
                .await
                .map_err(|e| {
                    Error::capi_installation(format!(
                        "failed to materialize image pull secrets: {e}"
                    ))
                })?;
        } else if !cp.spec.image_pull_secrets.is_empty() {
            tracing::warn!(
                provider = ?provider_type,
                "InfraProvider declares imagePullSecrets but provider has no CAPI namespace; ignoring"
            );
        }
    }

    let config =
        CapiProviderConfig::new(provider_type)?.with_image_pull_secrets(image_pull_secret_names);
    installer.ensure(&config).await?;

    tracing::info!(infrastructure = ?provider_type, "CAPI providers installed");
    Ok(())
}

// =============================================================================
// Public types
// =============================================================================

/// Provider types supported by CAPI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapiProviderType {
    Core,
    Bootstrap,
    ControlPlane,
    Infrastructure,
}

impl std::fmt::Display for CapiProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapiProviderType::Core => write!(f, "CoreProvider"),
            CapiProviderType::Bootstrap => write!(f, "BootstrapProvider"),
            CapiProviderType::ControlPlane => write!(f, "ControlPlaneProvider"),
            CapiProviderType::Infrastructure => write!(f, "InfrastructureProvider"),
        }
    }
}

/// Information about an installed CAPI provider
#[derive(Debug, Clone)]
pub struct InstalledProvider {
    pub name: String,
    pub provider_type: CapiProviderType,
    pub version: String,
    pub namespace: String,
}

/// Desired provider configuration
#[derive(Debug, Clone)]
pub struct DesiredProvider {
    pub name: String,
    pub provider_type: CapiProviderType,
    pub version: String,
}

/// Action to take for a provider
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderAction {
    Skip,
    Install,
    Upgrade { from: String, to: String },
}

/// Provider-specific configuration for CAPI infrastructure providers
#[derive(Debug, Clone)]
pub struct InfraProviderInfo {
    pub name: &'static str,
    pub version: String,
    pub credentials_secret: Option<(&'static str, &'static str)>,
    pub credentials_env_map: &'static [(&'static str, &'static str)],
    /// Whether this provider needs ipam-in-cluster (Proxmox)
    pub needs_ipam: bool,
}

impl InfraProviderInfo {
    /// Get provider info for a given infrastructure type
    pub fn for_provider(provider: ProviderType, capi_version: &str) -> Result<Self, Error> {
        match provider {
            ProviderType::Aws => Ok(Self {
                name: "aws",
                version: env!("CAPA_VERSION").to_string(),
                credentials_secret: Some((CAPA_NAMESPACE, AWS_CAPA_CREDENTIALS_SECRET)),
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::Docker => Ok(Self {
                name: "docker",
                version: capi_version.to_string(),
                credentials_secret: None,
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::OpenStack => Ok(Self {
                name: "openstack",
                version: env!("CAPO_VERSION").to_string(),
                credentials_secret: Some((CAPO_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET)),
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::Proxmox => Ok(Self {
                name: "proxmox",
                version: env!("CAPMOX_VERSION").to_string(),
                credentials_secret: Some((CAPMOX_NAMESPACE, PROXMOX_CREDENTIALS_SECRET)),
                credentials_env_map: &[
                    ("url", "PROXMOX_URL"),
                    ("token", "PROXMOX_TOKEN"),
                    ("secret", "PROXMOX_SECRET"),
                ],
                needs_ipam: true,
            }),
            ProviderType::Basis => Ok(Self {
                name: "basis",
                version: env!("CAPI_BASIS_VERSION").to_string(),
                // Each BasisCluster carries its own `spec.credentialsRef`
                // pointing at the Secret Lattice seeds in `lattice-secrets`;
                // the provider reconciler reads that Secret per-reconcile.
                credentials_secret: None,
                credentials_env_map: &[],
                needs_ipam: false,
            }),
            ProviderType::Gcp | ProviderType::Azure | _ => Err(Error::capi_installation(format!(
                "Provider {:?} is not yet implemented",
                provider
            ))),
        }
    }
}

/// Configuration for CAPI provider installation
#[derive(Debug, Clone)]
pub struct CapiProviderConfig {
    pub infrastructure: ProviderType,
    pub capi_version: String,
    pub rke2_version: String,
    pub infra_info: InfraProviderInfo,
    pub credentials_secret_override: Option<(String, String)>,
    /// Names of Secrets (already materialized in the infrastructure provider's
    /// namespace by the caller) that the infrastructure provider's Deployment
    /// should reference via `imagePullSecrets`. Used when the CAPI provider
    /// image lives in a private registry.
    pub image_pull_secret_names: Vec<String>,
}

impl CapiProviderConfig {
    /// Create a new CAPI provider configuration from compile-time versions.
    pub fn new(infrastructure: ProviderType) -> Result<Self, Error> {
        let capi_version = env!("CAPI_VERSION").to_string();
        let infra_info = InfraProviderInfo::for_provider(infrastructure, &capi_version)?;

        Ok(Self {
            infrastructure,
            capi_version,
            rke2_version: env!("RKE2_VERSION").to_string(),
            infra_info,
            credentials_secret_override: None,
            image_pull_secret_names: Vec::new(),
        })
    }

    pub fn with_credentials_secret(mut self, namespace: String, name: String) -> Self {
        self.credentials_secret_override = Some((namespace, name));
        self
    }

    /// Attach names of image pull Secrets to wire onto the infrastructure
    /// provider's Deployment. The Secrets must already exist in the provider
    /// namespace (typically materialized by ESO).
    pub fn with_image_pull_secrets(mut self, names: Vec<String>) -> Self {
        self.image_pull_secret_names = names;
        self
    }

    /// Get the effective credentials secret location.
    pub fn credentials_secret(&self) -> Option<(&str, &str)> {
        if let Some((ref ns, ref name)) = self.credentials_secret_override {
            Some((ns.as_str(), name.as_str()))
        } else {
            self.infra_info.credentials_secret
        }
    }

    /// Create config with explicit versions (for testing).
    pub fn with_versions(
        infrastructure: ProviderType,
        capi_version: String,
        rke2_version: String,
    ) -> Result<Self, Error> {
        let name = match infrastructure {
            ProviderType::Aws => "aws",
            ProviderType::Docker => "docker",
            ProviderType::OpenStack => "openstack",
            ProviderType::Proxmox => "proxmox",
            ProviderType::Basis => "basis",
            ProviderType::Gcp | ProviderType::Azure | _ => {
                return Err(Error::capi_installation(format!(
                    "Provider {:?} is not yet implemented",
                    infrastructure
                )));
            }
        };

        let infra_info = InfraProviderInfo {
            name,
            version: capi_version.clone(),
            credentials_secret: None,
            credentials_env_map: &[],
            needs_ipam: false,
        };

        Ok(Self {
            infrastructure,
            capi_version,
            rke2_version,
            infra_info,
            credentials_secret_override: None,
            image_pull_secret_names: Vec::new(),
        })
    }

    /// Get the list of desired providers based on this config.
    pub fn desired_providers(&self) -> Vec<DesiredProvider> {
        let mut providers = vec![
            DesiredProvider {
                name: "cluster-api".to_string(),
                provider_type: CapiProviderType::Core,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "kubeadm".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.capi_version),
            },
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::Bootstrap,
                version: format!("v{}", self.rke2_version),
            },
            DesiredProvider {
                name: "rke2".to_string(),
                provider_type: CapiProviderType::ControlPlane,
                version: format!("v{}", self.rke2_version),
            },
            DesiredProvider {
                name: self.infra_info.name.to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", self.infra_info.version),
            },
        ];

        // Proxmox needs the IPAM in-cluster provider
        if self.infra_info.needs_ipam {
            providers.push(DesiredProvider {
                name: "in-cluster".to_string(),
                provider_type: CapiProviderType::Infrastructure,
                version: format!("v{}", env!("IPAM_IN_CLUSTER_VERSION")),
            });
        }

        providers
    }

    /// Return the Kubernetes namespaces where all desired CAPI providers run.
    ///
    /// Used by the installer to wait for deployments before starting the pivot.
    pub fn provider_namespaces(&self) -> Vec<&'static str> {
        self.desired_providers()
            .iter()
            .filter_map(|p| provider_namespace(&p.name, p.provider_type))
            .collect()
    }
}

// =============================================================================
// Installer trait and implementation
// =============================================================================

/// Trait for installing CAPI providers
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CapiInstaller: Send + Sync {
    /// Ensure CAPI providers are installed and up to date.
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error>;
}

/// Native CAPI installer that reads pre-downloaded YAML manifests and applies them directly.
pub struct NativeInstaller;

impl NativeInstaller {
    pub fn new() -> Self {
        Self
    }

    /// Resolve the providers directory from env var or compile-time default.
    fn providers_dir() -> PathBuf {
        let dir = std::env::var("PROVIDERS_DIR").unwrap_or_else(|_| {
            option_env!("PROVIDERS_DIR")
                .unwrap_or("/providers")
                .to_string()
        });
        PathBuf::from(dir)
    }

    /// Read a provider's component YAML files from disk.
    fn read_provider_manifests(
        providers_dir: &Path,
        dir_name: &str,
        version: &str,
        components: &[&str],
    ) -> Result<Vec<String>, Error> {
        let provider_path = providers_dir.join(dir_name).join(version);
        let mut manifests = Vec::new();

        for component in components {
            let file_path = provider_path.join(component);
            let content = std::fs::read_to_string(&file_path).map_err(|e| {
                Error::capi_installation(format!(
                    "Failed to read provider manifest {}: {}",
                    file_path.display(),
                    e
                ))
            })?;
            manifests.push(content);
        }

        Ok(manifests)
    }

    /// Apply a single provider's manifests with env var substitution.
    async fn apply_provider(
        client: &KubeClient,
        providers_dir: &Path,
        desired: &DesiredProvider,
        env_vars: &[(String, String)],
        image_pull_secret_names: &[String],
    ) -> Result<(), Error> {
        let dir_name = provider_dir_name(&desired.name, desired.provider_type);
        let components = provider_component_files(&desired.name, desired.provider_type);

        let raw_manifests =
            Self::read_provider_manifests(providers_dir, dir_name, &desired.version, components)?;

        let mut all_documents = Vec::new();
        for raw in &raw_manifests {
            let substituted = substitute_vars(raw, env_vars);
            all_documents.extend(kube_utils::split_yaml_documents(&substituted));
        }

        // Rewrite Deployment PodSpecs before the first SSA so that the
        // initial rollout already carries our control-plane toleration and
        // any required imagePullSecrets. Patching post-apply forced a second
        // ReplicaSet revision and — on private registries — an ImagePullBackOff
        // cycle while the first revision waited for a non-existent pull secret.
        let all_documents = inject_deployment_overrides(all_documents, image_pull_secret_names)?;

        info!(
            provider = %desired.name,
            provider_type = %desired.provider_type,
            version = %desired.version,
            documents = all_documents.len(),
            "Applying provider manifests"
        );

        let provider_label = format!("{} {}", desired.provider_type, desired.name);
        retry_with_backoff(
            &RetryConfig {
                initial_delay: Duration::from_secs(2),
                ..RetryConfig::default()
            },
            &provider_label,
            || {
                let client = client.clone();
                let docs = all_documents.clone();
                async move {
                    kube_utils::apply_manifests(&client, &docs, &ApplyOptions::default()).await
                }
            },
        )
        .await
        .map_err(|e| {
            Error::capi_installation(format!("Failed to apply {}: {}", provider_label, e))
        })?;

        Ok(())
    }
}

/// Rewrite every `Deployment` document's `spec.template.spec` to carry the
/// control-plane `NoSchedule` toleration and any caller-supplied
/// `imagePullSecrets`. Non-Deployment documents pass through unchanged.
///
/// Merges rather than replaces: existing tolerations and pull secrets are
/// preserved, and re-injection is idempotent (duplicates are skipped by
/// `key`+`effect` and `name` respectively).
///
/// Deployment docs round-trip through `serde_json`, so they come out as JSON —
/// `apply_manifests` accepts both JSON and YAML.
fn inject_deployment_overrides(
    docs: Vec<String>,
    image_pull_secret_names: &[String],
) -> Result<Vec<String>, Error> {
    docs.into_iter()
        .map(|doc| inject_one(&doc, image_pull_secret_names))
        .collect()
}

fn inject_one(doc: &str, image_pull_secret_names: &[String]) -> Result<String, Error> {
    // Cheap pre-check: `split_yaml_documents` guarantees every doc contains
    // `kind:`, but only Deployments need rewriting.
    if !doc.contains("kind: Deployment") && !doc.contains("\"kind\": \"Deployment\"") {
        return Ok(doc.to_string());
    }

    let mut value: serde_json::Value = if doc.trim_start().starts_with('{') {
        serde_json::from_str(doc).map_err(|e| {
            Error::capi_installation(format!("failed to parse Deployment JSON: {e}"))
        })?
    } else {
        lattice_core::yaml::parse_yaml(doc).map_err(|e| {
            Error::capi_installation(format!("failed to parse Deployment YAML: {e}"))
        })?
    };

    if value.get("kind").and_then(|k| k.as_str()) != Some("Deployment") {
        return Ok(doc.to_string());
    }

    let Some(pod_spec) = value
        .pointer_mut("/spec/template/spec")
        .and_then(|v| v.as_object_mut())
    else {
        return Ok(doc.to_string());
    };

    merge_control_plane_toleration(pod_spec);
    merge_image_pull_secrets(pod_spec, image_pull_secret_names);

    serde_json::to_string(&value)
        .map_err(|e| Error::capi_installation(format!("failed to serialize Deployment: {e}")))
}

/// Append the control-plane `NoSchedule` toleration unless an entry with the
/// same `key` and `effect` already exists.
fn merge_control_plane_toleration(pod_spec: &mut serde_json::Map<String, serde_json::Value>) {
    let tolerations = pod_spec
        .entry("tolerations".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let Some(arr) = tolerations.as_array_mut() else {
        return;
    };
    let already = arr.iter().any(|t| {
        t.get("key").and_then(|v| v.as_str()) == Some("node-role.kubernetes.io/control-plane")
            && t.get("effect").and_then(|v| v.as_str()) == Some("NoSchedule")
    });
    if !already {
        arr.push(serde_json::json!({
            "key": "node-role.kubernetes.io/control-plane",
            "operator": "Exists",
            "effect": "NoSchedule",
        }));
    }
}

/// Append each pull secret name unless an entry with the same `name` already
/// exists.
fn merge_image_pull_secrets(
    pod_spec: &mut serde_json::Map<String, serde_json::Value>,
    names: &[String],
) {
    if names.is_empty() {
        return;
    }
    let secrets = pod_spec
        .entry("imagePullSecrets".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let Some(arr) = secrets.as_array_mut() else {
        return;
    };
    for name in names {
        let already = arr
            .iter()
            .any(|s| s.get("name").and_then(|v| v.as_str()) == Some(name.as_str()));
        if !already {
            arr.push(serde_json::json!({ "name": name }));
        }
    }
}

impl Default for NativeInstaller {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CapiInstaller for NativeInstaller {
    async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error> {
        let client = kube_utils::create_client(None, None, None)
            .await
            .map_err(|e| Error::capi_installation(format!("Failed to create k8s client: {}", e)))?;

        let installed = get_installed_providers(&client).await;
        let desired = config.desired_providers();

        debug!(
            installed = ?installed.iter().map(|p| format!("{}:{:?}@{}", p.name, p.provider_type, p.version)).collect::<Vec<_>>(),
            "Found installed CAPI providers"
        );

        let actions = compute_provider_actions(&installed, &desired);

        for (key, action) in &actions {
            match action {
                ProviderAction::Skip => debug!(provider = %key, "Provider up to date"),
                ProviderAction::Install => info!(provider = %key, "Provider will be installed"),
                ProviderAction::Upgrade { from, to } => {
                    info!(provider = %key, from = %from, to = %to, "Provider will be upgraded")
                }
            }
        }

        let needs_work = actions
            .values()
            .any(|a| *a == ProviderAction::Install || matches!(a, ProviderAction::Upgrade { .. }));

        if !needs_work {
            info!("All CAPI providers are up to date");
            return Ok(());
        }

        let providers_dir = Self::providers_dir();

        // NOTE: cert-manager is installed separately via Helm-rendered manifests
        // (see lattice-infra::bootstrap::cert_manager). It must be ready before
        // this function is called.

        // Read provider credentials for template substitution
        let env_vars = get_provider_env_vars(&client, config).await;

        // Apply each provider that needs install or upgrade
        for desired_provider in &desired {
            let action_key = format!(
                "{}:{:?}",
                desired_provider.name, desired_provider.provider_type
            );
            let action = actions.get(&action_key).unwrap_or(&ProviderAction::Skip);

            // Only the infrastructure provider consumes InfraProvider-declared
            // image pull secrets — core/bootstrap/control-plane providers ship
            // from public registries.
            let pull_secrets: &[String] =
                if desired_provider.provider_type == CapiProviderType::Infrastructure {
                    &config.image_pull_secret_names
                } else {
                    &[]
                };

            match action {
                ProviderAction::Skip => continue,
                ProviderAction::Install => {
                    Self::apply_provider(
                        &client,
                        &providers_dir,
                        desired_provider,
                        &env_vars,
                        pull_secrets,
                    )
                    .await?;
                }
                ProviderAction::Upgrade { from, to } => {
                    info!(
                        provider = %desired_provider.name,
                        from = %from,
                        to = %to,
                        "Upgrading provider (re-applying manifests)"
                    );
                    // For upgrades, re-apply the manifests (SSA handles diffs)
                    if let Err(e) = Self::apply_provider(
                        &client,
                        &providers_dir,
                        desired_provider,
                        &env_vars,
                        pull_secrets,
                    )
                    .await
                    {
                        warn!(
                            provider = %desired_provider.name,
                            error = %e,
                            "Provider upgrade had issues, continuing"
                        );
                    }
                }
            }
        }

        // Wait for all provider deployments to be ready
        // Check each provider namespace that was installed/upgraded
        for desired_provider in &desired {
            let action_key = format!(
                "{}:{:?}",
                desired_provider.name, desired_provider.provider_type
            );
            let action = actions.get(&action_key).unwrap_or(&ProviderAction::Skip);
            if *action == ProviderAction::Skip {
                continue;
            }

            let Some(namespace) =
                provider_namespace(&desired_provider.name, desired_provider.provider_type)
            else {
                debug!(provider = %desired_provider.name, "Unknown provider namespace, skipping readiness check");
                continue;
            };

            info!(namespace = %namespace, "Waiting for provider deployments...");
            if let Err(e) =
                kube_utils::wait_for_all_deployments(&client, namespace, DEPLOYMENT_READY_TIMEOUT)
                    .await
            {
                warn!(namespace = %namespace, error = %e, "Provider readiness check failed, continuing");
            }
        }

        info!("CAPI providers installed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_vars_replaces_patterns() {
        let yaml = "url: ${PROXMOX_URL}\ntoken: ${PROXMOX_TOKEN}";
        let vars = vec![
            (
                "PROXMOX_URL".to_string(),
                "https://pve.example.com".to_string(),
            ),
            ("PROXMOX_TOKEN".to_string(), "root@pam!token".to_string()),
        ];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(
            result,
            "url: https://pve.example.com\ntoken: root@pam!token"
        );
    }

    #[test]
    fn substitute_vars_leaves_unknown_patterns() {
        let yaml = "value: ${UNKNOWN_VAR}";
        let vars = vec![("OTHER".to_string(), "val".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "value: ${UNKNOWN_VAR}");
    }

    #[test]
    fn substitute_vars_handles_colon_equals_default() {
        let yaml = "- --insecure-diagnostics=${CAPI_INSECURE_DIAGNOSTICS:=false}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "- --insecure-diagnostics=false");
    }

    #[test]
    fn substitute_vars_colon_equals_prefers_provided_value() {
        let yaml = "- --insecure-diagnostics=${CAPI_INSECURE_DIAGNOSTICS:=false}";
        let vars = vec![("CAPI_INSECURE_DIAGNOSTICS".to_string(), "true".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "- --insecure-diagnostics=true");
    }

    #[test]
    fn substitute_vars_handles_colon_dash_default() {
        let yaml = "value: ${MY_VAR:-hello}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "value: hello");
    }

    #[test]
    fn substitute_vars_handles_equals_quoted_default() {
        let yaml = "host: ${PROXMOX_URL=\"\"}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "host: ");
    }

    #[test]
    fn substitute_vars_handles_bash_string_substitution() {
        // ${VAR/#pattern/replacement} should resolve to value or empty
        let yaml = "role: ${AWS_CONTROLLER_IAM_ROLE/#arn/eks.amazonaws.com/role-arn: arn}";
        let result = substitute_vars(yaml, &[]);
        assert_eq!(result, "role: ");
    }

    #[test]
    fn substitute_vars_handles_multiple_defaults_in_one_string() {
        let yaml = "a=${X:=1} b=${Y:=2} c=${Z:=3}";
        let vars = vec![("Y".to_string(), "override".to_string())];
        let result = substitute_vars(yaml, &vars);
        assert_eq!(result, "a=1 b=override c=3");
    }

    #[test]
    fn provider_dir_name_maps_correctly() {
        assert_eq!(
            provider_dir_name("cluster-api", CapiProviderType::Core),
            "cluster-api"
        );
        assert_eq!(
            provider_dir_name("kubeadm", CapiProviderType::Bootstrap),
            "bootstrap-kubeadm"
        );
        assert_eq!(
            provider_dir_name("kubeadm", CapiProviderType::ControlPlane),
            "control-plane-kubeadm"
        );
        assert_eq!(
            provider_dir_name("rke2", CapiProviderType::Bootstrap),
            "bootstrap-rke2"
        );
        assert_eq!(
            provider_dir_name("docker", CapiProviderType::Infrastructure),
            "infrastructure-docker"
        );
        assert_eq!(
            provider_dir_name("proxmox", CapiProviderType::Infrastructure),
            "infrastructure-proxmox"
        );
        assert_eq!(
            provider_dir_name("in-cluster", CapiProviderType::Infrastructure),
            "ipam-in-cluster"
        );
    }

    #[test]
    fn provider_component_files_returns_correct_files() {
        assert_eq!(
            provider_component_files("cluster-api", CapiProviderType::Core),
            &["core-components.yaml"]
        );
        assert_eq!(
            provider_component_files("docker", CapiProviderType::Infrastructure),
            &["infrastructure-components-development.yaml"]
        );
        assert_eq!(
            provider_component_files("in-cluster", CapiProviderType::Infrastructure),
            &["ipam-components.yaml"]
        );
    }

    #[test]
    fn desired_providers_includes_all_required() {
        let config = CapiProviderConfig::with_versions(
            ProviderType::Docker,
            "1.12.1".to_string(),
            "0.11.0".to_string(),
        )
        .expect("Docker provider should be supported");
        let providers = config.desired_providers();

        assert_eq!(providers.len(), 6);
        assert!(providers
            .iter()
            .any(|p| p.name == "cluster-api" && p.provider_type == CapiProviderType::Core));
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "kubeadm" && p.provider_type == CapiProviderType::ControlPlane));
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::Bootstrap));
        assert!(providers
            .iter()
            .any(|p| p.name == "rke2" && p.provider_type == CapiProviderType::ControlPlane));
        assert!(providers
            .iter()
            .any(|p| p.name == "docker" && p.provider_type == CapiProviderType::Infrastructure));
    }

    #[test]
    fn desired_providers_includes_ipam_for_proxmox() {
        let config =
            CapiProviderConfig::new(ProviderType::Proxmox).expect("Proxmox should be supported");
        let providers = config.desired_providers();
        assert!(providers.iter().any(|p| p.name == "in-cluster"));
    }

    #[test]
    fn compute_actions_identifies_missing_providers() {
        let installed = vec![];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = compute_provider_actions(&installed, &desired);
        assert_eq!(
            actions.get("cluster-api:Core"),
            Some(&ProviderAction::Install)
        );
    }

    #[test]
    fn compute_actions_identifies_upgrades() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.11.0".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = compute_provider_actions(&installed, &desired);
        assert_eq!(
            actions.get("cluster-api:Core"),
            Some(&ProviderAction::Upgrade {
                from: "v1.11.0".to_string(),
                to: "v1.12.1".to_string()
            })
        );
    }

    #[test]
    fn compute_actions_skips_up_to_date() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = compute_provider_actions(&installed, &desired);
        assert_eq!(actions.get("cluster-api:Core"), Some(&ProviderAction::Skip));
    }

    #[test]
    fn compute_actions_handles_unknown_version() {
        let installed = vec![InstalledProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "unknown".to_string(),
            namespace: "capi-system".to_string(),
        }];
        let desired = vec![DesiredProvider {
            name: "cluster-api".to_string(),
            provider_type: CapiProviderType::Core,
            version: "v1.12.1".to_string(),
        }];

        let actions = compute_provider_actions(&installed, &desired);
        assert_eq!(actions.get("cluster-api:Core"), Some(&ProviderAction::Skip));
    }

    #[test]
    fn supported_infrastructure_providers_map_correctly() {
        for (provider, expected) in [
            (ProviderType::Aws, "aws"),
            (ProviderType::Docker, "docker"),
            (ProviderType::OpenStack, "openstack"),
            (ProviderType::Proxmox, "proxmox"),
        ] {
            let config = CapiProviderConfig::with_versions(
                provider,
                "1.12.1".to_string(),
                "0.11.0".to_string(),
            )
            .expect("supported provider should succeed");
            let providers = config.desired_providers();
            assert!(
                providers
                    .iter()
                    .any(|p| p.name == expected
                        && p.provider_type == CapiProviderType::Infrastructure)
            );
        }
    }

    #[tokio::test]
    async fn mock_installer_can_be_used() {
        let mut installer = MockCapiInstaller::new();
        installer.expect_ensure().returning(|_| Ok(()));

        let config =
            CapiProviderConfig::new(ProviderType::Docker).expect("Docker provider should work");
        let result = installer.ensure(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_installer_propagates_errors() {
        let mut installer = MockCapiInstaller::new();
        installer
            .expect_ensure()
            .returning(|_| Err(Error::capi_installation("test error".to_string())));

        let config =
            CapiProviderConfig::new(ProviderType::Docker).expect("Docker provider should work");
        let result = installer.ensure(&config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }

    const DEPLOYMENT_YAML: &str = r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: capi-controller
  namespace: capi-system
spec:
  template:
    spec:
      containers:
        - name: manager
          image: ghcr.io/example/capi:v1
"#;

    fn pod_spec(deployment_doc: &str) -> serde_json::Value {
        let value: serde_json::Value = if deployment_doc.trim_start().starts_with('{') {
            serde_json::from_str(deployment_doc).unwrap()
        } else {
            lattice_core::yaml::parse_yaml(deployment_doc).unwrap()
        };
        value
            .pointer("/spec/template/spec")
            .cloned()
            .expect("pod spec missing")
    }

    #[test]
    fn inject_adds_toleration_and_pull_secrets_for_deployment() {
        let out = inject_deployment_overrides(
            vec![DEPLOYMENT_YAML.to_string()],
            &["default-credentials".to_string()],
        )
        .expect("inject should succeed");
        assert_eq!(out.len(), 1);

        let spec = pod_spec(&out[0]);
        let tolerations = spec.get("tolerations").and_then(|v| v.as_array()).unwrap();
        assert_eq!(tolerations.len(), 1);
        assert_eq!(
            tolerations[0].get("key").and_then(|v| v.as_str()),
            Some("node-role.kubernetes.io/control-plane")
        );
        assert_eq!(
            tolerations[0].get("effect").and_then(|v| v.as_str()),
            Some("NoSchedule")
        );

        let pulls = spec
            .get("imagePullSecrets")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(pulls.len(), 1);
        assert_eq!(
            pulls[0].get("name").and_then(|v| v.as_str()),
            Some("default-credentials")
        );
    }

    #[test]
    fn inject_skips_pull_secrets_when_none_requested() {
        let out = inject_deployment_overrides(vec![DEPLOYMENT_YAML.to_string()], &[])
            .expect("inject should succeed");
        let spec = pod_spec(&out[0]);
        assert!(spec.get("imagePullSecrets").is_none());
        assert!(spec.get("tolerations").is_some());
    }

    #[test]
    fn inject_is_idempotent() {
        let names = vec!["default-credentials".to_string()];
        let once = inject_deployment_overrides(vec![DEPLOYMENT_YAML.to_string()], &names).unwrap();
        let twice = inject_deployment_overrides(once.clone(), &names).unwrap();

        let spec = pod_spec(&twice[0]);
        assert_eq!(
            spec.get("tolerations")
                .and_then(|v| v.as_array())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            spec.get("imagePullSecrets")
                .and_then(|v| v.as_array())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn inject_preserves_existing_tolerations_and_pull_secrets() {
        let yaml = r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: capi-controller
  namespace: capi-system
spec:
  template:
    spec:
      tolerations:
        - key: custom-taint
          operator: Exists
          effect: NoExecute
      imagePullSecrets:
        - name: upstream-secret
      containers:
        - name: manager
          image: ghcr.io/example/capi:v1
"#;
        let out = inject_deployment_overrides(
            vec![yaml.to_string()],
            &["default-credentials".to_string()],
        )
        .unwrap();
        let spec = pod_spec(&out[0]);

        let tolerations = spec.get("tolerations").and_then(|v| v.as_array()).unwrap();
        assert_eq!(tolerations.len(), 2);
        assert!(tolerations
            .iter()
            .any(|t| t.get("key").and_then(|v| v.as_str()) == Some("custom-taint")));
        assert!(tolerations
            .iter()
            .any(|t| t.get("key").and_then(|v| v.as_str())
                == Some("node-role.kubernetes.io/control-plane")));

        let pulls = spec
            .get("imagePullSecrets")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(pulls.len(), 2);
        assert!(pulls
            .iter()
            .any(|s| s.get("name").and_then(|v| v.as_str()) == Some("upstream-secret")));
        assert!(pulls
            .iter()
            .any(|s| s.get("name").and_then(|v| v.as_str()) == Some("default-credentials")));
    }

    #[test]
    fn inject_leaves_non_deployment_docs_unchanged() {
        let configmap = r#"---
apiVersion: v1
kind: ConfigMap
metadata:
  name: capi-config
data:
  foo: bar
"#;
        let out = inject_deployment_overrides(
            vec![configmap.to_string()],
            &["default-credentials".to_string()],
        )
        .unwrap();
        assert_eq!(out, vec![configmap.to_string()]);
    }
}
