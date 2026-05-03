//! ApiResource building: discovery, HasApiResource trait, and pluralization.
//!
//! **Default**: Use `build_api_resource_with_discovery()` — it queries the API
//! server for the correct version and is always accurate.
//!
//! `build_api_resource()` exists only for offline contexts (pivot import where
//! CRDs may not be installed yet, or core K8s types like `v1/Secret`).

use kube::discovery::ApiResource;
use kube::Client;

use crate::Error;

/// Trait for types that have a known API group, version, and kind.
///
/// Implement this for CRD types to derive their `ApiResource` from their
/// internal constants, ensuring consistency between serialization and API calls.
///
/// **When to use**: Types where the API version is known at compile time and you
/// want type-safe, consistent API access. The version is baked into the type.
///
/// For runtime version discovery (e.g., CAPI resources that may be at different
/// versions), use `build_api_resource_with_discovery()` instead.
///
/// # Example
/// ```ignore
/// impl HasApiResource for AuthorizationPolicy {
///     const API_VERSION: &'static str = "security.istio.io/v1";
///     const KIND: &'static str = "AuthorizationPolicy";
/// }
///
/// // Now you can get the ApiResource:
/// let ar = AuthorizationPolicy::api_resource();
/// ```
pub trait HasApiResource {
    /// Full API version (e.g., "security.istio.io/v1", "v1")
    const API_VERSION: &'static str;
    /// Resource kind (e.g., "AuthorizationPolicy")
    const KIND: &'static str;

    /// Build an ApiResource from the type's constants.
    fn api_resource() -> ApiResource {
        build_api_resource(Self::API_VERSION, Self::KIND)
    }
}

/// Generate the boilerplate `fn api_version()` and `fn kind()` serde default methods
/// required by types with `#[serde(default = "Type::api_version")]` attributes.
#[macro_export]
macro_rules! impl_api_resource_defaults {
    ($type:ty) => {
        impl $type {
            fn api_version() -> String {
                <Self as $crate::kube_utils::HasApiResource>::API_VERSION.to_string()
            }
            fn kind() -> String {
                <Self as $crate::kube_utils::HasApiResource>::KIND.to_string()
            }
        }
    };
}

/// Discover the API version for a resource group/kind.
///
/// Uses Kubernetes API discovery to find the resource. Searches all versions within
/// the group, picking the highest stability version for each kind. This handles cases
/// where different resources in the same group exist at different versions (e.g.,
/// KubeadmControlPlane at v1beta2 and RKE2ControlPlane at v1beta1).
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `group` - API group (e.g., "cluster.x-k8s.io")
/// * `kind` - Resource kind (e.g., "Cluster")
///
/// # Returns
/// The full api_version string (e.g., "cluster.x-k8s.io/v1beta2")
pub(crate) async fn discover_api_version(
    client: &Client,
    group: &str,
    kind: &str,
) -> Result<String, Error> {
    use kube::discovery::Discovery;

    let discovery = Discovery::new(client.clone())
        .filter(&[group])
        .run()
        .await
        .map_err(|e| {
            Error::internal_with_context(
                "discover_api_version",
                format!("API discovery failed: {}", e),
            )
        })?;

    // Find the group
    for api_group in discovery.groups() {
        if api_group.name() != group {
            continue;
        }

        // Search ALL versions - resources_by_stability returns all resources across
        // all versions, picking the highest stability version for each kind.
        // This handles cases like RKE2ControlPlane at v1beta1 while the group's
        // preferred version is v1beta2 (which only has KubeadmControlPlane).
        for (ar, _caps) in api_group.resources_by_stability() {
            if ar.kind == kind {
                return Ok(ar.api_version.clone());
            }
        }
    }

    Err(Error::internal_with_context(
        "discover_api_version",
        format!("Resource {}/{} not found in API discovery", group, kind),
    ))
}

/// Build an ApiResource using discovery to find the correct version.
///
/// This is the primary way to build an ApiResource at runtime. It queries
/// the API server to find the installed version, so it's always correct
/// regardless of hardcoded version constants.
pub async fn build_api_resource_with_discovery(
    client: &Client,
    group: &str,
    kind: &str,
) -> Result<ApiResource, Error> {
    let api_version = discover_api_version(client, group, kind).await?;
    let (group_str, version) = parse_api_version(&api_version);
    let plural = pluralize_kind(kind);

    Ok(ApiResource {
        group: group_str,
        version,
        kind: kind.to_string(),
        api_version,
        plural,
    })
}

/// Build an ApiResource from a known apiVersion and kind without discovery.
///
/// Only for offline contexts where discovery is unavailable: pivot import
/// (CRDs may not exist on target), manifest parsing, or stable core K8s
/// types (`v1`, `policy/v1`). Prefer `build_api_resource_with_discovery()`
/// for all runtime API operations.
pub fn build_api_resource(api_version: &str, kind: &str) -> ApiResource {
    let (group, version) = parse_api_version(api_version);
    ApiResource {
        group,
        version,
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        plural: pluralize_kind(kind),
    }
}

/// Parse apiVersion into (group, version)
///
/// # Examples
/// ```
/// use lattice_common::kube_utils::parse_api_version;
///
/// let (group, version) = parse_api_version("apps/v1");
/// assert_eq!(group, "apps");
/// assert_eq!(version, "v1");
///
/// let (group, version) = parse_api_version("v1");
/// assert_eq!(group, "");
/// assert_eq!(version, "v1");
/// ```
pub fn parse_api_version(api_version: &str) -> (String, String) {
    match api_version.find('/') {
        Some(pos) => (
            api_version[..pos].to_string(),
            api_version[pos + 1..].to_string(),
        ),
        None => (String::new(), api_version.to_string()),
    }
}

/// Known Kubernetes/CAPI resource pluralizations
const KIND_PLURALS: &[(&str, &str)] = &[
    // Core CAPI types
    ("cluster", "clusters"),
    ("machine", "machines"),
    ("machinedeployment", "machinedeployments"),
    ("machineset", "machinesets"),
    ("machinepool", "machinepools"),
    // Control plane providers
    ("kubeadmcontrolplane", "kubeadmcontrolplanes"),
    (
        "kubeadmcontrolplanetemplate",
        "kubeadmcontrolplanetemplates",
    ),
    ("rke2controlplane", "rke2controlplanes"),
    ("rke2controlplanetemplate", "rke2controlplanetemplates"),
    // Bootstrap providers
    ("kubeadmconfig", "kubeadmconfigs"),
    ("kubeadmconfigtemplate", "kubeadmconfigtemplates"),
    ("rke2config", "rke2configs"),
    ("rke2configtemplate", "rke2configtemplates"),
    // Docker provider
    ("dockercluster", "dockerclusters"),
    ("dockerclustertemplate", "dockerclustertemplates"),
    ("dockermachine", "dockermachines"),
    ("dockermachinetemplate", "dockermachinetemplates"),
    ("dockermachinepool", "dockermachinepools"),
    ("dockermachinepooltemplate", "dockermachinepooltemplates"),
    // AWS provider
    ("awscluster", "awsclusters"),
    ("awsmachine", "awsmachines"),
    ("awsmachinetemplate", "awsmachinetemplates"),
    ("awsmanagedcluster", "awsmanagedclusters"),
    ("awsmanagedmachinepool", "awsmanagedmachinepools"),
    // GCP provider
    ("gcpcluster", "gcpclusters"),
    ("gcpmachine", "gcpmachines"),
    ("gcpmachinetemplate", "gcpmachinetemplates"),
    // Azure provider
    ("azurecluster", "azureclusters"),
    ("azuremachine", "azuremachines"),
    ("azuremachinetemplate", "azuremachinetemplates"),
    ("azuremanagedcluster", "azuremanagedclusters"),
    ("azuremanagedmachinepool", "azuremanagedmachinepools"),
    // Proxmox provider
    ("proxmoxcluster", "proxmoxclusters"),
    ("proxmoxmachine", "proxmoxmachines"),
    ("proxmoxmachinetemplate", "proxmoxmachinetemplates"),
    // IPAM
    ("ipaddress", "ipaddresses"),
    ("ipaddressclaim", "ipaddressclaims"),
    // ClusterClass
    ("clusterclass", "clusterclasses"),
];

/// Pluralize a Kubernetes resource kind
///
/// Uses a lookup table for known CAPI/Kubernetes types, falling back to
/// simple pluralization rules for unknown types.
pub fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();

    // Look up in known kinds
    for (singular, plural) in KIND_PLURALS {
        if *singular == lower {
            return (*plural).to_string();
        }
    }

    // Fallback: simple pluralization
    if lower.ends_with('s') || lower.ends_with("ch") || lower.ends_with("sh") {
        format!("{}es", lower)
    } else if lower.ends_with('y') && !lower.ends_with("ay") && !lower.ends_with("ey") {
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pluralize_kind() {
        // Core Kubernetes types
        assert_eq!(pluralize_kind("Deployment"), "deployments");
        assert_eq!(pluralize_kind("Pod"), "pods");
        assert_eq!(pluralize_kind("Policy"), "policies");
        assert_eq!(pluralize_kind("Ingress"), "ingresses");
        assert_eq!(pluralize_kind("Service"), "services");
        assert_eq!(pluralize_kind("ConfigMap"), "configmaps");
        assert_eq!(pluralize_kind("Secret"), "secrets");
        assert_eq!(pluralize_kind("NetworkPolicy"), "networkpolicies");

        // CAPI types (lookup table)
        assert_eq!(pluralize_kind("Cluster"), "clusters");
        assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");
        assert_eq!(
            pluralize_kind("KubeadmControlPlane"),
            "kubeadmcontrolplanes"
        );
        assert_eq!(pluralize_kind("RKE2ControlPlane"), "rke2controlplanes");
        assert_eq!(
            pluralize_kind("DockerMachineTemplate"),
            "dockermachinetemplates"
        );
        assert_eq!(pluralize_kind("ClusterClass"), "clusterclasses");
    }

    #[test]
    fn test_parse_api_version_with_group() {
        let (group, version) = parse_api_version("apps/v1");
        assert_eq!(group, "apps");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_core() {
        let (group, version) = parse_api_version("v1");
        assert_eq!(group, "");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_crd() {
        let (group, version) = parse_api_version("lattice.io/v1alpha1");
        assert_eq!(group, "lattice.io");
        assert_eq!(version, "v1alpha1");
    }
}
