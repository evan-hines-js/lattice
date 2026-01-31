//! Common types for Lattice: CRDs, errors, and utilities

#![deny(missing_docs)]

pub mod clusterctl;
pub mod crd;
pub mod credentials;
pub mod error;
pub mod fips;
pub mod graph;
pub mod kube_utils;
pub mod policy;
pub mod protocol;
pub mod retry;
pub mod template;
pub mod yaml;

pub use credentials::{AwsCredentials, CredentialError, OpenStackCredentials, ProxmoxCredentials};
pub use error::Error;
pub use kube_utils::{
    apply_manifests_with_discovery, apply_manifest_with_discovery, kind_priority, pluralize_kind,
    ApplyOptions,
};
pub use protocol::{CsrRequest, CsrResponse, DistributableResources};

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Default port for the bootstrap HTTPS server
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Default port for the K8s API proxy server (CAPI controller access to child clusters)
pub const DEFAULT_PROXY_PORT: u16 = 8081;

/// Namespace for Lattice system resources (CA, credentials, operator)
pub const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// Construct a Kubernetes service DNS name for a Lattice service.
///
/// Returns `{service}.{LATTICE_SYSTEM_NAMESPACE}.svc`
pub fn lattice_svc_dns(service: &str) -> String {
    format!("{}.{}.svc", service, LATTICE_SYSTEM_NAMESPACE)
}

/// Construct a fully-qualified Kubernetes service DNS name for a Lattice service.
///
/// Returns `{service}.{LATTICE_SYSTEM_NAMESPACE}.svc.cluster.local`
pub fn lattice_svc_dns_fqdn(service: &str) -> String {
    format!("{}.{}.svc.cluster.local", service, LATTICE_SYSTEM_NAMESPACE)
}

/// Environment variable to indicate this is a bootstrap cluster
pub const BOOTSTRAP_CLUSTER_ENV: &str = "LATTICE_BOOTSTRAP_CLUSTER";

/// Check if the current operator is running on a bootstrap cluster
///
/// Returns true if LATTICE_BOOTSTRAP_CLUSTER is set to "true" or "1".
/// Bootstrap clusters are temporary clusters used during initial installation
/// that don't need the full proxy/pivot setup.
pub fn is_bootstrap_cluster() -> bool {
    std::env::var(BOOTSTRAP_CLUSTER_ENV)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Install the FIPS-validated crypto provider for rustls.
///
/// This must be called before creating any TLS connections (including kube clients).
/// Safe to call multiple times - subsequent calls are no-ops.
///
/// Uses aws-lc-rs which provides FIPS 140-2/140-3 validated cryptography.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Parse a cell endpoint URL into (host, port)
///
/// Parses URLs like "https://172.18.255.10:50051" or "https://cell.example.com:50051"
///
/// # Examples
/// ```
/// use lattice_common::parse_cell_endpoint;
///
/// let result = parse_cell_endpoint("https://172.18.255.10:50051");
/// assert_eq!(result, Some(("172.18.255.10".to_string(), 50051)));
///
/// let result = parse_cell_endpoint("https://cell.example.com:8443");
/// assert_eq!(result, Some(("cell.example.com".to_string(), 8443)));
/// ```
pub fn parse_cell_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let url = endpoint.strip_prefix("https://").unwrap_or(endpoint);
    let url = url.strip_prefix("http://").unwrap_or(url);

    if let Some((host, port_str)) = url.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((host.to_string(), port));
        }
    }
    None
}

// CAPI provider namespaces
/// Target namespace for CAPA (AWS) provider
pub const CAPA_NAMESPACE: &str = "capa-system";
/// Target namespace for CAPMOX (Proxmox) provider
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// Target namespace for CAPO (OpenStack) provider
pub const CAPO_NAMESPACE: &str = "capo-system";

// CAPI provider credential secret names (source secrets in lattice-system)
/// Secret name for Proxmox credentials
pub const PROXMOX_CREDENTIALS_SECRET: &str = "proxmox-credentials";
/// Secret name for AWS credentials (source secret)
pub const AWS_CREDENTIALS_SECRET: &str = "aws-credentials";
/// Secret name for OpenStack credentials
pub const OPENSTACK_CREDENTIALS_SECRET: &str = "openstack-cloud-config";

// CAPI provider secret names (target secrets in provider namespaces)
// These are the names expected by each CAPI provider
/// AWS CAPA expects this specific secret name
pub const AWS_CAPA_CREDENTIALS_SECRET: &str = "capa-manager-bootstrap-credentials";

/// Label key for provider identification on secrets
pub const PROVIDER_LABEL: &str = "lattice.dev/provider";

// Standard Kubernetes labels (see https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)
/// Standard name label key - identifies the name of the application
pub const LABEL_NAME: &str = "app.kubernetes.io/name";
/// Standard managed-by label key - identifies the tool managing the resource
pub const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
/// Standard managed-by label value for Lattice-managed resources
pub const LABEL_MANAGED_BY_LATTICE: &str = "lattice";

// Cilium label selectors (use k8s: prefix for Kubernetes labels)
/// Cilium selector for app name label
pub const CILIUM_LABEL_NAME: &str = "k8s:app.kubernetes.io/name";
/// Cilium selector for pod namespace
pub const CILIUM_LABEL_NAMESPACE: &str = "k8s:io.kubernetes.pod.namespace";
