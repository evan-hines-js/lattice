//! Ingress and Gateway API types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Ingress specification for exposing services externally via Gateway API
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressSpec {
    /// Hostnames for the ingress (e.g., "api.example.com")
    pub hosts: Vec<String>,

    /// URL paths to route (defaults to ["/"])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<IngressPath>>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<IngressTls>,

    /// GatewayClass name (default: "istio")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_class: Option<String>,
}

/// Path configuration for ingress routing
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressPath {
    /// The URL path to match
    pub path: String,

    /// Path match type (PathPrefix or Exact)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_type: Option<PathMatchType>,
}

/// Path match type for Gateway API HTTPRoute
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum PathMatchType {
    /// Exact path match
    Exact,
    /// Prefix-based path match (default)
    #[default]
    PathPrefix,
}

/// TLS configuration for ingress
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressTls {
    /// TLS mode: auto (cert-manager) or manual (pre-existing secret)
    #[serde(default)]
    pub mode: TlsMode,

    /// Secret name containing TLS certificate (for manual mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// Cert-manager issuer reference (for auto mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<CertIssuerRef>,
}

/// TLS provisioning mode
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Automatic certificate provisioning via cert-manager
    #[default]
    Auto,
    /// Manual certificate management (use pre-existing secret)
    Manual,
}

/// Reference to a cert-manager issuer
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerRef {
    /// Name of the issuer
    pub name: String,

    /// Kind of issuer (default: ClusterIssuer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}
