//! Istio ServiceEntry types
//!
//! Types for generating Istio ServiceEntry resources for external service
//! mesh integration (registering external services with the mesh).

use serde::{Deserialize, Serialize};

use super::PolicyMetadata;

/// Istio ServiceEntry for external service mesh integration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    /// API version
    #[serde(default = "ServiceEntry::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "ServiceEntry::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: ServiceEntrySpec,
}

impl ServiceEntry {
    const API_VERSION: &'static str = "networking.istio.io/v1beta1";
    const KIND: &'static str = "ServiceEntry";

    fn api_version() -> String {
        Self::API_VERSION.to_string()
    }
    fn kind() -> String {
        Self::KIND.to_string()
    }

    /// Create a new ServiceEntry
    pub fn new(metadata: PolicyMetadata, spec: ServiceEntrySpec) -> Self {
        Self {
            api_version: Self::API_VERSION.to_string(),
            kind: Self::KIND.to_string(),
            metadata,
            spec,
        }
    }
}

/// ServiceEntry spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntrySpec {
    /// Hosts (DNS names)
    pub hosts: Vec<String>,
    /// Ports
    pub ports: Vec<ServiceEntryPort>,
    /// Location: MESH_EXTERNAL or MESH_INTERNAL
    pub location: String,
    /// Resolution: DNS, STATIC, NONE
    pub resolution: String,
}

/// ServiceEntry port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntryPort {
    /// Port number
    pub number: u16,
    /// Port name
    pub name: String,
    /// Protocol (HTTP, HTTPS, TCP, GRPC)
    pub protocol: String,
}
