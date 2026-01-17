//! Infrastructure provider types for E2E tests
//!
//! Provider types are used as hints for test behavior (e.g., which verification
//! steps to run). Actual cluster configuration comes from LatticeCluster CRD files.

#![cfg(feature = "provider-e2e")]

/// Supported infrastructure providers
///
/// Used as hints for test behavior - the actual configuration comes from CRD files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraProvider {
    Docker,
    Aws,
    OpenStack,
    Proxmox,
}

impl InfraProvider {
    /// Parse provider from environment variable
    pub fn from_env(var: &str, default: Self) -> Self {
        match std::env::var(var).as_deref() {
            Ok("aws") | Ok("AWS") => Self::Aws,
            Ok("openstack") | Ok("OPENSTACK") | Ok("ovh") | Ok("OVH") => Self::OpenStack,
            Ok("proxmox") | Ok("PROXMOX") => Self::Proxmox,
            Ok("docker") | Ok("DOCKER") => Self::Docker,
            _ => default,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Aws => "aws",
            Self::OpenStack => "openstack",
            Self::Proxmox => "proxmox",
        }
    }
}

impl std::fmt::Display for InfraProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
