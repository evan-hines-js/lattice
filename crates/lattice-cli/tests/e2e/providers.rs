//! Infrastructure provider types for E2E tests
//!
//! Provider types are used as hints for test behavior (e.g., which verification
//! steps to run). Actual cluster configuration comes from LatticeCluster CRD files.

#![cfg(feature = "provider-e2e")]

use lattice_crd::crd::ProviderType;

/// Supported infrastructure providers
///
/// Used as hints for test behavior - the actual configuration comes from CRD files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraProvider {
    Docker,
    Aws,
    OpenStack,
    Proxmox,
    Basis,
}

impl From<ProviderType> for InfraProvider {
    fn from(pt: ProviderType) -> Self {
        match pt {
            ProviderType::Docker => Self::Docker,
            ProviderType::Aws => Self::Aws,
            ProviderType::OpenStack => Self::OpenStack,
            ProviderType::Proxmox => Self::Proxmox,
            ProviderType::Basis => Self::Basis,
            // Cloud-shaped providers without a dedicated e2e variant
            // share AWS's LoadBalancer-based transport profile. The
            // `_` arm catches future `#[non_exhaustive]` additions.
            ProviderType::Gcp | ProviderType::Azure => Self::Aws,
            _ => Self::Aws,
        }
    }
}

impl std::fmt::Display for InfraProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Docker => "docker",
            Self::Aws => "aws",
            Self::OpenStack => "openstack",
            Self::Proxmox => "proxmox",
            Self::Basis => "basis",
        };
        write!(f, "{}", name)
    }
}
