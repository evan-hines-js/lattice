//! Basis provider configuration
//!
//! Basis is a minimal bare-metal VM scheduler designed as a Proxmox
//! replacement for Lattice's on-prem use case: VMs for Kubernetes node
//! substrate, nothing more. The Basis controller owns scheduling, IP
//! allocation, and VIP reservation, so this per-cluster config is much
//! smaller than its Proxmox counterpart — the only input Basis needs
//! per cluster is which IP pool to draw from.
//!
//! K8s-level concerns that belong across providers (SSH keys, DNS
//! servers, kube-vip, LB-IPAM range) are handled by the cluster-wide
//! bootstrap path, not by per-provider config.
//!
//! Reference: https://github.com/lattos/basis/blob/main/docs/lattice-integration.md

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Basis per-cluster configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BasisConfig {
    /// Name of an IP pool configured in the Basis controller. Determines
    /// which subnet this cluster's VIP and VM IPs are drawn from.
    ///
    /// Pools are defined in the controller's config file; see the Basis
    /// deploy docs. A typical homelab value is `"default"`.
    pub ipv4_pool: String,
}
