//! Basis provider configuration.
//!
//! Basis is a minimal bare-metal VM scheduler designed as a Proxmox
//! replacement for Lattice's on-prem use case: VMs for Kubernetes node
//! substrate, nothing more.
//!
//! Everything about a cluster's addressing is derived from the named
//! `ipv4Pool`:
//!   - VM IPs come from the pool's vm sub-range (auto-allocated per VM).
//!   - The control-plane VIP is auto-allocated by basis from the pool's
//!     vip sub-range when the `BasisCluster` CR is reconciled — Lattice
//!     does not pick it and users do not specify it. The provider
//!     reconciler writes the allocated address onto
//!     `BasisCluster.spec.controlPlaneEndpoint`; CAPI core propagates
//!     it to `Cluster.spec.controlPlaneEndpoint`, and Lattice patches
//!     the kube-vip static pod manifest into the `KubeadmControlPlane`
//!     once that value is known.
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

    /// Optional override for the interface kube-vip binds the VIP on.
    /// Defaults to `ens3` — the first virtio-net interface the
    /// basis-agent attaches to each VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_ip_network_interface: Option<String>,

    /// Optional override for the kube-vip container image. Omit to let
    /// the generator pick a tested default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,

    /// CIDR from which Cilium hands out `type: LoadBalancer` addresses
    /// (the `CiliumLoadBalancerIPPool`). Must be on the same L2 segment
    /// as the cluster's nodes — Cilium announces via ARP — and must NOT
    /// overlap with the basis IP pool (otherwise basis would hand the
    /// same IP to a future VM and collide with Cilium's announcement).
    /// Without this set, `type: LoadBalancer` Services stay `<pending>`
    /// forever and the Lattice cell proxy never becomes reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_cidr: Option<String>,
}
