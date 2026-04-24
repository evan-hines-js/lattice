//! Basis provider configuration.
//!
//! Basis is a minimal bare-metal VM scheduler designed as a Proxmox
//! replacement for Lattice's on-prem use case: VMs for Kubernetes node
//! substrate, nothing more.
//!
//! Each cluster belongs to a **tree** (trust domain) in basis. The
//! tree a `LatticeCluster` joins is *implied by where it's applied*:
//! every `BasisCluster` CR is reconciled by the basis-capi-provider
//! deployed into the hosting cell, and that provider is configured
//! with the cell's `basisClusterId` at deploy time — all clusters it
//! creates become children of that cell. The root cell is
//! bootstrapped by `lattice-cli up` calling basis directly with no
//! parent. There is no per-LatticeCluster parent field because there
//! is no per-cluster choice: the API server you apply to IS the parent.
//!
//! The control-plane VIP is always allocated by basis from the
//! LAN-routable `edge_pool`. Whether kube-vip *claims* that VIP on the
//! LAN is per-cluster: see [`BasisConfig::control_plane_lan_vip`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Basis per-cluster configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BasisConfig {
    /// When `true`, control-plane nodes are provisioned with
    /// `edge: true` (a second NIC on the uplink bridge, `ens4`) and
    /// kube-vip claims the apiserver VIP on that NIC — so callers
    /// *outside* the basis tree (operator laptops, bootstrap kind
    /// cluster, Cluster API core in a parent cell) can reach the
    /// apiserver directly at the VIP.
    ///
    /// When `false` (default), CPs stay tree-only and kube-vip claims
    /// the VIP on `ens3` (overlay). External callers reach the
    /// apiserver through Lattice's parent-cell auth proxy instead;
    /// the VIP is still a unique address from the edge pool (cert SAN,
    /// CAPI endpoint identifier) but isn't announced outside the tree.
    ///
    /// Set `true` on the root/management cluster; leave unset on
    /// nested workload clusters that are reached through the proxy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub control_plane_edge: bool,

    /// Optional override for the kube-vip container image. Omit to let
    /// the generator pick a tested default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,

    /// CIDR from which Cilium hands out `type: LoadBalancer` addresses
    /// (the `CiliumLoadBalancerIPPool`). Must be on the same L2 segment
    /// as the cluster's nodes — Cilium announces via ARP inside the
    /// tree's VXLAN — and must NOT overlap with the tree's VM or VIP
    /// sub-ranges. Without this set, `type: LoadBalancer` Services stay
    /// `<pending>` forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_cidr: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}
