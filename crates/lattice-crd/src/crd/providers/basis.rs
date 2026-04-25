//! Basis provider configuration.
//!
//! Basis is a minimal bare-metal VM scheduler: VMs on a per-cluster
//! VXLAN overlay, plus named LAN-routable pools the cluster's external
//! IPs come from.
//!
//! Each cluster belongs to a **cell** (trust domain) in basis. The cell
//! a `LatticeCluster` joins is *implied by where it's applied*: every
//! `BasisCluster` CR is reconciled by the basis-capi-provider deployed
//! into the hosting cell, and that provider is configured with the
//! cell's id at deploy time. The root cell is bootstrapped by
//! `lattice-cli up` calling basis directly with no parent.
//!
//! # Addressing
//!
//! Basis hands the cluster two LAN-routable allocations from a single
//! named pool (`externalIpPool`):
//!
//!   * one /32 — the apiserver VIP, ARP-claimed by kube-vip on the
//!     cluster's tree NIC
//!   * one /N  — the Cilium LoadBalancer Service block, sized by
//!     `externalServiceIps` (cell-wide default applies when omitted),
//!     handed to Cilium IPAM via `CiliumLoadBalancerIPPool`
//!
//! Every host carrying the cluster's tree advertises both via the
//! cell BGP reflector and answers proxy-ARP for them on the underlay,
//! so LAN clients reach them without per-cluster router config.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Basis per-cluster configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BasisConfig {
    /// Named LAN pool the cluster's external IPs come from — both the
    /// apiserver VIP and the Cilium LoadBalancer Service block.
    /// Forwarded to `BasisCluster.spec.externalIpPool`. Defaults to
    /// `cell-internal` for child clusters; root/management clusters
    /// typically set `cell-public` so external callers can reach the
    /// apiserver directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip_pool: Option<String>,

    /// Override for the cell-wide default LoadBalancer Service IP
    /// count. Forwarded to `BasisCluster.spec.externalServiceIps`.
    /// Must be a power of two; `None` (the common case) lets basis
    /// apply its cell default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_service_ips: Option<u32>,

    /// Optional override for the kube-vip container image. Omit to let
    /// the generator pick a tested default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,
}
