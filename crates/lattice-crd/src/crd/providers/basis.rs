//! Basis provider configuration.
//!
//! Basis is a minimal bare-metal VM scheduler: VMs on a per-cluster
//! VXLAN overlay, plus named LAN-routable pools the cluster picks
//! from for its apiserver VIP. Anything above that — LB IP slicing,
//! BGP advertisement, pod-CIDR routing — is Lattice's responsibility.
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
//! Basis hands the cluster an apiserver VIP from a named pool (the
//! `apiserverVipPool` it's told to use, also the source for any
//! `edge: true` machines' second NIC). Lattice owns everything else:
//!
//! * `addressPools` — Lattice declares which pool/slice combinations
//!   this cluster will advertise. Drives one `CiliumLoadBalancerIPPool`
//!   per entry; Services select a pool via
//!   `service.kubernetes.io/load-balancer-class: lattice.dev/<pool>`.
//!   The named pool must exist in basis's `network.pools` config —
//!   basis validates the apiserver-VIP allocation against that name.
//! * `bgpPeer` — kube-vip's BGP peer for VIP advertisement. Today
//!   typically the customer upstream router (basis itself doesn't
//!   speak BGP).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Basis per-cluster configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BasisConfig {
    /// BGP peer kube-vip uses to advertise the apiserver VIP. Today
    /// this is whatever upstream router the cluster's edge NICs can
    /// reach (basis is not itself a BGP speaker).
    pub bgp_peer: BgpPeer,

    /// LB pool slices this cluster will advertise. Must be non-empty.
    /// Each entry's `name` must match a pool defined in basis's
    /// controller config (`network.pools[]`); the `cidr` is the slice
    /// Lattice carves for this cluster's Cilium LB IPAM. Lattice owns
    /// the slicing — basis only validates the names it sees.
    pub address_pools: Vec<AddressPoolBinding>,

    /// Pool the apiserver VIP is drawn from. Forwarded to
    /// `BasisCluster.spec.apiserverVipPool`. Defaults to `cell-internal`
    /// for child clusters; root/management clusters typically set
    /// `cell-public` so external callers can reach the apiserver
    /// directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apiserver_vip_pool: Option<String>,

    /// Optional override for the kube-vip container image. Omit to let
    /// the generator pick a tested default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,
}

/// One LB pool slice this cluster advertises.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AddressPoolBinding {
    /// Pool name (e.g., `cell-internal`, `cell-public`). Must match a
    /// pool declared in the hosting cell's basis controller config.
    pub name: String,

    /// CIDR slice this cluster advertises into the pool. Lattice
    /// renders one `CiliumLoadBalancerIPPool` from this; the
    /// allocator inside Cilium hands /32s out to LoadBalancer Services.
    pub cidr: String,
}

/// BGP peer kube-vip advertises the apiserver VIP to. Currently a
/// pointer to the customer upstream router; sessions are eBGP at the
/// router's ASN.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BgpPeer {
    /// Reachable IP of the BGP peer.
    pub address: String,

    /// Peer ASN. Used as both local and remote — kube-vip's static-pod
    /// manifest takes a single asn knob today.
    pub asn: u32,
}
