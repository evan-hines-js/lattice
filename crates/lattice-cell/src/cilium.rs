//! Cilium LB-IPAM and BGP resource generation.
//!
//! Two flows:
//!
//! - `generate_l2_lb_resources(cidr)` — Cilium L2 announcement, used by
//!   on-prem providers that share an L2 segment with their LB IPs
//!   (Docker/kind, Proxmox).
//! - `generate_bgp_lb_resources(req)` — Cilium BGP control plane plus
//!   one IP pool per address-pool binding. Used by basis, where each
//!   node advertises its hosted LB /32s via iBGP to the basis
//!   controller (the cell's route reflector).

use serde::{Deserialize, Serialize};

use lattice_crd::crd::{AddressPoolBinding, BgpPeer};

/// Service annotation/label-class prefix used by Lattice. Services
/// pick a pool with `service.kubernetes.io/load-balancer-class:
/// lattice.dev/<pool-name>`. The corresponding `CiliumLoadBalancerIPPool`
/// carries `lattice.dev/address-pool=<pool-name>` as a label, and a
/// `serviceSelector` that matches that LB class.
pub const LOAD_BALANCER_CLASS_PREFIX: &str = "lattice.dev/";
pub const ADDRESS_POOL_LABEL: &str = "lattice.dev/address-pool";

/// Inputs for BGP-mode LB rendering on a basis cluster.
pub struct BgpLbRequest<'a> {
    pub cluster_name: &'a str,
    pub bgp_peer: &'a BgpPeer,
    pub pools: &'a [AddressPoolBinding],
}

/// L2-mode (Docker, Proxmox): one pool, one announcement policy.
pub(crate) fn generate_l2_lb_resources(cidr: &str) -> Result<Vec<String>, serde_json::Error> {
    Ok(vec![
        generate_ip_pool_l2("default", cidr)?,
        generate_l2_policy()?,
    ])
}

/// BGP-mode (basis): per-pool IP pools plus Cilium BGP cluster /
/// peer / advertisement CRDs. Two advertisements are emitted —
/// `LoadBalancerIP` for Service VIPs, `PodCIDR` so per-node pod ranges
/// are routable on the underlay (no VXLAN encap).
pub(crate) fn generate_bgp_lb_resources(
    req: &BgpLbRequest<'_>,
) -> Result<Vec<String>, serde_json::Error> {
    let mut out = Vec::with_capacity(req.pools.len() + 4);
    for pool in req.pools {
        out.push(generate_ip_pool_bgp(pool)?);
    }
    out.push(generate_bgp_cluster_config(req.cluster_name, req.bgp_peer)?);
    out.push(generate_bgp_peer_config()?);
    out.push(generate_bgp_lb_advertisement()?);
    out.push(generate_bgp_pod_advertisement()?);
    Ok(out)
}

fn generate_ip_pool_l2(name: &str, cidr: &str) -> Result<String, serde_json::Error> {
    let pool = CiliumLoadBalancerIPPool {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumLoadBalancerIPPool".to_string(),
        metadata: Metadata {
            name: name.to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: IPPoolSpec {
            blocks: vec![IPBlock {
                cidr: cidr.to_string(),
            }],
            service_selector: None,
        },
    };
    serde_json::to_string(&pool)
}

fn generate_ip_pool_bgp(pool: &AddressPoolBinding) -> Result<String, serde_json::Error> {
    let mut labels = managed_by_labels();
    labels.insert(ADDRESS_POOL_LABEL.to_string(), pool.name.clone());

    let lb_class = format!("{}{}", LOAD_BALANCER_CLASS_PREFIX, pool.name);
    let selector = LabelSelector {
        match_expressions: vec![LabelSelectorRequirement {
            key: "service.kubernetes.io/load-balancer-class".to_string(),
            operator: "In".to_string(),
            values: vec![lb_class],
        }],
    };

    let res = CiliumLoadBalancerIPPool {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumLoadBalancerIPPool".to_string(),
        metadata: Metadata {
            name: pool.name.clone(),
            labels: Some(labels),
        },
        spec: IPPoolSpec {
            blocks: vec![IPBlock {
                cidr: pool.cidr.clone(),
            }],
            service_selector: Some(selector),
        },
    };
    serde_json::to_string(&res)
}

fn generate_l2_policy() -> Result<String, serde_json::Error> {
    let policy = CiliumL2AnnouncementPolicy {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumL2AnnouncementPolicy".to_string(),
        metadata: Metadata {
            name: "default".to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: L2PolicySpec {
            load_balancer_ips: true,
            interfaces: vec!["^.*$".to_string()],
        },
    };
    serde_json::to_string(&policy)
}

fn generate_bgp_cluster_config(
    cluster_name: &str,
    peer: &BgpPeer,
) -> Result<String, serde_json::Error> {
    let cfg = CiliumBGPClusterConfig {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumBGPClusterConfig".to_string(),
        metadata: Metadata {
            name: "default".to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: BgpClusterSpec {
            node_selector: LabelSelector::empty(),
            bgp_instances: vec![BgpInstance {
                name: format!("{cluster_name}-instance"),
                local_asn: peer.asn,
                peers: vec![BgpClusterPeer {
                    name: "basis".to_string(),
                    peer_asn: peer.asn,
                    peer_address: peer.address.clone(),
                    peer_config_ref: PeerConfigRef {
                        name: "basis-peer".to_string(),
                    },
                }],
            }],
        },
    };
    serde_json::to_string(&cfg)
}

fn generate_bgp_peer_config() -> Result<String, serde_json::Error> {
    let cfg = CiliumBGPPeerConfig {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumBGPPeerConfig".to_string(),
        metadata: Metadata {
            name: "basis-peer".to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: BgpPeerSpec {
            families: vec![BgpFamily {
                afi: "ipv4".to_string(),
                safi: "unicast".to_string(),
                advertisements: AdvertSelector {
                    match_labels: advertisement_labels(),
                },
            }],
        },
    };
    serde_json::to_string(&cfg)
}

fn generate_bgp_lb_advertisement() -> Result<String, serde_json::Error> {
    let mut labels = managed_by_labels();
    labels.insert("advertise".to_string(), "lb-ip".to_string());

    let advert = CiliumBGPAdvertisement {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumBGPAdvertisement".to_string(),
        metadata: Metadata {
            name: "lb-services".to_string(),
            labels: Some(labels),
        },
        spec: BgpAdvertisementSpec {
            advertisements: vec![Advertisement {
                advertisement_type: "Service".to_string(),
                service: Some(ServiceAdvert {
                    addresses: vec!["LoadBalancerIP".to_string()],
                }),
                selector: Some(LabelSelector {
                    match_expressions: vec![LabelSelectorRequirement {
                        key: ADDRESS_POOL_LABEL.to_string(),
                        operator: "Exists".to_string(),
                        values: vec![],
                    }],
                }),
            }],
        },
    };
    serde_json::to_string(&advert)
}

fn generate_bgp_pod_advertisement() -> Result<String, serde_json::Error> {
    let mut labels = managed_by_labels();
    labels.insert("advertise".to_string(), "lb-ip".to_string());

    let advert = CiliumBGPAdvertisement {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumBGPAdvertisement".to_string(),
        metadata: Metadata {
            name: "pod-cidr".to_string(),
            labels: Some(labels),
        },
        spec: BgpAdvertisementSpec {
            advertisements: vec![Advertisement {
                advertisement_type: "PodCIDR".to_string(),
                service: None,
                selector: None,
            }],
        },
    };
    serde_json::to_string(&advert)
}

fn managed_by_labels() -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        lattice_common::LABEL_MANAGED_BY.to_string(),
        lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
    );
    labels
}

fn advertisement_labels() -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("advertise".to_string(), "lb-ip".to_string());
    labels
}

// =============================================================================
// CRD types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumLoadBalancerIPPool {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: IPPoolSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IPPoolSpec {
    blocks: Vec<IPBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_selector: Option<LabelSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IPBlock {
    cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumL2AnnouncementPolicy {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: L2PolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2PolicySpec {
    #[serde(rename = "loadBalancerIPs")]
    load_balancer_ips: bool,
    interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumBGPClusterConfig {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: BgpClusterSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BgpClusterSpec {
    node_selector: LabelSelector,
    bgp_instances: Vec<BgpInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BgpInstance {
    name: String,
    #[serde(rename = "localASN")]
    local_asn: u32,
    peers: Vec<BgpClusterPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BgpClusterPeer {
    name: String,
    #[serde(rename = "peerASN")]
    peer_asn: u32,
    peer_address: String,
    peer_config_ref: PeerConfigRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerConfigRef {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumBGPPeerConfig {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: BgpPeerSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BgpPeerSpec {
    families: Vec<BgpFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BgpFamily {
    afi: String,
    safi: String,
    advertisements: AdvertSelector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdvertSelector {
    match_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumBGPAdvertisement {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: BgpAdvertisementSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BgpAdvertisementSpec {
    advertisements: Vec<Advertisement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Advertisement {
    advertisement_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<ServiceAdvert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<LabelSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceAdvert {
    addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    fn empty() -> Self {
        Self {
            match_expressions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LabelSelectorRequirement {
    key: String,
    operator: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_pool_round_trip() {
        let json = generate_ip_pool_l2("default", "172.18.255.1/32").unwrap();
        assert!(json.contains(r#""kind":"CiliumLoadBalancerIPPool""#));
        assert!(json.contains(r#""cidr":"172.18.255.1/32""#));
        assert!(json.contains(r#""app.kubernetes.io/managed-by":"lattice""#));
        assert!(!json.contains("serviceSelector"));
    }

    #[test]
    fn test_l2_policy_round_trip() {
        let json = generate_l2_policy().unwrap();
        assert!(json.contains(r#""kind":"CiliumL2AnnouncementPolicy""#));
        assert!(json.contains(r#""loadBalancerIPs":true"#));
        assert!(json.contains(r#""^.*$""#));
    }

    #[test]
    fn test_l2_lb_resources_emits_pool_and_policy() {
        let resources = generate_l2_lb_resources("10.0.100.0/24").unwrap();
        assert_eq!(resources.len(), 2);
        assert!(resources[0].contains("CiliumLoadBalancerIPPool"));
        assert!(resources[0].contains("10.0.100.0/24"));
        assert!(resources[1].contains("CiliumL2AnnouncementPolicy"));
    }

    #[test]
    fn test_bgp_pool_carries_pool_label_and_lb_class_selector() {
        let pool = AddressPoolBinding {
            name: "cell-public".to_string(),
            cidr: "10.0.0.176/28".to_string(),
        };
        let json = generate_ip_pool_bgp(&pool).unwrap();
        assert!(json.contains(r#""name":"cell-public""#));
        assert!(json.contains(r#""cidr":"10.0.0.176/28""#));
        assert!(json.contains(r#""lattice.dev/address-pool":"cell-public""#));
        assert!(json.contains(r#""lattice.dev/cell-public""#));
        assert!(json.contains("service.kubernetes.io/load-balancer-class"));
    }

    #[test]
    fn test_bgp_lb_resources_full_render() {
        let peer = BgpPeer {
            address: "10.0.0.1".to_string(),
            asn: 64500,
        };
        let pools = vec![
            AddressPoolBinding {
                name: "cell-internal".to_string(),
                cidr: "10.255.4.16/28".to_string(),
            },
            AddressPoolBinding {
                name: "cell-public".to_string(),
                cidr: "10.0.0.176/28".to_string(),
            },
        ];
        let req = BgpLbRequest {
            cluster_name: "root",
            bgp_peer: &peer,
            pools: &pools,
        };
        let resources = generate_bgp_lb_resources(&req).unwrap();
        assert_eq!(
            resources.len(),
            6,
            "two pools + cluster + peer + lb advert + pod-cidr advert"
        );
        assert!(resources[0].contains("cell-internal"));
        assert!(resources[1].contains("cell-public"));
        assert!(resources[2].contains("CiliumBGPClusterConfig"));
        assert!(resources[2].contains(r#""localASN":64500"#));
        assert!(resources[2].contains(r#""peerASN":64500"#));
        assert!(resources[2].contains(r#""peerAddress":"10.0.0.1""#));
        assert!(resources[3].contains("CiliumBGPPeerConfig"));
        assert!(resources[4].contains("CiliumBGPAdvertisement"));
        assert!(resources[4].contains(r#""advertisementType":"Service""#));
        assert!(resources[4].contains(r#""LoadBalancerIP""#));
        assert!(resources[5].contains(r#""advertisementType":"PodCIDR""#));
    }

    #[test]
    fn test_bgp_resources_omit_md5_password_field() {
        let peer = BgpPeer {
            address: "10.0.0.1".to_string(),
            asn: 64500,
        };
        let pools = vec![AddressPoolBinding {
            name: "cell-internal".to_string(),
            cidr: "10.255.4.16/28".to_string(),
        }];
        let req = BgpLbRequest {
            cluster_name: "wkr",
            bgp_peer: &peer,
            pools: &pools,
        };
        let resources = generate_bgp_lb_resources(&req).unwrap();
        for r in &resources {
            assert!(!r.contains("authSecret"), "no MD5 path: {r}");
            assert!(!r.contains("password"), "no MD5 path: {r}");
        }
    }
}
