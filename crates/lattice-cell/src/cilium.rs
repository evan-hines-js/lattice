//! Cilium LB-IPAM resource generation.
//!
//! All providers use the same shape: one `CiliumLoadBalancerIPPool`
//! with a single host range plus one `CiliumL2AnnouncementPolicy` so
//! Cilium gratuitous-ARPs the assigned IPs on the cluster nodes'
//! primary NIC.
//!
//! The CIDR's *source* differs by provider (static `lb_cidr` for
//! Docker/Proxmox, dynamic `BasisCluster.spec.serviceBlockCidr` for
//! basis), but resolution happens upstream in
//! `ClusterFacts::from_cluster`; this module only renders.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CiliumRenderError {
    #[error("invalid CIDR '{0}': {1}")]
    InvalidCidr(String, String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// One IPPool + one L2 announcement policy. Cilium assigns IPs from
/// the pool to LoadBalancer Services; the announcement policy makes
/// it gratuitous-ARP for them on every node interface so the IPs are
/// reachable on the cluster's L2 segment.
pub(crate) fn generate_l2_lb_resources(cidr: &str) -> Result<Vec<String>, CiliumRenderError> {
    Ok(vec![generate_ip_pool_l2(cidr)?, generate_l2_policy()?])
}

/// Convert a CIDR (operator-friendly) into an inclusive host range
/// (Cilium-friendly). Cilium's `cidr` block form treats every address
/// as assignable, including the network and broadcast — which on a
/// /28 means LBIPAM hands out `.0` and `.15`, neither of which any
/// upstream device will accept. `start`/`stop` lets us narrow to
/// `[network+1, broadcast-1]`. /32 is a single host (start==stop).
fn generate_ip_pool_l2(cidr: &str) -> Result<String, CiliumRenderError> {
    let net: ipnet::Ipv4Net = cidr.parse().map_err(|e: ipnet::AddrParseError| {
        CiliumRenderError::InvalidCidr(cidr.into(), e.to_string())
    })?;
    let (start, stop) = host_range(&net);
    let pool = CiliumLoadBalancerIPPool {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumLoadBalancerIPPool".to_string(),
        metadata: Metadata {
            name: "default".to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: IPPoolSpec {
            blocks: vec![IPBlock {
                start: start.to_string(),
                stop: stop.to_string(),
            }],
        },
    };
    Ok(serde_json::to_string(&pool)?)
}

/// `[network+1, broadcast-1]` for /N≤30; the network address itself
/// for /32. (Pool validation upstream rejects /31 — RFC 3021 has no
/// usable hosts under our model.)
fn host_range(net: &ipnet::Ipv4Net) -> (Ipv4Addr, Ipv4Addr) {
    if net.prefix_len() == 32 {
        return (net.network(), net.network());
    }
    let net_u32 = u32::from(net.network());
    let bcast_u32 = u32::from(net.broadcast());
    (Ipv4Addr::from(net_u32 + 1), Ipv4Addr::from(bcast_u32 - 1))
}

fn generate_l2_policy() -> Result<String, CiliumRenderError> {
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
    Ok(serde_json::to_string(&policy)?)
}

fn managed_by_labels() -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        lattice_common::LABEL_MANAGED_BY.to_string(),
        lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
    );
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IPBlock {
    start: String,
    stop: String,
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
struct Metadata {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_pool_single_host_for_slash_32() {
        let json = generate_ip_pool_l2("172.18.255.1/32").unwrap();
        assert!(json.contains(r#""kind":"CiliumLoadBalancerIPPool""#));
        assert!(json.contains(r#""start":"172.18.255.1""#));
        assert!(json.contains(r#""stop":"172.18.255.1""#));
        assert!(json.contains(r#""app.kubernetes.io/managed-by":"lattice""#));
    }

    #[test]
    fn test_l2_pool_skips_network_and_broadcast_for_slash_28() {
        // /28 = 16 addrs; usable = .1..=.14 inside .0/28.
        let json = generate_ip_pool_l2("10.0.0.208/28").unwrap();
        assert!(json.contains(r#""start":"10.0.0.209""#));
        assert!(json.contains(r#""stop":"10.0.0.222""#));
        // Network + broadcast must NOT leak as cidr/start/stop.
        assert!(!json.contains("10.0.0.208\""));
        assert!(!json.contains("10.0.0.223"));
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
        assert!(resources[0].contains(r#""start":"10.0.100.1""#));
        assert!(resources[0].contains(r#""stop":"10.0.100.254""#));
        assert!(resources[1].contains("CiliumL2AnnouncementPolicy"));
    }

    #[test]
    fn test_l2_pool_rejects_garbage_cidr() {
        let err = generate_ip_pool_l2("not-a-cidr").unwrap_err();
        match err {
            CiliumRenderError::InvalidCidr(input, _) => assert_eq!(input, "not-a-cidr"),
            other => panic!("expected InvalidCidr, got {other:?}"),
        }
    }
}
