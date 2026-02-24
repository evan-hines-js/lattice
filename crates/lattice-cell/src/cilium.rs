//! Cilium LB-IPAM resource generation
//!
//! Generates CiliumLoadBalancerIPPool and CiliumL2AnnouncementPolicy resources
//! for on-prem providers (Docker, Proxmox) that need Cilium to allocate
//! LoadBalancer IPs from a CIDR block.

use serde::{Deserialize, Serialize};

/// Generate Cilium LB-IPAM resources for the given CIDR
///
/// Returns YAML strings for:
/// - CiliumLoadBalancerIPPool with the given CIDR
/// - CiliumL2AnnouncementPolicy (enables L2 announcements)
pub(crate) fn generate_lb_resources(cidr: &str) -> Result<Vec<String>, serde_json::Error> {
    Ok(vec![
        generate_ip_pool("default", cidr)?,
        generate_l2_policy()?,
    ])
}

/// Generate a CiliumLoadBalancerIPPool resource
fn generate_ip_pool(name: &str, cidr: &str) -> Result<String, serde_json::Error> {
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
        },
    };

    serde_json::to_string(&pool)
}

/// Generate CiliumL2AnnouncementPolicy resource
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
            interfaces: vec!["^.*$".to_string()], // Match all interfaces
        },
    };

    serde_json::to_string(&policy)
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
// Cilium CRD Types
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
struct IPPoolSpec {
    blocks: Vec<IPBlock>,
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
struct Metadata {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ip_pool() {
        let json = generate_ip_pool("default", "172.18.255.1/32").unwrap();

        assert!(json.contains(r#""apiVersion":"cilium.io/v2alpha1""#));
        assert!(json.contains(r#""kind":"CiliumLoadBalancerIPPool""#));
        assert!(json.contains(r#""name":"default""#));
        assert!(json.contains(r#""cidr":"172.18.255.1/32""#));
        assert!(json.contains(r#""app.kubernetes.io/managed-by":"lattice""#));
    }

    #[test]
    fn test_generate_l2_policy() {
        let json = generate_l2_policy().unwrap();

        assert!(json.contains(r#""apiVersion":"cilium.io/v2alpha1""#));
        assert!(json.contains(r#""kind":"CiliumL2AnnouncementPolicy""#));
        assert!(json.contains(r#""loadBalancerIPs":true"#));
        assert!(json.contains(r#""^.*$""#)); // Match all interfaces
    }

    #[test]
    fn test_generate_lb_resources() {
        let resources = generate_lb_resources("10.0.100.0/24").unwrap();

        assert_eq!(resources.len(), 2); // IP pool + L2 policy
        assert!(resources[0].contains("CiliumLoadBalancerIPPool"));
        assert!(resources[0].contains("10.0.100.0/24"));
        assert!(resources[1].contains("CiliumL2AnnouncementPolicy"));
    }

    #[test]
    fn test_single_ip_cidr() {
        // Single IP for cell LoadBalancer
        let json = generate_ip_pool("cell", "172.18.255.1/32").unwrap();

        assert!(json.contains(r#""cidr":"172.18.255.1/32""#));
    }
}
