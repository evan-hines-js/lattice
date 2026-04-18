//! Cilium helm chart manifests + `CiliumClusterwideNetworkPolicy` generators.
//!
//! Policies land as part of the Cilium install: they are enforcement rules
//! owned by the Cilium CNI, not by individual workloads.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{CILIUM_GATEWAY_NAME_LABEL, HBONE_PORT, ISTIOD_XDS_PORT};
use lattice_common::policy::cilium::{
    CiliumClusterwideNetworkPolicy, CiliumClusterwideSpec, CiliumPort, CiliumPortRule,
    ClusterwideEgressRule, ClusterwideIngressRule, ClusterwideMetadata, DnsMatch, DnsRules,
    EnableDefaultDeny, EndpointSelector, MatchExpression,
};
use lattice_core::system_namespaces;

static CILIUM_MANIFESTS: LazyLock<Vec<String>> =
    LazyLock::new(|| split_yaml_documents(include_str!(concat!(env!("OUT_DIR"), "/cilium.yaml"))));

/// Cilium chart version pinned at build time from `versions.toml`.
pub fn cilium_version() -> &'static str {
    env!("CILIUM_VERSION")
}

/// Pre-rendered Cilium helm chart manifests.
pub fn generate_cilium_manifests() -> &'static [String] {
    &CILIUM_MANIFESTS
}

/// Generate a `CiliumClusterwideNetworkPolicy` to allow ztunnel/ambient traffic.
///
/// Required for Istio ambient mode when default-deny is active. ztunnel uses
/// link-local 169.254.7.127 for SNAT-ed kubelet health probes.
/// See: <https://istio.io/latest/docs/ambient/install/platform-prerequisites/>
pub fn generate_ztunnel_allowlist() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("allow-ambient-hostprobes"),
        CiliumClusterwideSpec {
            description: Some(
                "Allows SNAT-ed kubelet health check probes into ambient pods".to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::default(),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec!["169.254.7.127/32".to_string()],
                from_endpoints: vec![],
                to_ports: vec![],
            }],
            egress: vec![],
        },
    )
}

/// Mesh-wide default-deny policy — L4 defense-in-depth alongside Istio's L7
/// AuthorizationPolicy.
///
/// - No ingress rules → deny all ingress.
/// - Only DNS egress to `kube-dns` + kube-apiserver egress allowed.
/// - System namespaces excluded via `matchExpressions`.
pub fn generate_default_deny() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("default-deny"),
        CiliumClusterwideSpec {
            description: Some(
                "Block all ingress traffic by default, allow DNS and K8s API egress".to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: "k8s:io.kubernetes.pod.namespace".to_string(),
                    operator: "NotIn".to_string(),
                    values: system_namespaces::all()
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }],
            },
            ingress: vec![],
            egress: vec![
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "UDP".to_string(),
                            },
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "TCP".to_string(),
                            },
                        ],
                        rules: Some(DnsRules {
                            dns: vec![DnsMatch {
                                match_pattern: Some("*".to_string()),
                            }],
                        }),
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec!["kube-apiserver".to_string()],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
            ],
        },
    )
}

/// Egress policy for every Istio Gateway API proxy pod (waypoints + ingress
/// gateways), keyed off `gateway.networking.k8s.io/gateway-name`.
///
/// One cluster-wide policy covers every service namespace without duplicating
/// namespace-scoped policies.
pub fn generate_mesh_proxy_egress_policy() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("mesh-proxy-egress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow Istio mesh proxy pods (waypoints + ingress gateways) to reach istiod and forward traffic"
                    .to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: CILIUM_GATEWAY_NAME_LABEL.to_string(),
                    operator: "Exists".to_string(),
                    values: vec![],
                }],
            },
            ingress: vec![],
            egress: vec![
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "UDP".to_string(),
                            },
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "TCP".to_string(),
                            },
                        ],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "istio-system".to_string(),
                        ),
                        ("k8s:app".to_string(), "istiod".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: ISTIOD_XDS_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: HBONE_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector {
                        match_labels: BTreeMap::new(),
                        match_expressions: vec![MatchExpression {
                            key: "k8s:io.kubernetes.pod.namespace".to_string(),
                            operator: "NotIn".to_string(),
                            values: system_namespaces::all()
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        }],
                    }],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec!["0.0.0.0/0".to_string()],
                    to_ports: vec![],
                },
            ],
        },
    )
}

/// Ingress policy for the east-west gateway accepting cross-cluster HBONE
/// on port 15008. Egress is covered by the mesh-proxy-egress policy since the
/// gateway pods carry the gateway-name label.
pub fn generate_eastwest_gateway_policy() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("eastwest-gateway-ingress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow east-west gateway to receive cross-cluster HBONE traffic from external networks"
                    .to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::from_labels(BTreeMap::from([
                (
                    "k8s:io.kubernetes.pod.namespace".to_string(),
                    "istio-system".to_string(),
                ),
                (
                    CILIUM_GATEWAY_NAME_LABEL.to_string(),
                    "istio-eastwestgateway".to_string(),
                ),
            ])),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec!["0.0.0.0/0".to_string()],
                from_endpoints: vec![],
                to_ports: vec![CiliumPortRule {
                    ports: vec![CiliumPort {
                        port: HBONE_PORT.to_string(),
                        protocol: "TCP".to_string(),
                    }],
                    rules: None,
                }],
            }],
            egress: vec![],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!cilium_version().is_empty());
    }

    #[test]
    fn manifests_contain_agent() {
        let m = generate_cilium_manifests();
        assert!(!m.is_empty());
        let combined = m.join("\n");
        assert!(combined.contains("kind: DaemonSet"));
        assert!(combined.contains("cilium-agent"));
    }

    #[test]
    fn ztunnel_allowlist_allows_link_local() {
        let p = generate_ztunnel_allowlist();
        assert_eq!(p.metadata.name, "allow-ambient-hostprobes");
        assert!(p
            .spec
            .ingress
            .iter()
            .any(|r| r.from_cidr.contains(&"169.254.7.127/32".to_string())));
    }

    #[test]
    fn default_deny_excludes_system_namespaces() {
        let p = generate_default_deny();
        let expr = &p.spec.endpoint_selector.match_expressions[0];
        assert_eq!(expr.operator, "NotIn");
        assert!(expr.values.contains(&"kube-system".to_string()));
        assert!(p.spec.ingress.is_empty());
    }

    #[test]
    fn mesh_proxy_egress_has_all_five_rules() {
        let p = generate_mesh_proxy_egress_policy();
        assert_eq!(p.spec.egress.len(), 5);
    }

    #[test]
    fn eastwest_gateway_ingress_on_hbone_port() {
        let p = generate_eastwest_gateway_policy();
        let port = &p.spec.ingress[0].to_ports[0].ports[0];
        assert_eq!(port.port, HBONE_PORT.to_string());
    }
}
