//! L4 policy compilation: CiliumNetworkPolicy
//!
//! Generates eBPF-based network enforcement at the kernel level using Cilium.
//!
//! ## Ambient mesh interaction
//!
//! In Istio ambient mesh, ztunnel wraps all pod-to-pod traffic in HBONE
//! (port 15008). Cilium sees the raw pod-to-pod connection on port 15008,
//! so it cannot distinguish individual service ports at L4.
//!
//! Enforcement is split across two layers:
//! - **Cilium (L4)**: Broad HBONE allow for mesh traffic, plus DNS and
//!   external FQDN/CIDR rules for non-mesh egress.
//! - **Istio AuthorizationPolicy (L7)**: Identity-based enforcement using
//!   SPIFFE identities inside the HBONE tunnel.

use std::collections::BTreeMap;

use lattice_common::crd::{derived_name, EgressTarget};
use lattice_common::graph::{ActiveEdge, ServiceNode, ServiceType};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::cilium::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector,
};
use lattice_common::{mesh, CILIUM_LABEL_NAME, CILIUM_LABEL_NAMESPACE};

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Compile a CiliumNetworkPolicy for a mesh member.
    ///
    /// Uses the member's custom selector labels for the endpoint selector.
    /// Permissive ports get direct TCP ingress (not HBONE) for plaintext callers.
    /// Non-mesh egress rules (entity, CIDR, FQDN) are applied from the spec.
    pub(super) fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
        permissive_ports: &[u16],
    ) -> CiliumNetworkPolicy {
        // Endpoint selector: custom labels or Cilium name label
        let endpoint_labels = service
            .selector
            .as_ref()
            .map(|labels| {
                labels
                    .iter()
                    .map(|(k, v)| (format!("k8s:{}", k), v.clone()))
                    .collect()
            })
            .unwrap_or_else(|| {
                let mut m = BTreeMap::new();
                m.insert(CILIUM_LABEL_NAME.to_string(), service.name.clone());
                m
            });

        let mut ingress_rules = Vec::new();

        // HBONE ingress for mesh callers (ztunnel wraps all pod-to-pod on port 15008)
        if !inbound_edges.is_empty() {
            ingress_rules.push(Self::hbone_ingress_rule());
        }

        // Direct TCP ingress for permissive ports (plaintext callers like kube-apiserver)
        if !permissive_ports.is_empty() {
            ingress_rules.push(CiliumIngressRule {
                from_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
                to_ports: vec![CiliumPortRule {
                    ports: permissive_ports
                        .iter()
                        .map(|p| CiliumPort {
                            port: p.to_string(),
                            protocol: "TCP".to_string(),
                        })
                        .collect(),
                    rules: None,
                }],
            });
        }

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Check if service has external FQDN dependencies or FQDN egress rules
        let has_external_fqdns = outbound_edges.iter().any(|edge| {
            self.graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
                .map(|callee| {
                    callee.type_ == ServiceType::External
                        && callee
                            .endpoints
                            .values()
                            .any(|ep| !Self::is_ip_address(&ep.host))
                })
                .unwrap_or(false)
        });
        let has_fqdn_egress = service
            .egress_rules
            .iter()
            .any(|r| matches!(r.target, EgressTarget::Fqdn(_)));

        // Always allow DNS to kube-dns
        let mut kube_dns_labels = BTreeMap::new();
        kube_dns_labels.insert(
            CILIUM_LABEL_NAMESPACE.to_string(),
            "kube-system".to_string(),
        );
        kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(kube_dns_labels)],
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
                rules: if has_external_fqdns || has_fqdn_egress {
                    Some(DnsRules {
                        dns: vec![DnsMatch {
                            match_pattern: Some("*".to_string()),
                        }],
                    })
                } else {
                    None
                },
            }],
            ..Default::default()
        });

        // HBONE egress for outbound mesh dependencies
        if !outbound_edges.is_empty() {
            egress_rules.push(Self::hbone_egress_rule());
        }

        // External deps egress (FQDN/CIDR from outbound edges)
        self.build_egress_rules_for_external_deps(outbound_edges, &mut egress_rules);

        // Non-mesh egress rules from spec (entity, CIDR, FQDN)
        for rule in &service.egress_rules {
            let to_ports = if rule.ports.is_empty() {
                vec![]
            } else {
                vec![CiliumPortRule {
                    ports: rule
                        .ports
                        .iter()
                        .map(|p| CiliumPort {
                            port: p.to_string(),
                            protocol: "TCP".to_string(),
                        })
                        .collect(),
                    rules: None,
                }]
            };

            match &rule.target {
                EgressTarget::Entity(entity) => {
                    egress_rules.push(CiliumEgressRule {
                        to_entities: vec![entity.clone()],
                        to_ports,
                        ..Default::default()
                    });
                }
                EgressTarget::Cidr(cidr) => {
                    egress_rules.push(CiliumEgressRule {
                        to_cidr: vec![cidr.clone()],
                        to_ports,
                        ..Default::default()
                    });
                }
                EgressTarget::Fqdn(fqdn) => {
                    egress_rules.push(CiliumEgressRule {
                        to_fqdns: vec![FqdnSelector {
                            match_name: Some(fqdn.clone()),
                            match_pattern: None,
                        }],
                        to_ports,
                        ..Default::default()
                    });
                }
            }
        }

        CiliumNetworkPolicy::new(
            ObjectMeta::new(
                derived_name("cnp-mesh-", &[namespace, &service.name]),
                namespace,
            ),
            CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector::from_labels(endpoint_labels),
                ingress: ingress_rules,
                egress: egress_rules,
            },
        )
    }

    /// Build egress rules for external (non-mesh) dependencies only.
    /// Local service dependencies are covered by the broad HBONE egress rule.
    fn build_egress_rules_for_external_deps(
        &self,
        outbound_edges: &[ActiveEdge],
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        for edge in outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                if callee.type_ == ServiceType::External {
                    self.build_external_dependency_rules(&callee, egress_rules);
                }
            }
        }
    }

    /// Build egress rules for an external service dependency
    fn build_external_dependency_rules(
        &self,
        callee: &ServiceNode,
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        let (fqdns, cidrs) = Self::categorize_external_endpoints(callee);
        let to_ports = Self::build_external_port_rules(callee);

        if !fqdns.is_empty() {
            egress_rules.push(CiliumEgressRule {
                to_fqdns: fqdns,
                to_ports: to_ports.clone(),
                ..Default::default()
            });
        }

        if !cidrs.is_empty() {
            egress_rules.push(CiliumEgressRule {
                to_cidr: cidrs,
                to_ports,
                ..Default::default()
            });
        }
    }

    /// Categorize external endpoints into FQDNs and CIDRs
    pub(crate) fn categorize_external_endpoints(
        callee: &ServiceNode,
    ) -> (Vec<FqdnSelector>, Vec<String>) {
        let mut fqdns: Vec<FqdnSelector> = Vec::new();
        let mut cidrs: Vec<String> = Vec::new();

        for ep in callee.endpoints.values() {
            if Self::is_ip_address(&ep.host) {
                let prefix = if ep.host.contains(':') { 128 } else { 32 };
                cidrs.push(format!("{}/{}", ep.host, prefix));
            } else {
                fqdns.push(FqdnSelector {
                    match_name: Some(ep.host.clone()),
                    match_pattern: None,
                });
            }
        }

        (fqdns, cidrs)
    }

    /// Broad HBONE ingress: allow any pod to deliver traffic on port 15008.
    /// Identity enforcement is handled by Istio AuthorizationPolicy at L7.
    fn hbone_ingress_rule() -> CiliumIngressRule {
        CiliumIngressRule {
            from_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
        }
    }

    /// Broad HBONE egress: allow this pod to reach any pod on port 15008.
    fn hbone_egress_rule() -> CiliumEgressRule {
        CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
            ..Default::default()
        }
    }

    /// Build port rules for external service endpoints (TCP only)
    fn build_external_port_rules(callee: &ServiceNode) -> Vec<CiliumPortRule> {
        let ports: Vec<CiliumPort> = callee
            .endpoints
            .values()
            .map(|ep| CiliumPort {
                port: ep.port.to_string(),
                protocol: "TCP".to_string(),
            })
            .collect();

        if ports.is_empty() {
            vec![]
        } else {
            vec![CiliumPortRule { ports, rules: None }]
        }
    }
}
