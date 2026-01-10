//! Network policy generation for Lattice services
//!
//! This module generates Istio AuthorizationPolicies and CiliumNetworkPolicies
//! from the service graph's active edges. It implements a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! # Architecture
//!
//! The policy generation follows the bilateral agreement pattern from the service graph:
//! only when both caller declares dependency AND callee allows caller do we generate
//! allow policies.
//!
//! ```text
//! ServiceGraph (active edges)
//!         │
//!         ▼
//! PolicyCompiler.compile_for_service()
//!         │
//!         ├──► AuthorizationPolicy (L7 - mTLS identity)
//!         ├──► WaypointPolicy (L4 - HBONE allow)
//!         ├──► CiliumNetworkPolicy (L4 - eBPF)
//!         └──► ServiceEntry (external services)
//! ```

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::graph::{ActiveEdge, ServiceGraph, ServiceNode, ServiceType};

// =============================================================================
// Istio AuthorizationPolicy
// =============================================================================

/// Istio AuthorizationPolicy for L7 mTLS identity-based access control
///
/// This policy is applied to Services via targetRefs (Istio Ambient mode)
/// and enforced at the waypoint proxy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: AuthorizationPolicySpec,
}

/// Metadata for policy resources
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyMetadata {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl PolicyMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        Self {
            name: name.into(),
            namespace: namespace.into(),
            labels,
        }
    }
}

/// AuthorizationPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPolicySpec {
    /// Target references (Service, ServiceEntry)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<TargetRef>,

    /// Selector for workloads (used for waypoint policies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<WorkloadSelector>,

    /// Action: ALLOW, DENY, AUDIT, CUSTOM
    pub action: String,

    /// Rules defining who can access
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<AuthorizationRule>,
}

/// Target reference for AuthorizationPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetRef {
    /// API group (empty for core resources)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Resource kind
    pub kind: String,
    /// Resource name
    pub name: String,
}

/// Workload selector for AuthorizationPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Authorization rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationRule {
    /// Source conditions (who is calling)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<AuthorizationSource>,
    /// Destination conditions (what operation)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<AuthorizationOperation>,
}

/// Authorization source (caller identity)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationSource {
    /// Source specification
    pub source: SourceSpec,
}

/// Source specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SourceSpec {
    /// SPIFFE principals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<String>,
}

/// Authorization operation (what's being accessed)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationOperation {
    /// Operation specification
    pub operation: OperationSpec,
}

/// Operation specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OperationSpec {
    /// Allowed ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    /// Allowed hosts (for external services)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

// =============================================================================
// CiliumNetworkPolicy
// =============================================================================

/// Cilium Network Policy for L4 eBPF-based network enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumNetworkPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: CiliumNetworkPolicySpec,
}

/// CiliumNetworkPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumNetworkPolicySpec {
    /// Endpoint selector (which pods this applies to)
    pub endpoint_selector: EndpointSelector,
    /// Ingress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<CiliumIngressRule>,
    /// Egress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<CiliumEgressRule>,
}

/// Endpoint selector for CiliumNetworkPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Cilium ingress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumIngressRule {
    /// From endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_endpoints: Vec<EndpointSelector>,
    /// To ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<CiliumPortRule>,
}

/// Cilium egress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumEgressRule {
    /// To endpoints (internal services)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_endpoints: Vec<EndpointSelector>,
    /// To FQDNs (external DNS names)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_fqdns: Vec<FqdnSelector>,
    /// To CIDRs (IP ranges)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_cidr: Vec<String>,
    /// To ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<CiliumPortRule>,
}

/// FQDN selector for Cilium egress
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FqdnSelector {
    /// Exact match name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_name: Option<String>,
    /// Pattern match (supports wildcards)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_pattern: Option<String>,
}

/// Cilium port rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CiliumPortRule {
    /// Ports
    pub ports: Vec<CiliumPort>,
}

/// Cilium port specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CiliumPort {
    /// Port number
    pub port: String,
    /// Protocol (TCP, UDP)
    pub protocol: String,
}

// =============================================================================
// Istio ServiceEntry
// =============================================================================

/// Istio ServiceEntry for external service mesh integration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: ServiceEntrySpec,
}

/// ServiceEntry spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntrySpec {
    /// Hosts (DNS names)
    pub hosts: Vec<String>,
    /// Ports
    pub ports: Vec<ServiceEntryPort>,
    /// Location: MESH_EXTERNAL or MESH_INTERNAL
    pub location: String,
    /// Resolution: DNS, STATIC, NONE
    pub resolution: String,
}

/// ServiceEntry port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntryPort {
    /// Port number
    pub number: u16,
    /// Port name
    pub name: String,
    /// Protocol (HTTP, HTTPS, TCP, GRPC)
    pub protocol: String,
}

// =============================================================================
// Generated Policies Container
// =============================================================================

/// Collection of all policies generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedPolicies {
    /// Istio AuthorizationPolicies
    pub authorization_policies: Vec<AuthorizationPolicy>,
    /// Cilium Network Policies
    pub cilium_policies: Vec<CiliumNetworkPolicy>,
    /// Istio ServiceEntries
    pub service_entries: Vec<ServiceEntry>,
}

impl GeneratedPolicies {
    /// Create empty policy collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.authorization_policies.is_empty()
            && self.cilium_policies.is_empty()
            && self.service_entries.is_empty()
    }

    /// Total count of all generated policies
    pub fn total_count(&self) -> usize {
        self.authorization_policies.len()
            + self.cilium_policies.len()
            + self.service_entries.len()
    }
}

// =============================================================================
// Policy Compiler
// =============================================================================

/// HBONE port for Istio Ambient waypoint communication
const HBONE_PORT: u16 = 15008;

/// Policy compiler that generates network policies from service graph edges
pub struct PolicyCompiler<'a> {
    graph: &'a ServiceGraph,
    namespace: String,
    trust_domain: String,
}

impl<'a> PolicyCompiler<'a> {
    /// Create a new policy compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph to compile policies from
    /// * `namespace` - The Kubernetes namespace for generated policies
    /// * `trust_domain` - The SPIFFE trust domain (e.g., "mgmt-cluster.lattice.local")
    pub fn new(
        graph: &'a ServiceGraph,
        namespace: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            graph,
            namespace: namespace.into(),
            trust_domain: trust_domain.into(),
        }
    }

    /// Generate the mesh-wide default-deny AuthorizationPolicy
    ///
    /// This is applied once per environment in istio-system namespace.
    /// Uses ALLOW action with empty rules to deny everything by default.
    pub fn compile_mesh_default_deny(&self) -> AuthorizationPolicy {
        AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new("mesh-default-deny", "istio-system"),
            spec: AuthorizationPolicySpec {
                target_refs: vec![],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![], // Empty rules = deny all
            },
        }
    }

    /// Compile all policies for a specific service
    ///
    /// This generates:
    /// - AuthorizationPolicy for L7 access control (who can call this service)
    /// - Waypoint AuthorizationPolicy for L4 HBONE traffic
    /// - CiliumNetworkPolicy for L4 ingress/egress
    /// - ServiceEntries for external dependencies
    pub fn compile_for_service(&self, env: &str, service_name: &str) -> GeneratedPolicies {
        let mut policies = GeneratedPolicies::new();

        let Some(service) = self.graph.get_service(env, service_name) else {
            return policies;
        };

        // Skip Unknown services
        if service.type_ == ServiceType::Unknown {
            return policies;
        }

        // Get active edges
        let inbound_edges = self.graph.get_active_inbound_edges(env, service_name);
        let outbound_edges = self.graph.get_active_outbound_edges(env, service_name);

        // Generate policies based on service type
        match service.type_ {
            ServiceType::Local => {
                // Generate L7 AuthorizationPolicy for inbound traffic
                if !inbound_edges.is_empty() {
                    if let Some(auth_policy) =
                        self.compile_service_allow_policy(&service, &inbound_edges)
                    {
                        policies.authorization_policies.push(auth_policy);
                    }

                    // Generate waypoint allow policy
                    if let Some(waypoint_policy) =
                        self.compile_waypoint_allow_policy(&service)
                    {
                        policies.authorization_policies.push(waypoint_policy);
                    }
                }

                // Generate CiliumNetworkPolicy
                policies
                    .cilium_policies
                    .push(self.compile_cilium_policy(&service, &inbound_edges, &outbound_edges));

                // Generate ServiceEntries for external dependencies
                for edge in &outbound_edges {
                    if let Some(callee) = self.graph.get_service(env, &edge.callee) {
                        if callee.type_ == ServiceType::External {
                            if let Some(entry) = self.compile_service_entry(&callee) {
                                policies.service_entries.push(entry);
                            }
                        }
                    }
                }
            }
            ServiceType::External => {
                // External services don't get their own policies
                // They're referenced in caller policies
            }
            ServiceType::Unknown => {
                // Unknown services are placeholders, no policies needed
            }
        }

        policies
    }

    /// Compile all policies for an entire environment
    pub fn compile_for_environment(&self, env: &str) -> GeneratedPolicies {
        let mut policies = GeneratedPolicies::new();
        let mut seen_external: HashSet<String> = HashSet::new();

        // Add mesh default-deny
        policies
            .authorization_policies
            .push(self.compile_mesh_default_deny());

        // Compile policies for each local service
        for service in self.graph.list_services(env) {
            let service_policies = self.compile_for_service(env, &service.name);

            policies
                .authorization_policies
                .extend(service_policies.authorization_policies);
            policies
                .cilium_policies
                .extend(service_policies.cilium_policies);

            // Deduplicate service entries
            for entry in service_policies.service_entries {
                if seen_external.insert(entry.metadata.name.clone()) {
                    policies.service_entries.push(entry);
                }
            }
        }

        policies
    }

    /// Generate AuthorizationPolicy for a service (L7 allow policy)
    fn compile_service_allow_policy(
        &self,
        service: &ServiceNode,
        inbound_edges: &[ActiveEdge],
    ) -> Option<AuthorizationPolicy> {
        if inbound_edges.is_empty() {
            return None;
        }

        // Collect SPIFFE principals from callers
        let principals: Vec<String> = inbound_edges
            .iter()
            .map(|edge| self.spiffe_principal(&edge.caller))
            .collect();

        // Collect allowed ports
        let ports: Vec<String> = service
            .ports
            .values()
            .map(|p| p.to_string())
            .collect();

        Some(AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(
                format!("allow-to-{}", service.name),
                &self.namespace,
            ),
            spec: AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec { principals },
                    }],
                    to: if ports.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        })
    }

    /// Generate waypoint AuthorizationPolicy (L4 allow from waypoint proxy)
    fn compile_waypoint_allow_policy(&self, service: &ServiceNode) -> Option<AuthorizationPolicy> {
        let mut match_labels = BTreeMap::new();
        match_labels.insert("app.kubernetes.io/name".to_string(), service.name.clone());

        Some(AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(
                format!("allow-waypoint-to-{}", service.name),
                &self.namespace,
            ),
            spec: AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.waypoint_principal()],
                        },
                    }],
                    to: vec![],
                }],
            },
        })
    }

    /// Generate CiliumNetworkPolicy for a service
    fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
    ) -> CiliumNetworkPolicy {
        let mut endpoint_labels = BTreeMap::new();
        endpoint_labels.insert("app.kubernetes.io/name".to_string(), service.name.clone());

        // Build ingress rules
        let mut ingress_rules = Vec::new();

        // Allow from callers if there are inbound edges
        if !inbound_edges.is_empty() {
            let from_endpoints: Vec<EndpointSelector> = inbound_edges
                .iter()
                .map(|edge| {
                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "k8s:io.kubernetes.pod.namespace".to_string(),
                        self.namespace.clone(),
                    );
                    labels.insert("app.kubernetes.io/name".to_string(), edge.caller.clone());
                    EndpointSelector {
                        match_labels: labels,
                    }
                })
                .collect();

            // Collect ports from service
            let to_ports: Vec<CiliumPortRule> = if service.ports.is_empty() {
                vec![]
            } else {
                vec![CiliumPortRule {
                    ports: service
                        .ports
                        .values()
                        .flat_map(|p| {
                            vec![
                                CiliumPort {
                                    port: p.to_string(),
                                    protocol: "TCP".to_string(),
                                },
                                CiliumPort {
                                    port: p.to_string(),
                                    protocol: "UDP".to_string(),
                                },
                            ]
                        })
                        .collect(),
                }]
            };

            ingress_rules.push(CiliumIngressRule {
                from_endpoints,
                to_ports,
            });
        }

        // Allow HBONE from waypoint
        let mut waypoint_labels = BTreeMap::new();
        waypoint_labels.insert(
            "k8s:io.kubernetes.pod.namespace".to_string(),
            self.namespace.clone(),
        );
        waypoint_labels.insert(
            "istio.io/waypoint-for".to_string(),
            "service".to_string(),
        );
        ingress_rules.push(CiliumIngressRule {
            from_endpoints: vec![EndpointSelector {
                match_labels: waypoint_labels,
            }],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Always allow DNS to kube-dns
        let mut kube_dns_labels = BTreeMap::new();
        kube_dns_labels.insert(
            "k8s:io.kubernetes.pod.namespace".to_string(),
            "kube-system".to_string(),
        );
        kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: kube_dns_labels,
            }],
            to_fqdns: vec![],
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
            }],
        });

        // Always allow HBONE to waypoint
        let mut waypoint_egress_labels = BTreeMap::new();
        waypoint_egress_labels.insert(
            "istio.io/waypoint-for".to_string(),
            "service".to_string(),
        );
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: waypoint_egress_labels,
            }],
            to_fqdns: vec![],
            to_cidr: vec![],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Add egress rules for internal dependencies
        for edge in outbound_edges {
            if let Some(callee) = self.graph.get_service(&self.namespace, &edge.callee) {
                match callee.type_ {
                    ServiceType::Local => {
                        let mut dep_labels = BTreeMap::new();
                        dep_labels.insert(
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            self.namespace.clone(),
                        );
                        dep_labels.insert(
                            "app.kubernetes.io/name".to_string(),
                            edge.callee.clone(),
                        );

                        let to_ports: Vec<CiliumPortRule> = if callee.ports.is_empty() {
                            vec![]
                        } else {
                            vec![CiliumPortRule {
                                ports: callee
                                    .ports
                                    .values()
                                    .flat_map(|p| {
                                        vec![
                                            CiliumPort {
                                                port: p.to_string(),
                                                protocol: "TCP".to_string(),
                                            },
                                            CiliumPort {
                                                port: p.to_string(),
                                                protocol: "UDP".to_string(),
                                            },
                                        ]
                                    })
                                    .collect(),
                            }]
                        };

                        egress_rules.push(CiliumEgressRule {
                            to_endpoints: vec![EndpointSelector {
                                match_labels: dep_labels,
                            }],
                            to_fqdns: vec![],
                            to_cidr: vec![],
                            to_ports,
                        });
                    }
                    ServiceType::External => {
                        // Add FQDN-based egress for external services
                        let fqdns: Vec<FqdnSelector> = callee
                            .endpoints
                            .values()
                            .map(|ep| FqdnSelector {
                                match_name: Some(ep.host.clone()),
                                match_pattern: None,
                            })
                            .collect();

                        let ports: Vec<CiliumPort> = callee
                            .endpoints
                            .values()
                            .map(|ep| CiliumPort {
                                port: ep.port.to_string(),
                                protocol: "TCP".to_string(),
                            })
                            .collect();

                        if !fqdns.is_empty() {
                            egress_rules.push(CiliumEgressRule {
                                to_endpoints: vec![],
                                to_fqdns: fqdns,
                                to_cidr: vec![],
                                to_ports: if ports.is_empty() {
                                    vec![]
                                } else {
                                    vec![CiliumPortRule { ports }]
                                },
                            });
                        }
                    }
                    ServiceType::Unknown => {}
                }
            }
        }

        CiliumNetworkPolicy {
            api_version: "cilium.io/v2".to_string(),
            kind: "CiliumNetworkPolicy".to_string(),
            metadata: PolicyMetadata::new(format!("policy-{}", service.name), &self.namespace),
            spec: CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector {
                    match_labels: endpoint_labels,
                },
                ingress: ingress_rules,
                egress: egress_rules,
            },
        }
    }

    /// Generate ServiceEntry for an external service
    fn compile_service_entry(&self, service: &ServiceNode) -> Option<ServiceEntry> {
        if service.endpoints.is_empty() {
            return None;
        }

        let hosts: Vec<String> = service
            .endpoints
            .values()
            .map(|ep| ep.host.clone())
            .collect();

        let ports: Vec<ServiceEntryPort> = service
            .endpoints
            .iter()
            .map(|(name, ep)| ServiceEntryPort {
                number: ep.port,
                name: name.clone(),
                protocol: ep.protocol.to_uppercase(),
            })
            .collect();

        let mut metadata = PolicyMetadata::new(&service.name, &self.namespace);
        metadata.labels.insert(
            "istio.io/use-waypoint".to_string(),
            format!("{}-waypoint", self.namespace),
        );

        Some(ServiceEntry {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "ServiceEntry".to_string(),
            metadata,
            spec: ServiceEntrySpec {
                hosts,
                ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution: "DNS".to_string(),
            },
        })
    }

    /// Generate SPIFFE principal for a service
    ///
    /// Uses the full SPIFFE URI format with trust domain for cross-cluster identity:
    /// `spiffe://{trust_domain}/ns/{namespace}/sa/{service}`
    fn spiffe_principal(&self, service_name: &str) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, self.namespace, service_name
        )
    }

    /// Generate SPIFFE principal for the namespace waypoint
    fn waypoint_principal(&self) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}-waypoint",
            self.trust_domain, self.namespace, self.namespace
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{LatticeExternalServiceSpec, LatticeServiceSpec};

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> LatticeServiceSpec {
        use crate::crd::{
            ContainerSpec, DeploySpec, DependencyDirection, PortSpec, ReplicaSpec, ResourceSpec,
            ResourceType, ServicePortsSpec,
        };
        use std::collections::BTreeMap;

        let mut resources = BTreeMap::new();
        for dep in deps {
            resources.insert(
                dep.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    params: None,
                    class: None,
                },
            );
        }
        for caller in callers {
            // The resource name IS the caller service name (allowed_callers returns the key)
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Inbound,
                    id: None,
                    params: None,
                    class: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 8080,
                target_port: None,
                protocol: None,
            },
        );

        LatticeServiceSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
        }
    }

    fn make_external_spec(endpoints: Vec<(&str, &str)>, allowed: Vec<&str>) -> LatticeExternalServiceSpec {
        use std::collections::BTreeMap;
        use crate::crd::Resolution;

        let mut ep_map = BTreeMap::new();
        for (name, url) in endpoints {
            ep_map.insert(name.to_string(), url.to_string());
        }

        LatticeExternalServiceSpec {
            endpoints: ep_map,
            allowed_requesters: allowed.into_iter().map(String::from).collect(),
            resolution: Resolution::Dns,
            description: None,
        }
    }

    // =========================================================================
    // Story: Mesh Default Deny
    // =========================================================================

    #[test]
    fn story_mesh_default_deny_policy() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "test-ns", "test-cluster.lattice.local");

        let policy = compiler.compile_mesh_default_deny();

        assert_eq!(policy.metadata.name, "mesh-default-deny");
        assert_eq!(policy.metadata.namespace, "istio-system");
        assert_eq!(policy.spec.action, "ALLOW");
        assert!(policy.spec.rules.is_empty(), "Empty rules = deny all");
    }

    // =========================================================================
    // Story: Service With Inbound Edges Gets Allow Policy
    // =========================================================================

    #[test]
    fn story_service_with_callers_gets_authorization_policy() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api service allows gateway to call it
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway service calls api
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let policies = compiler.compile_for_service(env, "api");

        // Should have AuthorizationPolicy for api
        assert_eq!(policies.authorization_policies.len(), 2); // allow + waypoint

        let allow_policy = policies
            .authorization_policies
            .iter()
            .find(|p| p.metadata.name == "allow-to-api")
            .expect("should have allow policy");

        assert_eq!(allow_policy.spec.action, "ALLOW");
        assert_eq!(allow_policy.spec.target_refs.len(), 1);
        assert_eq!(allow_policy.spec.target_refs[0].name, "api");

        // Check SPIFFE principal
        let principals = &allow_policy.spec.rules[0].from[0].source.principals;
        assert_eq!(principals.len(), 1);
        assert!(principals[0].contains("gateway"));
    }

    // =========================================================================
    // Story: Service Without Callers Gets No Allow Policy
    // =========================================================================

    #[test]
    fn story_service_without_callers_gets_no_allow_policy() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api service allows nobody
        let api_spec = make_service_spec(vec![], vec![]);
        graph.put_service(env, "api", &api_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let policies = compiler.compile_for_service(env, "api");

        // Should have no AuthorizationPolicy (no inbound edges)
        assert!(
            policies.authorization_policies.is_empty(),
            "No callers = no allow policy"
        );
    }

    // =========================================================================
    // Story: Bilateral Agreement Required
    // =========================================================================

    #[test]
    fn story_no_policy_without_bilateral_agreement() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api declares it calls database
        let api_spec = make_service_spec(vec!["database"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // database does NOT allow api
        let db_spec = make_service_spec(vec![], vec![]); // No allowed callers
        graph.put_service(env, "database", &db_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let api_policies = compiler.compile_for_service(env, "api");
        let db_policies = compiler.compile_for_service(env, "database");

        // api should have no egress rules for database (no bilateral agreement)
        let cilium = api_policies.cilium_policies.first().expect("should have cilium policy");
        let has_db_egress = cilium.spec.egress.iter().any(|e| {
            e.to_endpoints.iter().any(|ep| {
                ep.match_labels
                    .get("app.kubernetes.io/name")
                    .map(|v| v == "database")
                    .unwrap_or(false)
            })
        });
        assert!(!has_db_egress, "No bilateral agreement = no egress rule");

        // database should have no authorization policy (no allowed callers)
        assert!(db_policies.authorization_policies.is_empty());
    }

    // =========================================================================
    // Story: CiliumNetworkPolicy Always Has DNS and HBONE
    // =========================================================================

    #[test]
    fn story_cilium_policy_has_dns_and_hbone_egress() {
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec![], vec![]);
        graph.put_service(env, "api", &api_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let policies = compiler.compile_for_service(env, "api");

        let cilium = policies.cilium_policies.first().expect("should have cilium policy");

        // Should have DNS egress
        let has_dns = cilium.spec.egress.iter().any(|e| {
            e.to_endpoints.iter().any(|ep| {
                ep.match_labels.get("k8s:k8s-app").map(|v| v == "kube-dns").unwrap_or(false)
            })
        });
        assert!(has_dns, "Should allow DNS egress");

        // Should have HBONE egress to waypoint
        let has_hbone = cilium.spec.egress.iter().any(|e| {
            e.to_ports.iter().any(|p| p.ports.iter().any(|port| port.port == "15008"))
        });
        assert!(has_hbone, "Should allow HBONE egress");

        // Should have HBONE ingress from waypoint
        let has_hbone_ingress = cilium.spec.ingress.iter().any(|i| {
            i.to_ports.iter().any(|p| p.ports.iter().any(|port| port.port == "15008"))
        });
        assert!(has_hbone_ingress, "Should allow HBONE ingress");
    }

    // =========================================================================
    // Story: External Service Gets ServiceEntry
    // =========================================================================

    #[test]
    fn story_external_dependency_generates_service_entry() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api depends on stripe
        let api_spec = make_service_spec(vec!["stripe"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // stripe is external service that allows api
        let stripe_spec = make_external_spec(
            vec![("api", "https://api.stripe.com")],
            vec!["api"],
        );
        graph.put_external_service(env, "stripe", &stripe_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let policies = compiler.compile_for_service(env, "api");

        // Should have ServiceEntry for stripe
        assert_eq!(policies.service_entries.len(), 1);
        let entry = &policies.service_entries[0];
        assert_eq!(entry.metadata.name, "stripe");
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
    }

    // =========================================================================
    // Story: Wildcard Caller Allows Everyone
    // =========================================================================

    #[test]
    fn story_wildcard_caller_allows_all() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // public-api allows everyone with wildcard
        let public_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service(env, "public-api", &public_spec);

        // service-a calls public-api
        let a_spec = make_service_spec(vec!["public-api"], vec![]);
        graph.put_service(env, "service-a", &a_spec);

        // service-b also calls public-api
        let b_spec = make_service_spec(vec!["public-api"], vec![]);
        graph.put_service(env, "service-b", &b_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-ns", "prod.lattice.local");
        let policies = compiler.compile_for_service(env, "public-api");

        // Should have allow policy with both callers
        let allow_policy = policies
            .authorization_policies
            .iter()
            .find(|p| p.metadata.name == "allow-to-public-api")
            .expect("should have allow policy");

        let principals = &allow_policy.spec.rules[0].from[0].source.principals;
        assert_eq!(principals.len(), 2);
    }

    // =========================================================================
    // Story: Environment Compilation
    // =========================================================================

    #[test]
    fn story_compile_entire_environment() {
        let graph = ServiceGraph::new();
        let env = "staging";

        let api_spec = make_service_spec(vec!["database"], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        let db_spec = make_service_spec(vec![], vec!["api"]);
        graph.put_service(env, "database", &db_spec);

        let compiler = PolicyCompiler::new(&graph, "staging-ns", "staging.lattice.local");
        let policies = compiler.compile_for_environment(env);

        // Should have mesh-default-deny
        assert!(policies
            .authorization_policies
            .iter()
            .any(|p| p.metadata.name == "mesh-default-deny"));

        // Should have policies for api, gateway, database
        assert_eq!(policies.cilium_policies.len(), 3);

        // Should have allow policies for api and database (they have callers)
        let allow_count = policies
            .authorization_policies
            .iter()
            .filter(|p| p.metadata.name.starts_with("allow-to-"))
            .count();
        assert_eq!(allow_count, 2); // api and database
    }

    // =========================================================================
    // Story: SPIFFE Principal Format
    // =========================================================================

    #[test]
    fn story_spiffe_principals_correctly_formatted() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "my-namespace", "my-cluster.lattice.local");

        let principal = compiler.spiffe_principal("my-service");
        assert_eq!(
            principal,
            "spiffe://my-cluster.lattice.local/ns/my-namespace/sa/my-service"
        );

        let waypoint = compiler.waypoint_principal();
        assert_eq!(
            waypoint,
            "spiffe://my-cluster.lattice.local/ns/my-namespace/sa/my-namespace-waypoint"
        );
    }

    // =========================================================================
    // Story: Policy Serialization
    // =========================================================================

    #[test]
    fn story_policies_serialize_to_yaml() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "default", "default.lattice.local");

        let policy = compiler.compile_mesh_default_deny();
        let yaml = serde_yaml::to_string(&policy).expect("should serialize");

        assert!(yaml.contains("apiVersion: security.istio.io/v1beta1"));
        assert!(yaml.contains("kind: AuthorizationPolicy"));
        assert!(yaml.contains("name: mesh-default-deny"));
        assert!(yaml.contains("namespace: istio-system"));
    }
}
