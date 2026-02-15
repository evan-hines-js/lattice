//! Network policy types and compilation for Lattice mesh members
//!
//! This module provides policy compilation logic implementing a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! Policy compilation is split into provider-specific sub-modules:
//! - [`istio_ambient`]: L7 policies (AuthorizationPolicy, ServiceEntry, PeerAuthentication)
//! - [`cilium`]: L4 policies (CiliumNetworkPolicy)

mod cilium;
mod istio_ambient;

use lattice_common::graph::{ServiceGraph, ServiceType};
use lattice_common::policy::cilium::CiliumNetworkPolicy;
use lattice_common::policy::istio::{AuthorizationPolicy, PeerAuthentication};
use lattice_common::policy::service_entry::ServiceEntry;

// =============================================================================
// Generated Policies Container
// =============================================================================

/// Collection of all policies generated for a mesh member
#[derive(Clone, Debug, Default)]
pub struct GeneratedPolicies {
    /// Istio AuthorizationPolicies
    pub authorization_policies: Vec<AuthorizationPolicy>,
    /// Cilium Network Policies
    pub cilium_policies: Vec<CiliumNetworkPolicy>,
    /// Istio ServiceEntries
    pub service_entries: Vec<ServiceEntry>,
    /// Istio PeerAuthentication (port-level mTLS overrides)
    pub peer_authentications: Vec<PeerAuthentication>,
}

impl GeneratedPolicies {
    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.authorization_policies.is_empty()
            && self.cilium_policies.is_empty()
            && self.service_entries.is_empty()
            && self.peer_authentications.is_empty()
    }

    /// Total count of all generated policies
    pub fn total_count(&self) -> usize {
        self.authorization_policies.len()
            + self.cilium_policies.len()
            + self.service_entries.len()
            + self.peer_authentications.len()
    }
}

// =============================================================================
// Policy Compiler
// =============================================================================

/// Compiler for generating network policies from the service graph
///
/// This compiler implements defense-in-depth with:
/// - L7 (Istio AuthorizationPolicy): mTLS identity-based access control
/// - L4 (CiliumNetworkPolicy): eBPF-based network enforcement
///
/// Policies are only generated for edges that satisfy bilateral agreement:
/// caller declares dependency AND callee allows caller.
pub struct PolicyCompiler<'a> {
    graph: &'a ServiceGraph,
    cluster_name: String,
}

impl<'a> PolicyCompiler<'a> {
    /// Create a new policy compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for bilateral agreement checks
    /// * `cluster_name` - Cluster name used in trust domain (lattice.{cluster}.local)
    pub fn new(graph: &'a ServiceGraph, cluster_name: impl Into<String>) -> Self {
        Self {
            graph,
            cluster_name: cluster_name.into(),
        }
    }

    /// Compile all mesh policies for a member.
    ///
    /// This is the single entry point for all mesh policy generation.
    /// Uses the node's custom selector labels and supports permissive ports,
    /// peer traffic, non-mesh egress rules, and external dependencies.
    pub fn compile(
        &self,
        name: &str,
        namespace: &str,
        permissive_ports: &[u16],
    ) -> GeneratedPolicies {
        let Some(service_node) = self.graph.get_service(namespace, name) else {
            return GeneratedPolicies::default();
        };

        if service_node.type_ == ServiceType::Unknown {
            return GeneratedPolicies::default();
        }

        let mut output = GeneratedPolicies::default();

        let inbound_edges = self.graph.get_active_inbound_edges(namespace, name);
        let outbound_edges = self.graph.get_active_outbound_edges(namespace, name);

        // Istio AuthorizationPolicy for inbound (ztunnel-enforced)
        if let Some(auth_policy) =
            self.compile_inbound_policy(&service_node, namespace, &inbound_edges)
        {
            output.authorization_policies.push(auth_policy);
        }

        // Waypoint: if service has external deps, need ztunnel allow for waypoint→pod
        let has_external_deps = outbound_edges.iter().any(|edge| {
            self.graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
                .map(|s| s.type_ == ServiceType::External)
                .unwrap_or(false)
        });
        if has_external_deps {
            if let Some(waypoint_policy) =
                self.compile_ztunnel_allow_policy(&service_node, namespace)
            {
                output.authorization_policies.push(waypoint_policy);
            }
        }

        // Cilium policy
        output.cilium_policies.push(self.compile_cilium_policy(
            &service_node,
            namespace,
            &inbound_edges,
            &outbound_edges,
            permissive_ports,
        ));

        // Permissive policies (PeerAuthentication + AuthorizationPolicy for plaintext ports)
        let (peer_auths, auth_policies) =
            self.compile_permissive_policies_for_ports(&service_node, namespace, permissive_ports);
        output.peer_authentications.extend(peer_auths);
        output.authorization_policies.extend(auth_policies);

        // ServiceEntries and access policies for external dependencies
        for edge in &outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                if callee.type_ == ServiceType::External {
                    if let Some(entry) = self.compile_service_entry(&callee, &edge.callee_namespace)
                    {
                        output.service_entries.push(entry);
                    }
                    output
                        .authorization_policies
                        .push(self.compile_external_access_policy(
                            &service_node.name,
                            &callee,
                            namespace,
                        ));
                }
            }
        }

        output
    }

    /// Check if a string is an IP address (IPv4 or IPv6)
    pub(crate) fn is_ip_address(host: &str) -> bool {
        use std::net::IpAddr;
        host.parse::<IpAddr>().is_ok()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::PolicyCompiler;
    use lattice_common::crd::{
        ContainerSpec, DependencyDirection, LatticeExternalServiceSpec, PortSpec, Resolution,
        ResourceSpec, ServicePortsSpec, WorkloadSpec,
    };
    use lattice_common::graph::ServiceGraph;
    use lattice_common::mesh;
    use lattice_common::policy::cilium::{CiliumEgressRule, FqdnSelector};
    use std::collections::BTreeMap;

    fn make_external_spec(allowed: Vec<&str>) -> LatticeExternalServiceSpec {
        LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([(
                "api".to_string(),
                "https://api.stripe.com:443".to_string(),
            )]),
            allowed_requesters: allowed.into_iter().map(String::from).collect(),
            resolution: Resolution::Dns,
            description: None,
        }
    }

    fn make_service_spec(
        deps: Vec<&str>,
        callers: Vec<&str>,
    ) -> lattice_common::crd::LatticeServiceSpec {
        let mut resources = BTreeMap::new();
        for dep in deps {
            resources.insert(
                dep.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
        }
        for caller in callers {
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                ..Default::default()
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

        lattice_common::crd::LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec { ports }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn bilateral_agreement_generates_policy() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns", &[]);

        assert!(!output.authorization_policies.is_empty());
        let auth = &output.authorization_policies[0];
        // No external deps → ztunnel path (selector, no targetRefs)
        assert!(auth.spec.target_refs.is_empty());
        assert!(auth.spec.selector.is_some());
        assert!(auth.spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn no_policy_without_bilateral_agreement() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec![], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns", &[]);

        assert!(output.authorization_policies.is_empty());
    }

    #[test]
    fn no_policies_when_not_in_graph() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("nonexistent", "default", &[]);
        assert!(output.is_empty());
    }

    #[test]
    fn spiffe_uses_trust_domain() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "my-cluster");
        let output = compiler.compile("api", "prod-ns", &[]);

        let principals = &output.authorization_policies[0].spec.rules[0].from[0]
            .source
            .principals;
        assert!(principals[0].starts_with("lattice.my-cluster.local/ns/prod-ns/sa/"));
        assert_eq!(
            principals[0],
            "lattice.my-cluster.local/ns/prod-ns/sa/gateway"
        );
    }

    #[test]
    fn cilium_policy_always_generated() {
        let graph = ServiceGraph::new();
        let ns = "default";

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service(ns, "my-app", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("my-app", ns, &[]);

        assert_eq!(output.cilium_policies.len(), 1);

        // DNS egress always present
        assert!(output.cilium_policies[0].spec.egress.iter().any(|e| e
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "53"))));

        // No ztunnel HBONE ingress for services without callers or external deps
        assert!(
            output.cilium_policies[0].spec.ingress.is_empty(),
            "service with no callers or external deps should have no ingress rules"
        );
    }

    #[test]
    fn external_service_generates_service_entry() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec!["stripe-api"], vec![]);
        graph.put_service(ns, "api", &api_spec);

        graph.put_external_service(ns, "stripe-api", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns", &[]);

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert_eq!(entry.metadata.name, "stripe-api");
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
    }

    #[test]
    fn total_count() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec!["stripe"], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        graph.put_external_service(ns, "stripe", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns", &[]);

        assert_eq!(output.cilium_policies.len(), 1);

        // AuthorizationPolicies:
        //    - allow inbound from gateway
        //    - allow-waypoint-to-api for L7 policy
        //    - allow-api-to-stripe for external access
        assert_eq!(output.authorization_policies.len(), 3);

        assert_eq!(output.service_entries.len(), 1);

        // Total: 1 Cilium + 3 AuthZ + 1 ServiceEntry = 5
        assert_eq!(output.total_count(), 5);
    }

    #[test]
    fn cilium_fqdn_field_serializes_correctly() {
        let rule = CiliumEgressRule {
            to_endpoints: vec![],
            to_entities: vec![],
            to_fqdns: vec![FqdnSelector {
                match_name: Some("api.example.com".to_string()),
                match_pattern: None,
            }],
            to_cidr: vec!["10.0.0.0/8".to_string()],
            to_ports: vec![],
        };

        let json = serde_json::to_string(&rule).expect("rule should serialize");

        assert!(json.contains("\"toFQDNs\""));
        assert!(json.contains("\"toCIDR\""));
    }

    #[test]
    fn is_ip_address_detection() {
        assert!(PolicyCompiler::is_ip_address("1.1.1.1"));
        assert!(PolicyCompiler::is_ip_address("::1"));
        assert!(!PolicyCompiler::is_ip_address("example.com"));
        assert!(!PolicyCompiler::is_ip_address("api.stripe.com"));
    }

    #[test]
    fn wildcard_inbound_generates_policy() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns, &[]);

        assert!(!output.authorization_policies.is_empty());
        assert!(output.authorization_policies[0].spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn ipv6_cidr_uses_128_prefix() {
        use lattice_common::crd::ParsedEndpoint;

        let mut node = lattice_common::graph::ServiceNode::unknown("test-ns", "external-svc");
        node.endpoints.insert(
            "ipv4".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "192.168.1.1".to_string(),
                port: 443,
                url: "tcp://192.168.1.1:443".to_string(),
            },
        );
        node.endpoints.insert(
            "ipv6".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "2001:db8::1".to_string(),
                port: 443,
                url: "tcp://[2001:db8::1]:443".to_string(),
            },
        );

        let (fqdns, cidrs) = PolicyCompiler::categorize_external_endpoints(&node);

        assert!(fqdns.is_empty());
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&"192.168.1.1/32".to_string()));
        assert!(cidrs.contains(&"2001:db8::1/128".to_string()));
    }

    #[test]
    fn cilium_hbone_ingress_and_egress_for_mesh_service() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");

        // Check api (has inbound callers, no outbound)
        let api_cnp = &compiler.compile("api", ns, &[]).cilium_policies[0];
        assert_eq!(
            api_cnp.spec.ingress.len(),
            1,
            "api should have HBONE ingress"
        );
        let ingress = &api_cnp.spec.ingress[0];
        assert!(ingress.from_endpoints[0].match_labels.is_empty());
        assert!(ingress.to_ports[0].ports[0].port == mesh::HBONE_PORT.to_string());
        assert!(
            !api_cnp
                .spec
                .egress
                .iter()
                .any(|e| e.to_ports.iter().any(|pr| pr
                    .ports
                    .iter()
                    .any(|p| p.port == mesh::HBONE_PORT.to_string()))),
            "api should not have HBONE egress (no outbound deps)"
        );

        // Check gateway (has outbound deps, no inbound callers)
        let gw_cnp = &compiler.compile("gateway", ns, &[]).cilium_policies[0];
        assert!(gw_cnp.spec.ingress.is_empty(), "gateway has no callers");
        let hbone_egress = gw_cnp.spec.egress.iter().find(|e| {
            e.to_ports.iter().any(|pr| {
                pr.ports
                    .iter()
                    .any(|p| p.port == mesh::HBONE_PORT.to_string())
            })
        });
        assert!(
            hbone_egress.is_some(),
            "gateway should have HBONE egress for local deps"
        );
    }

    #[test]
    fn cilium_hbone_with_external_deps() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec!["stripe"], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        graph.put_external_service(ns, "stripe", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns, &[]);

        let cnp = &output.cilium_policies[0];

        assert_eq!(cnp.spec.ingress.len(), 1);
        assert!(cnp.spec.ingress[0].from_endpoints[0]
            .match_labels
            .is_empty());

        let hbone_port = mesh::HBONE_PORT.to_string();
        assert!(
            cnp.spec.egress.iter().any(|e| e
                .to_ports
                .iter()
                .any(|pr| pr.ports.iter().any(|p| p.port == hbone_port))),
            "should have HBONE egress for external deps"
        );

        assert!(
            cnp.spec.egress.iter().any(|e| !e.to_fqdns.is_empty()),
            "should have FQDN egress for stripe"
        );
    }

    #[test]
    fn mixed_endpoints_categorized_correctly() {
        use lattice_common::crd::ParsedEndpoint;

        let mut node = lattice_common::graph::ServiceNode::unknown("test-ns", "external-svc");
        node.endpoints.insert(
            "fqdn".to_string(),
            ParsedEndpoint {
                protocol: "https".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                url: "https://api.example.com".to_string(),
            },
        );
        node.endpoints.insert(
            "ipv4".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "10.0.0.1".to_string(),
                port: 8080,
                url: "tcp://10.0.0.1:8080".to_string(),
            },
        );

        let (fqdns, cidrs) = PolicyCompiler::categorize_external_endpoints(&node);

        assert_eq!(fqdns.len(), 1);
        assert_eq!(fqdns[0].match_name, Some("api.example.com".to_string()));

        assert_eq!(cidrs.len(), 1);
        assert!(cidrs.contains(&"10.0.0.1/32".to_string()));
    }
}
