//! L7 policy compilation: Istio AuthorizationPolicy, ServiceEntry
//!
//! Generates mTLS identity-based access control using SPIFFE principals
//! within the Istio ambient mesh.
//!
//! ## Ztunnel-first enforcement model
//!
//! By default, policies are enforced by ztunnel directly (no waypoint in the traffic path).
//! A waypoint is only deployed for services that need L7 features (currently: external
//! outbound dependencies via ServiceEntry; future: rate limiting, header matching).
//!
//! ## Policy enforcement points
//!
//! - **Ztunnel-enforced** (`selector`): evaluated by ztunnel on the destination node.
//!   Uses the **container target port**. This is the default path.
//! - **Waypoint-enforced** (`targetRefs: Service`): evaluated by the waypoint proxy.
//!   Uses the K8s **service port**. Only used when the service has external dependencies.

use std::collections::BTreeMap;

use lattice_common::crd::derived_name;
use lattice_common::graph::{ActiveEdge, ServiceNode};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh;
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, PeerAuthentication, SourceSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::policy::service_entry::{ServiceEntry, ServiceEntryPort, ServiceEntrySpec};
use lattice_common::LABEL_NAME;

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Compile an AuthorizationPolicy for inbound traffic.
    ///
    /// Always ztunnel-enforced (selector-based). Uses the node's custom selector
    /// labels if available, otherwise falls back to `LABEL_NAME`.
    /// If `allow_peer_traffic` is set on the node, adds own SPIFFE principal.
    pub(super) fn compile_inbound_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
    ) -> Option<AuthorizationPolicy> {
        if inbound_edges.is_empty() && !service.allow_peer_traffic {
            return None;
        }

        let mut principals: Vec<String> = inbound_edges
            .iter()
            .map(|edge| {
                mesh::trust_domain::principal(
                    &self.cluster_name,
                    &edge.caller_namespace,
                    &edge.caller_name,
                )
            })
            .collect();

        // If allow_peer_traffic, add own principal so pods can talk to each other
        if service.allow_peer_traffic {
            principals.push(mesh::trust_domain::principal(
                &self.cluster_name,
                namespace,
                &service.name,
            ));
        }

        if principals.is_empty() {
            return None;
        }

        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.target_port.to_string())
            .collect();

        if ports.is_empty() {
            return None;
        }

        // Use custom selector labels if available, otherwise fall back to LABEL_NAME
        let match_labels = service.selector.clone().unwrap_or_else(|| {
            let mut m = BTreeMap::new();
            m.insert(LABEL_NAME.to_string(), service.name.clone());
            m
        });

        Some(AuthorizationPolicy::allow_to_workload(
            derived_name("allow-to-", &[namespace, &service.name]),
            namespace,
            match_labels,
            principals,
            ports,
        ))
    }

    /// Compile a ztunnel-enforced AuthorizationPolicy (waypoint → pod).
    ///
    /// Uses `selector` matching the pod labels, so ztunnel evaluates this policy
    /// on the destination node. Port matching uses the **container target port**
    /// because ztunnel delivers traffic directly to the pod after HBONE decap.
    pub(super) fn compile_ztunnel_allow_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<AuthorizationPolicy> {
        let ports: Vec<String> = service
            .ports
            .values()
            .map(|pm| pm.target_port.to_string())
            .collect();

        if ports.is_empty() {
            return None;
        }

        let mut match_labels = BTreeMap::new();
        match_labels.insert(LABEL_NAME.to_string(), service.name.clone());

        Some(AuthorizationPolicy::new(
            ObjectMeta::new(format!("allow-waypoint-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![mesh::trust_domain::waypoint_principal(
                                &self.cluster_name,
                                namespace,
                            )],
                        },
                    }],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        ))
    }

    pub(super) fn compile_service_entry(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<ServiceEntry> {
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

        let metadata = ObjectMeta::new(&service.name, namespace)
            .with_label(mesh::USE_WAYPOINT_LABEL, mesh::waypoint_name(namespace));

        let resolution = service
            .resolution
            .as_ref()
            .map(|r| r.to_istio_format())
            .unwrap_or("DNS")
            .to_string();

        Some(ServiceEntry::new(
            metadata,
            ServiceEntrySpec {
                hosts,
                ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution,
            },
        ))
    }

    pub(super) fn compile_external_access_policy(
        &self,
        caller: &str,
        external_service: &ServiceNode,
        namespace: &str,
    ) -> AuthorizationPolicy {
        let ports: Vec<String> = external_service
            .endpoints
            .values()
            .map(|ep| ep.port.to_string())
            .collect();

        AuthorizationPolicy::new(
            ObjectMeta::new(
                format!("allow-{}-to-{}", caller, external_service.name),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: external_service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![mesh::trust_domain::principal(
                                &self.cluster_name,
                                namespace,
                                caller,
                            )],
                        },
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
        )
    }

    /// Compile permissive policies for specific ports on a mesh member.
    ///
    /// - PeerAuthentication: STRICT default with PERMISSIVE overrides on specified ports
    /// - AuthorizationPolicy: ALLOW with no `from` restriction on permissive ports
    ///   (allows plaintext callers like kube-apiserver)
    pub(super) fn compile_permissive_policies_for_ports(
        &self,
        service: &ServiceNode,
        namespace: &str,
        permissive_ports: &[u16],
    ) -> (Vec<PeerAuthentication>, Vec<AuthorizationPolicy>) {
        if permissive_ports.is_empty() {
            return (vec![], vec![]);
        }

        let match_labels = service.selector.clone().unwrap_or_else(|| {
            let mut m = BTreeMap::new();
            m.insert(LABEL_NAME.to_string(), service.name.clone());
            m
        });

        // PeerAuthentication with port-level PERMISSIVE
        let peer_auth = PeerAuthentication::with_permissive_ports(
            derived_name("permissive-", &[namespace, &service.name]),
            namespace,
            match_labels.clone(),
            permissive_ports,
        );

        // AuthorizationPolicy: ALLOW with empty from (any caller) on permissive ports only
        let port_strings: Vec<String> = permissive_ports.iter().map(|p| p.to_string()).collect();
        let auth_policy = AuthorizationPolicy::new(
            ObjectMeta::new(
                derived_name("allow-webhook-", &[namespace, &service.name]),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![], // Empty from = allow any caller
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports: port_strings,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        );

        (vec![peer_auth], vec![auth_policy])
    }
}
