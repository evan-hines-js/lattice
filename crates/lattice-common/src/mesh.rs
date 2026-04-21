//! Service mesh constants for Istio Ambient + Cilium
//!
//! Single source of truth for mesh-related constants used across policy
//! and ingress compilation. We're committed to Istio Ambient mode with
//! Cilium CNI - no abstraction layer needed.

// =============================================================================
// Ports
// =============================================================================

/// HBONE port for Istio Ambient waypoint communication.
///
/// In ambient mode, traffic flows: client -> ztunnel -> waypoint:15008 -> service
/// HBONE (HTTP-Based Overlay Network Encapsulation) is Istio's L7 tunnel protocol.
pub const HBONE_PORT: u16 = 15008;

/// Istiod xDS port for control plane communication.
pub const ISTIOD_XDS_PORT: u16 = 15012;

// =============================================================================
// Gateway Classes
// =============================================================================

/// Istio waypoint GatewayClass for ambient mesh L7 enforcement.
pub const WAYPOINT_GATEWAY_CLASS: &str = "istio-waypoint";

/// Istio GatewayClass for north-south ingress.
///
/// Istiod natively reconciles Gateway API resources. Gateway proxy pods are
/// created per-Gateway in the service namespace, automatically enrolled in
/// ambient mesh with SPIFFE identity.
pub const INGRESS_GATEWAY_CLASS: &str = "istio";

// =============================================================================
// Labels
// =============================================================================

/// Label key indicating what type of traffic a waypoint handles.
/// Value: "service" for service-destined traffic.
pub const WAYPOINT_FOR_LABEL: &str = "istio.io/waypoint-for";

/// Label key to route traffic through a specific waypoint.
/// Value: name of the waypoint Gateway (e.g., "{namespace}-waypoint").
pub const USE_WAYPOINT_LABEL: &str = "istio.io/use-waypoint";

/// Cilium label selector for Gateway API gateway-name label.
///
/// Present on all pods created by a Gateway API controller (both ingress
/// gateways and waypoint proxies). Used for cluster-wide Cilium policies
/// that apply to all mesh proxy pods.
pub const CILIUM_GATEWAY_NAME_LABEL: &str = "k8s:gateway.networking.k8s.io/gateway-name";

/// Label key for Istio dataplane mode.
/// Value: "ambient" to enroll pods in ambient mesh.
pub const DATAPLANE_MODE_LABEL: &str = "istio.io/dataplane-mode";

// =============================================================================
// Label Values
// =============================================================================

/// Value for WAYPOINT_FOR_LABEL indicating service-destined traffic.
pub const WAYPOINT_FOR_SERVICE: &str = "service";

/// Value for DATAPLANE_MODE_LABEL enabling ambient mesh enrollment.
pub const DATAPLANE_MODE_AMBIENT: &str = "ambient";

/// ConfigMap name containing the Lattice CA trust bundle for cross-cluster mTLS.
///
/// Gateway API frontend mTLS references this ConfigMap to validate client certs.
/// The operator ensures this ConfigMap exists with the CA trust bundle PEM.
pub const LATTICE_CA_CONFIGMAP: &str = "lattice-ca-trust";

// =============================================================================
// Naming Helpers
// =============================================================================

/// Get the waypoint Gateway name for a namespace.
///
/// Waypoints are per-namespace in Istio Ambient mode.
pub fn waypoint_name(namespace: &str) -> String {
    format!("{}-waypoint", namespace)
}

/// Get the shared ingress Gateway name for a namespace.
///
/// A single shared Gateway per namespace reduces resource overhead.
/// Individual services bind to it via listener `section_name` references.
pub fn ingress_gateway_name(namespace: &str) -> String {
    format!("{}-ingress", namespace)
}

/// Get the service account name for the namespace's ingress gateway proxy.
///
/// Istio creates a service account `{gateway_name}-istio` for the proxy pod.
pub fn ingress_gateway_sa_name(namespace: &str) -> String {
    format!("{}-istio", ingress_gateway_name(namespace))
}

// =============================================================================
// Bootstrap Manifest Helpers
// =============================================================================
//
// Small builders for constructs that every dependency install crate needs
// (ambient-enrolled Namespace YAML, kube-apiserver egress rule, namespaced
// LatticeMeshMember constructor). Previously lived as `pub(crate)` helpers
// inside lattice-infra/bootstrap; hoisted here so per-component install
// crates can reuse them without depending on lattice-infra.

use lattice_crd::crd::{EgressRule, EgressTarget, LatticeMeshMember, LatticeMeshMemberSpec};

/// Minimal Namespace YAML.
pub fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Namespace YAML with the Istio multi-cluster network label.
///
/// `topology.istio.io/network` tells istiod which network the namespace lives
/// on; required for cross-network routing.
pub fn namespace_yaml_with_network(name: &str, network: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n  labels:\n    topology.istio.io/network: {}",
        name, network
    )
}

/// Namespace YAML with Istio ambient mesh enrollment.
///
/// Sets `istio.io/dataplane-mode: ambient` so pods are ztunneled.
pub fn namespace_yaml_ambient(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n  labels:\n    istio.io/dataplane-mode: ambient",
        name
    )
}

/// Egress rule that permits traffic to the kube-apiserver (TCP 6443 on the
/// `kube-apiserver` entity).
///
/// Required for system components (KEDA, VM operator, ESO, etc.) that need
/// to reach the Kubernetes API from inside the ambient mesh.
pub fn kube_apiserver_egress() -> EgressRule {
    EgressRule::tcp(
        EgressTarget::Entity("kube-apiserver".to_string()),
        vec![6443],
    )
}

/// Construct a namespaced `LatticeMeshMember`.
pub fn mesh_member(name: &str, namespace: &str, spec: LatticeMeshMemberSpec) -> LatticeMeshMember {
    let mut member = LatticeMeshMember::new(name, spec);
    member.metadata.namespace = Some(namespace.to_string());
    member
}

// =============================================================================
// Trust Domain Helpers
// =============================================================================

/// Trust domain module for SPIFFE identity generation.
///
/// Lattice uses per-cluster trust domains: `lattice.{cluster}.local`
/// This provides multi-cluster isolation while maintaining a consistent format.
pub mod trust_domain {
    pub use lattice_core::trust_domain::principal;

    /// Build a SPIFFE principal for a namespace's waypoint proxy.
    ///
    /// Waypoint service accounts follow the pattern: `{namespace}-waypoint`
    pub fn waypoint_principal(trust_domain: &str, namespace: &str) -> String {
        principal(trust_domain, namespace, &super::waypoint_name(namespace))
    }

    /// Build a SPIFFE principal for the namespace's shared ingress gateway proxy.
    ///
    /// The gateway name is derived deterministically from the namespace
    /// (`{namespace}-ingress`), so only trust_domain and namespace are needed.
    /// Istio creates a service account `{gateway_name}-istio` for the proxy.
    pub fn gateway_principal(trust_domain: &str, namespace: &str) -> String {
        principal(
            trust_domain,
            namespace,
            &super::ingress_gateway_sa_name(namespace),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hbone_port_is_correct() {
        assert_eq!(HBONE_PORT, 15008);
    }

    #[test]
    fn waypoint_gateway_class_is_istio() {
        assert_eq!(WAYPOINT_GATEWAY_CLASS, "istio-waypoint");
    }

    #[test]
    fn principal_format_no_spiffe_prefix() {
        let principal = trust_domain::principal("lattice.abcd1234.local", "default", "api");
        assert_eq!(principal, "lattice.abcd1234.local/ns/default/sa/api");
        assert!(!principal.starts_with("spiffe://"));
    }

    #[test]
    fn waypoint_principal_format() {
        let principal = trust_domain::waypoint_principal("lattice.abcd1234.local", "myns");
        assert_eq!(principal, "lattice.abcd1234.local/ns/myns/sa/myns-waypoint");
    }

    #[test]
    fn gateway_principal_format() {
        let principal = trust_domain::gateway_principal("lattice.abcd1234.local", "my-ns");
        assert_eq!(
            principal,
            "lattice.abcd1234.local/ns/my-ns/sa/my-ns-ingress-istio"
        );
    }

    #[test]
    fn ingress_gateway_name_format() {
        assert_eq!(ingress_gateway_name("prod"), "prod-ingress");
        assert_eq!(ingress_gateway_name("my-ns"), "my-ns-ingress");
    }

    #[test]
    fn ingress_gateway_sa_name_format() {
        assert_eq!(ingress_gateway_sa_name("prod"), "prod-ingress-istio");
        assert_eq!(ingress_gateway_sa_name("my-ns"), "my-ns-ingress-istio");
    }
}
