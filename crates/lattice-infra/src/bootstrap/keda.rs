//! KEDA manifest generation
//!
//! Embeds pre-rendered KEDA manifests from build time.
//! KEDA provides event-driven autoscaling via ScaledObject triggers.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::crd::{
    CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth,
    ServiceRef,
};

use super::prometheus::MONITORING_NAMESPACE;
use super::{namespace_yaml_ambient, split_yaml_documents};

/// Namespace for KEDA components.
pub const KEDA_NAMESPACE: &str = "keda";

/// KEDA operator service account name (derived from chart defaults).
/// Used to construct SPIFFE identity for AuthorizationPolicy.
pub const KEDA_SERVICE_ACCOUNT: &str = "keda-operator";

/// KEDA metrics server service account name.
/// The metrics-apiserver calls keda-operator on port 9666 (gRPC) to fetch metrics.
pub const KEDA_METRICS_SERVICE_ACCOUNT: &str = "keda-operator-metrics-apiserver";

/// VM read target LMM name, referenced by KEDA operator's dependency
pub const VM_READ_TARGET_LMM_NAME: &str = "vm-read-target";

static KEDA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(KEDA_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/keda.yaml"
    ))));
    manifests
});

pub fn keda_version() -> &'static str {
    env!("KEDA_VERSION")
}

pub fn generate_keda() -> &'static [String] {
    &KEDA_MANIFESTS
}

/// Generate LatticeMeshMember CRDs for KEDA components.
///
/// Produces 3 LMMs:
/// 1. **keda-metrics-apiserver** — webhook called by kube-apiserver (Permissive mTLS)
/// 2. **keda-admission-webhooks** — webhook called by kube-apiserver (Permissive mTLS)
/// 3. **keda-operator** — receives gRPC from metrics-apiserver, queries VictoriaMetrics
pub fn generate_keda_mesh_members() -> Vec<LatticeMeshMember> {
    let mut members = Vec::with_capacity(3);

    // 1. keda-metrics-apiserver — webhook called by kube-apiserver
    let mut metrics_api = LatticeMeshMember::new(
        "keda-metrics-apiserver",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "keda-operator-metrics-apiserver".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 6443,
                name: "metrics-api".to_string(),
                peer_auth: PeerAuth::Permissive,
            }],
            allowed_callers: vec![], // open to non-mesh callers (apiserver)
            dependencies: vec![ServiceRef::new(KEDA_NAMESPACE, "keda-operator")],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    );
    metrics_api.metadata.namespace = Some(KEDA_NAMESPACE.to_string());
    members.push(metrics_api);

    // 2. keda-admission-webhooks — webhook called by kube-apiserver
    let mut admission = LatticeMeshMember::new(
        "keda-admission-webhooks",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "keda-admission-webhooks".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 9443,
                name: "webhook".to_string(),
                peer_auth: PeerAuth::Permissive,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    );
    admission.metadata.namespace = Some(KEDA_NAMESPACE.to_string());
    members.push(admission);

    // 3. keda-operator — receives gRPC from metrics-apiserver, queries VictoriaMetrics
    let mut operator = LatticeMeshMember::new(
        "keda-operator",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "keda-operator".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 9666,
                name: "grpc".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![CallerRef {
                name: "keda-metrics-apiserver".to_string(),
                namespace: Some(KEDA_NAMESPACE.to_string()),
            }],
            dependencies: vec![ServiceRef::new(
                MONITORING_NAMESPACE,
                VM_READ_TARGET_LMM_NAME,
            )],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    );
    operator.metadata.namespace = Some(KEDA_NAMESPACE.to_string());
    members.push(operator);

    members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!keda_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_keda();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "KEDA namespace must be enrolled in ambient mesh for mTLS identity"
        );
    }

    #[test]
    fn keda_mesh_members_count() {
        let members = generate_keda_mesh_members();
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn keda_metrics_apiserver_lmm() {
        let members = generate_keda_mesh_members();
        let m = &members[0];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-metrics-apiserver"));
        assert_eq!(m.metadata.namespace.as_deref(), Some(KEDA_NAMESPACE));
        assert_eq!(m.spec.ports.len(), 1);
        assert_eq!(m.spec.ports[0].port, 6443);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Permissive);
        assert!(m.spec.allowed_callers.is_empty(), "open to non-mesh callers");
        assert_eq!(m.spec.dependencies.len(), 1);
        assert_eq!(m.spec.dependencies[0].name, "keda-operator");
        assert!(m.spec.validate().is_ok());
    }

    #[test]
    fn keda_admission_webhooks_lmm() {
        let members = generate_keda_mesh_members();
        let m = &members[1];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-admission-webhooks"));
        assert_eq!(m.metadata.namespace.as_deref(), Some(KEDA_NAMESPACE));
        assert_eq!(m.spec.ports[0].port, 9443);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Permissive);
        assert!(m.spec.allowed_callers.is_empty());
        assert!(m.spec.dependencies.is_empty());
        assert!(m.spec.validate().is_ok());
    }

    #[test]
    fn keda_operator_lmm() {
        let members = generate_keda_mesh_members();
        let m = &members[2];
        assert_eq!(m.metadata.name.as_deref(), Some("keda-operator"));
        assert_eq!(m.metadata.namespace.as_deref(), Some(KEDA_NAMESPACE));
        assert_eq!(m.spec.ports[0].port, 9666);
        assert_eq!(m.spec.ports[0].peer_auth, PeerAuth::Strict);
        assert_eq!(m.spec.allowed_callers.len(), 1);
        assert_eq!(m.spec.allowed_callers[0].name, "keda-metrics-apiserver");
        assert_eq!(m.spec.dependencies.len(), 1);
        assert_eq!(m.spec.dependencies[0].name, VM_READ_TARGET_LMM_NAME);
        assert_eq!(
            m.spec.dependencies[0].namespace.as_deref(),
            Some(MONITORING_NAMESPACE)
        );
        assert!(m.spec.validate().is_ok());
    }
}
