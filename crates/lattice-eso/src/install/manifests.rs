//! ESO helm chart manifests + mesh enrollment.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_common::{LABEL_NAME, OPERATOR_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth,
    ServiceRef,
};

static ESO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient("external-secrets")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/eso.yaml"
    ))));
    manifests
});

/// ESO chart version pinned at build time from `versions.toml`.
pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

/// Pre-rendered ESO helm chart manifests, including the ambient-enrolled
/// `external-secrets` namespace.
pub fn generate_eso() -> &'static [String] {
    &ESO_MANIFESTS
}

/// LatticeMeshMembers for ESO components.
///
/// - `external-secrets-webhook`: admission webhook on port 10250 (Webhook mTLS
///   since the caller is kube-apiserver, which lacks mesh identity).
/// - `external-secrets`: main operator, egress-only (reaches kube-apiserver +
///   the operator's local-secrets webhook via declared dependency).
/// - `external-secrets-cert-controller`: cert management, egress-only.
pub fn generate_eso_mesh_members() -> Vec<LatticeMeshMember> {
    vec![
        mesh_member(
            "external-secrets-webhook",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets-webhook".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 10250,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ),
        mesh_member(
            "external-secrets",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![ServiceRef::new(LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME)],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ),
        mesh_member(
            "external-secrets-cert-controller",
            "external-secrets",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    LABEL_NAME.to_string(),
                    "external-secrets-cert-controller".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!eso_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_eso();
        assert!(!m.is_empty());
        assert!(m[0].contains("kind: Namespace"));
        assert!(m[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn mesh_members_have_expected_shape() {
        let members = generate_eso_mesh_members();
        assert_eq!(members.len(), 3);
        for m in &members {
            assert_eq!(m.metadata.namespace.as_deref(), Some("external-secrets"));
            assert!(m.spec.ambient);
            assert!(m.spec.validate().is_ok());
        }

        let wh = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("external-secrets-webhook"))
            .expect("webhook member");
        assert_eq!(wh.spec.ports[0].port, 10250);
        assert_eq!(wh.spec.ports[0].peer_auth, PeerAuth::Webhook);

        let op = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("external-secrets"))
            .expect("operator member");
        assert!(op.spec.ports.is_empty());
        assert_eq!(op.spec.dependencies[0].name, "lattice-operator");
    }
}
