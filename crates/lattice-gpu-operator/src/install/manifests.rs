//! GPU Operator helm chart + mesh enrollment manifests.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_common::LABEL_NAME;
use lattice_crd::crd::{LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget};

use super::NAMESPACE;

static GPU_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gpu-operator.yaml"
    ))));
    manifests
});

/// NVIDIA GPU Operator version pinned at build time from `versions.toml`.
pub fn gpu_operator_version() -> &'static str {
    env!("GPU_OPERATOR_VERSION")
}

/// Pre-rendered GPU Operator manifests, including the ambient-enrolled
/// namespace. The Volcano vGPU device plugin is deployed as part of Volcano,
/// not here — it's a scheduler component that lives next to Volcano.
pub fn generate_gpu_stack() -> &'static [String] {
    &GPU_MANIFESTS
}

/// LatticeMeshMember for the GPU Operator main pod.
///
/// Egress-only (K8s API for CRD reconciliation). NFD master/GC/worker
/// DaemonSets are internal to the operator and run in `kube-system`, which is
/// already excluded from mesh policies.
pub fn generate_gpu_mesh_members() -> Vec<LatticeMeshMember> {
    vec![mesh_member(
        "gpu-operator",
        NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "gpu-operator".to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("gpu-operator".to_string()),
            depends_all: false,
            ambient: true,
            advertise: None,
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!gpu_operator_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_gpu_stack();
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(
            manifests[0].contains("istio.io/dataplane-mode: ambient"),
            "GPU namespace must be enrolled in ambient mesh"
        );
    }

    #[test]
    fn gpu_mesh_members_generated() {
        let members = generate_gpu_mesh_members();
        assert_eq!(members.len(), 1);

        let op = &members[0];
        assert_eq!(op.metadata.name.as_deref(), Some("gpu-operator"));
        assert_eq!(op.metadata.namespace.as_deref(), Some(NAMESPACE));
        assert!(op.spec.validate().is_ok());
        assert!(op.spec.ambient);
        assert!(op.spec.ports.is_empty(), "gpu-operator is egress-only");
        assert_eq!(op.spec.service_account.as_deref(), Some("gpu-operator"));
    }
}
