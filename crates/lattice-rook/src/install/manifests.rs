//! Rook-Ceph manifests: operator chart (build-time render) plus runtime-
//! generated CephCluster / CephBlockPool / StorageClass derived from the
//! `RookInstall` spec.

use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::namespace_yaml;
use lattice_core::system_namespaces::ROOK_CEPH_NAMESPACE;
use lattice_crd::crd::RookInstallSpec;
use serde_json::{json, Value};

/// Ceph image tag. Squid (v19) is the current stable-LTS line as of the
/// Rook v1.18 release; bumping requires verifying the rook-ceph chart's
/// supported matrix.
pub const CEPH_IMAGE: &str = "quay.io/ceph/ceph:v19.2.1";

/// Default block pool + StorageClass name. Users get `rook-ceph-block` as
/// the provisioner identity — same name as the upstream examples to avoid
/// surprising operators coming from stock Rook.
pub const BLOCK_POOL_NAME: &str = "rook-ceph-block";

/// CephCluster CR name. Rook does not enforce the name but the CSI secrets
/// are named off it by the operator chart; `rook-ceph` keeps the default
/// CSI secret plumbing (`rook-csi-rbd-provisioner`, `rook-csi-rbd-node`)
/// lined up without extra overrides.
pub const CEPH_CLUSTER_NAME: &str = "rook-ceph";

/// Where Rook writes per-mon state on the host. VMs' rootfs (on the Basis
/// `vm-<id>` LV) is fine; this path is deliberately not on an OSD disk.
const DATA_DIR_HOST_PATH: &str = "/var/lib/rook";

/// Match only `/dev/vdc`..`/dev/vdz`. The Basis guest layout puts the
/// rootfs at `/dev/vda` (partition table) and the cloud-init cidata at
/// `/dev/vdb` (FAT filesystem); both would be skipped by Rook's own
/// `hasChildren` check, but an explicit allowlist is cheap insurance
/// against a future provider that presents something less predictable.
const DEVICE_FILTER: &str = "^vd[c-z]$";

/// Annotation that marks a StorageClass as the cluster default. Kubernetes
/// enforces at most one default; the controller clears the annotation on
/// any existing default before applying this one.
const DEFAULT_SC_ANNOTATION: &str = "storageclass.kubernetes.io/is-default-class";

static OPERATOR_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(env!("OUT_DIR"), "/rook-operator.yaml")))
});

/// Rook-Ceph chart version pinned at build time.
pub fn rook_ceph_version() -> &'static str {
    env!("ROOK_CEPH_VERSION")
}

/// Pre-rendered operator Deployment + CSI drivers + RBAC.
pub fn operator_manifests() -> &'static [String] {
    &OPERATOR_MANIFESTS
}

/// Bare `rook-ceph` Namespace. No Istio ambient label — ceph's msgr2
/// binary protocol on dynamic OSD port ranges can't be L7-meshed; the
/// namespace is covered by `lattice-core::system_namespaces::STORAGE`
/// so the cluster-wide default-deny CNP leaves it alone.
pub fn rook_ceph_namespace_yaml() -> String {
    namespace_yaml(ROOK_CEPH_NAMESPACE)
}

/// `CephCluster` CR, the thing that actually tells Rook to form a cluster.
///
/// `useAllDevices: false` + explicit `deviceFilter` is the safety net: we
/// only claim `/dev/vd[c-z]`, the range Basis attaches extras into.
pub fn generate_ceph_cluster(spec: &RookInstallSpec) -> Value {
    let encrypted = if spec.encrypt_osds { "true" } else { "false" };
    json!({
        "apiVersion": "ceph.rook.io/v1",
        "kind": "CephCluster",
        "metadata": {
            "name": CEPH_CLUSTER_NAME,
            "namespace": ROOK_CEPH_NAMESPACE,
        },
        "spec": {
            "cephVersion": { "image": CEPH_IMAGE },
            "dataDirHostPath": DATA_DIR_HOST_PATH,
            "mon": {
                "count": spec.mon_count,
                "allowMultiplePerNode": spec.allow_multiple_mons_per_node,
            },
            "mgr": {
                "count": 2,
                "allowMultiplePerNode": spec.allow_multiple_mons_per_node,
            },
            "dashboard": { "enabled": false },
            "storage": {
                "useAllNodes": true,
                "useAllDevices": false,
                "deviceFilter": DEVICE_FILTER,
                "config": { "encryptedDevice": encrypted },
            },
            // Size-1 pools are never production; refusing them at the
            // cluster level short-circuits misconfigured CephBlockPools.
            "cephConfig": {
                "global": { "mon_allow_pool_size_one": "false" }
            },
        }
    })
}

/// Default RBD pool backing `rook-ceph-block` StorageClass.
pub fn generate_block_pool(spec: &RookInstallSpec) -> Value {
    json!({
        "apiVersion": "ceph.rook.io/v1",
        "kind": "CephBlockPool",
        "metadata": {
            "name": BLOCK_POOL_NAME,
            "namespace": ROOK_CEPH_NAMESPACE,
        },
        "spec": {
            "failureDomain": spec.failure_domain.as_ceph_str(),
            "replicated": {
                "size": spec.replication,
                "requireSafeReplicaSize": true,
            },
            "parameters": { "compression_mode": "passive" },
        }
    })
}

/// RBD `StorageClass` wired through Rook's CSI provisioner. Default flag
/// is controlled by `spec.default_storage_class`; the controller is
/// responsible for clearing any previous default annotation first.
pub fn generate_storage_class(spec: &RookInstallSpec) -> Value {
    let mut annotations = serde_json::Map::new();
    if spec.default_storage_class {
        annotations.insert(
            DEFAULT_SC_ANNOTATION.to_string(),
            Value::String("true".to_string()),
        );
    }

    let mut metadata = serde_json::Map::new();
    metadata.insert("name".to_string(), Value::String(BLOCK_POOL_NAME.to_string()));
    if !annotations.is_empty() {
        metadata.insert("annotations".to_string(), Value::Object(annotations));
    }

    json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": Value::Object(metadata),
        "provisioner": "rook-ceph.rbd.csi.ceph.com",
        "reclaimPolicy": "Delete",
        "allowVolumeExpansion": true,
        "volumeBindingMode": "WaitForFirstConsumer",
        "parameters": {
            "clusterID": CEPH_CLUSTER_NAME,
            "pool": BLOCK_POOL_NAME,
            "imageFormat": "2",
            "imageFeatures": "layering",
            "csi.storage.k8s.io/provisioner-secret-name": "rook-csi-rbd-provisioner",
            "csi.storage.k8s.io/provisioner-secret-namespace": ROOK_CEPH_NAMESPACE,
            "csi.storage.k8s.io/controller-expand-secret-name": "rook-csi-rbd-provisioner",
            "csi.storage.k8s.io/controller-expand-secret-namespace": ROOK_CEPH_NAMESPACE,
            "csi.storage.k8s.io/node-stage-secret-name": "rook-csi-rbd-node",
            "csi.storage.k8s.io/node-stage-secret-namespace": ROOK_CEPH_NAMESPACE,
            "csi.storage.k8s.io/fstype": "ext4",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crd::crd::FailureDomain;

    fn default_spec() -> RookInstallSpec {
        serde_json::from_value(json!({ "version": "1.18.0" })).unwrap()
    }

    #[test]
    fn version_is_set() {
        assert!(!rook_ceph_version().is_empty());
    }

    #[test]
    fn operator_manifests_are_embedded() {
        let manifests = operator_manifests();
        assert!(
            !manifests.is_empty(),
            "operator chart must render at least one document"
        );
    }

    #[test]
    fn ceph_cluster_honors_spec() {
        let mut spec = default_spec();
        spec.mon_count = 5;
        spec.encrypt_osds = true;
        let cc = generate_ceph_cluster(&spec);
        assert_eq!(cc["spec"]["mon"]["count"], 5);
        assert_eq!(cc["spec"]["mon"]["allowMultiplePerNode"], false);
        assert_eq!(cc["spec"]["storage"]["config"]["encryptedDevice"], "true");
        assert_eq!(cc["spec"]["storage"]["deviceFilter"], DEVICE_FILTER);
        assert_eq!(cc["spec"]["storage"]["useAllDevices"], false);
    }

    #[test]
    fn ceph_cluster_disables_encryption_when_requested() {
        let mut spec = default_spec();
        spec.encrypt_osds = false;
        let cc = generate_ceph_cluster(&spec);
        assert_eq!(cc["spec"]["storage"]["config"]["encryptedDevice"], "false");
    }

    #[test]
    fn ceph_cluster_allows_stacking_when_requested() {
        let mut spec = default_spec();
        spec.allow_multiple_mons_per_node = true;
        let cc = generate_ceph_cluster(&spec);
        assert_eq!(cc["spec"]["mon"]["allowMultiplePerNode"], true);
        assert_eq!(cc["spec"]["mgr"]["allowMultiplePerNode"], true);
    }

    #[test]
    fn block_pool_follows_replication_and_failure_domain() {
        let mut spec = default_spec();
        spec.replication = 2;
        spec.failure_domain = FailureDomain::Osd;
        let pool = generate_block_pool(&spec);
        assert_eq!(pool["spec"]["replicated"]["size"], 2);
        assert_eq!(pool["spec"]["failureDomain"], "osd");
        assert_eq!(pool["spec"]["replicated"]["requireSafeReplicaSize"], true);
    }

    #[test]
    fn storage_class_default_annotation_toggles() {
        let mut spec = default_spec();
        spec.default_storage_class = true;
        let sc = generate_storage_class(&spec);
        assert_eq!(
            sc["metadata"]["annotations"][DEFAULT_SC_ANNOTATION],
            "true"
        );

        spec.default_storage_class = false;
        let sc = generate_storage_class(&spec);
        assert!(
            sc["metadata"].get("annotations").is_none(),
            "non-default StorageClass must omit the default annotation entirely"
        );
    }

    #[test]
    fn storage_class_points_at_rook_csi() {
        let spec = default_spec();
        let sc = generate_storage_class(&spec);
        assert_eq!(sc["provisioner"], "rook-ceph.rbd.csi.ceph.com");
        assert_eq!(sc["allowVolumeExpansion"], true);
        assert_eq!(sc["volumeBindingMode"], "WaitForFirstConsumer");
        assert_eq!(sc["parameters"]["pool"], BLOCK_POOL_NAME);
        assert_eq!(sc["parameters"]["csi.storage.k8s.io/fstype"], "ext4");
    }

    #[test]
    fn namespace_is_plain_not_ambient() {
        let ns = rook_ceph_namespace_yaml();
        assert!(ns.contains("name: rook-ceph"));
        assert!(
            !ns.contains("dataplane-mode"),
            "rook-ceph namespace must not opt into ambient — ceph msgr2 isn't mesh-compatible"
        );
    }
}
