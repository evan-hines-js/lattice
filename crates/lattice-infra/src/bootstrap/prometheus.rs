//! VictoriaMetrics K8s Stack manifest generation
//!
//! Embeds pre-rendered VictoriaMetrics manifests from build time.

use std::sync::LazyLock;

use lattice_common::crd::LatticeMeshMember;

use super::{namespace_yaml_ambient, split_yaml_documents};

/// Well-known service name for the VMCluster components.
/// Used as `fullnameOverride` so all downstream consumers (KEDA,
/// canary controller, KEDA, etc.) reference a stable integration point.
pub const VMCLUSTER_NAME: &str = "lattice-metrics";

/// Namespace for monitoring components.
pub const MONITORING_NAMESPACE: &str = "monitoring";

/// VMAgent service account name (derived from chart fullnameOverride).
/// Used to construct SPIFFE identity for AuthorizationPolicy.
pub const VMAGENT_SERVICE_ACCOUNT: &str = "vmagent-lattice-metrics";

/// VMSelect query port (Prometheus-compatible read path, HA mode).
pub const VMSELECT_PORT: u16 = 8481;

/// VMSelect URL path prefix for Prometheus-compatible queries (HA mode).
pub const VMSELECT_PATH: &str = "/select/0/prometheus";

/// VMInsert write port (HA mode).
pub const VMINSERT_PORT: u16 = 8480;

/// VMSingle query port (Prometheus-compatible read path, single-node mode).
pub const VMSINGLE_PORT: u16 = 8428;

/// VMSingle URL path prefix for Prometheus-compatible queries (single-node mode).
pub const VMSINGLE_PATH: &str = "/prometheus";

/// Build the VMSelect service URL from well-known constants (HA mode).
/// Returns e.g. `http://vmselect-lattice-metrics.monitoring.svc`
pub fn vmselect_url() -> String {
    format!(
        "http://vmselect-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Build the VMSingle service URL from well-known constants (single-node mode).
/// Returns e.g. `http://vmsingle-lattice-metrics.monitoring.svc`
pub fn vmsingle_url() -> String {
    format!(
        "http://vmsingle-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Return the Prometheus-compatible query port for the given HA mode.
pub fn query_port(ha: bool) -> u16 {
    if ha {
        VMSELECT_PORT
    } else {
        VMSINGLE_PORT
    }
}

/// Return the Prometheus-compatible query path for the given HA mode.
pub fn query_path(ha: bool) -> &'static str {
    if ha {
        VMSELECT_PATH
    } else {
        VMSINGLE_PATH
    }
}

/// Return the full Prometheus-compatible query base URL for the given HA mode.
pub fn query_url(ha: bool) -> String {
    if ha {
        vmselect_url()
    } else {
        vmsingle_url()
    }
}

/// Pre-rendered VictoriaMetrics HA manifests with namespace prepended.
static PROMETHEUS_HA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-ha.yaml"
    ))));
    manifests
});

/// Pre-rendered VictoriaMetrics single-node manifests with namespace prepended.
static PROMETHEUS_SINGLE_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-single.yaml"
    ))));
    manifests
});

/// VictoriaMetrics K8s Stack version (pinned at build time)
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Generate VictoriaMetrics K8s Stack manifests.
///
/// When `ha` is true, returns the HA VMCluster manifests (2 replicas each).
/// When `ha` is false, returns the single-node VMSingle manifests.
pub fn generate_prometheus(ha: bool) -> &'static [String] {
    if ha {
        &PROMETHEUS_HA_MANIFESTS
    } else {
        &PROMETHEUS_SINGLE_MANIFESTS
    }
}

/// Generate LatticeMeshMember CRDs for monitoring components.
///
/// Produces LMMs for:
/// - **VM write target** (vmsingle or vminsert) — receives scraped metrics from vmagent
/// - **VM read target** (vmsingle or vmselect) — queried by KEDA for autoscaling
/// - **victoria-metrics-operator** — webhook called by kube-apiserver
///
/// In single-node mode, write and read targets are the same workload (vmsingle),
/// so they are merged into a single LMM with both callers.
pub fn generate_monitoring_mesh_members(ha: bool) -> Vec<LatticeMeshMember> {
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        CallerRef, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
        PeerAuth, ServiceRef,
    };

    use super::keda::{KEDA_NAMESPACE, VM_READ_TARGET_LMM_NAME};

    let mut members = Vec::new();

    let vm_instance_labels = |component: &str| -> BTreeMap<String, String> {
        BTreeMap::from([
            ("app.kubernetes.io/name".to_string(), component.to_string()),
            (
                "app.kubernetes.io/instance".to_string(),
                VMCLUSTER_NAME.to_string(),
            ),
        ])
    };

    let vmagent_caller = CallerRef {
        name: "vm-write-target".to_string(),
        namespace: Some(MONITORING_NAMESPACE.to_string()),
    };

    let keda_caller = CallerRef {
        name: "keda-operator".to_string(),
        namespace: Some(KEDA_NAMESPACE.to_string()),
    };

    if ha {
        // HA mode: separate write (vminsert) and read (vmselect) targets

        // VM write target — vminsert
        let mut write = LatticeMeshMember::new(
            "vm-write-target",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vminsert")),
                ports: vec![MeshMemberPort {
                    port: VMINSERT_PORT,
                    name: "write".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        );
        write.metadata.namespace = Some(MONITORING_NAMESPACE.to_string());
        members.push(write);

        // VM read target — vmselect
        let mut read = LatticeMeshMember::new(
            VM_READ_TARGET_LMM_NAME,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmselect")),
                ports: vec![MeshMemberPort {
                    port: VMSELECT_PORT,
                    name: "read".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![keda_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        );
        read.metadata.namespace = Some(MONITORING_NAMESPACE.to_string());
        members.push(read);
    } else {
        // Single-node mode: vmsingle serves both write and read
        // Merge into one LMM with both callers and both ports
        let mut single = LatticeMeshMember::new(
            VM_READ_TARGET_LMM_NAME,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmsingle")),
                ports: vec![MeshMemberPort {
                    port: VMSINGLE_PORT,
                    name: "http".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller, keda_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
            },
        );
        single.metadata.namespace = Some(MONITORING_NAMESPACE.to_string());
        members.push(single);
    }

    // victoria-metrics-operator — webhook called by kube-apiserver
    let mut vm_operator = LatticeMeshMember::new(
        "victoria-metrics-operator",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "victoria-metrics-operator".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 9443,
                name: "webhook".to_string(),
                peer_auth: PeerAuth::Permissive,
            }],
            allowed_callers: vec![], // open to non-mesh callers (apiserver)
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    );
    vm_operator.metadata.namespace = Some(MONITORING_NAMESPACE.to_string());
    members.push(vm_operator);

    // vmagent — scrapes targets and writes to VM storage
    let mut vmagent = LatticeMeshMember::new(
        "vm-write-target",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "vmagent".to_string(),
            ), (
                "app.kubernetes.io/instance".to_string(),
                VMCLUSTER_NAME.to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 8429,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![{
                if ha {
                    ServiceRef::new(MONITORING_NAMESPACE, "vm-write-target")
                } else {
                    ServiceRef::new(MONITORING_NAMESPACE, VM_READ_TARGET_LMM_NAME)
                }
            }],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        },
    );
    vmagent.metadata.namespace = Some(MONITORING_NAMESPACE.to_string());
    // Use a distinct name so it doesn't collide with the write target LMM
    vmagent.metadata.name = Some("vmagent".to_string());
    members.push(vmagent);

    members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = victoria_metrics_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_namespace_is_correct() {
        let ns = namespace_yaml_ambient("monitoring");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: monitoring"));
        assert!(ns.contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn ha_manifests_are_embedded() {
        let manifests = generate_prometheus(true);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(manifests[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn single_manifests_are_embedded() {
        let manifests = generate_prometheus(false);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(manifests[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn query_helpers_return_correct_values() {
        assert_eq!(query_port(true), VMSELECT_PORT);
        assert_eq!(query_port(false), VMSINGLE_PORT);
        assert_eq!(query_path(true), VMSELECT_PATH);
        assert_eq!(query_path(false), VMSINGLE_PATH);
        assert!(query_url(true).contains("vmselect"));
        assert!(query_url(false).contains("vmsingle"));
    }

    #[test]
    fn monitoring_mesh_members_single_node() {
        use lattice_common::crd::PeerAuth;

        let members = generate_monitoring_mesh_members(false);
        // single-node: 1 merged vmsingle + 1 vm-operator + 1 vmagent = 3
        assert_eq!(members.len(), 3);

        // vmsingle (merged read+write target)
        let single = &members[0];
        assert_eq!(single.metadata.name.as_deref(), Some("vm-read-target"));
        assert_eq!(single.metadata.namespace.as_deref(), Some(MONITORING_NAMESPACE));
        assert_eq!(single.spec.ports[0].port, VMSINGLE_PORT);
        assert_eq!(single.spec.ports[0].peer_auth, PeerAuth::Strict);
        assert_eq!(single.spec.allowed_callers.len(), 2); // vmagent + keda
        assert!(single.spec.validate().is_ok());

        // vm-operator webhook
        let op = &members[1];
        assert_eq!(op.metadata.name.as_deref(), Some("victoria-metrics-operator"));
        assert_eq!(op.spec.ports[0].port, 9443);
        assert_eq!(op.spec.ports[0].peer_auth, PeerAuth::Permissive);
        assert!(op.spec.allowed_callers.is_empty());
        assert!(op.spec.validate().is_ok());

        // vmagent
        let agent = &members[2];
        assert_eq!(agent.metadata.name.as_deref(), Some("vmagent"));
        assert!(agent.spec.validate().is_ok());
    }

    #[test]
    fn monitoring_mesh_members_ha() {
        let members = generate_monitoring_mesh_members(true);
        // HA: 1 vminsert + 1 vmselect + 1 vm-operator + 1 vmagent = 4
        assert_eq!(members.len(), 4);

        let write = &members[0];
        assert_eq!(write.metadata.name.as_deref(), Some("vm-write-target"));
        assert_eq!(write.spec.ports[0].port, VMINSERT_PORT);

        let read = &members[1];
        assert_eq!(read.metadata.name.as_deref(), Some("vm-read-target"));
        assert_eq!(read.spec.ports[0].port, VMSELECT_PORT);

        let op = &members[2];
        assert_eq!(op.metadata.name.as_deref(), Some("victoria-metrics-operator"));

        let agent = &members[3];
        assert_eq!(agent.metadata.name.as_deref(), Some("vmagent"));

        for m in &members {
            assert!(m.spec.validate().is_ok());
        }
    }
}
