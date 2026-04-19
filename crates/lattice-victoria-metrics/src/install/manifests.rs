//! VictoriaMetrics K8s Stack helm chart + mesh enrollment manifests.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_common::{
    LABEL_NAME, MONITORING_NAMESPACE, OPERATOR_NAME, VMAGENT_SA_NAME, VM_READ_TARGET_LMM_NAME,
};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth,
    ServiceRef,
};

/// Namespace KEDA lands in. Referenced here so the vmselect read-path LMM
/// allows KEDA as a caller; stays duplicated with `lattice-keda::install::NAMESPACE`
/// because neither install crate should depend on the other.
const KEDA_NAMESPACE: &str = "keda";

/// `fullnameOverride` used when rendering the chart — every downstream consumer
/// references services by this stable prefix.
pub const VMCLUSTER_NAME: &str = "lattice-metrics";

/// VMSelect query port (Prometheus-compatible read path, HA mode).
pub const VMSELECT_PORT: u16 = 8481;
/// VMSelect URL path prefix (HA mode).
pub const VMSELECT_PATH: &str = "/select/0/prometheus";
/// VMInsert write port (HA mode).
pub const VMINSERT_PORT: u16 = 8480;
/// VMSingle query port (single-node mode).
pub const VMSINGLE_PORT: u16 = 8428;
/// VMSingle URL path prefix (single-node mode).
pub const VMSINGLE_PATH: &str = "/prometheus";

/// VMSelect service URL (HA mode).
pub fn vmselect_url() -> String {
    format!(
        "http://vmselect-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// VMSingle service URL (single-node mode).
pub fn vmsingle_url() -> String {
    format!(
        "http://vmsingle-{}.{}.svc",
        VMCLUSTER_NAME, MONITORING_NAMESPACE
    )
}

/// Prometheus-compatible query port for the given HA mode.
pub fn query_port(ha: bool) -> u16 {
    if ha {
        VMSELECT_PORT
    } else {
        VMSINGLE_PORT
    }
}

/// Prometheus-compatible query path for the given HA mode.
pub fn query_path(ha: bool) -> &'static str {
    if ha {
        VMSELECT_PATH
    } else {
        VMSINGLE_PATH
    }
}

/// Base URL for the Prometheus-compatible query API.
pub fn query_url(ha: bool) -> String {
    if ha {
        vmselect_url()
    } else {
        vmsingle_url()
    }
}

static HA_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-ha.yaml"
    ))));
    manifests
});

static SINGLE_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient(MONITORING_NAMESPACE)];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/victoria-metrics-single.yaml"
    ))));
    manifests
});

/// VictoriaMetrics K8s Stack chart version pinned at build time.
pub fn victoria_metrics_version() -> &'static str {
    env!("VICTORIA_METRICS_VERSION")
}

/// Pre-rendered VictoriaMetrics manifests. HA mode returns the VMCluster
/// variant; single-node returns VMSingle.
pub fn generate_victoria_metrics(ha: bool) -> &'static [String] {
    if ha {
        &HA_MANIFESTS
    } else {
        &SINGLE_MANIFESTS
    }
}

fn vm_instance_labels(component: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_NAME.to_string(), component.to_string()),
        (
            "app.kubernetes.io/instance".to_string(),
            VMCLUSTER_NAME.to_string(),
        ),
    ])
}

/// LatticeMeshMembers for monitoring components:
///
/// - **VM write target** (vmsingle or vminsert) — receives scraped metrics from vmagent
/// - **VM read target** (vmsingle or vmselect) — queried by KEDA for autoscaling
/// - **vmagent** — scrapes targets and pushes to VM storage
/// - **victoria-metrics-operator** — webhook called by kube-apiserver
/// - **vm-kube-state-metrics** — metrics scraped by vmagent
///
/// In single-node mode the write and read targets are the same workload, so
/// they merge into one LMM with both caller groups.
pub fn generate_monitoring_mesh_members(ha: bool) -> Vec<LatticeMeshMember> {
    let mut members = Vec::new();

    let vmagent_caller = ServiceRef::new(MONITORING_NAMESPACE, "vmagent");
    let keda_caller = ServiceRef::new(KEDA_NAMESPACE, "keda-operator");
    let operator_caller = ServiceRef::new(LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME);

    if ha {
        members.push(mesh_member(
            "vm-write-target",
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vminsert")),
                ports: vec![MeshMemberPort {
                    port: VMINSERT_PORT,
                    service_port: None,
                    name: "write".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller.clone()],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ));

        members.push(mesh_member(
            VM_READ_TARGET_LMM_NAME,
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmselect")),
                ports: vec![MeshMemberPort {
                    port: VMSELECT_PORT,
                    service_port: None,
                    name: "read".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![keda_caller, operator_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ));
    } else {
        members.push(mesh_member(
            VM_READ_TARGET_LMM_NAME,
            MONITORING_NAMESPACE,
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(vm_instance_labels("vmsingle")),
                ports: vec![MeshMemberPort {
                    port: VMSINGLE_PORT,
                    service_port: None,
                    name: "http".to_string(),
                    peer_auth: PeerAuth::Strict,
                }],
                allowed_callers: vec![vmagent_caller.clone(), keda_caller, operator_caller],
                dependencies: vec![],
                egress: vec![],
                allow_peer_traffic: false,
                ingress: None,
                service_account: None,
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ));
    }

    let write_dep = if ha {
        ServiceRef::new(MONITORING_NAMESPACE, "vm-write-target")
    } else {
        ServiceRef::new(MONITORING_NAMESPACE, VM_READ_TARGET_LMM_NAME)
    };
    members.push(mesh_member(
        "vmagent",
        MONITORING_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(vm_instance_labels("vmagent")),
            ports: vec![MeshMemberPort {
                port: 8429,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![write_dep],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some(VMAGENT_SA_NAME.to_string()),
            depends_all: true,
            ambient: true,
            advertise: None,
        },
    ));

    members.push(mesh_member(
        "victoria-metrics-operator",
        MONITORING_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "victoria-metrics-operator".to_string(),
            )])),
            ports: vec![
                MeshMemberPort {
                    port: 9443,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: 8080,
                    service_port: None,
                    name: "metrics".to_string(),
                    peer_auth: PeerAuth::Strict,
                },
            ],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("vm-victoria-metrics-operator".to_string()),
            depends_all: false,
            ambient: true,
            advertise: None,
        },
    ));

    members.push(mesh_member(
        "vm-kube-state-metrics",
        MONITORING_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "kube-state-metrics".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "metrics".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("vm-kube-state-metrics".to_string()),
            depends_all: false,
            ambient: true,
            advertise: None,
        },
    ));

    members
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!victoria_metrics_version().is_empty());
    }

    #[test]
    fn ha_manifests_are_embedded() {
        let manifests = generate_victoria_metrics(true);
        assert!(!manifests.is_empty());
        assert!(manifests[0].contains("kind: Namespace"));
        assert!(manifests[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn single_manifests_are_embedded() {
        let manifests = generate_victoria_metrics(false);
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
        let members = generate_monitoring_mesh_members(false);
        assert_eq!(members.len(), 4);
        let single = &members[0];
        assert_eq!(
            single.metadata.name.as_deref(),
            Some(VM_READ_TARGET_LMM_NAME)
        );
        assert_eq!(single.spec.ports[0].port, VMSINGLE_PORT);
        assert_eq!(single.spec.allowed_callers.len(), 3);
    }

    #[test]
    fn monitoring_mesh_members_ha() {
        let members = generate_monitoring_mesh_members(true);
        assert_eq!(members.len(), 5);
        assert_eq!(members[0].metadata.name.as_deref(), Some("vm-write-target"));
        assert_eq!(
            members[1].metadata.name.as_deref(),
            Some(VM_READ_TARGET_LMM_NAME)
        );
        assert_eq!(members[2].metadata.name.as_deref(), Some("vmagent"));
    }
}
