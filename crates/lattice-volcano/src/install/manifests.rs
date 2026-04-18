//! Volcano helm chart manifests (scheduler + controllers + admission + vGPU
//! device plugin) plus topology-discovery ConfigMap generation + mesh
//! enrollment.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_crd::crd::{
    LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
    NetworkTopologyConfig, PeerAuth, ProviderType, TopologyDiscoverySpec,
};

static VOLCANO_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml_ambient("volcano-system")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/volcano.yaml"
    ))));

    // Volcano vGPU device plugin (runs alongside Volcano for GPU scheduling)
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/volcano-vgpu-device-plugin.yaml"
    ))));

    manifests
});

/// Volcano chart version pinned at build time from `versions.toml`.
pub fn volcano_version() -> &'static str {
    env!("VOLCANO_VERSION")
}

/// Pre-rendered Volcano helm chart manifests (including the vGPU device plugin
/// DaemonSet).
pub fn generate_volcano() -> &'static [String] {
    &VOLCANO_MANIFESTS
}

/// Generate a topology discovery ConfigMap for the Volcano controller.
///
/// Returns `None` for manual mode (discovery is `None` — user creates
/// `HyperNode` CRDs directly). For UFM or Label discovery, renders a ConfigMap
/// in `volcano-system` that the `network-topology-aware` plugin reads.
pub fn generate_topology_discovery_configmap(
    config: &NetworkTopologyConfig,
    provider: ProviderType,
) -> Option<String> {
    let discovery = config.discovery.as_ref()?;

    let config_yaml = match discovery {
        TopologyDiscoverySpec::Ufm(ufm) => {
            let interval = ufm.interval.as_deref().unwrap_or("10m");
            let skip_verify = if ufm.insecure_skip_verify {
                "\n    insecureSkipVerify: true"
            } else {
                ""
            };
            format!(
                r#"source: ufm
ufm:
    endpoint: "{}"
    credentialSecretRef: "{}"{}
    interval: "{}""#,
                ufm.endpoint, ufm.credential_secret_ref, skip_verify, interval
            )
        }
        TopologyDiscoverySpec::Label(label) => {
            let interval = label.interval.as_deref().unwrap_or("10m");
            let tiers = if label.tiers.is_empty() {
                auto_label_tiers(provider)
            } else {
                label
                    .tiers
                    .iter()
                    .map(|t| format!("    - nodeLabel: \"{}\"", t.node_label))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                r#"source: label
label:
    interval: "{}"
    tiers:
{}"#,
                interval, tiers
            )
        }
        _ => return None,
    };

    Some(format!(
        r#"---
apiVersion: v1
kind: ConfigMap
metadata:
  name: volcano-topology-discovery
  namespace: volcano-system
data:
  config.yaml: |
    {}"#,
        config_yaml.replace('\n', "\n    ")
    ))
}

/// Auto-configure label tiers from the cloud provider.
///
/// Cloud providers (AWS, GCP, Azure, OpenStack) get zone + hostname tiers.
/// Local providers (Docker, Proxmox) get hostname only. No region tier —
/// K8s clusters are almost never multi-region.
fn auto_label_tiers(provider: ProviderType) -> String {
    match provider {
        ProviderType::Aws | ProviderType::Gcp | ProviderType::Azure | ProviderType::OpenStack => [
            "    - nodeLabel: \"topology.kubernetes.io/zone\"",
            "    - nodeLabel: \"kubernetes.io/hostname\"",
        ]
        .join("\n"),
        _ => "    - nodeLabel: \"kubernetes.io/hostname\"".to_string(),
    }
}

/// LatticeMeshMembers for Volcano components.
///
/// - `volcano-admission`: admission webhooks called by kube-apiserver
///   (port 8443, Webhook mTLS).
/// - `volcano-controllers`: reconciliation controller, egress-only.
/// - `volcano-scheduler`: batch scheduler, egress-only.
pub fn generate_volcano_mesh_members() -> Vec<LatticeMeshMember> {
    vec![
        mesh_member(
            "volcano-admission",
            "volcano-system",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "volcano-admission".to_string(),
                )])),
                ports: vec![MeshMemberPort {
                    port: 8443,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                }],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: Some("volcano-admission".to_string()),
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ),
        mesh_member(
            "volcano-controllers",
            "volcano-system",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "volcano-controllers".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: Some("volcano-controllers".to_string()),
                depends_all: false,
                ambient: true,
                advertise: None,
            },
        ),
        mesh_member(
            "volcano-scheduler",
            "volcano-system",
            LatticeMeshMemberSpec {
                target: MeshMemberTarget::Selector(BTreeMap::from([(
                    "app".to_string(),
                    "volcano-scheduler".to_string(),
                )])),
                ports: vec![],
                allowed_callers: vec![],
                dependencies: vec![],
                egress: vec![kube_apiserver_egress()],
                allow_peer_traffic: false,
                ingress: None,
                service_account: Some("volcano-scheduler".to_string()),
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
        assert!(!volcano_version().is_empty());
    }

    #[test]
    fn manifests_are_embedded() {
        let m = generate_volcano();
        assert!(!m.is_empty());
        assert!(m[0].contains("volcano-system"));
        assert!(m[0].contains("istio.io/dataplane-mode: ambient"));
    }

    #[test]
    fn webhook_excludes_lattice_system() {
        let m = generate_volcano();
        for wh in m
            .iter()
            .filter(|doc| doc.contains("MutatingWebhookConfiguration"))
        {
            assert!(
                wh.contains("lattice-system"),
                "MutatingWebhookConfiguration should exclude lattice-system"
            );
        }
    }

    #[test]
    fn mesh_members_have_expected_shape() {
        let members = generate_volcano_mesh_members();
        assert_eq!(members.len(), 3);

        let adm = members
            .iter()
            .find(|m| m.metadata.name.as_deref() == Some("volcano-admission"))
            .expect("admission member");
        assert_eq!(adm.spec.ports[0].port, 8443);
        assert_eq!(adm.spec.ports[0].peer_auth, PeerAuth::Webhook);
    }
}
