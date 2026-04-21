//! Istio manifest assembly — charts, template substitution, cacerts Secret,
//! east-west gateway, mesh-wide policies.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use base64::Engine;

use lattice_common::kube_utils::{split_yaml_documents, ObjectMeta};
use lattice_common::mesh::{namespace_yaml_with_network, HBONE_PORT};
use lattice_common::policy::istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    MtlsConfig, OperationSpec, PeerAuthentication, PeerAuthenticationSpec, TargetRef,
    WorkloadSelector,
};
use lattice_common::OPERATOR_NAME;
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_infra::pki::{CertificateAuthority, PkiError};

/// Static Istio manifests (base CRDs + CNI) that don't need per-cluster values.
static ISTIO_STATIC_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = Vec::new();
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/istio-base.yaml"
    ))));
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/istio-cni.yaml"
    ))));
    manifests
});

static ISTIOD_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/istiod.yaml"));
static ZTUNNEL_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/ztunnel.yaml"));

/// Istio chart version pinned at build time.
pub fn istio_version() -> &'static str {
    env!("ISTIO_VERSION")
}

/// Render istiod and ztunnel by substituting the per-cluster placeholders
/// (cluster name, trust domain, meshNetworks).
pub fn render_istio_manifests(
    cluster_name: &str,
    trust_domain: &str,
    remote_networks: &[String],
) -> Vec<String> {
    let mut all = ISTIO_STATIC_MANIFESTS.clone();

    let mut istiod_yaml = ISTIOD_TEMPLATE
        .replace("__LATTICE_CLUSTER_NAME__", cluster_name)
        .replace("__LATTICE_TRUST_DOMAIN__", trust_domain);
    istiod_yaml = istiod_yaml.replace(
        "__LATTICE_MESH_NETWORKS__: __LATTICE_MESH_NETWORKS__",
        &build_mesh_networks_yaml(remote_networks),
    );
    all.extend(split_yaml_documents(&istiod_yaml));

    let ztunnel_yaml = ZTUNNEL_TEMPLATE.replace("__LATTICE_CLUSTER_NAME__", cluster_name);
    all.extend(split_yaml_documents(&ztunnel_yaml));

    all
}

/// Namespace YAML for `istio-system` with the multi-cluster network label.
pub fn istio_namespace_yaml(cluster_name: &str) -> String {
    namespace_yaml_with_network("istio-system", cluster_name)
}

/// Build the YAML content for istiod's `meshNetworks` block. Each remote
/// cluster maps to its east-west gateway via `registryServiceName` so istiod
/// auto-discovers the gateway's external IP from that cluster's registry.
fn build_mesh_networks_yaml(remote_networks: &[String]) -> String {
    if remote_networks.is_empty() {
        return "{}".to_string();
    }

    let indent = "      ";
    let mut lines = Vec::new();
    for (i, name) in remote_networks.iter().enumerate() {
        if i == 0 {
            lines.push(format!("{}:", name));
        } else {
            lines.push(format!("{}{}:", indent, name));
        }
        lines.push(format!("{}  endpoints:", indent));
        lines.push(format!("{}  - fromRegistry: {}", indent, name));
        lines.push(format!("{}  gateways:", indent));
        lines.push(format!(
            "{}  - registryServiceName: istio-eastwestgateway.istio-system",
            indent
        ));
        lines.push(format!("{}    port: 15008", indent));
    }
    lines.join("\n")
}

/// East-west Gateway resource: HBONE on port 15008, `istio-east-west` class,
/// terminates ISTIO_MUTUAL TLS.
pub fn generate_eastwest_gateway(cluster_name: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {
            "name": "istio-eastwestgateway",
            "namespace": "istio-system",
            "labels": {
                "topology.istio.io/network": cluster_name,
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "spec": {
            "gatewayClassName": "istio-east-west",
            "listeners": [{
                "name": "mesh",
                "port": HBONE_PORT,
                "protocol": "HBONE",
                "tls": {
                    "mode": "Terminate",
                    "options": {
                        "gateway.istio.io/tls-terminate-mode": "ISTIO_MUTUAL"
                    }
                }
            }]
        }
    }))
    .expect("serialize eastwest gateway")
}

/// `cacerts` Secret for Istio's intermediate CA.
///
/// Istio expects four PEM files in a `cacerts` Secret in `istio-system`:
/// `ca-cert.pem` (per-cluster intermediate), `ca-key.pem`, `root-cert.pem`
/// (shared root), `cert-chain.pem` (intermediate + root).
pub fn generate_cacerts_manifest(
    root_ca: &CertificateAuthority,
    cluster_name: &str,
) -> Result<String, PkiError> {
    let intermediate = root_ca.generate_istio_intermediate_ca(cluster_name)?;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());

    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "cacerts",
            "namespace": "istio-system",
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "data": {
            "ca-cert.pem": b64(&intermediate.ca_cert_pem),
            "ca-key.pem": b64(&intermediate.ca_key_pem),
            "root-cert.pem": b64(&intermediate.root_cert_pem),
            "cert-chain.pem": b64(&intermediate.cert_chain_pem)
        }
    });

    Ok(serde_json::to_string_pretty(&secret).expect("serialize cacerts"))
}

/// Mesh-wide PeerAuthentication enforcing STRICT mTLS.
pub fn generate_peer_authentication() -> PeerAuthentication {
    PeerAuthentication::new(
        ObjectMeta::new("default", "istio-system"),
        PeerAuthenticationSpec {
            selector: None,
            mtls: MtlsConfig {
                mode: "STRICT".to_string(),
            },
            port_level_mtls: None,
        },
    )
}

/// Mesh-wide default-deny AuthorizationPolicy. No rules, no action → deny all.
pub fn generate_default_deny() -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        ObjectMeta::new("mesh-default-deny", "istio-system"),
        AuthorizationPolicySpec {
            target_refs: vec![],
            selector: None,
            action: String::new(),
            rules: vec![],
        },
    )
}

/// Waypoint-class default-deny. Attached to the `istio-waypoint` GatewayClass
/// so default-deny is enforced AT the waypoint, not just at ztunnel. Without
/// this, once waypoint→target is allowed, the waypoint becomes permissive to
/// all sources (see istio/istio#54696).
pub fn generate_waypoint_default_deny() -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        ObjectMeta::new("waypoint-default-deny", "istio-system"),
        AuthorizationPolicySpec {
            target_refs: vec![TargetRef {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "GatewayClass".to_string(),
                name: "istio-waypoint".to_string(),
            }],
            selector: None,
            action: String::new(),
            rules: vec![],
        },
    )
}

/// East-west gateway ALLOW policy for cross-cluster HBONE forwarding.
///
/// mesh-default-deny applies to the gateway envoy since it's in the mesh; this
/// re-opens it. Rules are allow-all because after HBONE termination the
/// destination port is the inner service port, not 15008 — port filtering
/// doesn't work here, mTLS identity is the enforcement layer.
pub fn generate_eastwest_gateway_allow() -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        ObjectMeta::new("eastwest-gateway-allow", "istio-system"),
        AuthorizationPolicySpec {
            target_refs: vec![TargetRef {
                group: "gateway.networking.k8s.io".to_string(),
                kind: "Gateway".to_string(),
                name: "istio-eastwestgateway".to_string(),
            }],
            selector: None,
            action: "ALLOW".to_string(),
            rules: vec![AuthorizationRule {
                from: vec![],
                to: vec![],
            }],
        },
    )
}

/// Operator-allow AuthorizationPolicy.
///
/// The operator accepts connections from:
/// - workload-cluster bootstrap (kubeadm postKubeadmCommands → webhook :8443)
/// - workload-cluster agents (gRPC :50051)
///
/// These come from outside the mesh (bootstrap nodes have no SPIFFE identity;
/// agent gRPC uses Lattice's own PKI, not Istio mTLS). Restricting `from`
/// principals would break bootstrap. Authentication is handled at the
/// application layer (bootstrap token, Lattice-issued client certs).
pub fn generate_operator_allow_policy() -> AuthorizationPolicy {
    AuthorizationPolicy::new(
        ObjectMeta::new("lattice-operator-allow", LATTICE_SYSTEM_NAMESPACE),
        AuthorizationPolicySpec {
            target_refs: vec![],
            selector: Some(WorkloadSelector {
                match_labels: BTreeMap::from([("app".to_string(), OPERATOR_NAME.to_string())]),
            }),
            action: "ALLOW".to_string(),
            rules: vec![AuthorizationRule {
                from: vec![],
                to: vec![AuthorizationOperation {
                    operation: OperationSpec {
                        ports: vec![
                            "8443".to_string(),
                            "50051".to_string(),
                            "8081".to_string(),
                            "8082".to_string(),
                            "8787".to_string(),
                        ],
                        hosts: vec![],
                    },
                }],
            }],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!istio_version().is_empty());
    }

    #[test]
    fn static_manifests_contain_crd_and_cni() {
        let render = render_istio_manifests("c1", "lattice.test", &[]);
        assert!(render
            .iter()
            .any(|d| d.contains("CustomResourceDefinition")));
        assert!(render.iter().any(|d| d.contains("name: istio-cni")));
    }

    #[test]
    fn istiod_placeholders_substituted() {
        let render = render_istio_manifests("my-cluster", "lattice.abc", &[]);
        let combined = render.join("\n");
        assert!(!combined.contains("__LATTICE_CLUSTER_NAME__"));
        assert!(!combined.contains("__LATTICE_TRUST_DOMAIN__"));
        assert!(combined.contains("my-cluster"));
        assert!(combined.contains("lattice.abc"));
    }

    #[test]
    fn peer_authentication_is_strict() {
        let pa = generate_peer_authentication();
        assert_eq!(pa.spec.mtls.mode, "STRICT");
    }

    #[test]
    fn default_deny_has_no_rules() {
        let p = generate_default_deny();
        assert!(p.spec.rules.is_empty());
        assert!(p.spec.action.is_empty());
    }

    #[test]
    fn eastwest_gateway_uses_hbone_port() {
        let manifest = generate_eastwest_gateway("c1");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(parsed["spec"]["listeners"][0]["port"], HBONE_PORT);
        assert_eq!(parsed["spec"]["gatewayClassName"], "istio-east-west");
    }

    #[test]
    fn operator_allow_policy_lists_all_ports() {
        let p = generate_operator_allow_policy();
        let ports: Vec<&str> = p
            .spec
            .rules
            .iter()
            .flat_map(|r| r.to.iter())
            .flat_map(|t| t.operation.ports.iter())
            .map(|s| s.as_str())
            .collect();
        for port in ["8443", "50051", "8081", "8082", "8787"] {
            assert!(ports.contains(&port), "missing port {port}");
        }
    }
}
