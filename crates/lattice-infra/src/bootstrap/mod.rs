//! Bootstrap manifests that don't belong to a per-dependency install crate.
//!
//! Three things live here:
//! - **Gateway API CRDs** — copied from an upstream bundle, applied whenever
//!   service mesh is enabled.
//! - **operator-mesh-enrollment** — a `LatticeMeshMember` that tells the mesh
//!   how to reach lattice-operator's various ports (bootstrap webhook,
//!   agent gRPC, local-secrets webhook, …). Not a dependency install, just
//!   mesh metadata for our own Deployment.
//! - **cluster-access / admin-access Cedar policies** — operator-scoped grants
//!   that pair with the mesh enrollment.
//!
//! Every per-dependency install (Istio, Cilium, KEDA, …) has its own crate
//! with its own CRD + controller; this module does not know about them.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_common::{
    DEFAULT_AUTH_PROXY_PORT, DEFAULT_WEBHOOK_PORT, LOCAL_SECRETS_PORT, MONITORING_NAMESPACE,
    OPERATOR_NAME,
};
use lattice_core::{
    DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT, DEFAULT_PROXY_PORT, LATTICE_SYSTEM_NAMESPACE,
};
use lattice_crd::crd::{
    CedarPolicy, CedarPolicySpec, EgressRule, EgressTarget, LatticeMeshMember,
    LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget, PeerAuth, ServiceRef,
};

/// Assemble every manifest this crate is responsible for.
///
/// On bootstrap / mesh-disabled clusters (`skip_service_mesh = true`) the
/// result is empty — the bootstrap clusters have no mesh, and management
/// clusters with `services: false` run inert without mesh policies.
///
/// Serialization can only fail for the Cedar policy; surfaced as the error.
pub fn bootstrap_manifests(skip_service_mesh: bool) -> Result<Vec<String>, serde_json::Error> {
    if skip_service_mesh {
        return Ok(Vec::new());
    }

    let mut manifests: Vec<String> = generate_gateway_api_crds().to_vec();
    manifests.push(namespace_yaml_ambient(LATTICE_SYSTEM_NAMESPACE));
    manifests.push(serde_json::to_string_pretty(&generate_operator_mesh_member())?);
    manifests.push(serde_json::to_string_pretty(
        &generate_cluster_access_cedar_policy(),
    )?);
    Ok(manifests)
}

/// Read remote network names from LatticeClusterRoutes CRDs.
///
/// Returns `Some(names)` on success, `None` if CRDs can't be listed (e.g.
/// during startup before the CRD is registered). Callers that get `None`
/// should leave `remote_networks` unset so SSA preserves existing
/// `meshNetworks` in the ConfigMap.
pub async fn discover_remote_networks(client: &kube::Client) -> Option<Vec<String>> {
    use lattice_crd::crd::LatticeClusterRoutes;

    let routes_api: kube::Api<LatticeClusterRoutes> = kube::Api::all(client.clone());
    match routes_api.list(&kube::api::ListParams::default()).await {
        Ok(routes_list) => Some(
            routes_list
                .items
                .iter()
                .filter(|r| !r.spec.routes.is_empty())
                .filter_map(|r| r.metadata.name.clone())
                .collect(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "failed to list LatticeClusterRoutes, preserving existing meshNetworks");
            None
        }
    }
}

static GATEWAY_API_CRDS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gateway-api-crds.yaml"
    )))
});

/// Pre-rendered Gateway API CRDs embedded at build time.
pub fn generate_gateway_api_crds() -> &'static [String] {
    &GATEWAY_API_CRDS
}

/// LatticeMeshMember enrolling lattice-operator itself.
///
/// The operator is an ambient-mesh member so ESO (also ambient) can reach the
/// local-secrets webhook over HBONE/mTLS. Ports 8443 (bootstrap webhook) and
/// 50051 (agent gRPC) use `PeerAuth::Webhook` because their callers (kubeadm,
/// unprovisioned agents) lack mesh identity.
pub fn generate_operator_mesh_member() -> LatticeMeshMember {
    mesh_member(
        OPERATOR_NAME,
        LATTICE_SYSTEM_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                OPERATOR_NAME.to_string(),
            )])),
            ports: vec![
                MeshMemberPort {
                    port: DEFAULT_WEBHOOK_PORT,
                    service_port: None,
                    name: "validation-webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_BOOTSTRAP_PORT,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_GRPC_PORT,
                    service_port: None,
                    name: "grpc".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_PROXY_PORT,
                    service_port: None,
                    name: "proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_AUTH_PROXY_PORT,
                    service_port: None,
                    name: "auth-proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: LOCAL_SECRETS_PORT,
                    service_port: None,
                    name: "local-secrets".to_string(),
                    peer_auth: PeerAuth::Strict,
                },
            ],
            allowed_callers: vec![ServiceRef::new("external-secrets", "external-secrets")],
            dependencies: vec![ServiceRef::new(MONITORING_NAMESPACE, "vm-read-target")],
            egress: vec![
                kube_apiserver_egress(),
                // Agent connects outbound to parent cell's gRPC and bootstrap ports
                EgressRule::tcp(
                    EgressTarget::Entity("world".to_string()),
                    vec![DEFAULT_GRPC_PORT, DEFAULT_BOOTSTRAP_PORT],
                ),
                // Helm pulls OCI charts from container registries (HTTPS)
                EgressRule::tcp(EgressTarget::Entity("world".to_string()), vec![443]),
            ],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true,
            advertise: None,
        },
    )
}

/// Cedar grant that lets lattice-operator's service account talk to the
/// parent cell's auth proxy for multi-cluster routing.
pub fn generate_cluster_access_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "proxy-cluster-access",
        CedarPolicySpec {
            description: Some("Cluster access for lattice-operator peer route proxy".to_string()),
            policies: r#"permit(
    principal == Lattice::User::"system:serviceaccount:lattice-system:lattice-operator",
    action == Lattice::Action::"AccessCluster",
    resource
);"#
            .to_string(),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Cedar grant that gives the lattice-admin ServiceAccount full access.
/// Applied by `lattice install`; not part of `bootstrap_manifests`.
pub fn generate_admin_access_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "lattice-admin-access",
        CedarPolicySpec {
            description: Some("Full admin access for lattice-admin SA".to_string()),
            policies: r#"permit(
    principal == Lattice::User::"system:serviceaccount:lattice-system:lattice-admin",
    action,
    resource
);"#
            .to_string(),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_api_crds_embedded() {
        let crds = generate_gateway_api_crds();
        assert!(!crds.is_empty());
        assert!(crds.iter().any(|c| c.contains("CustomResourceDefinition")));
    }

    #[test]
    fn bootstrap_manifests_skip_returns_empty() {
        let m = bootstrap_manifests(true).expect("skip path");
        assert!(m.is_empty());
    }

    #[test]
    fn bootstrap_manifests_mesh_includes_expected_items() {
        let m = bootstrap_manifests(false).expect("mesh path");
        // Gateway API CRDs (many) + ambient namespace + operator LMM + Cedar policy.
        assert!(m.len() > 3);
        assert!(m.iter().any(|d| d.contains("CustomResourceDefinition")));
        assert!(m
            .iter()
            .any(|d| d.contains("istio.io/dataplane-mode: ambient")));
        assert!(m.iter().any(|d| d.contains("LatticeMeshMember")
            && d.contains("\"name\": \"lattice-operator\"")));
        assert!(m.iter().any(|d| d.contains("CedarPolicy")
            && d.contains("\"name\": \"proxy-cluster-access\"")));
    }

    #[test]
    fn operator_mesh_member_generated() {
        let member = generate_operator_mesh_member();
        assert_eq!(member.metadata.name.as_deref(), Some("lattice-operator"));
        assert_eq!(
            member.metadata.namespace.as_deref(),
            Some(LATTICE_SYSTEM_NAMESPACE)
        );
        assert!(member.spec.validate().is_ok());
        assert!(member.spec.ambient);

        // 6 ports: validation-webhook, webhook, grpc, proxy, auth-proxy, local-secrets.
        assert_eq!(member.spec.ports.len(), 6);

        let webhook = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "webhook")
            .expect("webhook port");
        assert_eq!(webhook.port, DEFAULT_BOOTSTRAP_PORT);
        assert_eq!(webhook.peer_auth, PeerAuth::Webhook);

        let grpc = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "grpc")
            .expect("grpc port");
        assert_eq!(grpc.port, DEFAULT_GRPC_PORT);

        let secrets = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "local-secrets")
            .expect("local-secrets port");
        assert_eq!(secrets.port, LOCAL_SECRETS_PORT);
        assert_eq!(secrets.peer_auth, PeerAuth::Strict);

        assert_eq!(member.spec.allowed_callers.len(), 1);
        assert_eq!(member.spec.allowed_callers[0].name, "external-secrets");
    }
}
