//! Kubernetes Service and ServiceAccount construction utilities.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// Build the externally-reachable cell Service.
///
/// Exposes only the bootstrap, gRPC, and auth-proxy ports — the read-only
/// K8s API proxy lives on a separate in-cluster Service (see
/// [`build_cell_internal_service`]) so a misconfigured LoadBalancer can't
/// hand out anonymous read access to child K8s APIs.
///
/// `service_type` mirrors `LatticeCluster.spec.parent_config.service.type`:
/// `"LoadBalancer"`, `"NodePort"`, or `"ClusterIP"`. Cloud-specific LB
/// annotations are emitted only for LoadBalancer.
pub fn build_cell_service(
    bootstrap_port: u16,
    grpc_port: u16,
    service_type: &str,
    provider_type: &lattice_crd::crd::ProviderType,
) -> Service {
    let auth_proxy_port = crate::DEFAULT_AUTH_PROXY_PORT;

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lattice-operator".to_string());

    let annotations = if service_type == "LoadBalancer" {
        provider_type.load_balancer_annotations()
    } else {
        Default::default()
    };

    Service {
        metadata: kube::core::ObjectMeta {
            name: Some(crate::CELL_SERVICE_NAME.to_string()),
            namespace: Some(lattice_core::LATTICE_SYSTEM_NAMESPACE.to_string()),
            labels: Some(labels),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some(service_type.to_string()),
            selector: Some(leader_pod_selector()),
            ports: Some(vec![
                tcp_port("bootstrap", bootstrap_port),
                tcp_port("grpc", grpc_port),
                tcp_port("auth-proxy", auth_proxy_port),
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the in-cluster-only cell Service that exposes the read-only K8s
/// API proxy port.
///
/// Always ClusterIP — CAPI providers (cluster-api, basis-capi-provider,
/// etc.) all run in the management cluster and reach this Service via its
/// in-cluster DNS name. There is no legitimate caller from outside the
/// cluster, so the port must not appear on any LoadBalancer.
pub fn build_cell_internal_service(proxy_port: u16) -> Service {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "lattice-operator".to_string());

    Service {
        metadata: kube::core::ObjectMeta {
            name: Some(crate::CELL_INTERNAL_SERVICE_NAME.to_string()),
            namespace: Some(lattice_core::LATTICE_SYSTEM_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            selector: Some(leader_pod_selector()),
            ports: Some(vec![tcp_port("proxy", proxy_port)]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Both cell Services route only to the leader pod (selector pinned by the
/// leader-election label that only the elected pod carries).
fn leader_pod_selector() -> BTreeMap<String, String> {
    let mut selector = BTreeMap::new();
    selector.insert("app".to_string(), "lattice-operator".to_string());
    selector.insert(
        crate::leader_election::LEADER_LABEL_KEY.to_string(),
        crate::leader_election::LEADER_LABEL_VALUE.to_string(),
    );
    selector
}

fn tcp_port(name: &str, port: u16) -> ServicePort {
    ServicePort {
        name: Some(name.to_string()),
        port: port as i32,
        target_port: Some(IntOrString::Int(port as i32)),
        protocol: Some("TCP".to_string()),
        ..Default::default()
    }
}

/// Compile a minimal ServiceAccount JSON for server-side apply.
///
/// Produces a JSON value with `automountServiceAccountToken: false` and
/// standard metadata. Callers can extend the result (e.g., add ownerReferences).
pub fn compile_service_account(name: &str, namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "automountServiceAccountToken": false
    })
}
