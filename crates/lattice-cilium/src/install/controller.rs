//! CiliumInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the `cilium` agent DaemonSet reporting all pods ready.
//! Cilium is the L3/L4 substrate — if the agent DS isn't healthy, pod
//! networking doesn't work.

use std::sync::Arc;
use std::time::Duration;

use kube::api::Api;
use kube::runtime::controller::Action;
use kube::Client;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{
    ApiServerEndpoint, ControllerContext, ReconcileError, REQUEUE_CRD_NOT_FOUND_SECS,
};
use lattice_crd::crd::{CiliumInstall, LatticeCluster};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cilium-install-controller";
const NAMESPACE: &str = "kube-system";
const DAEMONSET: &str = "cilium";
/// Cilium rolls per-node, each pod loading eBPF + reconciling endpoints.
/// Generous budget for slower nodes / large clusters.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

pub async fn reconcile(
    install: Arc<CiliumInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let local_cluster = load_local_cluster(&ctx.client, &ctx.config).await?;
    // Single source: read the canonical apiserver endpoint off the local
    // LatticeCluster's status. The cluster controller's
    // `refresh_status_endpoint` writes it from the CAPI Cluster CR (or
    // local kubeadm-config for the management kind cluster) every
    // reconcile. If it isn't populated yet, requeue rather than render
    // Cilium against a guessed value — picking a transient node IP would
    // break agent re-bootstrap on any CP node restart.
    let Some(endpoint) = local_cluster
        .status
        .as_ref()
        .and_then(|s| s.endpoint.as_deref())
    else {
        return Ok(Action::requeue(Duration::from_secs(
            REQUEUE_CRD_NOT_FOUND_SECS,
        )));
    };
    let endpoint = ApiServerEndpoint::parse(endpoint).map_err(|e| {
        ReconcileError::Validation(format!(
            "LatticeCluster.status.endpoint {endpoint:?} is not a valid host:port: {e}"
        ))
    })?;
    // Pod CIDR comes from the local LatticeCluster CR — same value
    // `lattice-capi` writes into the CAPI Cluster's
    // `clusterNetwork.pods.cidrBlocks`. Cilium's
    // `ipv4NativeRoutingCIDR` MUST match exactly; wider CIDRs leak
    // pod IPs out of the cluster.
    let pod_cidr = local_cluster
        .spec
        .provider
        .kubernetes
        .cluster_network
        .pod_cidr
        .clone();
    let mut manifests: Vec<String> = manifests::render_cilium_manifests(&endpoint, &pod_cidr);
    for policy in [
        serde_json::to_string_pretty(&manifests::generate_ztunnel_allowlist()),
        serde_json::to_string_pretty(&manifests::generate_allow_node_ingress()),
        serde_json::to_string_pretty(&manifests::generate_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_mesh_proxy_egress_policy()),
        serde_json::to_string_pretty(&manifests::generate_eastwest_gateway_policy()),
    ] {
        manifests
            .push(policy.map_err(|e| {
                ReconcileError::Validation(format!("serialize Cilium policy: {e}"))
            })?);
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "CiliumInstall",
        manifests,
        readiness: ReadinessCheck::DaemonSet {
            name: DAEMONSET,
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
        webhook_service: None,
    })
    .await
}

/// Read the local `LatticeCluster` CR that describes this cluster.
///
/// Looks up by `LATTICE_CLUSTER_NAME` rather than `Api::all().next()`.
/// A cell hosts sibling LatticeCluster CRs for every child it tracks;
/// `.list().next()` picks whichever sorts first, which on at least one
/// edge cell rendered Cilium with the *backend* cluster's
/// `status.endpoint` (a 172.20.0.1 kind/Docker apiserver IP), breaking
/// worker-pod auth on the local apiserver.
///
/// The cilium reconciler needs both `status.endpoint` (canonical
/// apiserver address for `k8sServiceHost`) and
/// `spec.provider.kubernetes.cluster_network.pod_cidr` (which must
/// exactly match Cilium's `ipv4NativeRoutingCIDR`).
async fn load_local_cluster(
    client: &Client,
    config: &lattice_common::SharedConfig,
) -> Result<LatticeCluster, ReconcileError> {
    let cluster_name = config.cluster_name.as_deref().ok_or_else(|| {
        ReconcileError::Validation(
            "LATTICE_CLUSTER_NAME must be set so Cilium installs against the right cluster"
                .to_string(),
        )
    })?;
    let api: Api<LatticeCluster> = Api::all(client.clone());
    api.get_opt(cluster_name)
        .await
        .map_err(|e| {
            ReconcileError::Validation(format!("get LatticeCluster '{cluster_name}': {e}"))
        })?
        .ok_or_else(|| {
            ReconcileError::Validation(format!(
                "LatticeCluster '{cluster_name}' not found; Cilium install cannot proceed"
            ))
        })
}
