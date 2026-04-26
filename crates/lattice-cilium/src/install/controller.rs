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
use lattice_common::{ApiServerEndpoint, ControllerContext, ReconcileError};
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
    let endpoint = ApiServerEndpoint::from_kubeadm_config(&ctx.client)
        .await
        .map_err(|e| {
            ReconcileError::Validation(format!(
                "failed to resolve API server endpoint for Cilium install: {e}"
            ))
        })?;
    // Pod CIDR comes from the local LatticeCluster CR — same value
    // `lattice-capi` writes into the CAPI Cluster's
    // `clusterNetwork.pods.cidrBlocks`. Cilium's
    // `ipv4NativeRoutingCIDR` MUST match exactly; wider CIDRs leak
    // pod IPs out of the cluster.
    let pod_cidr = resolve_local_pod_cidr(&ctx.client).await?;
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
    })
    .await
}

/// Read pod CIDR off the local LatticeCluster CR. Each workload
/// cluster has exactly one (its own). Errors if missing — Cilium
/// install can't proceed without the right CIDR; running with a
/// stale default would silently break pod egress.
async fn resolve_local_pod_cidr(client: &Client) -> Result<String, ReconcileError> {
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let list = api
        .list(&Default::default())
        .await
        .map_err(|e| ReconcileError::Validation(format!("list LatticeCluster: {e}")))?;
    list.items
        .into_iter()
        .next()
        .map(|c| c.spec.provider.kubernetes.cluster_network.pod_cidr)
        .ok_or_else(|| {
            ReconcileError::Validation(
                "no LatticeCluster CR found; cannot resolve pod CIDR for Cilium install"
                    .to_string(),
            )
        })
}
