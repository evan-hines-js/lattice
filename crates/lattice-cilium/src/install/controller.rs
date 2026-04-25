//! CiliumInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the `cilium` agent DaemonSet reporting all pods ready.
//! Cilium is the L3/L4 substrate — if the agent DS isn't healthy, pod
//! networking doesn't work.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ApiServerEndpoint, ControllerContext, ReconcileError};
use lattice_crd::crd::CiliumInstall;

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
    let mut manifests: Vec<String> = manifests::render_cilium_manifests(&endpoint);
    for policy in [
        serde_json::to_string_pretty(&manifests::generate_ztunnel_allowlist()),
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
