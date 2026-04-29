//! GpuOperatorInstall reconciler — Phase 1: install-only.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::GpuOperatorInstall;

use super::{manifests, NAMESPACE};

const FIELD_MANAGER: &str = "lattice-gpu-operator-install-controller";
/// The operator pulls + launches NFD + device plugin + dcgm-exporter DaemonSets
/// on every GPU node; cold-install on a fresh cluster legitimately takes
/// several minutes before the operator Deployment flips to Available.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

pub async fn reconcile(
    install: Arc<GpuOperatorInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let mut manifests: Vec<String> = manifests::generate_gpu_stack().to_vec();
    for lmm in manifests::generate_gpu_mesh_members() {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "GpuOperatorInstall",
        manifests,
        readiness: ReadinessCheck::Deployments {
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
        webhook_service: None,
    })
    .await
}
