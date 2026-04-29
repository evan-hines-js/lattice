//! VolcanoInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the Deployments in `volcano-system` (admission, controllers,
//! scheduler) reporting Available. The vGPU device plugin DaemonSet is GPU-
//! node-only and may legitimately have zero desired pods on clusters without
//! GPU nodes, so we don't block Ready on it.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::VolcanoInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-volcano-install-controller";
const NAMESPACE: &str = "volcano-system";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<VolcanoInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let mut manifests: Vec<String> = manifests::generate_volcano().to_vec();
    for lmm in manifests::generate_volcano_mesh_members() {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "VolcanoInstall",
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
