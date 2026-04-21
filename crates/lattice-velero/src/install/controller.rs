//! VeleroInstall reconciler — Phase 1: install-only.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::VeleroInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-velero-install-controller";
const NAMESPACE: &str = "velero";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<VeleroInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let mut manifests: Vec<String> = manifests::generate_velero().to_vec();
    for lmm in manifests::generate_velero_mesh_members() {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "VeleroInstall",
        manifests,
        readiness: ReadinessCheck::Deployments {
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
    })
    .await
}
