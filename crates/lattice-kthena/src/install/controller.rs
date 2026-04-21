//! KthenaInstall reconciler — Phase 1: install-only.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::KthenaInstall;

use super::{manifests, policies, NAMESPACE};

const FIELD_MANAGER: &str = "lattice-kthena-install-controller";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<KthenaInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let mut manifests: Vec<String> = manifests::generate_kthena().to_vec();
    for lmm in manifests::generate_kthena_mesh_members() {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }
    for policy in [
        policies::generate_kthena_router_cedar_policy(),
        policies::generate_kthena_autoscaler_cedar_policy(),
    ] {
        manifests.push(
            serde_json::to_string_pretty(&policy)
                .map_err(|e| ReconcileError::Validation(format!("serialize Cedar policy: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "KthenaInstall",
        manifests,
        readiness: ReadinessCheck::Deployments {
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
    })
    .await
}
