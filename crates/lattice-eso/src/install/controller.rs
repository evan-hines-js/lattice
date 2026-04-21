//! ESOInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the Deployments in `external-secrets` reporting Available —
//! ESO's webhook admits `ExternalSecret` resources; no webhook means no ESO
//! reconcile.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::ESOInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-eso-install-controller";
const NAMESPACE: &str = "external-secrets";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<ESOInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    // Helm chart + LatticeMeshMember enrollment land together. The mesh
    // member controller picks up the LMM objects once they appear.
    let mut manifests: Vec<String> = manifests::generate_eso().to_vec();
    for lmm in manifests::generate_eso_mesh_members() {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "ESOInstall",
        manifests,
        readiness: ReadinessCheck::Deployments {
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
    })
    .await
}
