//! TetragonInstall reconciler — Phase 1: install-only.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::TetragonInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-tetragon-install-controller";
const NAMESPACE: &str = "kube-system";
const DAEMONSET: &str = "tetragon";
/// Tetragon loads eBPF programs per node; first install on a fresh cluster can
/// legitimately take several minutes.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<TetragonInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let mut manifests: Vec<String> = manifests::generate_tetragon().to_vec();
    manifests.push(
        serde_json::to_string_pretty(&manifests::generate_baseline_tracing_policy()).map_err(
            |e| ReconcileError::Validation(format!("serialize baseline TracingPolicy: {e}")),
        )?,
    );

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "TetragonInstall",
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
