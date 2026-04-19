//! MetricsServerInstall reconciler — Phase 1: install-only.
//!
//! metrics-server lands in `kube-system`, so readiness is gated on its single
//! named Deployment — scanning the whole namespace would false-negative on
//! unrelated tenants.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{
    run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig,
};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::MetricsServerInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-metrics-server-install-controller";
const NAMESPACE: &str = "kube-system";
const DEPLOYMENT: &str = "metrics-server";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<MetricsServerInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "MetricsServerInstall",
        manifests: manifests::generate_metrics_server().to_vec(),
        readiness: ReadinessCheck::Deployment {
            name: DEPLOYMENT,
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
    })
    .await
}
