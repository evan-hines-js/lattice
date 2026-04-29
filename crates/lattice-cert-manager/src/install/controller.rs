//! CertManagerInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on every Deployment in the `cert-manager` namespace reporting
//! Available. The webhook Deployment specifically gates new Certificate /
//! CertificateRequest admission; treating all three (controller, webhook,
//! cainjector) uniformly keeps the Ready signal meaningful.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError};
use lattice_crd::crd::CertManagerInstall;

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cert-manager-install-controller";
const NAMESPACE: &str = "cert-manager";
/// cert-manager ships a `startupapicheck` Job that waits for the webhook to
/// be reachable before signaling completion; 300s covers its grace.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<CertManagerInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "CertManagerInstall",
        manifests: manifests::generate_cert_manager()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        readiness: ReadinessCheck::Deployments {
            namespace: NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
        webhook_service: None,
    })
    .await
}
