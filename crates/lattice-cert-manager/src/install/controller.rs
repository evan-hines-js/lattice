//! CertManagerInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on every Deployment in the `cert-manager` namespace reporting
//! Available. The webhook Deployment specifically gates new Certificate /
//! CertificateRequest admission; treating all three (controller, webhook,
//! cainjector) uniformly keeps the Ready signal meaningful.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{info, warn};

use lattice_common::kube_utils::{self, wait_for_all_deployments};
use lattice_common::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{CertManagerInstall, CertManagerInstallStatus, InstallPhase};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cert-manager-install-controller";

const CERT_MANAGER_NAMESPACE: &str = "cert-manager";

/// Time budget for cert-manager Deployments to report Available.
/// cert-manager ships a `startupapicheck` Job that waits for the webhook to
/// be reachable before signaling completion; 300s covers its grace.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<CertManagerInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("CertManagerInstall missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(install = %name, version = %install.spec.version, "Reconciling CertManagerInstall");

    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
    )
    .await?;

    let mfs = manifests::generate_cert_manager();

    if let Err(e) = apply_manifests(&ctx.client, mfs, &ApplyOptions::default()).await {
        warn!(install = %name, error = %e, "CertManagerInstall apply failed");
        write_status(
            &ctx.client,
            &install,
            InstallPhase::Failed,
            Some(format!("apply failed: {e}")),
            generation,
            None,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    match wait_for_all_deployments(&ctx.client, CERT_MANAGER_NAMESPACE, READY_TIMEOUT).await {
        Ok(()) => {
            info!(install = %name, version = %install.spec.version, "CertManagerInstall Ready");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Ready,
                None,
                generation,
                Some(&install.spec.version),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(install = %name, error = %e, "cert-manager Deployments not ready in time");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Failed,
                Some(format!("Deployments not ready: {e}")),
                generation,
                None,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

async fn write_status(
    client: &Client,
    install: &CertManagerInstall,
    phase: InstallPhase,
    message: Option<String>,
    observed_generation: i64,
    observed_version: Option<&str>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &phase,
        message.as_deref(),
        Some(observed_generation),
    ) {
        return Ok(());
    }

    let status = CertManagerInstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.version.clone()),
        message,
        conditions: Vec::new(),
        last_upgrade: None,
    };

    kube_utils::patch_cluster_resource_status::<CertManagerInstall>(
        client,
        &install.name_any(),
        &status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
