//! TetragonInstall reconciler — Phase 1: install-only.
//!
//! Phase 1 scope only: version-change / upgrade handling + auto-rollback land
//! in Phase 2. The reconciler currently reapplies manifests on every observed
//! spec change and marks Ready once the tetragon DaemonSet reports all pods
//! ready.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{info, warn};

use lattice_common::install::patch_install_status;
use lattice_common::kube_utils::wait_for_daemonset;
use lattice_common::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{InstallPhase, InstallStatus, TetragonInstall};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-tetragon-install-controller";
const TETRAGON_NAMESPACE: &str = "kube-system";
const TETRAGON_DS: &str = "tetragon";
/// Tetragon loads eBPF programs per node; first install on a fresh cluster can
/// legitimately take several minutes.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<TetragonInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("TetragonInstall missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(install = %name, version = %install.spec.base.version, "Reconciling TetragonInstall");
    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
    )
    .await?;

    let mut mfs = manifests::generate_tetragon().to_vec();
    mfs.push(
        serde_json::to_string_pretty(&manifests::generate_baseline_tracing_policy())
            .map_err(|e| {
                ReconcileError::Validation(format!("serialize baseline TracingPolicy: {e}"))
            })?,
    );

    if let Err(e) = apply_manifests(&ctx.client, &mfs, &ApplyOptions::default()).await {
        warn!(install = %name, error = %e, "TetragonInstall apply failed");
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

    match wait_for_daemonset(&ctx.client, TETRAGON_DS, TETRAGON_NAMESPACE, READY_TIMEOUT).await {
        Ok(()) => {
            info!(install = %name, version = %install.spec.base.version, "TetragonInstall Ready");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Ready,
                None,
                generation,
                Some(&install.spec.base.version),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(install = %name, error = %e, "Tetragon DaemonSet not ready in time");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Failed,
                Some(format!("DaemonSet not ready: {e}")),
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
    install: &TetragonInstall,
    phase: InstallPhase,
    message: Option<String>,
    observed_generation: i64,
    observed_version: Option<&str>,
) -> Result<(), ReconcileError> {
    let status = InstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.base.version.clone()),
        message,
        trust_domain: None,
        conditions: Vec::new(),
        last_upgrade: None,
    };
    patch_install_status::<TetragonInstall>(
        client,
        &install.name_any(),
        install.status.as_ref(),
        status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
