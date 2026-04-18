//! TetragonInstall reconciler — Phase 1: install-only.
//!
//! Watches `TetragonInstall` CRs and drives them through:
//!   `Pending → Installing → Ready` (or → `Failed` on error).
//!
//! Phase 1 scope only: version-change/upgrade handling, auto-rollback, and the
//! baseline TracingPolicy GC are Phase 2 work. This controller currently
//! reapplies manifests on every observable spec change and marks Ready once
//! the tetragon DaemonSet reports all pods ready.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{info, warn};

use lattice_common::kube_utils::{self, wait_for_daemonset};
use lattice_common::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{InstallPhase, TetragonInstall, TetragonInstallStatus};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-tetragon-install-controller";

/// Namespace the Tetragon helm chart renders into (set in build.rs).
const TETRAGON_NAMESPACE: &str = "kube-system";

/// Name of the Tetragon agent DaemonSet — the readiness gate for "Ready".
const TETRAGON_DS: &str = "tetragon";

/// Time budget for the DaemonSet to converge before marking Failed.
/// Tetragon loads eBPF programs per node, so first-install on a fresh cluster
/// can legitimately take several minutes.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Reconcile a TetragonInstall resource.
pub async fn reconcile(
    install: Arc<TetragonInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("TetragonInstall missing metadata.generation".into())
    })?;

    // Skip work if spec unchanged and already Ready.
    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(install = %name, version = %install.spec.version, "Reconciling TetragonInstall");

    // Transition to Installing so status reflects in-flight work.
    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
    )
    .await?;

    // Render and apply manifests: helm chart output + cluster-wide baseline policy.
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

    // Gate Ready on the agent DaemonSet reporting all pods ready.
    match wait_for_daemonset(&ctx.client, TETRAGON_DS, TETRAGON_NAMESPACE, READY_TIMEOUT).await {
        Ok(()) => {
            info!(install = %name, version = %install.spec.version, "TetragonInstall Ready");
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

/// Patch status only when it would change — avoids reconcile storms from
/// stamping a fresh `lastTransitionTime` on every loop.
async fn write_status(
    client: &Client,
    install: &TetragonInstall,
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

    let status = TetragonInstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.version.clone()),
        message,
        conditions: Vec::new(),
        last_upgrade: None,
    };

    kube_utils::patch_cluster_resource_status::<TetragonInstall>(
        client,
        &install.name_any(),
        &status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
