//! ESOInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the webhook Deployment being available — ESO's webhook
//! admits ExternalSecret resources; no webhook means no ESO reconcile.
//! The controller + cert-controller Deployments share the same namespace and
//! are covered by `wait_for_all_deployments`.

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
use lattice_crd::crd::{ESOInstall, ESOInstallStatus, InstallPhase};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-eso-install-controller";

const ESO_NAMESPACE: &str = "external-secrets";

/// Time budget for the ESO Deployments (controller, webhook, cert-controller)
/// to report Available.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<ESOInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("ESOInstall missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(install = %name, version = %install.spec.version, "Reconciling ESOInstall");

    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
    )
    .await?;

    // Apply helm chart + LatticeMeshMember enrollment together. The mesh
    // member controller picks up the LMM objects once they land.
    let mut mfs = manifests::generate_eso().to_vec();
    for lmm in manifests::generate_eso_mesh_members() {
        mfs.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }

    if let Err(e) = apply_manifests(&ctx.client, &mfs, &ApplyOptions::default()).await {
        warn!(install = %name, error = %e, "ESOInstall apply failed");
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

    match wait_for_all_deployments(&ctx.client, ESO_NAMESPACE, READY_TIMEOUT).await {
        Ok(()) => {
            info!(install = %name, version = %install.spec.version, "ESOInstall Ready");
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
            warn!(install = %name, error = %e, "ESO Deployments not ready in time");
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
    install: &ESOInstall,
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

    let status = ESOInstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.version.clone()),
        message,
        conditions: Vec::new(),
        last_upgrade: None,
    };

    kube_utils::patch_cluster_resource_status::<ESOInstall>(
        client,
        &install.name_any(),
        &status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
