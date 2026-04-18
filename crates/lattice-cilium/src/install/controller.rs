//! CiliumInstall reconciler — Phase 1: install-only.
//!
//! Gates Ready on the `cilium` agent DaemonSet reporting all pods ready.
//! Cilium is the L3/L4 substrate — if the agent DS isn't healthy, pod
//! networking doesn't work.

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
use lattice_crd::crd::{CiliumInstall, CiliumInstallStatus, InstallPhase};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cilium-install-controller";

const CILIUM_NAMESPACE: &str = "kube-system";

const CILIUM_DS: &str = "cilium";

/// Cilium rolls per-node, each pod loading eBPF + reconciling endpoints.
/// Generous budget for slower nodes / large clusters.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

pub async fn reconcile(
    install: Arc<CiliumInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("CiliumInstall missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(install = %name, version = %install.spec.version, "Reconciling CiliumInstall");

    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
    )
    .await?;

    let mut mfs = manifests::generate_cilium_manifests().to_vec();
    for policy in [
        serde_json::to_string_pretty(&manifests::generate_ztunnel_allowlist()),
        serde_json::to_string_pretty(&manifests::generate_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_mesh_proxy_egress_policy()),
        serde_json::to_string_pretty(&manifests::generate_eastwest_gateway_policy()),
    ] {
        mfs.push(
            policy.map_err(|e| {
                ReconcileError::Validation(format!("serialize Cilium policy: {e}"))
            })?,
        );
    }

    if let Err(e) = apply_manifests(&ctx.client, &mfs, &ApplyOptions::default()).await {
        warn!(install = %name, error = %e, "CiliumInstall apply failed");
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

    match wait_for_daemonset(&ctx.client, CILIUM_DS, CILIUM_NAMESPACE, READY_TIMEOUT).await {
        Ok(()) => {
            info!(install = %name, version = %install.spec.version, "CiliumInstall Ready");
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
            warn!(install = %name, error = %e, "Cilium agent DS not ready in time");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Failed,
                Some(format!("agent DS not ready: {e}")),
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
    install: &CiliumInstall,
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

    let status = CiliumInstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.version.clone()),
        message,
        conditions: Vec::new(),
        last_upgrade: None,
    };

    kube_utils::patch_cluster_resource_status::<CiliumInstall>(
        client,
        &install.name_any(),
        &status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
