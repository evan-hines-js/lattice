//! Shared plumbing for per-dependency Install CRDs.
//!
//! Each install crate (`lattice-tetragon`, `lattice-cilium`, …) has its own
//! controller. The mechanical bits — SSA-patching the CR, writing an
//! `InstallStatus` only when it would change, and driving the apply/wait/Ready
//! loop — live here. Phase 2 upgrade semantics (revision canaries, DS rolling,
//! rollbacks) will slot in as additional drivers next to
//! [`run_simple_install_reconcile`].

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ClusterResourceScope;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde::de::DeserializeOwned;
use tracing::{info, warn};

use crate::kube_utils::{
    patch_cluster_resource_status, wait_for_all_deployments, wait_for_daemonset,
    wait_for_deployment,
};
use crate::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{InstallPhase, InstallResource, InstallStatus};

/// Server-side apply a cluster-scoped resource under the given field manager.
///
/// Used by every install crate's `ensure_install` to create-or-update its
/// singleton Install CR.
pub async fn apply_cluster_resource<K>(
    client: &Client,
    resource: &K,
    name: &str,
    field_manager: &str,
) -> Result<(), kube::Error>
where
    K: kube::Resource<Scope = ClusterResourceScope>
        + Clone
        + serde::Serialize
        + DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let api: Api<K> = Api::all(client.clone());
    api.patch(
        name,
        &PatchParams::apply(field_manager),
        &Patch::Apply(resource),
    )
    .await?;
    Ok(())
}

/// One status write for an install CR: phase + optional fields.
///
/// Built with the [`pending`](Self::pending) / [`installing`](Self::installing)
/// / [`ready`](Self::ready) / [`failed`](Self::failed) constructors so call
/// sites read like the English description of the transition. Only Istio sets
/// `trust_domain`; everyone else leaves the default.
#[derive(Default)]
pub struct StatusUpdate<'a> {
    /// Target lifecycle phase.
    pub phase: InstallPhase,
    /// Human-readable detail (typically populated on failure / pending).
    pub message: Option<String>,
    /// Version actually running. Set on `Ready`.
    pub observed_version: Option<&'a str>,
    /// Istio-derived trust domain. Other controllers leave this `None`.
    pub trust_domain: Option<&'a str>,
}

impl<'a> StatusUpdate<'a> {
    /// Pre-flight not yet satisfied (e.g. waiting for `lattice-ca`).
    pub fn pending(message: impl Into<String>) -> Self {
        Self {
            phase: InstallPhase::Pending,
            message: Some(message.into()),
            ..Self::default()
        }
    }

    /// Apply/wait in progress.
    pub fn installing() -> Self {
        Self {
            phase: InstallPhase::Installing,
            ..Self::default()
        }
    }

    /// Install converged at `version`.
    pub fn ready(version: &'a str) -> Self {
        Self {
            phase: InstallPhase::Ready,
            observed_version: Some(version),
            ..Self::default()
        }
    }

    /// Terminal failure.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            phase: InstallPhase::Failed,
            message: Some(message.into()),
            ..Self::default()
        }
    }

    /// Attach a trust domain (Istio's derived identity field) to this update.
    pub fn with_trust_domain(mut self, td: &'a str) -> Self {
        self.trust_domain = Some(td);
        self
    }
}

/// Write one status transition for an install CR.
///
/// Skip-if-unchanged prevents reconcile storms: every merge patch generates a
/// watch event, and `Condition::new()` stamps a fresh `lastTransitionTime`
/// that would otherwise re-fire the controller every loop. Generation,
/// target_version, and name are read from `install`.
pub async fn write_install_status<K>(
    client: &Client,
    install: &K,
    field_manager: &str,
    update: StatusUpdate<'_>,
) -> Result<(), ReconcileError>
where
    K: kube::Resource<Scope = ClusterResourceScope>
        + InstallResource
        + Clone
        + DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let generation = install.meta().generation;
    let target_version = install.spec_base().version.clone();
    let status = InstallStatus {
        phase: update.phase,
        observed_generation: generation,
        observed_version: update.observed_version.map(str::to_string),
        target_version: Some(target_version),
        message: update.message,
        trust_domain: update.trust_domain.map(str::to_string),
        conditions: Vec::new(),
        last_upgrade: None,
    };

    if status_check::is_status_unchanged(
        install.install_status(),
        &status.phase,
        status.message.as_deref(),
        status.observed_generation,
    ) {
        return Ok(());
    }
    patch_cluster_resource_status::<K>(client, &install.name_any(), &status, field_manager)
        .await
        .map_err(ReconcileError::Kube)
}

/// Readiness gate checked after manifests are applied.
pub enum ReadinessCheck<'a> {
    /// Wait for all Deployments in the namespace to be Available.
    Deployments {
        /// Namespace to scan for Deployments.
        namespace: &'a str,
        /// Overall timeout for the wait.
        timeout: Duration,
    },
    /// Wait for a single named Deployment to be Available.
    Deployment {
        /// Deployment name.
        name: &'a str,
        /// Deployment namespace.
        namespace: &'a str,
        /// Overall timeout for the wait.
        timeout: Duration,
    },
    /// Wait for a specific DaemonSet to have all desired pods ready.
    DaemonSet {
        /// DaemonSet name.
        name: &'a str,
        /// DaemonSet namespace.
        namespace: &'a str,
        /// Overall timeout for the wait.
        timeout: Duration,
    },
}

impl ReadinessCheck<'_> {
    async fn run(&self, client: &Client) -> Result<(), crate::Error> {
        match self {
            Self::Deployments { namespace, timeout } => {
                wait_for_all_deployments(client, namespace, *timeout).await
            }
            Self::Deployment {
                name,
                namespace,
                timeout,
            } => wait_for_deployment(client, name, namespace, *timeout).await,
            Self::DaemonSet {
                name,
                namespace,
                timeout,
            } => wait_for_daemonset(client, name, namespace, *timeout).await,
        }
    }
}

/// Inputs for the boilerplate install reconcile loop.
///
/// Controllers build this once per reconcile and call
/// [`run_simple_install_reconcile`]. The helper owns phase transitions,
/// status skip-if-unchanged, and requeue cadence.
pub struct SimpleInstallConfig<'a, K> {
    /// The install CR being reconciled.
    pub install: Arc<K>,
    /// Shared controller context (client, event publisher, …).
    pub ctx: Arc<ControllerContext>,
    /// Field manager for SSA status patches (one per install crate).
    pub field_manager: &'a str,
    /// Human-readable CR kind used in log lines (e.g. `"TetragonInstall"`).
    pub log_kind: &'a str,
    /// Manifests (and inline JSON docs) to apply for this install.
    pub manifests: Vec<String>,
    /// Gate used to decide when the install is Ready.
    pub readiness: ReadinessCheck<'a>,
    /// Stamp this value onto every status write (used by Istio for
    /// `trust_domain`). `None` for installs that don't surface extra fields.
    pub trust_domain: Option<String>,
}

/// Drive an install CR through its lifecycle: apply manifests, wait on
/// readiness, transition to `Ready` or `Failed`.
///
/// If `status` already reports `Ready` at the current generation, no-ops and
/// requeues at the drift-detection interval. Callers that need pre-flight
/// gating (e.g. Istio waiting on `lattice-ca`) write a `Pending` status
/// themselves with [`write_install_status`] and return before calling this.
pub async fn run_simple_install_reconcile<K>(
    config: SimpleInstallConfig<'_, K>,
) -> Result<Action, ReconcileError>
where
    K: kube::Resource<Scope = ClusterResourceScope>
        + InstallResource
        + Clone
        + DeserializeOwned
        + std::fmt::Debug
        + 'static,
    <K as kube::Resource>::DynamicType: Default,
{
    let SimpleInstallConfig {
        install,
        ctx,
        field_manager,
        log_kind,
        manifests,
        readiness,
        trust_domain,
    } = config;

    let name = install.name_any();
    let version = install.spec_base().version.clone();
    let generation = install.meta().generation;
    if generation.is_none() {
        return Err(ReconcileError::Validation(format!(
            "{log_kind} missing metadata.generation"
        )));
    }

    if status_check::is_status_unchanged(
        install.install_status(),
        &InstallPhase::Ready,
        None,
        generation,
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    let td = trust_domain.as_deref();
    let install_ref = install.as_ref();

    info!(install = %name, kind = %log_kind, version = %version, "Reconciling install");
    write_with_td(
        &ctx.client,
        install_ref,
        field_manager,
        StatusUpdate::installing(),
        td,
    )
    .await?;

    if let Err(e) = apply_manifests(&ctx.client, &manifests, &ApplyOptions::default()).await {
        warn!(install = %name, kind = %log_kind, error = %e, "install apply failed");
        write_with_td(
            &ctx.client,
            install_ref,
            field_manager,
            StatusUpdate::failed(format!("apply failed: {e}")),
            td,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    match readiness.run(&ctx.client).await {
        Ok(()) => {
            info!(install = %name, kind = %log_kind, version = %version, "install Ready");
            write_with_td(
                &ctx.client,
                install_ref,
                field_manager,
                StatusUpdate::ready(&version),
                td,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(install = %name, kind = %log_kind, error = %e, "install readiness gate failed");
            write_with_td(
                &ctx.client,
                install_ref,
                field_manager,
                StatusUpdate::failed(format!("readiness gate failed: {e}")),
                td,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

/// Write a status, folding in the optional `trust_domain` carried by
/// [`SimpleInstallConfig`] without repeating the match at each call site.
async fn write_with_td<'a, K>(
    client: &Client,
    install: &K,
    field_manager: &str,
    update: StatusUpdate<'a>,
    trust_domain: Option<&'a str>,
) -> Result<(), ReconcileError>
where
    K: kube::Resource<Scope = ClusterResourceScope>
        + InstallResource
        + Clone
        + DeserializeOwned
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let update = match trust_domain {
        Some(td) => update.with_trust_domain(td),
        None => update,
    };
    write_install_status(client, install, field_manager, update).await
}
