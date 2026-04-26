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
    wait_for_deployment, wait_for_resource_status, GvkPlural,
};
use crate::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{
    CertManagerInstall, CiliumInstall, Condition, ConditionStatus, Dependency, ESOInstall,
    GpuOperatorInstall, InstallPhase, InstallResource, IstioInstall, KedaInstall, KthenaInstall,
    MetricsServerInstall, RookInstall, Subsystem, TetragonInstall, UpgradeAttempt, UpgradeOutcome,
    VeleroInstall, VictoriaMetricsInstall, VolcanoInstall,
};

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
/// / [`upgrading`](Self::upgrading) / [`ready`](Self::ready) /
/// [`failed`](Self::failed) constructors so call sites read like the English
/// description of the transition. Only Istio sets `trust_domain`; everyone
/// else leaves the default.
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
    /// Conditions to merge into `status.conditions` for this write.
    ///
    /// Each entry is folded in via [`Condition::merge_into`], so the
    /// existing `lastTransitionTime` is preserved when type/status/reason
    /// haven't changed. Other conditions on the resource are preserved.
    pub conditions: Vec<Condition>,
    /// Replace `status.lastUpgrade` with this attempt record. `None`
    /// preserves whatever record is already on the resource.
    pub last_upgrade: Option<UpgradeAttempt>,
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

    /// Initial install in progress (no prior `observed_version`).
    pub fn installing() -> Self {
        Self {
            phase: InstallPhase::Installing,
            ..Self::default()
        }
    }

    /// Version-to-version upgrade in progress (prior `observed_version`
    /// differs from `spec.version`).
    pub fn upgrading() -> Self {
        Self {
            phase: InstallPhase::Upgrading,
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

    /// Fold one condition into this update; preserves any conditions already
    /// present on the resource.
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Replace `status.lastUpgrade` with `attempt` on this write.
    pub fn with_last_upgrade(mut self, attempt: UpgradeAttempt) -> Self {
        self.last_upgrade = Some(attempt);
        self
    }
}

/// Write one status transition for an install CR.
///
/// Skip-if-unchanged prevents reconcile storms: every merge patch generates a
/// watch event, and `Condition::new()` stamps a fresh `lastTransitionTime`
/// that would otherwise re-fire the controller every loop. Existing
/// `conditions`, `trust_domain`, and `last_upgrade` are preserved unless the
/// caller provides new values; conditions are merged via
/// [`Condition::merge_into`] so unchanged conditions keep their original
/// timestamp.
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
    let mut status = install.install_status().cloned().unwrap_or_default();
    status.phase = update.phase;
    status.observed_generation = generation;
    status.observed_version = update.observed_version.map(str::to_string);
    status.target_version = Some(target_version);
    status.message = update.message;
    if let Some(td) = update.trust_domain {
        status.trust_domain = Some(td.to_string());
    }
    for condition in update.conditions {
        Condition::merge_into(condition, &mut status.conditions);
    }
    if let Some(attempt) = update.last_upgrade {
        status.last_upgrade = Some(attempt);
    }

    if install.install_status() == Some(&status) {
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
    /// Wait for a named CR's `.status` to satisfy a predicate.
    ///
    /// For Installs whose success can't be modeled as a Deployment/DaemonSet
    /// gate — e.g. Rook, where `rook-ceph-operator` running is a necessary
    /// but not sufficient condition; the actual success signal lives on
    /// `CephCluster.status.ceph.health`.
    ResourceStatus {
        /// GVK + plural of the resource to poll.
        gvk: GvkPlural<'a>,
        /// Resource name.
        name: &'a str,
        /// Namespace, or `None` for cluster-scoped resources.
        namespace: Option<&'a str>,
        /// Human-readable condition being waited on, used in timeout errors
        /// (e.g. `"HEALTH_OK"`).
        description: &'a str,
        /// Predicate on the resource's JSON representation. `true` = ready.
        ready_when: fn(&serde_json::Value) -> bool,
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
            Self::ResourceStatus {
                gvk,
                name,
                namespace,
                description,
                ready_when,
                timeout,
            } => {
                wait_for_resource_status(
                    client,
                    gvk,
                    name,
                    *namespace,
                    description,
                    *timeout,
                    *ready_when,
                )
                .await
            }
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

    // ── Cross-subsystem upgrade gate ──
    //
    // Block the apply/wait loop when `spec.requires` is unsatisfied. The
    // `UpgradeBlocked` condition rides along on each phase write; the merge
    // semantics in `write_install_status` then preserve it across the
    // installing → ready transition without each phase having to reassert.
    let requires_status = check_requires(&ctx.client, &install.spec_base().requires).await?;
    let requires_cond = upgrade_blocked_condition(&requires_status);
    if let RequiresStatus::Blocked(reason) = &requires_status {
        info!(install = %name, kind = %log_kind, reason = %reason, "install gated on spec.requires");
        write_with_td(
            &ctx.client,
            install_ref,
            field_manager,
            StatusUpdate::pending(format!("upgrade blocked: {reason}"))
                .with_condition(requires_cond),
            td,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    // Distinguish initial install from version-to-version upgrade: the
    // phase + UpgradeAttempt audit record both depend on whether there's a
    // prior `observed_version` that differs from the new target.
    let prior_observed = install
        .install_status()
        .and_then(|s| s.observed_version.clone());
    let is_upgrade = matches!(prior_observed.as_deref(), Some(v) if v != version);
    let in_progress_phase = if is_upgrade {
        InstallPhase::Upgrading
    } else {
        InstallPhase::Installing
    };
    let prior_attempt = install.install_status().and_then(|s| s.last_upgrade.clone());
    let started_attempt =
        UpgradeAttempt::started(prior_attempt.as_ref(), &version, prior_observed.as_deref());

    info!(
        install = %name, kind = %log_kind,
        from = ?prior_observed, to = %version,
        upgrade = is_upgrade,
        "Reconciling install",
    );
    let in_progress_update = StatusUpdate {
        phase: in_progress_phase,
        ..Default::default()
    }
    .with_condition(requires_cond.clone())
    .with_last_upgrade(started_attempt.clone());
    write_with_td(&ctx.client, install_ref, field_manager, in_progress_update, td).await?;

    if let Err(e) = apply_manifests(&ctx.client, &manifests, &ApplyOptions::default()).await {
        warn!(install = %name, kind = %log_kind, error = %e, "install apply failed");
        let failed = started_attempt
            .finished(UpgradeOutcome::Failed, Some(format!("apply failed: {e}")));
        write_with_td(
            &ctx.client,
            install_ref,
            field_manager,
            StatusUpdate::failed(format!("apply failed: {e}")).with_last_upgrade(failed),
            td,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    match readiness.run(&ctx.client).await {
        Ok(()) => {
            info!(install = %name, kind = %log_kind, version = %version, "install Ready");
            let succeeded = started_attempt.finished(UpgradeOutcome::Succeeded, None);
            write_with_td(
                &ctx.client,
                install_ref,
                field_manager,
                StatusUpdate::ready(&version).with_last_upgrade(succeeded),
                td,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(install = %name, kind = %log_kind, error = %e, "install readiness gate failed");
            let failed = started_attempt.finished(
                UpgradeOutcome::Failed,
                Some(format!("readiness gate failed: {e}")),
            );
            write_with_td(
                &ctx.client,
                install_ref,
                field_manager,
                StatusUpdate::failed(format!("readiness gate failed: {e}"))
                    .with_last_upgrade(failed),
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

// =============================================================================
// Cross-subsystem upgrade gating (`spec.requires`)
// =============================================================================
//
// Each Install controller checks `spec.requires` before progressing toward
// `spec.version`. The check is local: it reads the dependency's current
// `status.observedVersion` and matches it against the SemVer constraint. No
// orchestrator, no graph resolution — natural ordering emerges because each
// controller also `.watches()` the CRDs of its dependencies, so a dependency
// flipping to Ready re-fires this controller immediately.

/// Name of the singleton CR every `*Install` kind has. Each cluster runs
/// exactly one instance per managed dependency, so the install CRs are
/// effectively singletons keyed by their kind.
pub const INSTALL_SINGLETON: &str = "default";

/// Condition `type` published when `spec.requires` blocks an upgrade.
pub const COND_UPGRADE_BLOCKED: &str = "UpgradeBlocked";
/// Reason set on `UpgradeBlocked=True`.
pub const REASON_REQUIRES_UNSATISFIED: &str = "RequiresUnsatisfied";
/// Reason set on `UpgradeBlocked=False`.
pub const REASON_REQUIRES_SATISFIED: &str = "RequiresSatisfied";

/// Outcome of evaluating an Install's `spec.requires`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequiresStatus {
    /// All dependencies report a `status.observedVersion` matching their
    /// declared constraint.
    Satisfied,
    /// At least one dependency is missing, not yet observed, or out of range.
    /// The string concatenates each blocker's reason for status surfacing.
    Blocked(String),
}

/// Evaluate `spec.requires` against the live cluster.
///
/// For each [`Dependency`], fetches the dependency's singleton Install CR,
/// reads `status.observedVersion`, and tests it against `version_constraint`.
/// An empty `requires` returns `Satisfied` without any API calls.
pub async fn check_requires(
    client: &Client,
    requires: &[Dependency],
) -> Result<RequiresStatus, ReconcileError> {
    if requires.is_empty() {
        return Ok(RequiresStatus::Satisfied);
    }

    let mut blockers: Vec<String> = Vec::new();
    for dep in requires {
        let observed = observed_version(client, dep.subsystem).await?;
        if let Err(reason) = evaluate_dependency(dep, observed.as_deref()) {
            blockers.push(reason);
        }
    }

    if blockers.is_empty() {
        Ok(RequiresStatus::Satisfied)
    } else {
        Ok(RequiresStatus::Blocked(blockers.join("; ")))
    }
}

/// Pure check of one dependency against its observed version.
///
/// Split out from [`check_requires`] so the constraint-matching logic is
/// unit-testable without a kube client.
fn evaluate_dependency(dep: &Dependency, observed: Option<&str>) -> Result<(), String> {
    let req = semver::VersionReq::parse(&dep.version_constraint).map_err(|e| {
        format!(
            "{}: invalid version constraint {:?}: {e}",
            dep.subsystem, dep.version_constraint
        )
    })?;
    let Some(observed) = observed else {
        return Err(format!(
            "{} has no observed version yet (requires {})",
            dep.subsystem, dep.version_constraint
        ));
    };
    let parsed = semver::Version::parse(observed).map_err(|e| {
        format!(
            "{} reports unparsable version {observed:?}: {e}",
            dep.subsystem
        )
    })?;
    if req.matches(&parsed) {
        Ok(())
    } else {
        Err(format!(
            "{} is at {observed}, requires {}",
            dep.subsystem, dep.version_constraint
        ))
    }
}

/// Build the `UpgradeBlocked` condition for a given outcome.
///
/// `Satisfied` -> `False/RequiresSatisfied`, `Blocked` -> `True/RequiresUnsatisfied`.
/// Reconcilers merge this into existing `status.conditions` via
/// [`Condition::merge_into`], which preserves `lastTransitionTime` when state
/// is unchanged.
pub fn upgrade_blocked_condition(status: &RequiresStatus) -> Condition {
    match status {
        RequiresStatus::Satisfied => Condition::new(
            COND_UPGRADE_BLOCKED,
            ConditionStatus::False,
            REASON_REQUIRES_SATISFIED,
            "all spec.requires entries satisfied",
        ),
        RequiresStatus::Blocked(reason) => Condition::new(
            COND_UPGRADE_BLOCKED,
            ConditionStatus::True,
            REASON_REQUIRES_UNSATISFIED,
            reason.clone(),
        ),
    }
}

/// Look up the `status.observedVersion` of a dependency Install CR.
///
/// Returns `Ok(None)` when the CR is absent or has no observed version yet —
/// both treated as "not ready" for gating purposes. Other API errors bubble
/// up as `ReconcileError::Kube`.
async fn observed_version(
    client: &Client,
    subsystem: Subsystem,
) -> Result<Option<String>, ReconcileError> {
    macro_rules! fetch {
        ($kind:ty) => {{
            match Api::<$kind>::all(client.clone())
                .get(INSTALL_SINGLETON)
                .await
            {
                Ok(install) => Ok(install.status.and_then(|s| s.observed_version)),
                Err(kube::Error::Api(resp)) if resp.code == 404 => Ok(None),
                Err(e) => Err(ReconcileError::Kube(e)),
            }
        }};
    }
    match subsystem {
        Subsystem::CertManager => fetch!(CertManagerInstall),
        Subsystem::Cilium => fetch!(CiliumInstall),
        Subsystem::Eso => fetch!(ESOInstall),
        Subsystem::GpuOperator => fetch!(GpuOperatorInstall),
        Subsystem::Istio => fetch!(IstioInstall),
        Subsystem::Keda => fetch!(KedaInstall),
        Subsystem::Kthena => fetch!(KthenaInstall),
        Subsystem::MetricsServer => fetch!(MetricsServerInstall),
        Subsystem::Rook => fetch!(RookInstall),
        Subsystem::Tetragon => fetch!(TetragonInstall),
        Subsystem::Velero => fetch!(VeleroInstall),
        Subsystem::VictoriaMetrics => fetch!(VictoriaMetricsInstall),
        Subsystem::Volcano => fetch!(VolcanoInstall),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(subsystem: Subsystem, c: &str) -> Dependency {
        Dependency {
            subsystem,
            version_constraint: c.into(),
        }
    }

    #[test]
    fn satisfied_when_observed_in_range() {
        assert!(evaluate_dependency(&dep(Subsystem::Cilium, ">=1.31, <2"), Some("1.31.4")).is_ok());
        assert!(evaluate_dependency(&dep(Subsystem::Cilium, "^1.31"), Some("1.31.0")).is_ok());
        assert!(evaluate_dependency(&dep(Subsystem::Cilium, "1.31.4"), Some("1.31.4")).is_ok());
    }

    #[test]
    fn blocked_when_below_range() {
        let err = evaluate_dependency(&dep(Subsystem::Cilium, ">=1.31"), Some("1.30.0"))
            .expect_err("should block");
        assert!(err.contains("cilium is at 1.30.0"));
        assert!(err.contains(">=1.31"));
    }

    #[test]
    fn blocked_when_observed_missing() {
        let err = evaluate_dependency(&dep(Subsystem::Istio, ">=1.24"), None)
            .expect_err("should block");
        assert!(err.contains("istio has no observed version"));
    }

    #[test]
    fn blocked_on_invalid_constraint() {
        let err = evaluate_dependency(&dep(Subsystem::Rook, "not-a-range"), Some("1.31.0"))
            .expect_err("should block");
        assert!(err.contains("invalid version constraint"));
    }

    #[test]
    fn blocked_on_unparsable_observed() {
        let err = evaluate_dependency(&dep(Subsystem::Cilium, ">=1.31"), Some("v1.31"))
            .expect_err("should block");
        assert!(err.contains("unparsable version"));
    }

    #[test]
    fn upgrade_blocked_condition_shape() {
        let blocked = upgrade_blocked_condition(&RequiresStatus::Blocked("foo".into()));
        assert_eq!(blocked.type_, COND_UPGRADE_BLOCKED);
        assert_eq!(blocked.status, ConditionStatus::True);
        assert_eq!(blocked.reason, REASON_REQUIRES_UNSATISFIED);
        assert_eq!(blocked.message, "foo");

        let ok = upgrade_blocked_condition(&RequiresStatus::Satisfied);
        assert_eq!(ok.status, ConditionStatus::False);
        assert_eq!(ok.reason, REASON_REQUIRES_SATISFIED);
    }
}
