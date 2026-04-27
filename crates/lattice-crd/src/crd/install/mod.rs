//! Install CRDs for managed dependencies (Istio, Cilium, Tetragon, etc.).
//!
//! Each dependency is installed and upgraded by its own controller. The CRDs
//! in this module describe desired state (version, upgrade policy) and report
//! observed state (phase, current version, health). Shared types — the install
//! lifecycle phase enum and the upgrade policy — live here. Per-component CRDs
//! are in sibling modules.

pub mod cert_manager;
pub mod cilium;
pub mod eso;
pub mod gpu_operator;
pub mod istio;
pub mod keda;
pub mod kthena;
pub mod metrics_server;
pub mod rook;
pub mod tetragon;
pub mod velero;
pub mod victoria_metrics;
pub mod volcano;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::Condition;

/// Common access to the install-spec fields every dependency controller reads.
///
/// Each dependency CRD has a bespoke `Spec` (Istio adds `cluster_name`, etc.),
/// but the shared install helper only needs the target version and the last
/// reported status. Implementations are one-liners forwarding to `spec.base`.
pub trait InstallResource {
    fn spec_base(&self) -> &InstallSpecBase;
    fn install_status(&self) -> Option<&InstallStatus>;
}

/// Desired-state fields every dependency Install CRD carries.
///
/// Per-component specs embed this via `#[serde(flatten)]` and add
/// component-specific fields alongside (e.g. Istio's `cluster_name`).
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InstallSpecBase {
    /// Desired version of the managed dependency.
    pub version: String,
    /// Upgrade strategy overrides.
    #[serde(default)]
    pub upgrade_policy: UpgradePolicy,
    /// Other subsystems this install needs to be at a specific version range
    /// before it will progress to `spec.version`.
    ///
    /// Each controller checks `requires` on every reconcile. If any entry's
    /// `version_constraint` is not satisfied by the dependency's
    /// `status.observedVersion`, the controller publishes `UpgradeBlocked`
    /// and stays at the current version. Watches on the listed subsystem
    /// CRDs trigger immediate re-reconcile when the dependency advances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Dependency>,
}

/// One entry in `InstallSpecBase::requires`.
///
/// Holds the dependency subsystem and the SemVer range that must be matched by
/// that dependency's `status.observedVersion`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    /// Which subsystem we depend on.
    pub subsystem: Subsystem,
    /// SemVer range expression (e.g. `">=1.31, <2"`, `"^1.31"`).
    pub version_constraint: String,
}

impl Dependency {
    /// Construct a `Dependency` with a `&str` constraint, mirroring the
    /// shape every install crate's `install_requires()` uses.
    pub fn new(subsystem: Subsystem, version_constraint: impl Into<String>) -> Self {
        Self {
            subsystem,
            version_constraint: version_constraint.into(),
        }
    }
}

/// Identifies a managed-dependency subsystem.
///
/// One variant per Install CRD kind. Used in `Dependency::subsystem` so
/// upgrade ordering constraints can name a peer without each controller
/// knowing about every other CRD type. The string representation is the
/// kind's kebab-case name (`cilium`, `cert-manager`, `victoria-metrics`).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Subsystem {
    CertManager,
    Cilium,
    Eso,
    GpuOperator,
    Istio,
    Keda,
    Kthena,
    MetricsServer,
    Rook,
    Tetragon,
    Velero,
    VictoriaMetrics,
    Volcano,
}

impl std::fmt::Display for Subsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertManager => write!(f, "cert-manager"),
            Self::Cilium => write!(f, "cilium"),
            Self::Eso => write!(f, "eso"),
            Self::GpuOperator => write!(f, "gpu-operator"),
            Self::Istio => write!(f, "istio"),
            Self::Keda => write!(f, "keda"),
            Self::Kthena => write!(f, "kthena"),
            Self::MetricsServer => write!(f, "metrics-server"),
            Self::Rook => write!(f, "rook"),
            Self::Tetragon => write!(f, "tetragon"),
            Self::Velero => write!(f, "velero"),
            Self::VictoriaMetrics => write!(f, "victoria-metrics"),
            Self::Volcano => write!(f, "volcano"),
        }
    }
}

/// Observed-state shape shared by every Install CRD.
///
/// Every dependency reports the same lifecycle fields — adding per-component
/// diagnostic fields here lets one controller expose them (e.g. Istio's
/// derived `trust_domain`) without spawning a new status type per CRD.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InstallStatus {
    #[serde(default)]
    pub phase: InstallPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Istio-specific: trust domain currently in use (derived from `lattice-ca`).
    /// Other controllers leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upgrade: Option<UpgradeAttempt>,
    /// SHA-256 (hex) of the rendered manifest bundle that produced the
    /// current `Ready` state. The reconciler skips its server-side apply
    /// loop when this matches the desired manifest hash, which is what
    /// keeps steady-state CPU on the apiserver near zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_manifest_hash: Option<String>,
}

/// Lifecycle phase of a dependency Install CRD.
///
/// Every per-dependency controller drives its CR through the same phases, even
/// though the work inside each phase is component-specific.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum InstallPhase {
    /// Resource just created or pre-flight in progress.
    #[default]
    Pending,
    /// Pre-flight validation failed; awaiting spec correction.
    PreFlightFailed,
    /// First-time install in progress.
    Installing,
    /// `spec.version` differs from `status.observedVersion`; upgrade in progress.
    Upgrading,
    /// Upgrade failed health gate; restoring previous state.
    RollingBack,
    /// Desired version installed and healthy.
    Ready,
    /// Terminal failure; human intervention required.
    Failed,
}

impl std::fmt::Display for InstallPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::PreFlightFailed => write!(f, "PreFlightFailed"),
            Self::Installing => write!(f, "Installing"),
            Self::Upgrading => write!(f, "Upgrading"),
            Self::RollingBack => write!(f, "RollingBack"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Upgrade policy shared by all dependency Install CRDs.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpgradePolicy {
    /// Automatically roll back to the previous version when an upgrade
    /// fails a health gate. Currently informational — the rollback driver
    /// (vendored prior-version manifest render + re-apply + soak) is
    /// reserved for the upgrade-orchestrator follow-up; today the
    /// controller simply marks a failed install `Failed` regardless of
    /// this flag.
    #[serde(default = "super::default_true")]
    pub auto_rollback: bool,
}

impl Default for UpgradePolicy {
    fn default() -> Self {
        Self {
            auto_rollback: true,
        }
    }
}

/// One install or upgrade attempt recorded in status for audit.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAttempt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    pub to_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<UpgradeOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl UpgradeAttempt {
    /// Open a fresh attempt, resume an in-flight one, or return a completed
    /// one verbatim when nothing has changed.
    ///
    /// Idempotency rule: if `prior` describes the same `(from_version,
    /// to_version)` transition, return it unchanged — whether it's still
    /// in-flight or already terminal. This is what stops steady-state
    /// reconciles from stamping a fresh `started_at` and mutating status,
    /// which would fire the controller's own watch and create a hot loop.
    /// Only a genuine retarget (different `to_version` / `from_version`)
    /// stamps a new `started_at`.
    pub fn started(
        prior: Option<&Self>,
        target_version: impl Into<String>,
        from_version: Option<&str>,
    ) -> Self {
        let target_version = target_version.into();
        let from = from_version.map(str::to_string);
        if let Some(p) = prior {
            if p.to_version == target_version && p.from_version == from {
                return p.clone();
            }
        }
        Self {
            from_version: from,
            to_version: target_version,
            started_at: Some(chrono::Utc::now().to_rfc3339()),
            completed_at: None,
            outcome: None,
            failure_reason: None,
        }
    }

    /// Stamp terminal fields onto an in-progress attempt.
    ///
    /// Idempotency rule: if `self` already records the same `outcome` and
    /// `failure_reason`, return it unchanged so steady-state reconciles
    /// don't keep stamping fresh `completed_at` values. `failure_reason` is
    /// only meaningful for `UpgradeOutcome::Failed` / `RolledBack`; pass
    /// `None` for `Succeeded`.
    pub fn finished(&self, outcome: UpgradeOutcome, failure_reason: Option<String>) -> Self {
        if self.outcome == Some(outcome) && self.failure_reason == failure_reason {
            return self.clone();
        }
        Self {
            completed_at: Some(chrono::Utc::now().to_rfc3339()),
            outcome: Some(outcome),
            failure_reason,
            ..self.clone()
        }
    }
}

/// Terminal outcome of an upgrade attempt.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum UpgradeOutcome {
    Succeeded,
    RolledBack,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_records_initial_install() {
        let a = UpgradeAttempt::started(None, "1.19.1", None);
        assert_eq!(a.from_version, None);
        assert_eq!(a.to_version, "1.19.1");
        assert!(a.started_at.is_some());
        assert_eq!(a.completed_at, None);
        assert_eq!(a.outcome, None);
    }

    #[test]
    fn started_records_upgrade_from_prior_observed() {
        let a = UpgradeAttempt::started(None, "1.19.1", Some("1.18.0"));
        assert_eq!(a.from_version.as_deref(), Some("1.18.0"));
        assert_eq!(a.to_version, "1.19.1");
    }

    #[test]
    fn started_preserves_timestamp_within_attempt() {
        // Mid-flight reconcile must not reset duration metrics.
        let prior = UpgradeAttempt {
            from_version: Some("1.18.0".into()),
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: None,
            outcome: None,
            failure_reason: None,
        };
        let a = UpgradeAttempt::started(Some(&prior), "1.19.1", Some("1.18.0"));
        assert_eq!(a.started_at.as_deref(), Some("2026-04-25T10:00:00Z"));
    }

    #[test]
    fn started_resets_on_retarget() {
        // Different to_version → fresh attempt, prior open one is abandoned.
        let prior = UpgradeAttempt {
            from_version: Some("1.18.0".into()),
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: None,
            outcome: None,
            failure_reason: None,
        };
        let a = UpgradeAttempt::started(Some(&prior), "1.19.2", Some("1.18.0"));
        assert_ne!(a.started_at.as_deref(), Some("2026-04-25T10:00:00Z"));
        assert_eq!(a.to_version, "1.19.2");
    }

    #[test]
    fn started_returns_completed_attempt_verbatim() {
        // Steady-state reconcile after success: must not stamp a new
        // started_at, otherwise the status patch fires the self-watch.
        let prior = UpgradeAttempt {
            from_version: Some("1.18.0".into()),
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: Some("2026-04-25T10:01:00Z".into()),
            outcome: Some(UpgradeOutcome::Succeeded),
            failure_reason: None,
        };
        let a = UpgradeAttempt::started(Some(&prior), "1.19.1", Some("1.18.0"));
        assert_eq!(a, prior);
    }

    #[test]
    fn finished_returns_self_when_outcome_unchanged() {
        // Steady-state reconcile must not restamp completed_at.
        let done = UpgradeAttempt {
            from_version: Some("1.18.0".into()),
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: Some("2026-04-25T10:01:00Z".into()),
            outcome: Some(UpgradeOutcome::Succeeded),
            failure_reason: None,
        };
        let again = done.finished(UpgradeOutcome::Succeeded, None);
        assert_eq!(again, done);
    }

    #[test]
    fn finished_restamps_when_outcome_changes() {
        let started = UpgradeAttempt {
            from_version: None,
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: Some("2026-04-25T10:00:30Z".into()),
            outcome: Some(UpgradeOutcome::Failed),
            failure_reason: Some("readiness gate failed".into()),
        };
        let recovered = started.finished(UpgradeOutcome::Succeeded, None);
        assert_eq!(recovered.outcome, Some(UpgradeOutcome::Succeeded));
        assert_eq!(recovered.failure_reason, None);
        assert_ne!(recovered.completed_at, started.completed_at);
    }

    #[test]
    fn finished_stamps_terminal_fields() {
        let started = UpgradeAttempt {
            from_version: Some("1.18.0".into()),
            to_version: "1.19.1".into(),
            started_at: Some("2026-04-25T10:00:00Z".into()),
            completed_at: None,
            outcome: None,
            failure_reason: None,
        };
        let done = started.finished(UpgradeOutcome::Succeeded, None);
        assert_eq!(done.outcome, Some(UpgradeOutcome::Succeeded));
        assert!(done.completed_at.is_some());
        assert_eq!(done.from_version.as_deref(), Some("1.18.0"));

        let failed = started.finished(UpgradeOutcome::Failed, Some("readiness gate failed".into()));
        assert_eq!(failed.outcome, Some(UpgradeOutcome::Failed));
        assert_eq!(
            failed.failure_reason.as_deref(),
            Some("readiness gate failed"),
        );
    }
}
