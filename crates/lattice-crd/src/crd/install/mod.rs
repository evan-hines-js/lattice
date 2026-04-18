//! Install CRDs for managed dependencies (Istio, Cilium, Tetragon, etc.).
//!
//! Each dependency is installed and upgraded by its own controller. The CRDs
//! in this module describe desired state (version, upgrade policy) and report
//! observed state (phase, current version, health). Shared types — the install
//! lifecycle phase enum and the upgrade policy — live here. Per-component CRDs
//! are in sibling modules.

pub mod tetragon;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// Automatically roll back to the previous version on health-gate breach.
    #[serde(default = "super::default_true")]
    pub auto_rollback: bool,
    /// Health signal thresholds for gating upgrade progress.
    #[serde(default)]
    pub health_gate: HealthGate,
}

impl Default for UpgradePolicy {
    fn default() -> Self {
        Self {
            auto_rollback: true,
            health_gate: HealthGate::default(),
        }
    }
}

/// Health-gate settings used during upgrade verification.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HealthGate {
    /// Seconds of sustained healthy signal required before advancing a phase.
    #[serde(default = "default_stabilization_seconds")]
    pub stabilization_seconds: u32,
}

impl Default for HealthGate {
    fn default() -> Self {
        Self {
            stabilization_seconds: default_stabilization_seconds(),
        }
    }
}

fn default_stabilization_seconds() -> u32 {
    300
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

/// Terminal outcome of an upgrade attempt.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum UpgradeOutcome {
    Succeeded,
    RolledBack,
    Failed,
}
