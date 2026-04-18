//! TetragonInstall CRD — desired state for the Tetragon dependency.
//!
//! Singleton cluster-scoped CRD. One per cluster, typically named `default`.
//! The `lattice-tetragon` crate owns the controller that reconciles it.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallPhase, UpgradeAttempt, UpgradePolicy};
use crate::crd::types::Condition;

/// Desired state for the Tetragon install on this cluster.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "TetragonInstall",
    plural = "tetragoninstalls",
    shortname = "ti",
    status = "TetragonInstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TetragonInstallSpec {
    /// Desired Tetragon version. Defaults to the version bundled in the Lattice
    /// binary; the LatticeCluster orchestrator patches this on Lattice upgrades.
    pub version: String,

    /// Upgrade strategy overrides.
    #[serde(default)]
    pub upgrade_policy: UpgradePolicy,
}

/// Observed state reported by the Tetragon install controller.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TetragonInstallStatus {
    /// Current lifecycle phase.
    #[serde(default)]
    pub phase: InstallPhase,

    /// Generation of `spec` last processed by the controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Version last successfully applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_version: Option<String>,

    /// Version currently being installed or upgraded to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,

    /// Human-readable status message (error detail, progress hint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Standard Kubernetes-style conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Most recent install or upgrade attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upgrade: Option<UpgradeAttempt>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_serde_roundtrip() {
        let spec = TetragonInstallSpec {
            version: "1.6.0".to_string(),
            upgrade_policy: UpgradePolicy::default(),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let back: TetragonInstallSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn status_default_phase_is_pending() {
        let status = TetragonInstallStatus::default();
        assert_eq!(status.phase, InstallPhase::Pending);
    }

    #[test]
    fn status_omits_empty_optionals_in_json() {
        let status = TetragonInstallStatus::default();
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(!json.contains("observedGeneration"));
        assert!(!json.contains("observedVersion"));
        assert!(!json.contains("conditions"));
    }
}
