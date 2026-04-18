//! ESOInstall CRD — desired state for the External Secrets Operator install.
//!
//! Singleton cluster-scoped CRD. The `lattice-eso` crate owns the controller.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallPhase, UpgradeAttempt, UpgradePolicy};
use crate::crd::types::Condition;

/// Desired state for the ESO install on this cluster.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "ESOInstall",
    plural = "esoinstalls",
    shortname = "eso",
    status = "ESOInstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ESOInstallSpec {
    /// Desired ESO version.
    pub version: String,

    /// Upgrade strategy overrides.
    #[serde(default)]
    pub upgrade_policy: UpgradePolicy,
}

/// Observed state reported by the ESO install controller.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ESOInstallStatus {
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upgrade: Option<UpgradeAttempt>,
}
