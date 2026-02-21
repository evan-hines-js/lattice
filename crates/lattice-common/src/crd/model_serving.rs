//! LatticeModel CRD types
//!
//! Defines `LatticeModel` — model serving workloads backed by Volcano ModelServing.
//! Each model contains named roles (e.g. prefill, decode), each with its own `WorkloadSpec`.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workload::ingress::IngressSpec;
use super::workload::spec::{RuntimeSpec, WorkloadSpec};

// =============================================================================
// Phase
// =============================================================================

/// Lifecycle phase of a LatticeModel serving workload
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ModelServingPhase {
    /// Model is waiting for configuration
    #[default]
    Pending,
    /// Model artifacts are being loaded
    Loading,
    /// Model is serving inference requests
    Serving,
    /// Model has encountered an error
    Failed,
}

impl std::fmt::Display for ModelServingPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Loading => write!(f, "Loading"),
            Self::Serving => write!(f, "Serving"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// Role Spec
// =============================================================================

/// A single role within a LatticeModel serving workload.
///
/// Each role maps to a Volcano ModelServing role (e.g. prefill, decode)
/// with separate entry and optional worker pod templates for disaggregated inference.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoleSpec {
    /// Number of entry replicas for this role
    #[serde(default = "default_one")]
    pub replicas: u32,

    /// Entry pod workload spec (containers, volumes, env, etc.)
    pub entry_workload: WorkloadSpec,

    /// Entry pod runtime extensions (sidecars, sysctls, hostNetwork, etc.)
    #[serde(default)]
    pub entry_runtime: RuntimeSpec,

    /// Number of worker replicas (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_replicas: Option<u32>,

    /// Worker pod workload spec (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_workload: Option<WorkloadSpec>,

    /// Worker pod runtime extensions (falls back to entry_runtime if None)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_runtime: Option<RuntimeSpec>,
}

fn default_one() -> u32 {
    1
}

fn default_scheduler() -> String {
    "volcano".to_string()
}

// =============================================================================
// CRD
// =============================================================================

/// Model serving workload specification backed by Volcano ModelServing
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeModel",
    plural = "latticemodels",
    shortname = "lm",
    namespaced,
    status = "LatticeModelStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeModelSpec {
    /// Volcano scheduler name
    #[serde(default = "default_scheduler")]
    pub scheduler_name: String,

    /// Recovery policy for the serving group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<String>,

    /// Grace period for restart
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_grace_period_seconds: Option<u32>,

    /// Model serving roles — each maps to a ModelServing role (e.g. prefill, decode)
    #[serde(default)]
    pub roles: BTreeMap<String, ModelRoleSpec>,

    /// Ingress configuration for exposing the model externally
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,
}

impl Default for LatticeModelSpec {
    fn default() -> Self {
        Self {
            scheduler_name: default_scheduler(),
            recovery_policy: None,
            restart_grace_period_seconds: None,
            roles: BTreeMap::new(),
            ingress: None,
        }
    }
}

/// Status of a LatticeModel serving workload
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeModelStatus {
    /// Current phase of the model serving lifecycle
    #[serde(default)]
    pub phase: ModelServingPhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Generation observed by the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Conditions reflecting detailed status from ModelServing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<ModelCondition>>,
}

/// A condition on a LatticeModel (mirrored from ModelServing status)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelCondition {
    /// Condition type (e.g. "Available", "Progressing", "UpdateInProgress")
    #[serde(rename = "type")]
    pub type_: String,

    /// Condition status: "True", "False", or "Unknown"
    pub status: String,

    /// Machine-readable reason for the condition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Timestamp of last transition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_spec_default_has_empty_roles() {
        let spec = LatticeModelSpec::default();
        assert!(spec.roles.is_empty());
        assert_eq!(spec.scheduler_name, "volcano");
    }

    #[test]
    fn model_role_spec_entry_only() {
        let role = ModelRoleSpec {
            replicas: 2,
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
        };
        assert!(role.entry_workload.containers.is_empty());
        assert_eq!(role.replicas, 2);
        assert_eq!(role.worker_replicas, None);
    }

    #[test]
    fn model_role_spec_with_workers() {
        let role = ModelRoleSpec {
            replicas: 1,
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: Some(4),
            worker_workload: Some(WorkloadSpec::default()),
            worker_runtime: None,
        };
        assert_eq!(role.replicas, 1);
        assert_eq!(role.worker_replicas, Some(4));
        assert!(role.worker_workload.is_some());
        assert!(role.worker_runtime.is_none());
    }

    #[test]
    fn model_with_multiple_roles() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "prefill".to_string(),
            ModelRoleSpec {
                replicas: 1,
                entry_workload: WorkloadSpec::default(),
                entry_runtime: RuntimeSpec::default(),
                worker_replicas: None,
                worker_workload: None,
                worker_runtime: None,
            },
        );
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: 2,
                entry_workload: WorkloadSpec::default(),
                entry_runtime: RuntimeSpec::default(),
                worker_replicas: Some(4),
                worker_workload: Some(WorkloadSpec::default()),
                worker_runtime: None,
            },
        );

        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };

        assert_eq!(spec.roles.len(), 2);
        assert_eq!(spec.roles["prefill"].replicas, 1);
        assert_eq!(spec.roles["decode"].replicas, 2);
        assert_eq!(spec.roles["decode"].worker_replicas, Some(4));
    }

    #[test]
    fn model_serving_phase_display() {
        assert_eq!(ModelServingPhase::Pending.to_string(), "Pending");
        assert_eq!(ModelServingPhase::Loading.to_string(), "Loading");
        assert_eq!(ModelServingPhase::Serving.to_string(), "Serving");
        assert_eq!(ModelServingPhase::Failed.to_string(), "Failed");
    }
}
