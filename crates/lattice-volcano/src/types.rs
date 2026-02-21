//! Volcano VCJob serialization types
//!
//! Typed representation of Volcano `batch.volcano.sh/v1alpha1` Job resources.
//! Uses serde for JSON serialization compatible with server-side apply.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Volcano VCJob resource (`batch.volcano.sh/v1alpha1` Kind: Job)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJob {
    pub api_version: String,
    pub kind: String,
    pub metadata: VCJobMetadata,
    pub spec: VCJobSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

/// VCJob spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobSpec {
    pub scheduler_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retry: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,

    pub tasks: Vec<VCJobTask>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,
}

/// A single task within a VCJob
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTask {
    pub name: String,
    pub replicas: u32,
    /// Pod template — passed through as pre-serialized JSON from the workload compiler
    pub template: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,
}

/// Volcano lifecycle policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTaskPolicy {
    pub event: String,
    pub action: String,
}

/// Kthena ModelServing resource (`workload.serving.volcano.sh/v1alpha1` Kind: ModelServing)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServing {
    pub api_version: String,
    pub kind: String,
    pub metadata: ModelServingMetadata,
    pub spec: ModelServingSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingSpec {
    pub scheduler_name: String,
    pub replicas: u32,
    pub template: ServingGroupTemplate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_strategy: Option<RolloutStrategy>,
}

/// Template for a serving group containing named roles and gang scheduling policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServingGroupTemplate {
    pub roles: Vec<ModelServingRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gang_policy: Option<GangPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_grace_period_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<serde_json::Value>,
}

/// A single role within a ModelServing (e.g. prefill, decode)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingRole {
    pub name: String,
    pub replicas: u32,
    /// Entry pod template — passed through as pre-serialized JSON from the workload compiler
    pub entry_template: serde_json::Value,
    /// Number of worker replicas (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_replicas: Option<u32>,
    /// Worker pod template (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_template: Option<serde_json::Value>,
}

/// Gang scheduling policy for coordinated role startup
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GangPolicy {
    /// Minimum replicas per role required for the gang to start
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_role_replicas: BTreeMap<String, u32>,
}

/// Rollout strategy for serving updates
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RolloutStrategy {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfiguration>,
}

/// Configuration for rolling update strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcjob_serialization_roundtrip() {
        let vcjob = VCJob {
            api_version: "batch.volcano.sh/v1alpha1".to_string(),
            kind: "Job".to_string(),
            metadata: VCJobMetadata {
                name: "test-job".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: VCJobSpec {
                scheduler_name: "volcano".to_string(),
                min_available: Some(2),
                max_retry: None,
                queue: None,
                priority_class_name: None,
                tasks: vec![],
                policies: vec![],
            },
        };

        let json = serde_json::to_string(&vcjob).unwrap();
        let de: VCJob = serde_json::from_str(&json).unwrap();
        assert_eq!(vcjob, de);
    }

    #[test]
    fn model_serving_serialization_roundtrip() {
        let ms = ModelServing {
            api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
            kind: "ModelServing".to_string(),
            metadata: ModelServingMetadata {
                name: "test-model".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: ModelServingSpec {
                scheduler_name: "volcano".to_string(),
                replicas: 1,
                template: ServingGroupTemplate {
                    roles: vec![ModelServingRole {
                        name: "decode".to_string(),
                        replicas: 2,
                        entry_template: serde_json::json!({"spec": {"containers": []}}),
                        worker_replicas: Some(4),
                        worker_template: Some(
                            serde_json::json!({"spec": {"containers": [{"name": "worker"}]}}),
                        ),
                    }],
                    gang_policy: Some(GangPolicy {
                        min_role_replicas: BTreeMap::from([("decode".to_string(), 2)]),
                    }),
                    restart_grace_period_seconds: Some(30),
                    network_topology: None,
                },
                recovery_policy: Some("RestartAll".to_string()),
                rollout_strategy: None,
            },
        };

        let json = serde_json::to_string(&ms).unwrap();
        let de: ModelServing = serde_json::from_str(&json).unwrap();
        assert_eq!(ms, de);

        // Verify camelCase serialization of key fields
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let role = &value["spec"]["template"]["roles"][0];
        assert!(role.get("entryTemplate").is_some());
        assert!(role.get("workerReplicas").is_some());
        assert!(role.get("workerTemplate").is_some());
        assert!(
            value["spec"]["template"]
                .get("restartGracePeriodSeconds")
                .is_some()
        );
    }
}
