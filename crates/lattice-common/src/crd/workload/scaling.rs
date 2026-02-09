//! Replica scaling and autoscaling specifications shared across all Lattice workload CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Replica scaling specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ReplicaSpec {
    /// Minimum replicas
    #[serde(default)]
    pub min: u32,

    /// Maximum replicas
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,

    /// Custom autoscaling metrics (defaults to cpu at 80% if empty)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub autoscaling: Vec<AutoscalingMetric>,
}

impl Default for ReplicaSpec {
    fn default() -> Self {
        Self {
            min: 1,
            max: None,
            autoscaling: vec![],
        }
    }
}

/// Autoscaling metric specification
///
/// Built-in metrics ("cpu", "memory") use resource utilization percentage.
/// Custom metrics (e.g. "vllm_num_requests_waiting") use pods average value.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct AutoscalingMetric {
    /// Metric name ("cpu", "memory", or a custom Prometheus metric)
    pub metric: String,
    /// Target value (percentage for cpu/memory, absolute for custom metrics)
    pub target: u32,
}
