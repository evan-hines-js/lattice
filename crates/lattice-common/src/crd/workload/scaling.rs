//! Replica scaling and autoscaling specifications shared across all Lattice workload CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Autoscaling specification for KEDA-based horizontal pod autoscaling.
///
/// When present, KEDA scales the workload between `replicas` (from the parent spec)
/// and `max` replicas based on the configured metrics.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct AutoscalingSpec {
    /// Maximum replicas KEDA can scale to
    pub max: u32,

    /// Custom autoscaling metrics (defaults to cpu at 80% if empty)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<AutoscalingMetric>,
}

impl AutoscalingSpec {
    /// Validate autoscaling metric targets.
    pub fn validate(&self) -> Result<(), crate::Error> {
        for m in &self.metrics {
            if m.target == 0 {
                return Err(crate::Error::validation(format!(
                    "autoscaling metric '{}' target must be greater than 0",
                    m.metric
                )));
            }
            if (m.metric == "cpu" || m.metric == "memory") && m.target > 100 {
                return Err(crate::Error::validation(format!(
                    "autoscaling metric '{}' target cannot exceed 100%",
                    m.metric
                )));
            }
        }
        Ok(())
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
