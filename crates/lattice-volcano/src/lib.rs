//! Volcano compiler crate for Lattice batch and model serving workloads
//!
//! Compiles `LatticeJob` specs into Volcano VCJob resources and `LatticeModel`
//! specs into Kthena ModelServing resources for gang scheduling.
//! Pure compilation crate — no controller logic.

pub mod autoscaling_compiler;
mod compiler;
mod model_serving_compiler;
pub mod routing_compiler;
mod types;

pub use autoscaling_compiler::{compile_model_autoscaling, CompiledAutoscaling};
pub use compiler::compile_vcjob;
pub use model_serving_compiler::{compile_model_serving, RoleTemplates};
pub use routing_compiler::{compile_model_routing, CompiledRouting};
pub use types::{
    GangPolicy, KthenaAutoscalingBehavior, KthenaAutoscalingMetric, KthenaAutoscalingPolicy,
    KthenaAutoscalingPolicyBinding, KthenaAutoscalingPolicyBindingSpec,
    KthenaAutoscalingPolicySpec, KthenaAutoscalingTarget, KthenaHeaderMatch,
    KthenaHomogeneousTarget, KthenaKvConnector, KthenaMetricEndpoint, KthenaModelMatch,
    KthenaModelRoute, KthenaModelRouteSpec, KthenaModelServer, KthenaModelServerSpec,
    KthenaNetworkingMetadata, KthenaPanicPolicy, KthenaParentRef, KthenaPolicyRef, KthenaRateLimit,
    KthenaRetryPolicy, KthenaRouteRule, KthenaScaleDownBehavior, KthenaScaleUpBehavior,
    KthenaStablePolicy, KthenaSubTarget, KthenaTargetModel, KthenaTargetRef, KthenaTrafficPolicy,
    ModelServing, ModelServingMetadata, ModelServingRole, ModelServingSpec, PdGroup,
    RollingUpdateConfiguration, RolloutStrategy, ServingGroupTemplate, VCJob, VCJobSpec, VCJobTask,
    VCJobTaskPolicy, WorkloadPort, WorkloadSelector,
};
