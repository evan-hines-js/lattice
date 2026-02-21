//! Volcano compiler crate for Lattice batch and model serving workloads
//!
//! Compiles `LatticeJob` specs into Volcano VCJob resources and `LatticeModel`
//! specs into Kthena ModelServing resources for gang scheduling.
//! Pure compilation crate — no controller logic.

mod compiler;
mod model_serving_compiler;
pub mod routing_compiler;
mod types;

pub use compiler::compile_vcjob;
pub use model_serving_compiler::{compile_model_serving, RoleTemplates};
pub use routing_compiler::{compile_model_routing, CompiledRouting};
pub use types::{
    GangPolicy, KthenaHeaderMatch, KthenaKvConnector, KthenaModelMatch, KthenaModelRoute,
    KthenaModelRouteSpec, KthenaModelServer, KthenaModelServerSpec, KthenaNetworkingMetadata,
    KthenaParentRef, KthenaRateLimit, KthenaRetryPolicy, KthenaRouteRule, KthenaTargetModel,
    KthenaTrafficPolicy,
    ModelServing, ModelServingMetadata, ModelServingRole, ModelServingSpec, PdGroup,
    RollingUpdateConfiguration, RolloutStrategy, ServingGroupTemplate, VCJob, VCJobSpec, VCJobTask,
    VCJobTaskPolicy, WorkloadPort, WorkloadSelector,
};
