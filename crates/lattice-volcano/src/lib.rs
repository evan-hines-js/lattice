//! Volcano compiler crate for Lattice batch and model serving workloads
//!
//! Compiles `LatticeJob` specs into Volcano VCJob resources and `LatticeModel`
//! specs into Kthena ModelServing resources for gang scheduling.
//! Pure compilation crate — no controller logic.

mod compiler;
mod model_serving_compiler;
mod types;

pub use compiler::compile_vcjob;
pub use model_serving_compiler::compile_model_serving;
pub use types::{
    GangPolicy, ModelServing, ModelServingMetadata, ModelServingRole, ModelServingSpec,
    RollingUpdateConfiguration, RolloutStrategy, ServingGroupTemplate, VCJob, VCJobSpec, VCJobTask,
    VCJobTaskPolicy,
};
