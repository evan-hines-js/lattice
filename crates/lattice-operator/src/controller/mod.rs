//! Controller implementations for Lattice CRDs
//!
//! Re-exports controllers from lattice-cluster and lattice-service.
//! lattice-operator starts and manages these controllers.

// Re-export cluster controller (CAPIClient/CAPIClientImpl now from lattice_capi via lattice_cluster lib.rs)
pub use lattice_cluster::controller::{
    error_policy, reconcile, Context, ContextBuilder, KubeClient, KubeClientImpl, PivotOperations,
    PivotOperationsImpl, UnpivotChannel, UnpivotRequest,
};
pub use lattice_cluster::{CAPIClient, CAPIClientImpl};

// Re-export service controller
pub use lattice_service::controller::{
    cleanup_external_service, cleanup_service, error_policy as service_error_policy,
    error_policy_external, reconcile as service_reconcile, reconcile_external, ServiceContext,
    ServiceKubeClient, ServiceKubeClientImpl,
};
