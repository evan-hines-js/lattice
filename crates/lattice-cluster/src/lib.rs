//! Cluster lifecycle management for Lattice
//!
//! This crate provides the Kubernetes controller for LatticeCluster CRDs.
//!
//! Related crates:
//! - `lattice-cell`: Parent cluster infrastructure (servers, connections)
//! - `lattice-agent`: Child cluster runtime (agent client)
//! - `lattice-capi`: CAPI provider management

pub mod controller;
pub mod provider;

// Re-export controller types
pub use controller::{
    error_policy, reconcile, CAPIClient, CAPIClientImpl, Context, ContextBuilder, KubeClient,
    KubeClientImpl, PivotOperations, PivotOperationsImpl, UnpivotChannel, UnpivotRequest,
};

// Re-export provider types
pub use provider::{create_provider, CAPIManifest, Provider};

// Re-export common error types
pub use lattice_common::{Error, Result};
