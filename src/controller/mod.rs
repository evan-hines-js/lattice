//! Controller implementations for Lattice CRDs
//!
//! This module contains the reconciliation logic for all Lattice custom resources.
//! Controllers follow the Kubernetes controller pattern with observe-diff-act loops.

mod cluster;

pub use cluster::{
    error_policy, reconcile, CellCapabilities, ClusterBootstrap, ClusterBootstrapImpl, Context,
    ContextBuilder, KubeClient, KubeClientImpl, PivotOperations, PivotOperationsImpl,
};
