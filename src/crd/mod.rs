//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod cluster;
mod types;

pub use cluster::{LatticeCluster, LatticeClusterSpec, LatticeClusterStatus};
pub use types::{
    CellSpec, ClusterCondition, ClusterPhase, ConditionStatus, KubernetesSpec, NetworkPool,
    NetworkingSpec, NodeSpec, ProviderSpec, ProviderType, ServiceRef, ServiceSpec, WorkloadSpec,
};
