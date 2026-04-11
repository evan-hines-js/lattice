//! Service workload compilation and controller for Lattice
//!
//! This crate compiles LatticeService CRDs into Kubernetes workload resources:
//!
//! - **Compiler**: Compiles LatticeService CRDs to Deployments, Services, MeshMembers, etc.
//! - **Workload**: Generates Deployments, Services, PVCs, and related resources
//! - **Controller**: Kubernetes controller for LatticeService/ExternalService CRDs

pub mod compiler;
pub mod controller;
pub mod workload;

pub(crate) use lattice_common::Error;
pub(crate) use lattice_crd::crd;
pub(crate) use lattice_graph as graph;
