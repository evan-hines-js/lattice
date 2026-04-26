//! Cluster lifecycle management for Lattice
//!
//! This crate provides the Kubernetes controller for LatticeCluster CRDs.
//!
//! Related crates:
//! - `lattice-cell`: Parent cluster infrastructure (servers, connections)
//! - `lattice-agent`: Child cluster runtime (agent client)
//! - `lattice-capi`: CAPI provider management and client

pub mod controller;
pub mod lb_cidr_resolver;
pub mod phases;

pub use lb_cidr_resolver::capi_lb_cidr_resolver;
