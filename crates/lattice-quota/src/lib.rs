//! Quota controller for Lattice
//!
//! Owns the `LatticeQuota` CRD lifecycle and drives CAPI autoscaling:
//!
//! - Validates quota specs and tracks per-principal resource usage in status
//! - Computes aggregate hard/soft limits across all quotas on the cluster
//! - Translates quota sums into MachineDeployment min/max annotations
//! - Pool-level `min`/`max` overrides always win over quota-derived values
//!
//! Soft quotas define the burst ceiling (autoscaler max). Hard quotas define
//! guaranteed reserved capacity (autoscaler min). Soft-only quotas allow
//! scale-to-zero; hard quotas keep nodes provisioned even when idle.

#![deny(missing_docs)]

mod controller;
pub mod enforcement;

pub use controller::reconcile;
