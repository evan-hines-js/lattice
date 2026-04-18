//! Tetragon dependency install.
//!
//! Owns the Tetragon helm chart manifests and the cluster-wide baseline
//! TracingPolicy that blocks dangerous LSM-hook operations for all
//! Lattice-managed pods. Future work (Phase 2): the TetragonInstall controller
//! that reconciles the TetragonInstall CRD through install → ready → upgrade.
//!
//! The workload-level TracingPolicy compiler is a separate concern and lives in
//! `lattice-tetragon-policy`.

pub mod install;
