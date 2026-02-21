//! Backup and restore controllers for Lattice
//!
//! This crate provides controllers that manage Velero resources for backup/restore:
//!
//! - **backup_store_controller**: Reconciles BackupStore CRDs into Velero
//!   BackupStorageLocation resources
//! - **cluster_backup_controller**: Reconciles LatticeClusterBackup CRDs into Velero
//!   Schedule resources, resolving BackupStore references
//! - **service_backup_controller**: Watches LatticeService resources and creates Velero
//!   Schedule resources for services with `spec.backup.schedule`
//! - **restore_controller**: Reconciles LatticeRestore CRDs into Velero Restore resources
//! - **velero**: Typed structs for Velero resources (Schedule, BSL, Restore)

pub mod backup_store_controller;
pub mod cluster_backup_controller;
pub mod restore_controller;
pub mod service_backup_controller;
pub mod velero;

/// Requeue interval on successful reconciliation (5 minutes)
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval when a required CRD (e.g. Velero) is not found (30 seconds)
const REQUEUE_CRD_NOT_FOUND_SECS: u64 = 30;
/// Requeue interval on error (1 minute)
const REQUEUE_ERROR_SECS: u64 = 60;
/// Requeue interval while an operation is in progress (15 seconds)
const REQUEUE_IN_PROGRESS_SECS: u64 = 15;
