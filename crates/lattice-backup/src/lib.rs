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
