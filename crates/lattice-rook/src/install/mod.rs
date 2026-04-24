//! Rook-Ceph install module.

pub mod controller;
pub mod manifests;

pub use controller::reconcile;
