//! GPU Operator install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

/// Namespace the GPU Operator chart renders into.
pub const NAMESPACE: &str = "gpu-operator";
