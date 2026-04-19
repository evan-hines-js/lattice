//! KEDA install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

/// Namespace the KEDA chart renders into.
pub const NAMESPACE: &str = "keda";
