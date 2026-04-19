//! Kthena install module.

pub mod controller;
pub mod ensure;
pub mod manifests;
pub mod policies;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

/// Namespace the Kthena chart renders into.
pub const NAMESPACE: &str = "kthena-system";
