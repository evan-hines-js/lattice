//! Tetragon install — manifests, reconciler, and health signals for the
//! Tetragon dependency owned by this crate.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};
