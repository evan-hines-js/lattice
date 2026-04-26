//! Cilium install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

include!(concat!(env!("OUT_DIR"), "/kube_proxy_replacement.rs"));
