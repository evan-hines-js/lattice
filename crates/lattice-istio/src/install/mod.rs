//! Istio install module.

pub mod controller;
pub mod ensure;
pub mod manifests;
pub mod trust_domain;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};
pub use trust_domain::{resolve_istio_ca, trust_domain_from_ca, IstioCaConfig};
