//! Cilium install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use lattice_crd::crd::Dependency;

/// `CiliumInstall.spec.requires`. Cilium is the CNI substrate — no
/// managed-subsystem dependencies.
pub fn install_requires() -> Vec<Dependency> {
    Vec::new()
}

include!(concat!(env!("OUT_DIR"), "/kube_proxy_replacement.rs"));
