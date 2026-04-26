//! Volcano install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use lattice_crd::crd::{Dependency, Subsystem};

/// `VolcanoInstall.spec.requires`. Needs CNI for scheduler/controller
/// pod networking and cert-manager for the admission-webhook cert.
pub fn install_requires() -> Vec<Dependency> {
    vec![
        Dependency::new(Subsystem::Cilium, ">=1.18, <2"),
        Dependency::new(Subsystem::CertManager, ">=1.18, <2"),
    ]
}
