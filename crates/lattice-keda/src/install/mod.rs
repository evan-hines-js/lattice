//! KEDA install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::ensure_install;

use lattice_crd::crd::{Dependency, Subsystem};

/// `KedaInstall.spec.requires`. Needs CNI for in-cluster API access and
/// cert-manager for the admission-webhook cert.
pub fn install_requires() -> Vec<Dependency> {
    vec![
        Dependency::new(Subsystem::Cilium, ">=1.18, <2"),
        Dependency::new(Subsystem::CertManager, ">=1.18, <2"),
    ]
}

/// Namespace the KEDA chart renders into.
pub const NAMESPACE: &str = "keda";
