//! VictoriaMetrics install module.

pub mod controller;
pub mod ensure;
pub mod manifests;
pub mod policies;

pub use controller::reconcile;
pub use ensure::ensure_install;

use lattice_crd::crd::{Dependency, Subsystem};

/// `VictoriaMetricsInstall.spec.requires`. Needs CNI for scraping pod
/// targets and cert-manager for the vmoperator webhook cert.
pub fn install_requires() -> Vec<Dependency> {
    vec![
        Dependency::new(Subsystem::Cilium, ">=1.18, <2"),
        Dependency::new(Subsystem::CertManager, ">=1.18, <2"),
    ]
}
