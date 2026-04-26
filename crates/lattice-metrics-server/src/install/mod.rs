//! metrics-server install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::ensure_install;

use lattice_crd::crd::{Dependency, Subsystem};

/// `MetricsServerInstall.spec.requires`. Needs CNI to scrape kubelet
/// `/metrics` over pod networking.
pub fn install_requires() -> Vec<Dependency> {
    vec![Dependency::new(Subsystem::Cilium, ">=1.18, <2")]
}
