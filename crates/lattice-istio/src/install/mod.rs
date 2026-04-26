//! Istio install module.

pub mod controller;
pub mod ensure;
pub mod manifests;
pub mod trust_domain;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};
pub use trust_domain::{resolve_istio_ca, trust_domain_from_ca, IstioCaConfig};

use lattice_crd::crd::{Dependency, Subsystem};

/// `IstioInstall.spec.requires`. Ambient mode programs endpoints on top
/// of Cilium's eBPF routing — istiod can't converge until the CNI is
/// observed-Ready.
pub fn install_requires() -> Vec<Dependency> {
    vec![Dependency::new(Subsystem::Cilium, ">=1.18, <2")]
}
