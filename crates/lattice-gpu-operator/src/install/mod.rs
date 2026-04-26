//! GPU Operator install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::ensure_install;

use lattice_crd::crd::{Dependency, Subsystem};

/// `GpuOperatorInstall.spec.requires`. Needs CNI for the device-plugin /
/// dcgm DaemonSets and cert-manager for the validating-webhook cert.
pub fn install_requires() -> Vec<Dependency> {
    vec![
        Dependency::new(Subsystem::Cilium, ">=1.18, <2"),
        Dependency::new(Subsystem::CertManager, ">=1.18, <2"),
    ]
}

/// Namespace the GPU Operator chart renders into.
pub const NAMESPACE: &str = "gpu-operator";
