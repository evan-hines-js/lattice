//! Kthena install module.

pub mod controller;
pub mod ensure;
pub mod manifests;
pub mod policies;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use lattice_crd::crd::{Dependency, Subsystem};

/// `KthenaInstall.spec.requires`. Kthena schedules onto Volcano queues,
/// so Volcano must be observed-Ready before kthena's controllers will
/// succeed.
pub fn install_requires() -> Vec<Dependency> {
    vec![
        Dependency::new(Subsystem::Cilium, ">=1.18, <2"),
        Dependency::new(Subsystem::Volcano, ">=1.12, <2"),
    ]
}

/// Namespace the Kthena chart renders into.
pub const NAMESPACE: &str = "kthena-system";
