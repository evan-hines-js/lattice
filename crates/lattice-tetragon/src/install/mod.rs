//! Tetragon install — manifests, reconciler, and health signals for the
//! Tetragon dependency owned by this crate.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use lattice_crd::crd::{Dependency, Subsystem};

/// `TetragonInstall.spec.requires`. Tetragon's agent talks to the
/// apiserver via pod networking, so CNI must be up.
pub fn install_requires() -> Vec<Dependency> {
    vec![Dependency::new(Subsystem::Cilium, ">=1.18, <2")]
}
