//! Rook-Ceph install module.

pub mod controller;
pub mod manifests;

pub use controller::reconcile;

use lattice_crd::crd::{Dependency, Subsystem};

/// `RookInstall.spec.requires`. Ceph mons + OSDs need pod networking;
/// the CNI must be up before any of it.
pub fn install_requires() -> Vec<Dependency> {
    vec![Dependency::new(Subsystem::Cilium, ">=1.18, <2")]
}
