//! Volcano dependency install.
//!
//! Owns the Volcano helm manifests (gang scheduling), the vGPU device plugin
//! DaemonSet, mesh enrollment (admission webhook + controllers + scheduler),
//! and the VolcanoInstall controller.
//!
//! Distinct from `lattice-volcano-policy`, which compiles user `LatticeJob` /
//! `LatticeModel` specs into Volcano VCJob / Kthena ModelServing resources.

pub mod install;
