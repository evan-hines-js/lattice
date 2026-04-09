//! LatticePackage controller — Helm chart lifecycle with secret injection
//!
//! Reconciles LatticePackage CRDs through:
//! 1. Values tree expansion (collect referenced secrets)
//! 2. Cedar authorization (only referenced secrets)
//! 3. ExternalSecret generation + apply (only referenced secrets)
//! 4. Wait for synced Secrets
//! 5. Values resolution (substitute actual secret values + Secret names)
//! 6. Helm template (subprocess)
//! 7. Server-side apply rendered manifests
//! 8. MeshMember generation (optional)

mod controller;
mod error;
mod helm;
mod mesh;
mod secrets;

pub use controller::{reconcile, PackageContext};
pub use error::PackageError;
