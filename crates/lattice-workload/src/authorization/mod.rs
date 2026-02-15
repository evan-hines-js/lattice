//! Authorization for workload compilation (pub(crate))
//!
//! Only called by WorkloadCompiler — not exposed to CRD compilers.

pub(crate) mod secrets;
pub(crate) mod security;
pub(crate) mod volumes;

use lattice_common::graph::ServiceGraph;

/// Pluggable principal format for Cedar authorization
pub trait PrincipalFormatter: Send + Sync {
    fn format_principal(&self, namespace: &str, name: &str) -> String;
}

/// Principal format for LatticeService CRDs
pub struct ServicePrincipal;

impl PrincipalFormatter for ServicePrincipal {
    fn format_principal(&self, namespace: &str, name: &str) -> String {
        format!("Lattice::Service::\"{}/{}\"", namespace, name)
    }
}

/// How volume authorization behaves
pub enum VolumeAuthorizationMode<'a> {
    /// Full: owner consent via graph + Cedar policy
    Full { graph: &'a ServiceGraph },
    /// Cedar-only: skip owner consent check (used when no graph available)
    CedarOnly,
}
