//! Infrastructure components for Lattice
//!
//! This crate provides shared infrastructure used by both cluster and service operators:
//!
//! - **PKI**: Certificate authority, certificate generation, CSR signing
//! - **Bootstrap**: Manifest generation for Cilium, Istio, Gateway API
//!
//! Note: cert-manager and CAPI providers are installed via `clusterctl init`,
//! which manages their lifecycle including upgrades.
//!
//! # Architecture
//!
//! The infrastructure components are designed to be stateless where possible,
//! with persistence handled at the operator level (e.g., CA secrets stored in K8s).
//!
//! # Public API
//!
//! This crate exports the following types for external use:
//!
//! ## Bootstrap
//! - [`InfrastructureConfig`]: Configuration for infrastructure manifest generation
//! - [`IstioConfig`], [`IstioReconciler`]: Istio manifest generation
//! - Cilium policy generators: [`generate_cilium_manifests`], [`generate_default_deny`], etc.
//! - ESO generators: [`generate_eso`], [`eso_version`]
//! - Core generators: [`generate_all`], [`generate_core`], [`generate_istio`]
//!
//! ## PKI
//! - [`CertificateAuthority`]: CA operations for signing CSRs
//! - [`PkiError`]: Error type for PKI operations
//!
//! ## mTLS
//! - [`ServerMtlsConfig`], [`ClientMtlsConfig`]: TLS configuration for gRPC
//! - [`MtlsError`]: Error type for mTLS operations
//! - [`extract_cluster_id_from_cert`], [`verify_cert_chain`]: Certificate utilities
//!
//! # Internal Types (Not Exported)
//!
//! The following types are intentionally kept internal:
//!
//! - `CertificateInfo`: Used internally for certificate validity checking
//! - `AgentCertRequest`: Used internally by agents for CSR generation
//! - `CertificateAuthorityBundle`: Used internally for CA rotation
//! - `VerificationResult`: Used internally by verification functions

pub mod bootstrap;
pub mod mtls;
pub mod pki;
pub mod system_namespaces;

// Re-export main types
pub use bootstrap::cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use bootstrap::eso::{eso_version, generate_eso};
pub use bootstrap::{
    generate_all, generate_core, generate_gateway_api_crds, generate_istio, split_yaml_documents,
    InfrastructureConfig, IstioConfig, IstioReconciler,
};
pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};
pub use pki::{CertificateAuthority, PkiError};
