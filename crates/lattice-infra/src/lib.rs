//! Infrastructure components for Lattice.
//!
//! Provides shared infrastructure used by cluster and service operators:
//! - **PKI**: CA, certificate generation, CSR signing.
//! - **mTLS**: TLS configuration for gRPC (re-exported at crate root).
//! - **Bootstrap**: Gateway API CRDs + operator mesh enrollment + shared
//!   Cedar policies (admin access / cluster access). All per-dependency
//!   installs live in their own crates (`lattice-<name>`), not here.
//!
//! This crate MUST NOT depend on per-dependency install crates. The full
//! aggregate of upstream registries lives at the consumer (`lattice-capi`).

pub mod bootstrap;
pub mod mtls;
pub mod pki;

pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};
