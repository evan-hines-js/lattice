//! Infrastructure components for Lattice.
//!
//! Provides shared infrastructure used by cluster and service operators:
//! - **PKI**: CA, certificate generation, CSR signing.
//! - **mTLS**: TLS configuration for gRPC (re-exported at crate root).
//! - **Bootstrap**: Helm-rendered manifests for components not yet migrated
//!   to their own install crates (VictoriaMetrics).
//!
//! This crate MUST NOT depend on per-dependency install crates. It owns only
//! the components whose install it still renders directly. The full aggregate
//! of upstream registries lives at the consumer (`lattice-capi`).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use lattice_common::kube_utils::extract_image_registries;

pub mod bootstrap;
pub mod mtls;
pub mod pki;

pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};

/// Container registries referenced by components this crate still renders.
///
/// Migrated components contribute their own registries directly from their
/// install crates. `lattice-capi` unions everything.
pub fn bootstrap_registries() -> &'static [String] {
    static REGS: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut set: BTreeSet<String> = BTreeSet::new();
        set.extend(extract_image_registries(
            bootstrap::prometheus::generate_prometheus(true),
        ));
        set.extend(extract_image_registries(
            bootstrap::prometheus::generate_prometheus(false),
        ));
        set.into_iter().collect()
    });
    &REGS
}
