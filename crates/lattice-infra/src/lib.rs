//! Infrastructure components for Lattice.
//!
//! Provides shared infrastructure used by cluster and service operators:
//! - **PKI**: CA, certificate generation, CSR signing.
//! - **mTLS**: TLS configuration for gRPC (re-exported at crate root).
//! - **Bootstrap**: Helm-rendered manifest generation for components not yet
//!   migrated to their own install crates (Cilium, Istio, ESO, Velero, etc.).
//!
//! This crate MUST NOT depend on per-dependency install crates (`lattice-*`
//! for Tetragon, future Cilium/Istio/etc). It owns only the components whose
//! install it still renders directly. The overall aggregation of upstream
//! registries happens at the consumer (`lattice-capi`), which is the only
//! crate allowed to reach across every install crate.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use lattice_common::kube_utils::extract_image_registries;

pub mod bootstrap;
pub mod mtls;
pub mod pki;

// Re-export mTLS types (commonly used across many crates)
pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};

/// Container registries referenced by components this crate still renders.
///
/// Covers **only** components in `bootstrap/`. Components migrated out to
/// their own install crates (Tetragon today; future Cilium, Istio, etc.)
/// contribute their own registries separately. The consumer (`lattice-capi`)
/// unions across all producers.
///
/// LazyLock caches the scan so the ~20k-line walk across embedded manifests
/// happens once per process.
pub fn bootstrap_registries() -> &'static [String] {
    static REGS: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut set: BTreeSet<String> = BTreeSet::new();

        set.extend(extract_image_registries(
            bootstrap::cert_manager::generate_cert_manager(),
        ));
        set.extend(extract_image_registries(
            bootstrap::cilium::generate_cilium_manifests(),
        ));
        set.extend(extract_image_registries(bootstrap::eso::generate_eso()));
        set.extend(extract_image_registries(
            bootstrap::gpu::generate_gpu_stack(),
        ));
        set.extend(extract_image_registries(bootstrap::keda::generate_keda()));
        set.extend(extract_image_registries(
            bootstrap::kthena::generate_kthena(),
        ));
        set.extend(extract_image_registries(
            bootstrap::metrics_server::generate_metrics_server(),
        ));
        set.extend(extract_image_registries(
            bootstrap::prometheus::generate_prometheus(true),
        ));
        set.extend(extract_image_registries(
            bootstrap::prometheus::generate_prometheus(false),
        ));
        set.extend(extract_image_registries(
            bootstrap::velero::generate_velero(),
        ));
        set.extend(extract_image_registries(
            bootstrap::volcano::generate_volcano(),
        ));

        // Istio manifests depend on cluster-specific config, but `image:` lines
        // do not — a throwaway reconciler with placeholder values renders the
        // same image refs as the real one.
        let istio = bootstrap::istio::IstioReconciler::new(
            "registry-scan",
            "lattice.scan".to_string(),
            None,
        );
        set.extend(extract_image_registries(istio.manifests()));

        set.into_iter().collect()
    });
    &REGS
}
