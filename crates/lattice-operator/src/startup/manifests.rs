//! Manifest application utilities
//!
//! Thin wrapper around lattice_common::kube_utils for applying manifests.

use kube::Client;

use lattice_common::{apply_manifests_with_discovery, ApplyOptions};

/// Apply multiple YAML manifests to the cluster
///
/// Applies in two phases:
/// 1. Namespaces and CRDs (foundational resources)
/// 2. Re-run discovery to learn new CRD types
/// 3. Everything else (sorted by kind priority)
pub async fn apply_manifests(client: &Client, manifests: &[impl AsRef<str>]) -> anyhow::Result<()> {
    apply_manifests_with_discovery(client, manifests, &ApplyOptions::default())
        .await
        .map_err(anyhow::Error::from)
}
