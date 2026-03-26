//! Parent-initiated cluster deletion integration test.
//!
//! Verifies that deleting a LatticeCluster from the parent triggers the
//! full unpivot flow: parent sends DeleteCluster via gRPC → child
//! self-deletes → unpivot sends CAPI back → parent tears down infrastructure.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_CLUSTER_TO_DELETE=e2e-workload \
//! cargo test --features provider-e2e --test e2e test_parent_delete_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::delete_cluster_from_parent;
use super::super::providers::InfraProvider;

/// Delete a cluster from the parent and verify the full unpivot lifecycle.
///
/// The parent sends `DeleteCluster` via gRPC to the child agent, which
/// initiates self-deletion and unpivots CAPI resources back to the parent.
pub async fn delete_from_parent_and_verify(
    parent_kubeconfig: &str,
    cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!(
        "[Integration/ParentDelete] Deleting cluster {} from parent...",
        cluster_name
    );

    delete_cluster_from_parent(parent_kubeconfig, cluster_name, provider).await?;

    info!(
        "[Integration/ParentDelete] Cluster {} deleted from parent successfully",
        cluster_name
    );
    Ok(())
}
