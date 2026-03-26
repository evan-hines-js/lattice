//! Handler for parent-initiated cluster deletion.
//!
//! When the parent sends a `DeleteCluster` command, the agent deletes
//! its local LatticeCluster CRD. This sets the deletion timestamp,
//! which the existing deletion watcher detects and uses to start the
//! unpivot retry loop (sending CAPI resources back to the parent).

use tracing::{info, warn};

use lattice_common::crd::LatticeCluster;
use lattice_proto::DeleteCluster;

use super::CommandContext;

/// Handle a `DeleteCluster` command from the parent.
///
/// Deletes the local LatticeCluster CRD, which triggers the existing
/// unpivot flow via the deletion watcher in `client/deletion.rs`.
pub async fn handle(cmd: &DeleteCluster, ctx: &CommandContext) {
    info!(
        cluster = %cmd.cluster_name,
        "Parent requested cluster deletion, deleting local LatticeCluster"
    );

    let Some(client) =
        crate::kube_client::create_client_logged(&*ctx.kube_provider, "parent-initiated delete")
            .await
    else {
        warn!("Failed to create K8s client for parent-initiated delete");
        return;
    };

    let api: kube::Api<LatticeCluster> = kube::Api::all(client);

    match api
        .delete(&cmd.cluster_name, &Default::default())
        .await
    {
        Ok(_) => {
            info!(
                cluster = %cmd.cluster_name,
                "Local LatticeCluster deletion initiated (unpivot will follow)"
            );
        }
        Err(kube::Error::Api(resp)) if resp.code == 404 => {
            info!(
                cluster = %cmd.cluster_name,
                "LatticeCluster already deleted or not found"
            );
        }
        Err(e) => {
            warn!(
                cluster = %cmd.cluster_name,
                error = %e,
                "Failed to delete local LatticeCluster"
            );
        }
    }
}
