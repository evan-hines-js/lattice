//! Cluster deletion detection and unpivot logic.
//!
//! Detects when the local LatticeCluster is being deleted and runs
//! the unpivot retry loop, sending CAPI resources back to the parent.

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::commands::apply_manifests::extract_manifest_info_bytes;
use crate::kube_client::KubeClientProvider;
use lattice_common::capi_namespace;
use lattice_common::crd::LatticeCluster;
use lattice_proto::{agent_message::Payload, AgentMessage, ClusterDeleting, MoveObject};

use super::config::{UNPIVOT_BASE_INTERVAL, UNPIVOT_MAX_INTERVAL};
use super::AgentClient;

impl AgentClient {
    /// Check if the local LatticeCluster is being deleted
    ///
    /// Returns Some((namespace, cluster_name)) if the cluster has a deletion timestamp,
    /// indicating we should start the unpivot retry loop.
    pub(super) async fn check_cluster_deleting(
        kube_provider: &dyn KubeClientProvider,
    ) -> Option<(String, String)> {
        let client =
            crate::kube_client::create_client_logged(kube_provider, "cluster deletion check")
                .await?;
        let clusters: kube::Api<LatticeCluster> = kube::Api::all(client);
        let list = clusters
            .list(&kube::api::ListParams::default().limit(1))
            .await
            .ok()?;

        let cluster = list.items.first()?;
        if cluster.metadata.deletion_timestamp.is_some() {
            let name = cluster.metadata.name.clone()?;
            let namespace = capi_namespace(&name);
            Some((namespace, name))
        } else {
            None
        }
    }

    /// Run the unpivot retry loop
    ///
    /// Uses native CAPI discovery (same logic as pivot) to export resources.
    /// Keeps sending ClusterDeleting to parent every 5s until parent imports.
    /// No ACK is needed - the cluster will simply be deleted at the infrastructure level.
    pub(super) async fn run_unpivot_loop(
        message_tx: mpsc::Sender<AgentMessage>,
        cluster_name: &str,
        namespace: &str,
        kube_provider: &dyn KubeClientProvider,
    ) {
        let mut current_interval = UNPIVOT_BASE_INTERVAL;

        loop {
            // Create K8s client for this iteration
            let Some(client) =
                crate::kube_client::create_client_logged(kube_provider, "unpivot").await
            else {
                tokio::time::sleep(current_interval).await;
                current_interval = (current_interval * 2).min(UNPIVOT_MAX_INTERVAL);
                continue;
            };

            // Discover and prepare CAPI resources (same logic as pivot)
            match lattice_move::prepare_move_objects(&client, namespace, cluster_name).await {
                Ok(objects) => {
                    // Log each object being sent for debugging
                    for obj in &objects {
                        let (kind, name) = extract_manifest_info_bytes(&obj.manifest);
                        info!(
                            cluster = %cluster_name,
                            kind = %kind,
                            name = %name,
                            source_uid = %obj.source_uid,
                            owners = obj.owners.len(),
                            "Unpivot: sending object"
                        );
                    }
                    info!(
                        cluster = %cluster_name,
                        namespace = %namespace,
                        object_count = objects.len(),
                        "Sending ClusterDeleting to parent (unpivot)"
                    );

                    // Convert to proto format using From impl
                    let proto_objects: Vec<MoveObject> =
                        objects.into_iter().map(Into::into).collect();

                    let msg = AgentMessage {
                        cluster_name: cluster_name.to_string(),
                        payload: Some(Payload::ClusterDeleting(ClusterDeleting {
                            namespace: namespace.to_string(),
                            objects: proto_objects,
                            cluster_name: cluster_name.to_string(),
                        })),
                    };

                    if message_tx.send(msg).await.is_err() {
                        warn!("Unpivot message channel closed, stopping retry loop");
                        break;
                    }

                    // Success -- reset to base interval
                    current_interval = UNPIVOT_BASE_INTERVAL;
                }
                Err(e) => {
                    warn!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to prepare CAPI for unpivot, will retry"
                    );
                    // Backoff on failure
                    current_interval = (current_interval * 2).min(UNPIVOT_MAX_INTERVAL);
                }
            }

            tokio::time::sleep(current_interval).await;
        }
    }
}
