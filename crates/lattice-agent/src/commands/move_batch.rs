//! Move batch command handler.

use lattice_proto::{
    agent_message::Payload, AgentMessage, MoveObjectAck, MoveObjectBatch, MoveObjectError,
    UidMapping,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use super::CommandContext;

/// Handle a move batch command from the cell.
pub async fn handle(command_id: &str, batch: &MoveObjectBatch, ctx: &CommandContext) {
    let request_id = command_id.to_string();
    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let target_namespace = batch.target_namespace.clone();
    let batch_index = batch.batch_index;
    let total_batches = batch.total_batches;

    // Convert proto objects to domain objects
    let objects: Vec<lattice_move::MoveObjectInput> = batch
        .objects
        .iter()
        .map(|obj| lattice_move::MoveObjectInput {
            source_uid: obj.source_uid.clone(),
            manifest: obj.manifest.clone(),
            owners: obj
                .owners
                .iter()
                .map(|o| lattice_move::SourceOwnerRefInput {
                    source_uid: o.source_uid.clone(),
                    api_version: o.api_version.clone(),
                    kind: o.kind.clone(),
                    name: o.name.clone(),
                    controller: o.controller,
                    block_owner_deletion: o.block_owner_deletion,
                })
                .collect(),
        })
        .collect();

    info!(
        batch = %format!("{}/{}", batch_index + 1, total_batches),
        objects = objects.len(),
        namespace = %target_namespace,
        "Processing move batch"
    );

    let provider = ctx.kube_provider.clone();

    tokio::spawn(async move {
        let client = match provider.create().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = ?e, "Failed to create K8s client for move batch");
                send_batch_ack(
                    &message_tx,
                    &cluster_name,
                    &request_id,
                    vec![],
                    vec![MoveObjectError {
                        source_uid: String::new(),
                        message: format!("Failed to create K8s client: {}", e),
                        retryable: true,
                    }],
                )
                .await;
                return;
            }
        };

        let mut mover = lattice_move::AgentMover::new(client, &target_namespace);

        // Rebuild UID map from existing resources (idempotent - handles crash recovery)
        if let Err(e) = mover.rebuild_uid_map_from_resources().await {
            debug!(error = ?e, "UID map rebuild found no existing resources");
        }

        // Ensure namespace exists
        if let Err(e) = mover.ensure_namespace().await {
            send_batch_ack(
                &message_tx,
                &cluster_name,
                &request_id,
                vec![],
                vec![MoveObjectError {
                    source_uid: String::new(),
                    message: e.to_string(),
                    retryable: true,
                }],
            )
            .await;
            return;
        }

        // Apply batch (idempotent - handles already-exists)
        let (mappings, errors) = mover.apply_batch(&objects).await;

        // Send ack
        send_batch_ack(
            &message_tx,
            &cluster_name,
            &request_id,
            mappings
                .into_iter()
                .map(|(src, tgt)| UidMapping {
                    source_uid: src,
                    target_uid: tgt,
                })
                .collect(),
            errors
                .into_iter()
                .map(|e| MoveObjectError {
                    source_uid: e.source_uid,
                    message: e.message,
                    retryable: e.retryable,
                })
                .collect(),
        )
        .await;
    });
}

/// Send a MoveObject batch ack.
async fn send_batch_ack(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    mappings: Vec<UidMapping>,
    errors: Vec<MoveObjectError>,
) {
    let ack = MoveObjectAck {
        request_id: request_id.to_string(),
        mappings,
        errors,
    };
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::MoveAck(ack)),
    };
    if let Err(e) = tx.send(msg).await {
        error!(error = %e, "Failed to send move batch ack");
    }
}
