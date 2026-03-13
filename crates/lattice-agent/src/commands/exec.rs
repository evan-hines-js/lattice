//! Exec command handlers (ExecRequest, ExecStdin, ExecResize, ExecCancel).

use lattice_common::routing::split_first_hop;
use lattice_proto::{
    agent_message::Payload, AgentMessage, ExecCancel, ExecData, ExecRequest, ExecResize,
};
use tracing::{debug, error};

use crate::exec::send_exec_error;

use super::{CommandContext, StoredExecSession};

/// Handle an exec request from the cell.
///
/// Uses hop-by-hop routing: strips the first segment of `target_path`, and if
/// the remaining path is empty, executes locally; otherwise forwards to the
/// next child agent.
pub async fn handle_exec_request(req: &ExecRequest, ctx: &CommandContext) {
    let target_path = &req.target_path;
    let (first_hop, remaining) = split_first_hop(target_path);
    let is_local = first_hop == ctx.cluster_name && remaining.is_empty();

    debug!(
        request_id = %req.request_id,
        path = %req.path,
        target_path = %target_path,
        first_hop = %first_hop,
        is_local,
        "Received exec request"
    );

    if is_local {
        handle_local_exec(req, ctx).await;
    } else {
        // Forward with the remaining path (strip our hop)
        let forward_path = if first_hop == ctx.cluster_name && !remaining.is_empty() {
            remaining.to_string()
        } else {
            target_path.clone()
        };
        handle_forwarded_exec(req, &forward_path, ctx).await;
    }
}

/// Handle a local exec request.
async fn handle_local_exec(req: &ExecRequest, ctx: &CommandContext) {
    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let req = req.clone();
    let registry = ctx.exec_registry.clone();
    let provider = ctx.kube_provider.clone();

    tokio::spawn(async move {
        let client = match provider.create().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to create K8s client for exec");
                send_exec_error(
                    &message_tx,
                    &cluster_name,
                    &req.request_id,
                    &format!("Failed to create K8s client: {}", e),
                )
                .await;
                return;
            }
        };

        crate::exec::execute_exec(client, req, cluster_name, message_tx, registry).await;
    });
}

/// Handle a forwarded exec request to a child cluster.
///
/// `forward_path` is the remaining routing path after stripping our hop.
async fn handle_forwarded_exec(req: &ExecRequest, forward_path: &str, ctx: &CommandContext) {
    let request_id = req.request_id.clone();

    match &ctx.exec_forwarder {
        Some(f) => {
            debug!(
                request_id = %request_id,
                forward_path = %forward_path,
                "Forwarding exec request to child cluster"
            );

            let f = f.clone();
            let mut req = req.clone();
            req.target_path = forward_path.to_string();
            let cluster_name = ctx.cluster_name.clone();
            let message_tx = ctx.message_tx.clone();
            let sessions = ctx.forwarded_exec_sessions.clone();
            let forward_path = forward_path.to_string();

            tokio::spawn(async move {
                match f.forward_exec(&forward_path, req).await {
                    Ok(session) => {
                        let mut data_rx = session.data_rx;
                        let request_id = session.request_id.clone();
                        let cancel_token = session.cancel_token.clone();

                        // Store the session for stdin/resize forwarding
                        sessions
                            .insert(
                                request_id.clone(),
                                StoredExecSession {
                                    stdin_tx: session.stdin_tx,
                                    resize_tx: session.resize_tx,
                                    cancel_token,
                                },
                            )
                            .await;

                        // Relay data from child back to parent
                        while let Some(mut data) = data_rx.recv().await {
                            // Rewrite request_id to match the original command_id.
                            // When forwarding through child clusters, the inner tunnel
                            // generates a new request_id. The parent cell is waiting
                            // for the original one.
                            data.request_id = request_id.clone();
                            let msg = AgentMessage {
                                cluster_name: cluster_name.clone(),
                                payload: Some(Payload::ExecData(data)),
                            };
                            if message_tx.send(msg).await.is_err() {
                                break;
                            }
                        }

                        // Clean up session
                        sessions.remove(&request_id).await;
                    }
                    Err(e) => {
                        error!(
                            request_id = %request_id,
                            forward_path = %forward_path,
                            error = %e,
                            "Failed to forward exec request"
                        );
                        send_exec_error(
                            &message_tx,
                            &cluster_name,
                            &request_id,
                            &format!("exec forwarding failed: {}", e),
                        )
                        .await;
                    }
                }
            });
        }
        None => {
            debug!(
                request_id = %request_id,
                forward_path = %forward_path,
                "No exec forwarder configured, returning error"
            );
            let message_tx = ctx.message_tx.clone();
            let cluster_name = ctx.cluster_name.clone();
            let forward_path = forward_path.to_string();
            tokio::spawn(async move {
                send_exec_error(
                    &message_tx,
                    &cluster_name,
                    &request_id,
                    &format!("cluster '{}' not found in subtree", forward_path),
                )
                .await;
            });
        }
    }
}

/// Handle stdin data for an exec session.
pub async fn handle_exec_stdin(data: &ExecData, ctx: &CommandContext) {
    let request_id = data.request_id.clone();
    let data_bytes = data.data.clone();

    let exec_registry = ctx.exec_registry.clone();
    let forwarded = ctx.forwarded_exec_sessions.clone();

    tokio::spawn(async move {
        // Check if it's a local exec session
        if exec_registry
            .send_stdin(&request_id, data_bytes.clone())
            .await
        {
            return;
        }
        // Otherwise, try forwarded sessions
        if let Some(session) = forwarded.get(&request_id).await {
            let _ = session.stdin_tx.send(data_bytes).await;
        }
    });
}

/// Handle resize event for an exec session.
pub async fn handle_exec_resize(resize: &ExecResize, ctx: &CommandContext) {
    let request_id = resize.request_id.clone();
    let width = resize.width as u16;
    let height = resize.height as u16;

    let exec_registry = ctx.exec_registry.clone();
    let forwarded = ctx.forwarded_exec_sessions.clone();

    tokio::spawn(async move {
        // Check if it's a local exec session
        if exec_registry.send_resize(&request_id, width, height).await {
            return;
        }
        // Otherwise, try forwarded sessions
        if let Some(session) = forwarded.get(&request_id).await {
            let _ = session.resize_tx.send((width, height)).await;
        }
    });
}

/// Handle cancellation of an exec session.
pub async fn handle_exec_cancel(cancel: &ExecCancel, ctx: &CommandContext) {
    let request_id = &cancel.request_id;
    debug!(request_id = %request_id, "Received exec cancel");

    // Try local exec registry first
    if ctx.exec_registry.cancel(request_id) {
        return;
    }

    // Otherwise, try forwarded sessions
    if let Some(session) = ctx.forwarded_exec_sessions.remove(request_id).await {
        session.cancel_token.cancel();
    }
}
