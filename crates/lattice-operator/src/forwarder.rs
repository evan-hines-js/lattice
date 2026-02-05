//! K8s request forwarder for hierarchical routing
//!
//! Implements the K8sRequestForwarder and ExecRequestForwarder traits to enable
//! agents to forward requests to their child clusters via the gRPC tunnel.

use lattice_agent::{
    build_k8s_status_response, ExecRequest, ExecRequestForwarder, ForwardedExecSession,
    K8sRequestForwarder, KubernetesRequest, KubernetesResponse,
};
use lattice_cell::{
    start_exec_session, tunnel_request_streaming, ExecRequestParams, K8sRequestParams,
    SharedAgentRegistry, SharedSubtreeRegistry, TunnelError,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

/// Forwarder that routes K8s requests to child clusters via gRPC tunnel.
///
/// Uses the subtree registry to determine which agent connection to route through,
/// then uses the tunnel functions to forward requests.
pub struct SubtreeForwarder {
    subtree_registry: SharedSubtreeRegistry,
    agent_registry: SharedAgentRegistry,
}

/// Resolved route information for forwarding
struct ResolvedRoute {
    agent_id: String,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
}

impl SubtreeForwarder {
    /// Create a new SubtreeForwarder with the given registries.
    pub fn new(
        subtree_registry: SharedSubtreeRegistry,
        agent_registry: SharedAgentRegistry,
    ) -> Self {
        Self {
            subtree_registry,
            agent_registry,
        }
    }

    /// Resolve the route to a target cluster, returning the agent connection.
    async fn resolve_route(&self, target_cluster: &str) -> Result<ResolvedRoute, (u32, String)> {
        // Look up the route to the target cluster
        let route_info = self
            .subtree_registry
            .get_route(target_cluster)
            .await
            .ok_or_else(|| {
                (
                    404,
                    format!("cluster '{}' not found in subtree", target_cluster),
                )
            })?;

        // Get the agent ID to route through
        let agent_id = route_info
            .agent_id
            .ok_or((502, "internal routing error: missing agent_id".to_string()))?;

        // Get the agent's command channel
        let command_tx = self
            .agent_registry
            .get(&agent_id)
            .ok_or_else(|| (502, format!("agent '{}' not connected", agent_id)))?
            .command_tx
            .clone();

        Ok(ResolvedRoute {
            agent_id,
            command_tx,
        })
    }

    /// Build K8sRequestParams from a KubernetesRequest (takes ownership)
    fn build_params(target_cluster: &str, request: KubernetesRequest) -> K8sRequestParams {
        K8sRequestParams {
            method: request.verb,
            path: request.path,
            query: request.query,
            body: request.body,
            content_type: request.content_type,
            accept: request.accept,
            target_cluster: target_cluster.to_string(),
            source_user: request.source_user,
            source_groups: request.source_groups,
        }
    }
}

#[async_trait::async_trait]
impl K8sRequestForwarder for SubtreeForwarder {
    async fn forward(
        &self,
        target_cluster: &str,
        request: KubernetesRequest,
    ) -> KubernetesResponse {
        let request_id = request.request_id.clone();

        let route = match self.resolve_route(target_cluster).await {
            Ok(r) => r,
            Err((status, msg)) => {
                warn!(target = %target_cluster, request_id = %request_id, msg, "Route resolution failed");
                return build_k8s_status_response(&request_id, status, &msg);
            }
        };

        debug!(
            target = %target_cluster,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding request to child cluster"
        );

        let params = Self::build_params(target_cluster, request);

        // Use streaming tunnel but collect the full response for non-watch requests
        let mut rx = match tunnel_request_streaming(
            &self.agent_registry,
            target_cluster,
            route.command_tx,
            params,
        )
        .await
        {
            Ok(rx) => rx,
            Err(e) => {
                let (status, msg) = tunnel_error_to_status(&e);
                return build_k8s_status_response(&request_id, status, &msg);
            }
        };

        // For non-watch, we expect a single response
        match rx.recv().await {
            Some(response) => response,
            None => build_k8s_status_response(&request_id, 502, "no response received from agent"),
        }
    }

    async fn forward_watch(
        &self,
        target_cluster: &str,
        request: KubernetesRequest,
    ) -> Result<mpsc::Receiver<KubernetesResponse>, String> {
        let request_id = &request.request_id;

        let route = match self.resolve_route(target_cluster).await {
            Ok(r) => r,
            Err((_, msg)) => {
                warn!(target = %target_cluster, request_id = %request_id, msg, "Route resolution failed");
                return Err(msg);
            }
        };

        debug!(
            target = %target_cluster,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding watch request to child cluster"
        );

        let params = Self::build_params(target_cluster, request);

        tunnel_request_streaming(
            &self.agent_registry,
            target_cluster,
            route.command_tx,
            params,
        )
        .await
        .map_err(|e| format!("tunnel error: {:?}", e))
    }
}

#[async_trait::async_trait]
impl ExecRequestForwarder for SubtreeForwarder {
    async fn forward_exec(
        &self,
        target_cluster: &str,
        request: ExecRequest,
    ) -> Result<ForwardedExecSession, String> {
        let request_id = request.request_id.clone();

        let route = match self.resolve_route(target_cluster).await {
            Ok(r) => r,
            Err((_, msg)) => return Err(msg),
        };

        debug!(
            target = %target_cluster,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding exec request to child cluster"
        );

        let exec_params = ExecRequestParams {
            path: request.path,
            query: request.query,
            target_cluster: target_cluster.to_string(),
            source_user: request.source_user,
            source_groups: request.source_groups,
        };

        let (session, data_rx) = start_exec_session(
            &self.agent_registry,
            target_cluster,
            route.command_tx,
            exec_params,
        )
        .await
        .map_err(|e| format!("failed to start exec session: {}", e))?;

        // Create channels for stdin and resize
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
        let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(8);
        let cancel_token = CancellationToken::new();

        // Spawn relay task
        let cancel_token_relay = cancel_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token_relay.cancelled() => break,
                    Some(data) = stdin_rx.recv() => {
                        if let Err(e) = session.send_stdin(data).await {
                            error!(error = %e, "Failed to forward stdin to child exec session");
                            break;
                        }
                    }
                    Some((width, height)) = resize_rx.recv() => {
                        if let Err(e) = session.send_resize(width as u32, height as u32).await {
                            error!(error = %e, "Failed to forward resize to child exec session");
                            break;
                        }
                    }
                    else => break,
                }
            }
        });

        Ok(ForwardedExecSession {
            request_id,
            stdin_tx,
            resize_tx,
            data_rx,
            cancel_token,
        })
    }
}

/// Convert TunnelError to HTTP status code and message
fn tunnel_error_to_status(e: &TunnelError) -> (u32, String) {
    match e {
        TunnelError::SendFailed(m) => (502, format!("send failed: {}", m)),
        TunnelError::ChannelClosed => (502, "agent disconnected".to_string()),
        TunnelError::UnknownCluster(name) => (404, format!("unknown cluster: {}", name)),
        TunnelError::Timeout => (504, "request timed out".to_string()),
        TunnelError::AgentError(m) => (502, format!("agent error: {}", m)),
        TunnelError::ResponseBuild(m) => (500, format!("response build error: {}", m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_k8s_status_response() {
        let response = build_k8s_status_response("req-1", 404, "cluster not found");
        assert_eq!(response.request_id, "req-1");
        assert_eq!(response.status_code, 404);
        assert!(String::from_utf8_lossy(&response.body).contains("cluster not found"));
    }

    #[test]
    fn test_tunnel_error_to_status() {
        assert_eq!(
            tunnel_error_to_status(&TunnelError::Timeout),
            (504, "request timed out".to_string())
        );
        assert_eq!(
            tunnel_error_to_status(&TunnelError::ChannelClosed),
            (502, "agent disconnected".to_string())
        );
        assert_eq!(
            tunnel_error_to_status(&TunnelError::UnknownCluster("test".to_string())),
            (404, "unknown cluster: test".to_string())
        );
    }
}
