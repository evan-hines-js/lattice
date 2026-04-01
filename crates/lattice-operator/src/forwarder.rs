//! K8s request forwarder for hierarchical routing
//!
//! Implements the K8sRequestForwarder and ExecRequestForwarder traits to enable
//! agents to forward requests to their child clusters via the gRPC tunnel.
//! Fails fast if the agent isn't connected — the client retries.

use lattice_agent::{
    build_k8s_status_response, ExecRequestForwarder, ForwardedExecSession, K8sRequestForwarder,
};
use lattice_cell::{
    start_exec_session, tunnel_request_streaming, ExecRequestParams, K8sRequestParams,
    SharedAgentRegistry, TunnelError,
};
use lattice_common::routing::split_first_hop;
use lattice_proto::{ExecRequest, KubernetesRequest, KubernetesResponse};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

/// Forwarder that routes K8s requests to child clusters via gRPC tunnel.
///
/// Uses the subtree registry to determine which agent connection to route through,
/// then uses the tunnel functions to forward requests.
pub struct SubtreeForwarder {
    registry: SharedAgentRegistry,
}

struct ResolvedRoute {
    agent_id: String,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
}

impl SubtreeForwarder {
    /// Create a new forwarder backed by the agent registry.
    pub fn new(registry: SharedAgentRegistry) -> Self {
        Self { registry }
    }

    async fn resolve_route(&self, first_hop: &str) -> Result<ResolvedRoute, (u32, String)> {
        let route_info = self
            .registry
            .get_route(first_hop)
            .await
            .ok_or_else(|| (404, format!("cluster '{}' not found in subtree", first_hop)))?;

        let agent_id = route_info
            .agent_id
            .ok_or((502, "internal routing error: missing agent_id".to_string()))?;

        let command_tx = self
            .registry
            .get_connected_command_tx(&agent_id)
            .ok_or_else(|| (503, format!("agent '{}' not connected", agent_id)))?;

        Ok(ResolvedRoute {
            agent_id,
            command_tx,
        })
    }

    /// Build K8sRequestParams from a KubernetesRequest (takes ownership)
    fn build_params(target_path: &str, request: KubernetesRequest) -> K8sRequestParams {
        K8sRequestParams {
            method: request.verb,
            path: request.path,
            query: request.query,
            body: request.body,
            content_type: request.content_type,
            accept: request.accept,
            target_path: target_path.to_string(),
            source_user: request.source_user,
            source_groups: request.source_groups,
        }
    }
}

#[async_trait::async_trait]
impl K8sRequestForwarder for SubtreeForwarder {
    async fn forward(&self, target_path: &str, request: KubernetesRequest) -> KubernetesResponse {
        let request_id = request.request_id.clone();
        let (first_hop, _) = split_first_hop(target_path);

        let route = match self.resolve_route(first_hop).await {
            Ok(r) => r,
            Err((status, msg)) => {
                warn!(target_path = %target_path, request_id = %request_id, msg, "Route resolution failed");
                return build_k8s_status_response(&request_id, status, &msg);
            }
        };

        debug!(
            target_path = %target_path,
            first_hop = %first_hop,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding request to child cluster"
        );

        let params = Self::build_params(target_path, request);

        let mut rx = match tunnel_request_streaming(
            &self.registry,
            first_hop,
            route.command_tx,
            params,
        )
        .await
        {
            Ok((_request_id, rx)) => rx,
            Err(e) => {
                let (status, msg) = tunnel_error_to_status(&e);
                return build_k8s_status_response(&request_id, status, &msg);
            }
        };

        match rx.recv().await {
            Some(response) => response,
            None => build_k8s_status_response(&request_id, 502, "no response received from agent"),
        }
    }

    async fn forward_watch(
        &self,
        target_path: &str,
        request: KubernetesRequest,
    ) -> Result<mpsc::Receiver<KubernetesResponse>, String> {
        let request_id = &request.request_id;
        let (first_hop, _) = split_first_hop(target_path);

        let route = match self.resolve_route(first_hop).await {
            Ok(r) => r,
            Err((_, msg)) => {
                warn!(target_path = %target_path, request_id = %request_id, msg, "Route resolution failed");
                return Err(msg);
            }
        };

        debug!(
            target_path = %target_path,
            first_hop = %first_hop,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding watch request to child cluster"
        );

        let params = Self::build_params(target_path, request);

        tunnel_request_streaming(&self.registry, first_hop, route.command_tx, params)
            .await
            .map(|(_request_id, rx)| rx)
            .map_err(|e| format!("tunnel error: {:?}", e))
    }
}

#[async_trait::async_trait]
impl ExecRequestForwarder for SubtreeForwarder {
    async fn forward_exec(
        &self,
        target_path: &str,
        request: ExecRequest,
    ) -> Result<ForwardedExecSession, String> {
        let request_id = request.request_id.clone();
        let (first_hop, _) = split_first_hop(target_path);

        let route = match self.resolve_route(first_hop).await {
            Ok(r) => r,
            Err((_, msg)) => return Err(msg),
        };

        debug!(
            target_path = %target_path,
            first_hop = %first_hop,
            agent_id = %route.agent_id,
            request_id = %request_id,
            "Forwarding exec request to child cluster"
        );

        let exec_params = ExecRequestParams {
            path: request.path,
            query: request.query,
            target_path: target_path.to_string(),
            source_user: request.source_user,
            source_groups: request.source_groups,
        };

        let (session, data_rx) = start_exec_session(
            &self.registry,
            first_hop,
            route.command_tx,
            exec_params,
        )
        .await
        .map_err(|e| format!("failed to start exec session: {}", e))?;

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
        let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(8);
        let cancel_token = CancellationToken::new();

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

/// Convert TunnelError to HTTP status code and message.
///
/// Delegates to `TunnelError::status_code()` and `Display` to stay in sync
/// with the canonical error definitions.
fn tunnel_error_to_status(e: &TunnelError) -> (u32, String) {
    (e.status_code().as_u16() as u32, e.to_string())
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
        let (status, msg) = tunnel_error_to_status(&TunnelError::Timeout);
        assert_eq!(status, 504);
        assert!(msg.contains("timed out"));

        let (status, msg) = tunnel_error_to_status(&TunnelError::ChannelClosed);
        assert_eq!(status, 502);
        assert!(msg.contains("disconnected"));

        let (status, msg) = tunnel_error_to_status(&TunnelError::UnknownCluster("test".into()));
        assert_eq!(status, 404);
        assert!(msg.contains("test"));
    }
}
