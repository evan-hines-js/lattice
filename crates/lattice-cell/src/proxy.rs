//! HTTP proxy for K8s API access to child clusters
//!
//! This module provides an HTTP server that proxies Kubernetes API requests
//! to child clusters through the gRPC stream.
//!
//! # Endpoints
//!
//! - `GET/POST/PUT/PATCH/DELETE /clusters/{name}/api/...` - Proxy to child's K8s API
//!
//! # Watch Support
//!
//! Watch requests (with ?watch=true) are handled via Server-Sent Events (SSE).
//! The stream continues until the client disconnects or the watch ends.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::any;
use axum::Router;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{RequestMultiplexer, SharedAgentRegistry};
use lattice_proto::{cell_command::Command, CellCommand, KubernetesRequest};

/// Shared state for the proxy router
pub struct ProxyState {
    /// Registry of connected agents
    pub registry: SharedAgentRegistry,
    /// Request multiplexer for routing responses
    pub multiplexer: Arc<RequestMultiplexer>,
}

/// Query parameters for K8s API requests
#[derive(Debug, Deserialize, Default)]
pub struct K8sQueryParams {
    #[serde(flatten)]
    pub params: std::collections::HashMap<String, String>,
}

/// Create the proxy router
pub fn proxy_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/clusters/{cluster_name}/*path", any(handle_proxy_request))
        .with_state(state)
}

/// Handle a proxy request to a child cluster's K8s API
async fn handle_proxy_request(
    State(state): State<Arc<ProxyState>>,
    Path((cluster_name, path)): Path<(String, String)>,
    method: Method,
    Query(query): Query<K8sQueryParams>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let request_id = Uuid::new_v4().to_string();

    debug!(
        request_id = %request_id,
        cluster = %cluster_name,
        method = %method,
        path = %path,
        "Received proxy request"
    );

    // Check if agent is connected and get command sender
    let command_tx = match state.registry.get(&cluster_name) {
        Some(agent) => agent.command_tx.clone(),
        None => {
            warn!(cluster = %cluster_name, "Agent not connected");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Cluster '{}' is not connected", cluster_name),
            )
                .into_response();
        }
    };

    // Build query string
    let query_string = query
        .params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    // Determine if this is a watch request
    let is_watch = query.params.get("watch").map_or(false, |v| v == "true" || v == "1");

    // Get content type from headers
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // Build the K8s request
    let k8s_request = KubernetesRequest {
        request_id: request_id.clone(),
        verb: method.to_string(),
        path: format!("/{}", path),
        query: query_string,
        body: body.to_vec(),
        content_type,
        timeout_ms: if is_watch { 0 } else { 30000 },
        cancel: false,
    };

    // Create the cell command
    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(Command::KubernetesRequest(k8s_request)),
    };

    if is_watch {
        handle_watch_request(state, command_tx, command, request_id).await
    } else {
        handle_single_request(state, command_tx, command, request_id).await
    }
}

/// Handle a single (non-watch) request
async fn handle_single_request(
    state: Arc<ProxyState>,
    command_tx: mpsc::Sender<CellCommand>,
    command: CellCommand,
    request_id: String,
) -> Response {
    // Register the request
    let rx = state.multiplexer.register_single(request_id.clone());

    // Send command to agent
    if let Err(e) = command_tx.send(command).await {
        error!(request_id = %request_id, error = %e, "Failed to send command to agent");
        state.multiplexer.cancel(&request_id);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to send request to agent",
        )
            .into_response();
    }

    // Wait for response with timeout
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(response)) => {
            let status = StatusCode::from_u16(response.status_code as u16)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let mut builder = Response::builder().status(status);

            if !response.content_type.is_empty() {
                builder = builder.header("content-type", &response.content_type);
            }

            builder
                .body(Body::from(response.body))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
                })
        }
        Ok(Err(_)) => {
            // Sender dropped - agent disconnected
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Agent disconnected",
            )
                .into_response()
        }
        Err(_) => {
            // Timeout
            state.multiplexer.cancel(&request_id);
            (StatusCode::GATEWAY_TIMEOUT, "Request timed out").into_response()
        }
    }
}

/// Handle a watch request with SSE streaming
async fn handle_watch_request(
    state: Arc<ProxyState>,
    command_tx: mpsc::Sender<CellCommand>,
    command: CellCommand,
    request_id: String,
) -> Response {
    // Register streaming request
    let (mut rx, _cancel_token) = state.multiplexer.register_streaming(request_id.clone());

    // Send command to agent
    if let Err(e) = command_tx.send(command).await {
        error!(request_id = %request_id, error = %e, "Failed to send watch command to agent");
        state.multiplexer.cancel(&request_id);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to send request to agent",
        )
            .into_response();
    }

    // Create SSE stream
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Some(response) => {
                    if response.stream_end {
                        // Final message
                        if !response.body.is_empty() {
                            yield Ok::<_, std::convert::Infallible>(
                                axum::response::sse::Event::default()
                                    .data(String::from_utf8_lossy(&response.body).to_string())
                            );
                        }
                        break;
                    } else {
                        yield Ok(
                            axum::response::sse::Event::default()
                                .data(String::from_utf8_lossy(&response.body).to_string())
                        );
                    }
                }
                None => {
                    // Channel closed
                    break;
                }
            }
        }
    };

    // Set up cancellation on client disconnect
    let state_clone = state.clone();
    let request_id_clone = request_id.clone();
    tokio::spawn(async move {
        // This task will be aborted when the SSE stream is dropped
        // For now, we rely on the stream ending naturally
        // TODO: Detect client disconnect and send cancel command
        let _ = (state_clone, request_id_clone);
    });

    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRegistry;

    #[test]
    fn test_proxy_state_creation() {
        let registry = Arc::new(AgentRegistry::new());
        let multiplexer = Arc::new(RequestMultiplexer::new());
        let _state = ProxyState {
            registry,
            multiplexer,
        };
    }
}
