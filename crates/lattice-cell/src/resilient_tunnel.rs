//! K8s API tunnel proxy
//!
//! Transparent proxy for K8s API requests through gRPC agent tunnels.
//! Fails fast when the agent isn't connected — lets the client (istiod,
//! CAPI controllers) handle retry with their own backoff logic.

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use lattice_proto::KubernetesResponse;

use crate::connection::SharedAgentRegistry;
use crate::k8s_tunnel::{
    build_http_response, tunnel_request_streaming, K8sRequestParams, TunnelError, DEFAULT_TIMEOUT,
    RESPONSE_CHANNEL_SIZE,
};

/// Proxy a K8s API request through the agent tunnel.
///
/// Fails fast with 503 if the agent isn't connected. For watch requests,
/// streams the response body directly. When the stream ends (for any
/// reason), the HTTP response closes and the client reconnects.
pub async fn tunnel_request(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let command_tx = require_connected_agent(registry, cluster_name)?;

    if lattice_proto::is_watch_query(&params.query) {
        tunnel_watch(registry, cluster_name, command_tx, params).await
    } else {
        tunnel_single(registry, cluster_name, command_tx, params).await
    }
}

/// Handle a single (non-watch) request
async fn tunnel_single(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
    params: K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let (_request_id, mut response_rx) =
        tunnel_request_streaming(registry, cluster_name, command_tx, params).await?;

    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => build_http_response(&response),
        Ok(None) => Err(TunnelError::ChannelClosed),
        Err(_) => Err(TunnelError::Timeout),
    }
}

/// Handle a watch request — stream the response body directly.
///
/// Waits for the first chunk to extract status code and content type,
/// then streams remaining chunks into the HTTP response body. When the
/// agent stream ends (disconnect, error, or normal close), the body
/// channel drops and the client sees EOF.
async fn tunnel_watch(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
    params: K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let (_request_id, mut response_rx) =
        tunnel_request_streaming(registry, cluster_name, command_tx, params).await?;

    // Wait for the first chunk to determine status + content type
    let first = response_rx.recv().await.ok_or(TunnelError::ChannelClosed)?;

    let status = if first.status_code != 0 {
        first.status_code as u16
    } else {
        200
    };
    let content_type = if first.content_type.is_empty() {
        "application/json".to_string()
    } else {
        first.content_type.clone()
    };

    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    // Forward the first chunk's body
    if !first.body.is_empty() {
        let _ = body_tx.send(Ok(axum::body::Bytes::from(first.body))).await;
    }

    // Stream remaining chunks in the background
    if !first.stream_end {
        tokio::spawn(async move {
            forward_watch_stream(response_rx, body_tx).await;
        });
    }

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx));

    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header("Content-Type", content_type)
        .body(body)
        .map_err(|e| TunnelError::ResponseBuild(e.to_string()))
}

/// Forward watch response chunks to the HTTP body channel.
/// Returns when the stream ends (for any reason).
async fn forward_watch_stream(
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
    body_tx: mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
) {
    while let Some(response) = response_rx.recv().await {
        if !response.error.is_empty() {
            warn!(error = %response.error, "Watch error from agent");
        }

        if !response.body.is_empty()
            && body_tx
                .send(Ok(axum::body::Bytes::from(response.body)))
                .await
                .is_err()
        {
            break; // Client disconnected
        }

        if response.stream_end {
            break;
        }
    }
    // body_tx drops here → client sees EOF → informer reconnects
}

/// Return the command channel if the agent is connected, or 503 immediately.
///
/// Never waits. Prevents the proxy from holding TCP connections open for a
/// backend that isn't there — Go's net/http has no read deadline on initial
/// requests, so holding the connection causes informer hangs.
fn require_connected_agent(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
) -> Result<mpsc::Sender<lattice_proto::CellCommand>, TunnelError> {
    registry
        .get_connected_command_tx(cluster_name)
        .ok_or_else(|| {
            debug!(cluster = %cluster_name, "Agent not connected, returning 503");
            TunnelError::AgentNotConnected(cluster_name.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_error_status_codes() {
        assert_eq!(
            TunnelError::AgentNotConnected("test".into()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            TunnelError::Timeout.status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            TunnelError::ChannelClosed.status_code(),
            StatusCode::BAD_GATEWAY
        );
    }
}
