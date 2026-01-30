//! Read-only K8s API proxy for air-gapped pivot support
//!
//! Proxies K8s API requests through the gRPC tunnel to agents.
//! Only active during pre-pivot phase. Read-only operations only.
//!
//! # Architecture
//!
//! ```text
//! CAPI Controller ──► Proxy Server ──► gRPC Tunnel ──► Agent ──► Child K8s API
//!      (GET/LIST/WATCH)    :8081        (outbound)              (local)
//! ```
//!
//! # Security
//!
//! - **Read-only only**: Only GET, LIST, WATCH operations allowed
//! - **Pre-pivot only**: Proxy only active when `pivot_complete = false`
//! - **mTLS**: Proxy endpoint uses same CA as bootstrap/gRPC servers

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use lattice_proto::{cell_command, CellCommand, KubernetesRequest, KubernetesResponse};

use crate::connection::SharedAgentRegistry;

/// Default timeout for proxy requests (non-watch)
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for K8s API responses
const RESPONSE_CHANNEL_SIZE: usize = 64;

/// Proxy server configuration
#[derive(Clone)]
pub struct ProxyConfig {
    /// Address to bind the proxy server
    pub addr: SocketAddr,
    /// TLS certificate PEM
    pub cert_pem: String,
    /// TLS private key PEM
    pub key_pem: String,
}

/// Shared state for proxy handlers
#[derive(Clone)]
struct ProxyState {
    registry: SharedAgentRegistry,
}

/// Error type for proxy operations
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Agent not connected
    #[error("agent not connected for cluster: {0}")]
    AgentNotConnected(String),

    /// Cluster already pivoted
    #[error("cluster already pivoted: {0}")]
    AlreadyPivoted(String),

    /// Method not allowed (non-read operation)
    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    /// Request timeout
    #[error("request timeout")]
    Timeout,

    /// Failed to send request to agent
    #[error("failed to send request: {0}")]
    SendFailed(String),

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// Server error
    #[error("server error: {0}")]
    Server(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ProxyError::AgentNotConnected(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            ProxyError::AlreadyPivoted(_) => (StatusCode::GONE, self.to_string()),
            ProxyError::MethodNotAllowed(_) => (StatusCode::METHOD_NOT_ALLOWED, self.to_string()),
            ProxyError::Timeout => (StatusCode::GATEWAY_TIMEOUT, self.to_string()),
            ProxyError::SendFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            ProxyError::TlsConfig(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ProxyError::Server(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"{}","code":{}}}"#,
                message,
                status.as_u16()
            )))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            })
    }
}

/// Start the read-only K8s API proxy server
pub async fn start_proxy_server(
    registry: SharedAgentRegistry,
    config: ProxyConfig,
) -> Result<(), ProxyError> {
    let state = ProxyState { registry };

    let app = Router::new()
        // Route: /cluster/{cluster_name}/* - proxy to agent
        .route("/cluster/{cluster_name}", any(proxy_handler))
        .route("/cluster/{cluster_name}/{*path}", any(proxy_handler))
        // Health check
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let tls_config =
        RustlsConfig::from_pem(config.cert_pem.into_bytes(), config.key_pem.into_bytes())
            .await
            .map_err(|e| ProxyError::TlsConfig(e.to_string()))?;

    info!(addr = %config.addr, "Starting K8s API proxy server");

    axum_server::bind_rustls(config.addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| ProxyError::Server(e.to_string()))?;

    Ok(())
}

/// Check if a method is allowed (read-only)
fn is_read_only_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

/// Check if a query indicates a watch request
fn is_watch_query(query: Option<&str>) -> bool {
    query.is_some_and(|q| q.contains("watch=true") || q.contains("watch=1"))
}

/// Extract path parameters from axum
#[derive(serde::Deserialize)]
struct ProxyPathParams {
    cluster_name: String,
    #[serde(default)]
    path: String,
}

/// Handle proxy requests
async fn proxy_handler(
    State(state): State<ProxyState>,
    Path(params): Path<ProxyPathParams>,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let cluster_name = &params.cluster_name;
    let method = request.method().clone();
    let uri = request.uri().clone();
    let query = uri.query();

    debug!(
        cluster = %cluster_name,
        method = %method,
        path = %params.path,
        query = ?query,
        "Proxy request received"
    );

    // Check if method is read-only
    if !is_read_only_method(&method) {
        warn!(
            cluster = %cluster_name,
            method = %method,
            "Rejected non-read proxy request"
        );
        return Err(ProxyError::MethodNotAllowed(method.to_string()));
    }

    // Look up agent in registry
    let agent = state.registry.get(cluster_name).ok_or_else(|| {
        debug!(cluster = %cluster_name, "Agent not connected");
        ProxyError::AgentNotConnected(cluster_name.clone())
    })?;

    // Check if pivot is already complete (proxy should not be used post-pivot)
    if agent.pivot_complete {
        warn!(
            cluster = %cluster_name,
            "Rejected proxy request for already-pivoted cluster"
        );
        return Err(ProxyError::AlreadyPivoted(cluster_name.clone()));
    }

    // Get the command channel
    let command_tx = agent.command_tx.clone();
    drop(agent); // Release the lock

    // Build the API path
    let api_path = if params.path.is_empty() {
        "/".to_string()
    } else if params.path.starts_with('/') {
        params.path.clone()
    } else {
        format!("/{}", params.path)
    };

    // Generate unique request ID
    let request_id = Uuid::new_v4().to_string();

    // Check if this is a watch request
    let is_watch = is_watch_query(query);

    // Build KubernetesRequest
    let k8s_request = KubernetesRequest {
        request_id: request_id.clone(),
        verb: if is_watch {
            "GET".to_string()
        } else {
            method.to_string()
        },
        path: api_path,
        query: query.unwrap_or("").to_string(),
        body: Vec::new(), // Read-only, no body
        content_type: String::new(),
        timeout_ms: if is_watch {
            0
        } else {
            DEFAULT_TIMEOUT.as_millis() as u32
        },
        cancel: false,
    };

    // Create response channel
    let (response_tx, mut response_rx) = mpsc::channel::<KubernetesResponse>(RESPONSE_CHANNEL_SIZE);

    // Register pending response
    state
        .registry
        .register_pending_k8s_response(&request_id, response_tx);

    // Send request to agent
    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(cell_command::Command::KubernetesRequest(k8s_request)),
    };

    if let Err(e) = command_tx.send(command).await {
        state.registry.take_pending_k8s_response(&request_id);
        error!(
            cluster = %cluster_name,
            request_id = %request_id,
            error = %e,
            "Failed to send K8s request to agent"
        );
        return Err(ProxyError::SendFailed(e.to_string()));
    }

    debug!(
        cluster = %cluster_name,
        request_id = %request_id,
        is_watch = is_watch,
        "Sent K8s request to agent"
    );

    // Wait for response
    if is_watch {
        // For watch requests, stream responses (takes ownership of receiver)
        handle_watch_response(cluster_name, &request_id, response_rx, &state.registry).await
    } else {
        // For single requests, wait with timeout
        handle_single_response(cluster_name, &request_id, &mut response_rx, &state.registry).await
    }
}

/// Handle a single (non-watch) response
async fn handle_single_response(
    cluster_name: &str,
    request_id: &str,
    response_rx: &mut mpsc::Receiver<KubernetesResponse>,
    registry: &SharedAgentRegistry,
) -> Result<Response<Body>, ProxyError> {
    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %request_id,
                status_code = response.status_code,
                body_len = response.body.len(),
                "Received K8s API response"
            );

            // Clean up pending response
            registry.take_pending_k8s_response(request_id);

            build_http_response(&response)
        }
        Ok(None) => {
            // Channel closed unexpectedly
            registry.take_pending_k8s_response(request_id);
            error!(
                cluster = %cluster_name,
                request_id = %request_id,
                "Response channel closed unexpectedly"
            );
            Err(ProxyError::SendFailed("channel closed".to_string()))
        }
        Err(_) => {
            // Timeout
            registry.take_pending_k8s_response(request_id);
            warn!(
                cluster = %cluster_name,
                request_id = %request_id,
                "K8s API request timed out"
            );
            Err(ProxyError::Timeout)
        }
    }
}

/// Handle a watch (streaming) response
async fn handle_watch_response(
    cluster_name: &str,
    request_id: &str,
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
    registry: &SharedAgentRegistry,
) -> Result<Response<Body>, ProxyError> {
    // For watch responses, we need to stream events back
    // Create a channel to stream the body
    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    // Spawn a task to forward responses to the body stream
    let cluster_name = cluster_name.to_string();
    let request_id = request_id.to_string();
    let registry = registry.clone();

    tokio::spawn(async move {
        loop {
            match response_rx.recv().await {
                Some(response) => {
                    debug!(
                        cluster = %cluster_name,
                        request_id = %request_id,
                        streaming = response.streaming,
                        stream_end = response.stream_end,
                        body_len = response.body.len(),
                        "Forwarding watch event"
                    );

                    // Send the body as a chunk
                    if !response.body.is_empty() {
                        // Add newline to separate JSON events
                        let mut body = response.body;
                        body.push(b'\n');
                        if body_tx
                            .send(Ok(axum::body::Bytes::from(body)))
                            .await
                            .is_err()
                        {
                            // Client disconnected
                            debug!(
                                cluster = %cluster_name,
                                request_id = %request_id,
                                "Client disconnected during watch"
                            );
                            break;
                        }
                    }

                    // Check for errors
                    if !response.error.is_empty() {
                        warn!(
                            cluster = %cluster_name,
                            request_id = %request_id,
                            error = %response.error,
                            "Watch error from agent"
                        );
                    }

                    // Check for stream end
                    if response.stream_end {
                        debug!(
                            cluster = %cluster_name,
                            request_id = %request_id,
                            "Watch stream ended"
                        );
                        break;
                    }
                }
                None => {
                    // Channel closed (agent disconnected)
                    debug!(
                        cluster = %cluster_name,
                        request_id = %request_id,
                        "Watch channel closed (agent may have disconnected)"
                    );
                    break;
                }
            }
        }

        // Clean up
        registry.take_pending_k8s_response(&request_id);
    });

    // Build streaming response
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .unwrap())
}

/// Build HTTP response from KubernetesResponse
fn build_http_response(response: &KubernetesResponse) -> Result<Response<Body>, ProxyError> {
    let status = StatusCode::from_u16(response.status_code as u16).unwrap_or(StatusCode::OK);

    let content_type = if response.content_type.is_empty() {
        "application/json"
    } else {
        &response.content_type
    };

    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Body::from(response.body.clone()))
        .map_err(|e| ProxyError::Server(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_read_only_method() {
        assert!(is_read_only_method(&Method::GET));
        assert!(is_read_only_method(&Method::HEAD));
        assert!(is_read_only_method(&Method::OPTIONS));
        assert!(!is_read_only_method(&Method::POST));
        assert!(!is_read_only_method(&Method::PUT));
        assert!(!is_read_only_method(&Method::PATCH));
        assert!(!is_read_only_method(&Method::DELETE));
    }

    #[test]
    fn test_is_watch_query() {
        assert!(is_watch_query(Some("watch=true")));
        assert!(is_watch_query(Some("watch=1")));
        assert!(is_watch_query(Some("labelSelector=app&watch=true")));
        assert!(is_watch_query(Some("watch=true&resourceVersion=100")));
        assert!(!is_watch_query(Some("watch=false")));
        assert!(!is_watch_query(Some("labelSelector=app")));
        assert!(!is_watch_query(None));
    }

    #[test]
    fn test_proxy_error_response() {
        let error = ProxyError::AgentNotConnected("test".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let error = ProxyError::AlreadyPivoted("test".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::GONE);

        let error = ProxyError::MethodNotAllowed("POST".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let error = ProxyError::Timeout;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
