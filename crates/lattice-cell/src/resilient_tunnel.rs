//! Resilient K8s API tunneling with automatic reconnection
//!
//! Wraps the basic k8s_tunnel functionality to provide:
//! - Automatic retry on agent reconnection
//! - Client connection buffering during brief disconnections
//! - Watch resumption using resourceVersion

use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use lattice_proto::KubernetesResponse;

use crate::connection::{ReconnectionNotifier, SharedAgentRegistry};
use crate::k8s_tunnel::{
    build_http_response, tunnel_request_streaming, K8sRequestParams, TunnelError, DEFAULT_TIMEOUT,
    RESPONSE_CHANNEL_SIZE,
};

/// Default timeout for waiting for agent reconnection
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for resilient tunneling
#[derive(Clone, Debug)]
pub struct ResilientTunnelConfig {
    /// How long to wait for agent reconnection before giving up
    pub reconnect_timeout: Duration,
    /// Whether to enable resilient mode (wait for reconnect vs fail fast)
    pub enabled: bool,
}

impl Default for ResilientTunnelConfig {
    fn default() -> Self {
        Self {
            reconnect_timeout: RECONNECT_TIMEOUT,
            enabled: true,
        }
    }
}

/// Send a K8s request with automatic retry on agent reconnection.
///
/// For watch requests: Returns a streaming response that survives brief disconnections.
/// For regular requests: Retries once if agent reconnects within timeout.
///
/// This provides a better user experience by buffering the client connection
/// during temporary agent disconnections instead of immediately failing.
pub async fn tunnel_request_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    let is_watch = lattice_proto::is_watch_query(&params.query);

    if is_watch {
        tunnel_watch_resilient(registry, cluster_name, params, config).await
    } else {
        tunnel_single_resilient(registry, cluster_name, params, config).await
    }
}

/// Handle a single (non-watch) request with reconnection retry
async fn tunnel_single_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    // First attempt - handle both missing agent and request failure
    let first_attempt_result = match get_command_tx(registry, cluster_name) {
        Ok(command_tx) => tunnel_and_receive(registry, cluster_name, command_tx, &params).await,
        Err(e) => Err(e),
    };

    match first_attempt_result {
        Ok(response) => return Ok(response),
        Err(e) if !config.enabled || !is_retryable(&e) => return Err(e),
        Err(e) => {
            debug!(
                cluster = %cluster_name,
                error = %e,
                "Request failed, waiting for reconnection"
            );
        }
    }

    // Wait for reconnection and retry
    let mut reconnect_rx = registry.subscribe_reconnections();
    let deadline = tokio::time::Instant::now() + config.reconnect_timeout;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                warn!(cluster = %cluster_name, "Reconnection timeout exceeded");
                return Err(TunnelError::Timeout);
            }
            result = reconnect_rx.recv() => {
                match result {
                    Ok(notification) if notification.cluster_name == cluster_name => {
                        info!(cluster = %cluster_name, "Agent reconnected, retrying request");
                        return tunnel_and_receive(
                            registry,
                            cluster_name,
                            notification.command_tx,
                            &params,
                        ).await;
                    }
                    Ok(_) => continue, // Different cluster
                    Err(_) => {
                        return Err(TunnelError::ChannelClosed);
                    }
                }
            }
        }
    }
}

/// Handle a watch request with reconnection resilience
///
/// Creates a streaming response that survives brief disconnections by:
/// 1. Extracting resourceVersion from each event
/// 2. On disconnect, waiting for reconnect
/// 3. Re-establishing watch from last known resourceVersion
async fn tunnel_watch_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    // Clone what we need for the spawned task
    let registry = registry.clone();
    let cluster_name = cluster_name.to_string();
    let reconnect_timeout = config.reconnect_timeout;
    let resilient_enabled = config.enabled;

    tokio::spawn(async move {
        let mut current_params = params;

        loop {
            // Get command channel for current connection
            let command_tx = match get_command_tx(&registry, &cluster_name) {
                Ok(tx) => tx,
                Err(_) if !resilient_enabled => break,
                Err(_) => {
                    // Wait for reconnection
                    if !wait_for_reconnect(&registry, &cluster_name, reconnect_timeout).await {
                        break;
                    }
                    continue;
                }
            };

            // Start watch stream
            let response_rx = match tunnel_request_streaming(
                &registry,
                &cluster_name,
                command_tx,
                current_params.clone(),
            )
            .await
            {
                Ok(rx) => rx,
                Err(_) if !resilient_enabled => break,
                Err(e) => {
                    debug!(
                        cluster = %cluster_name,
                        error = %e,
                        "Watch request failed, waiting for reconnection"
                    );
                    if !wait_for_reconnect(&registry, &cluster_name, reconnect_timeout).await {
                        break;
                    }
                    continue;
                }
            };

            // Stream responses to client, tracking resourceVersion
            let disconnect =
                stream_watch_responses(response_rx, &body_tx, &mut current_params).await;

            if !disconnect || !resilient_enabled {
                break;
            }

            // Agent disconnected - wait for reconnect
            info!(
                cluster = %cluster_name,
                "Watch stream interrupted, waiting for reconnection"
            );
            if !wait_for_reconnect(&registry, &cluster_name, reconnect_timeout).await {
                break;
            }
            info!(
                cluster = %cluster_name,
                "Resuming watch after reconnection"
            );
        }
    });

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx));

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .map_err(|e| TunnelError::ResponseBuild(e.to_string()))
}

/// Get command channel for a cluster
///
/// Returns:
/// - Ok(sender) if agent is connected
/// - Err(ChannelClosed) if agent is known but disconnected (retryable)
/// - Err(UnknownCluster) if agent has never connected (not retryable)
fn get_command_tx(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
) -> Result<mpsc::Sender<lattice_proto::CellCommand>, TunnelError> {
    match registry.get(cluster_name) {
        Some(agent) if agent.connected => Ok(agent.command_tx.clone()),
        Some(_) => Err(TunnelError::ChannelClosed), // Known but disconnected
        None => Err(TunnelError::UnknownCluster(cluster_name.to_string())),
    }
}

/// Execute tunnel request and receive single response
async fn tunnel_and_receive(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
    params: &K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let mut response_rx =
        tunnel_request_streaming(registry, cluster_name, command_tx, params.clone()).await?;

    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => build_http_response(&response),
        Ok(None) => Err(TunnelError::ChannelClosed),
        Err(_) => Err(TunnelError::Timeout),
    }
}

/// Check if an error is retryable (worth waiting for reconnect)
///
/// Retryable errors indicate the agent was known but is temporarily disconnected.
/// Non-retryable errors (UnknownCluster, Timeout, AgentError) should fail fast.
fn is_retryable(e: &TunnelError) -> bool {
    matches!(e, TunnelError::ChannelClosed | TunnelError::SendFailed(_))
}

/// Wait for agent reconnection
///
/// Returns true if reconnected, false if timeout or should stop
async fn wait_for_reconnect(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    timeout: Duration,
) -> bool {
    let mut reconnect_rx = registry.subscribe_reconnections();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                warn!(cluster = %cluster_name, "Reconnection timeout exceeded");
                return false;
            }
            result = reconnect_rx.recv() => {
                match result {
                    Ok(notification) if notification.cluster_name == cluster_name => {
                        return true;
                    }
                    Ok(_) => continue, // Different cluster
                    Err(_) => return false,
                }
            }
        }
    }
}

/// Stream watch responses to client, tracking resourceVersion
///
/// Returns true if disconnected (should retry), false if stream ended normally
async fn stream_watch_responses(
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
    body_tx: &mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
    params: &mut K8sRequestParams,
) -> bool {
    while let Some(response) = response_rx.recv().await {
        // Extract resourceVersion from watch events for resume
        if let Some(rv) = extract_resource_version(&response.body) {
            update_resource_version_in_query(&mut params.query, &rv);
        }

        // Forward to client
        if !response.body.is_empty()
            && body_tx
                .send(Ok(axum::body::Bytes::from(response.body)))
                .await
                .is_err()
        {
            // Client disconnected
            return false;
        }

        if !response.error.is_empty() {
            warn!(error = %response.error, "Watch error from agent");
        }

        if response.stream_end {
            return false; // Normal end
        }
    }

    // Channel closed = agent disconnected
    true
}

/// Extract resourceVersion from a watch event JSON
///
/// Watch events look like: {"type":"ADDED","object":{"metadata":{"resourceVersion":"12345",...},...}}
fn extract_resource_version(body: &[u8]) -> Option<String> {
    // Simple JSON parsing - look for "resourceVersion":"<value>"
    let s = std::str::from_utf8(body).ok()?;

    // Find resourceVersion in the object's metadata
    let rv_key = "\"resourceVersion\":\"";
    let start = s.find(rv_key)? + rv_key.len();
    let end = s[start..].find('"')? + start;

    Some(s[start..end].to_string())
}

/// Update resourceVersion in query string for watch resume
fn update_resource_version_in_query(query: &mut String, resource_version: &str) {
    // Parse query params
    let mut params: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    // Update or add resourceVersion
    let mut found = false;
    for (k, v) in &mut params {
        if k == "resourceVersion" {
            *v = resource_version.to_string();
            found = true;
            break;
        }
    }
    if !found {
        params.push(("resourceVersion".to_string(), resource_version.to_string()));
    }

    // Rebuild query string
    *query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_resource_version() {
        let event =
            br#"{"type":"ADDED","object":{"metadata":{"resourceVersion":"12345","name":"test"}}}"#;
        assert_eq!(extract_resource_version(event), Some("12345".to_string()));
    }

    #[test]
    fn test_extract_resource_version_no_rv() {
        let event = br#"{"type":"ERROR","object":{}}"#;
        assert_eq!(extract_resource_version(event), None);
    }

    #[test]
    fn test_update_resource_version_in_query_existing() {
        let mut query = "watch=true&resourceVersion=100".to_string();
        update_resource_version_in_query(&mut query, "200");
        assert!(query.contains("resourceVersion=200"));
        assert!(!query.contains("resourceVersion=100"));
    }

    #[test]
    fn test_update_resource_version_in_query_new() {
        let mut query = "watch=true".to_string();
        update_resource_version_in_query(&mut query, "300");
        assert!(query.contains("resourceVersion=300"));
        assert!(query.contains("watch=true"));
    }

    #[test]
    fn test_update_resource_version_in_query_empty() {
        let mut query = String::new();
        update_resource_version_in_query(&mut query, "400");
        assert_eq!(query, "resourceVersion=400");
    }

    #[test]
    fn test_is_retryable() {
        // Retryable: known agent that disconnected
        assert!(is_retryable(&TunnelError::ChannelClosed));
        assert!(is_retryable(&TunnelError::SendFailed("test".into())));

        // Not retryable: unknown cluster or other errors
        assert!(!is_retryable(&TunnelError::UnknownCluster("test".into())));
        assert!(!is_retryable(&TunnelError::Timeout));
        assert!(!is_retryable(&TunnelError::AgentError("test".into())));
    }

    #[test]
    fn test_resilient_config_default() {
        let config = ResilientTunnelConfig::default();
        assert_eq!(config.reconnect_timeout, RECONNECT_TIMEOUT);
        assert!(config.enabled);
    }
}
