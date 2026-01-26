//! Watch execution for K8s API proxy
//!
//! Handles streaming watch requests from the parent cell by using
//! kube-rs to watch resources and streaming events back via gRPC.

use std::sync::Arc;

use dashmap::DashMap;
use kube::api::{DynamicObject, ListParams};
use kube::discovery::{ApiCapabilities, ApiResource, Scope};
use kube::{Api, Client, Discovery};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use lattice_proto::{agent_message::Payload, AgentMessage, KubernetesRequest, KubernetesResponse};

/// Registry for tracking active watches on the agent
#[derive(Default)]
pub struct WatchRegistry {
    active: DashMap<String, CancellationToken>,
}

impl WatchRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            active: DashMap::new(),
        }
    }

    /// Register a watch and return its cancellation token
    pub fn register(&self, request_id: String) -> CancellationToken {
        let token = CancellationToken::new();
        debug!(request_id = %request_id, "Registering watch");
        self.active.insert(request_id, token.clone());
        token
    }

    /// Cancel an active watch
    pub fn cancel(&self, request_id: &str) -> bool {
        if let Some((_, token)) = self.active.remove(request_id) {
            info!(request_id = %request_id, "Cancelling watch");
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Unregister a watch after completion
    pub fn unregister(&self, request_id: &str) {
        self.active.remove(request_id);
    }

    /// Cancel all active watches
    pub fn cancel_all(&self) {
        let count = self.active.len();
        if count > 0 {
            info!(count = count, "Cancelling all active watches");
            for entry in self.active.iter() {
                entry.value().cancel();
            }
            self.active.clear();
        }
    }
}

/// Execute a watch request and stream events back
pub async fn execute_watch(
    client: Client,
    req: KubernetesRequest,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    registry: Arc<WatchRegistry>,
) {
    let request_id = req.request_id.clone();
    let cancel_token = registry.register(request_id.clone());

    // Parse the path to determine resource type
    let (api_resource, namespace) = match parse_api_path(&req.path) {
        Ok(parsed) => parsed,
        Err(e) => {
            send_error_response(&message_tx, &cluster_name, &request_id, 400, &e).await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Discover the API resource
    let discovery = match Discovery::new(client.clone()).run().await {
        Ok(d) => d,
        Err(e) => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                500,
                &format!("Discovery failed: {}", e),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Find the API resource in discovery
    let (ar, caps) = match find_api_resource(&discovery, &api_resource) {
        Some(found) => found,
        None => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                404,
                &format!("Resource not found: {}", api_resource),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Create the API based on scope
    let api: Api<DynamicObject> = if caps.scope == Scope::Cluster {
        Api::all_with(client.clone(), &ar)
    } else if let Some(ns) = &namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else {
        Api::all_with(client.clone(), &ar)
    };

    // Parse query params for watch options
    let mut lp = ListParams::default();
    for param in req.query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "labelSelector" => {
                    lp = lp.labels(value);
                }
                "fieldSelector" => {
                    lp = lp.fields(value);
                }
                "resourceVersion" => {
                    // Resource version is handled by kube-rs internally
                }
                _ => {}
            }
        }
    }

    debug!(
        request_id = %request_id,
        resource = %api_resource,
        namespace = ?namespace,
        "Starting watch"
    );

    // Use kube-rs watcher
    use futures::StreamExt;
    use kube::runtime::{watcher, WatchStreamExt};

    let watcher = watcher(api, watcher::Config::default().any_semantic())
        .default_backoff()
        .applied_objects();

    tokio::pin!(watcher);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!(request_id = %request_id, "Watch cancelled");
                send_stream_end(&message_tx, &cluster_name, &request_id).await;
                break;
            }
            event = watcher.next() => {
                match event {
                    Some(Ok(obj)) => {
                        // Convert to watch event format
                        let event_json = serde_json::json!({
                            "type": "ADDED",
                            "object": obj
                        });
                        let body = serde_json::to_vec(&event_json).unwrap_or_default();

                        let response = KubernetesResponse {
                            request_id: request_id.clone(),
                            status_code: 200,
                            body,
                            content_type: "application/json".to_string(),
                            streaming: true,
                            stream_end: false,
                            error: String::new(),
                        };

                        if send_response(&message_tx, &cluster_name, response).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!(request_id = %request_id, error = %e, "Watch error");
                        send_error_response(
                            &message_tx,
                            &cluster_name,
                            &request_id,
                            500,
                            &e.to_string(),
                        ).await;
                        break;
                    }
                    None => {
                        // Stream ended
                        send_stream_end(&message_tx, &cluster_name, &request_id).await;
                        break;
                    }
                }
            }
        }
    }

    registry.unregister(&request_id);
}

/// Parse an API path to extract resource type and namespace
fn parse_api_path(path: &str) -> Result<(String, Option<String>), String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Handle different path formats:
    // /api/v1/pods -> core pods
    // /api/v1/namespaces/default/pods -> namespaced pods
    // /apis/apps/v1/deployments -> apps deployments
    // /apis/apps/v1/namespaces/default/deployments -> namespaced deployments

    if parts.is_empty() {
        return Err("Empty path".to_string());
    }

    let (resource, namespace) = if parts[0] == "api" {
        // Core API
        if parts.len() >= 4 && parts[2] == "namespaces" {
            // /api/v1/namespaces/{ns}/{resource}
            let ns = parts[3].to_string();
            let resource = parts.get(4).unwrap_or(&"").to_string();
            (resource, Some(ns))
        } else if parts.len() >= 3 {
            // /api/v1/{resource}
            (parts[2].to_string(), None)
        } else {
            return Err("Invalid core API path".to_string());
        }
    } else if parts[0] == "apis" {
        // Extended APIs
        if parts.len() >= 5 && parts[3] == "namespaces" {
            // /apis/{group}/{version}/namespaces/{ns}/{resource}
            let ns = parts[4].to_string();
            let resource = parts.get(5).unwrap_or(&"").to_string();
            (resource, Some(ns))
        } else if parts.len() >= 4 {
            // /apis/{group}/{version}/{resource}
            (parts[3].to_string(), None)
        } else {
            return Err("Invalid extended API path".to_string());
        }
    } else {
        return Err(format!("Unknown API prefix: {}", parts[0]));
    };

    if resource.is_empty() {
        return Err("Could not determine resource type".to_string());
    }

    Ok((resource, namespace))
}

/// Find an API resource in discovery results
fn find_api_resource(
    discovery: &Discovery,
    resource_name: &str,
) -> Option<(ApiResource, ApiCapabilities)> {
    for group in discovery.groups() {
        for (ar, caps) in group.recommended_resources() {
            if ar.plural == resource_name || ar.kind.to_lowercase() == resource_name.to_lowercase()
            {
                return Some((ar, caps));
            }
        }
    }
    None
}

async fn send_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    response: KubernetesResponse,
) -> Result<(), ()> {
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::KubernetesResponse(response)),
    };
    tx.send(msg).await.map_err(|_| ())
}

async fn send_error_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    status_code: u32,
    error: &str,
) {
    let response = KubernetesResponse {
        request_id: request_id.to_string(),
        status_code,
        error: error.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    };
    let _ = send_response(tx, cluster_name, response).await;
}

async fn send_stream_end(tx: &mpsc::Sender<AgentMessage>, cluster_name: &str, request_id: &str) {
    let response = KubernetesResponse {
        request_id: request_id.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    };
    let _ = send_response(tx, cluster_name, response).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_path_core_cluster_scoped() {
        let (resource, ns) = parse_api_path("/api/v1/nodes").unwrap();
        assert_eq!(resource, "nodes");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_core_namespaced() {
        let (resource, ns) = parse_api_path("/api/v1/namespaces/default/pods").unwrap();
        assert_eq!(resource, "pods");
        assert_eq!(ns, Some("default".to_string()));
    }

    #[test]
    fn test_parse_api_path_extended_cluster_scoped() {
        let (resource, ns) = parse_api_path("/apis/apps/v1/deployments").unwrap();
        assert_eq!(resource, "deployments");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_extended_namespaced() {
        let (resource, ns) =
            parse_api_path("/apis/apps/v1/namespaces/kube-system/deployments").unwrap();
        assert_eq!(resource, "deployments");
        assert_eq!(ns, Some("kube-system".to_string()));
    }

    #[test]
    fn test_parse_api_path_invalid() {
        assert!(parse_api_path("").is_err());
        assert!(parse_api_path("/unknown/v1/pods").is_err());
    }

    #[test]
    fn test_watch_registry() {
        let registry = WatchRegistry::new();

        let token = registry.register("watch-1".to_string());
        assert!(!token.is_cancelled());

        registry.cancel("watch-1");
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_watch_registry_cancel_all() {
        let registry = WatchRegistry::new();

        let t1 = registry.register("w1".to_string());
        let t2 = registry.register("w2".to_string());

        registry.cancel_all();

        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }
}
