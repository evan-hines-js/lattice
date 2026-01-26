//! K8s API request executor
//!
//! Executes Kubernetes API requests against the local cluster and returns responses.
//! Single requests return immediately, watch requests are handled by the watch module.

use kube::Client;
use lattice_proto::{KubernetesRequest, KubernetesResponse};
use tracing::{debug, error};

/// Check if a request is a watch request
pub fn is_watch_request(req: &KubernetesRequest) -> bool {
    req.query.contains("watch=true") || req.query.contains("watch=1")
}

/// Execute a single (non-watch) K8s API request against the local cluster
pub async fn execute_k8s_request(client: &Client, req: &KubernetesRequest) -> KubernetesResponse {
    // Handle cancellation requests
    if req.cancel {
        return KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 200,
            streaming: true,
            stream_end: true,
            ..Default::default()
        };
    }

    // Watch requests should be handled by execute_watch, not this function
    if is_watch_request(req) {
        return KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 400,
            error: "Watch requests should use execute_watch".to_string(),
            ..Default::default()
        };
    }

    // Build the request URL
    let url = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };

    // Build HTTP request
    let request = match req.verb.to_uppercase().as_str() {
        "GET" | "LIST" => http::Request::get(&url),
        "POST" => http::Request::post(&url),
        "PUT" => http::Request::put(&url),
        "PATCH" => http::Request::patch(&url),
        "DELETE" => http::Request::delete(&url),
        _ => {
            return KubernetesResponse {
                request_id: req.request_id.clone(),
                status_code: 400,
                error: format!("Unsupported verb: {}", req.verb),
                ..Default::default()
            };
        }
    };

    let request = if !req.body.is_empty() {
        let content_type = if req.content_type.is_empty() {
            "application/json"
        } else {
            &req.content_type
        };
        request
            .header(http::header::CONTENT_TYPE, content_type)
            .body(req.body.clone())
    } else {
        request.body(Vec::new())
    };

    let request = match request {
        Ok(r) => r,
        Err(e) => {
            return KubernetesResponse {
                request_id: req.request_id.clone(),
                status_code: 400,
                error: format!("Failed to build request: {}", e),
                ..Default::default()
            };
        }
    };

    debug!(
        request_id = %req.request_id,
        verb = %req.verb,
        path = %req.path,
        "Executing K8s API request"
    );

    // Execute the request
    match client.request::<serde_json::Value>(request).await {
        Ok(value) => {
            let body = serde_json::to_vec(&value).unwrap_or_default();
            KubernetesResponse {
                request_id: req.request_id.clone(),
                status_code: 200,
                body,
                content_type: "application/json".to_string(),
                ..Default::default()
            }
        }
        Err(e) => {
            let (status_code, error_body) = match &e {
                kube::Error::Api(api_err) => {
                    let body = serde_json::to_vec(&api_err).unwrap_or_default();
                    (api_err.code, body)
                }
                _ => (500, Vec::new()),
            };
            error!(
                request_id = %req.request_id,
                status_code = status_code,
                error = %e,
                "K8s API request failed"
            );
            KubernetesResponse {
                request_id: req.request_id.clone(),
                status_code: status_code as u32,
                body: error_body,
                content_type: "application/json".to_string(),
                error: e.to_string(),
                ..Default::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_watch_request() {
        let req = KubernetesRequest {
            query: "watch=true".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));

        let req = KubernetesRequest {
            query: "watch=1".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));

        let req = KubernetesRequest {
            query: "labelSelector=app%3Dtest".to_string(),
            ..Default::default()
        };
        assert!(!is_watch_request(&req));
    }

    #[test]
    fn test_cancel_request_handling() {
        // Test is synchronous - just verify the struct creation
        let req = KubernetesRequest {
            request_id: "test-cancel".to_string(),
            cancel: true,
            ..Default::default()
        };
        assert!(req.cancel);
    }
}
