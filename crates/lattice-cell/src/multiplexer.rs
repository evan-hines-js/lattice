//! Request multiplexer for K8s API proxy
//!
//! When the parent receives an HTTP request for a child's K8s API, it:
//! 1. Registers the request with the multiplexer
//! 2. Sends a KubernetesRequest to the agent via gRPC
//! 3. Waits for response(s) from the multiplexer
//!
//! The multiplexer routes incoming KubernetesResponse messages to the
//! correct pending request based on request_id.
//!
//! # Single vs Streaming Requests
//!
//! - Single (GET/POST/PUT/PATCH/DELETE): Returns one response via oneshot
//! - Streaming (watch): Returns multiple responses via mpsc channel
//!
//! # Backpressure
//!
//! Streaming channels are bounded. If a consumer is too slow, the watch
//! will be cancelled to prevent memory exhaustion.

use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use lattice_proto::KubernetesResponse;

/// Error dispatching a response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// No pending request with this request_id
    NoPendingRequest,
    /// Receiver was dropped (client disconnected)
    ReceiverDropped,
    /// Consumer is too slow (backpressure)
    ConsumerSlow,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::NoPendingRequest => write!(f, "no pending request with this ID"),
            DispatchError::ReceiverDropped => write!(f, "receiver dropped"),
            DispatchError::ConsumerSlow => write!(f, "consumer too slow"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Pending request waiting for response(s)
enum PendingRequest {
    /// Single request expecting one response
    Single(oneshot::Sender<KubernetesResponse>),
    /// Streaming request (watch) expecting multiple responses
    Streaming {
        sender: mpsc::Sender<KubernetesResponse>,
        cancel_token: CancellationToken,
    },
}

/// Multiplexer for routing K8s API responses to pending requests
///
/// Thread-safe using DashMap for concurrent access from multiple
/// gRPC handlers and HTTP handlers.
#[derive(Default)]
pub struct RequestMultiplexer {
    pending: DashMap<String, PendingRequest>,
}

/// Default buffer size for streaming channels
const STREAM_BUFFER_SIZE: usize = 64;

/// Timeout for sending to slow consumers before cancelling
const SLOW_CONSUMER_TIMEOUT: Duration = Duration::from_secs(5);

impl RequestMultiplexer {
    /// Create a new empty multiplexer
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }

    /// Register a single (non-streaming) request
    ///
    /// Returns a receiver that will get the response when it arrives.
    pub fn register_single(&self, request_id: String) -> oneshot::Receiver<KubernetesResponse> {
        let (tx, rx) = oneshot::channel();
        debug!(request_id = %request_id, "Registering single request");
        self.pending.insert(request_id, PendingRequest::Single(tx));
        rx
    }

    /// Register a streaming (watch) request
    ///
    /// Returns:
    /// - A receiver for streaming responses
    /// - A cancellation token that gets triggered if the watch is cancelled
    ///
    /// The receiver is bounded to prevent memory exhaustion with slow consumers.
    pub fn register_streaming(
        &self,
        request_id: String,
    ) -> (mpsc::Receiver<KubernetesResponse>, CancellationToken) {
        let (tx, rx) = mpsc::channel(STREAM_BUFFER_SIZE);
        let cancel_token = CancellationToken::new();
        debug!(request_id = %request_id, "Registering streaming request");
        self.pending.insert(
            request_id,
            PendingRequest::Streaming {
                sender: tx,
                cancel_token: cancel_token.clone(),
            },
        );
        (rx, cancel_token)
    }

    /// Dispatch a response to the appropriate pending request
    ///
    /// For single requests, the entry is removed after dispatch.
    /// For streaming requests, the entry remains until stream_end=true.
    pub async fn dispatch(&self, response: KubernetesResponse) -> Result<(), DispatchError> {
        let request_id = response.request_id.clone();
        let is_stream_end = response.stream_end;

        // Get the pending request
        let entry = self.pending.get(&request_id);
        match entry {
            Some(entry) => match entry.value() {
                PendingRequest::Single(_) => {
                    // For single requests, remove and send
                    drop(entry);
                    if let Some((_, PendingRequest::Single(tx))) = self.pending.remove(&request_id)
                    {
                        debug!(request_id = %request_id, "Dispatching single response");
                        tx.send(response).map_err(|_| DispatchError::ReceiverDropped)
                    } else {
                        // Race condition - another task removed it
                        Err(DispatchError::NoPendingRequest)
                    }
                }
                PendingRequest::Streaming { sender, cancel_token } => {
                    // Clone what we need before dropping the guard
                    let sender = sender.clone();
                    let cancel_token = cancel_token.clone();
                    drop(entry);

                    // Try send with timeout to detect slow consumers
                    match tokio::time::timeout(SLOW_CONSUMER_TIMEOUT, sender.send(response)).await {
                        Ok(Ok(())) => {
                            debug!(request_id = %request_id, stream_end = is_stream_end, "Dispatched streaming response");
                            // Remove entry on stream_end
                            if is_stream_end {
                                self.pending.remove(&request_id);
                            }
                            Ok(())
                        }
                        Ok(Err(_)) => {
                            // Channel closed - receiver dropped
                            warn!(request_id = %request_id, "Streaming receiver dropped");
                            self.pending.remove(&request_id);
                            Err(DispatchError::ReceiverDropped)
                        }
                        Err(_) => {
                            // Timeout - consumer too slow
                            warn!(request_id = %request_id, "Consumer too slow, cancelling watch");
                            cancel_token.cancel();
                            self.pending.remove(&request_id);
                            Err(DispatchError::ConsumerSlow)
                        }
                    }
                }
            },
            None => {
                warn!(request_id = %request_id, "No pending request for response");
                Err(DispatchError::NoPendingRequest)
            }
        }
    }

    /// Cancel a pending request
    ///
    /// For streaming requests, triggers the cancellation token.
    /// For single requests, the sender is dropped (receiver gets error).
    /// Returns true if a request was found and cancelled.
    pub fn cancel(&self, request_id: &str) -> bool {
        if let Some((_, pending)) = self.pending.remove(request_id) {
            info!(request_id = %request_id, "Cancelling pending request");
            if let PendingRequest::Streaming { cancel_token, .. } = pending {
                cancel_token.cancel();
            }
            true
        } else {
            false
        }
    }

    /// Cancel all pending requests
    ///
    /// Called when the agent disconnects to clean up all resources.
    pub fn cancel_all(&self) {
        let count = self.pending.len();
        if count > 0 {
            info!(count = count, "Cancelling all pending requests");
            for entry in self.pending.iter() {
                if let PendingRequest::Streaming { cancel_token, .. } = entry.value() {
                    cancel_token.cancel();
                }
            }
            self.pending.clear();
        }
    }

    /// Get the number of pending requests
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if multiplexer has no pending requests
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Check if a request is pending
    pub fn is_pending(&self, request_id: &str) -> bool {
        self.pending.contains_key(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(request_id: &str, streaming: bool, stream_end: bool) -> KubernetesResponse {
        KubernetesResponse {
            request_id: request_id.to_string(),
            status_code: 200,
            body: b"test".to_vec(),
            content_type: "application/json".to_string(),
            streaming,
            stream_end,
            error: String::new(),
        }
    }

    #[test]
    fn test_multiplexer_new() {
        let mux = RequestMultiplexer::new();
        assert!(mux.is_empty());
        assert_eq!(mux.len(), 0);
    }

    #[test]
    fn test_multiplexer_default() {
        let mux = RequestMultiplexer::default();
        assert!(mux.is_empty());
    }

    #[tokio::test]
    async fn test_single_request_success() {
        let mux = RequestMultiplexer::new();

        let rx = mux.register_single("req-1".to_string());
        assert!(mux.is_pending("req-1"));

        // Dispatch response
        let response = make_response("req-1", false, false);
        mux.dispatch(response.clone())
            .await
            .expect("dispatch should succeed");

        // Entry should be removed
        assert!(!mux.is_pending("req-1"));

        // Receiver should get the response
        let received = rx.await.expect("should receive response");
        assert_eq!(received.request_id, "req-1");
    }

    #[tokio::test]
    async fn test_single_request_receiver_dropped() {
        let mux = RequestMultiplexer::new();

        let rx = mux.register_single("req-1".to_string());
        drop(rx);

        let response = make_response("req-1", false, false);
        let result = mux.dispatch(response).await;

        assert!(matches!(result, Err(DispatchError::ReceiverDropped)));
        assert!(!mux.is_pending("req-1"));
    }

    #[tokio::test]
    async fn test_streaming_request_multiple_events() {
        let mux = RequestMultiplexer::new();

        let (mut rx, _cancel_token) = mux.register_streaming("watch-1".to_string());
        assert!(mux.is_pending("watch-1"));

        // Send multiple events
        for i in 0..3 {
            let response = KubernetesResponse {
                request_id: "watch-1".to_string(),
                status_code: 200,
                body: format!("event-{}", i).into_bytes(),
                content_type: "application/json".to_string(),
                streaming: true,
                stream_end: false,
                error: String::new(),
            };
            mux.dispatch(response)
                .await
                .expect("dispatch should succeed");
        }

        // Still pending (not stream_end)
        assert!(mux.is_pending("watch-1"));

        // Receive all events
        for i in 0..3 {
            let received = rx.recv().await.expect("should receive event");
            assert_eq!(received.body, format!("event-{}", i).into_bytes());
        }
    }

    #[tokio::test]
    async fn test_streaming_request_stream_end() {
        let mux = RequestMultiplexer::new();

        let (mut rx, _cancel_token) = mux.register_streaming("watch-1".to_string());

        // Send stream_end
        let response = make_response("watch-1", true, true);
        mux.dispatch(response)
            .await
            .expect("dispatch should succeed");

        // Entry should be removed
        assert!(!mux.is_pending("watch-1"));

        // Should receive the final response
        let received = rx.recv().await.expect("should receive response");
        assert!(received.stream_end);
    }

    #[tokio::test]
    async fn test_dispatch_no_pending_request() {
        let mux = RequestMultiplexer::new();

        let response = make_response("unknown", false, false);
        let result = mux.dispatch(response).await;

        assert!(matches!(result, Err(DispatchError::NoPendingRequest)));
    }

    #[tokio::test]
    async fn test_cancel_single_request() {
        let mux = RequestMultiplexer::new();

        let rx = mux.register_single("req-1".to_string());

        let cancelled = mux.cancel("req-1");
        assert!(cancelled);
        assert!(!mux.is_pending("req-1"));

        // Receiver should get error
        let result = rx.await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cancel_streaming_request() {
        let mux = RequestMultiplexer::new();

        let (_rx, cancel_token) = mux.register_streaming("watch-1".to_string());

        assert!(!cancel_token.is_cancelled());

        let cancelled = mux.cancel("watch-1");
        assert!(cancelled);
        assert!(cancel_token.is_cancelled());
        assert!(!mux.is_pending("watch-1"));
    }

    #[test]
    fn test_cancel_unknown() {
        let mux = RequestMultiplexer::new();
        let cancelled = mux.cancel("nonexistent");
        assert!(!cancelled);
    }

    #[tokio::test]
    async fn test_cancel_all() {
        let mux = RequestMultiplexer::new();

        let rx1 = mux.register_single("req-1".to_string());
        let (_, cancel_token2) = mux.register_streaming("watch-2".to_string());
        let rx3 = mux.register_single("req-3".to_string());

        assert_eq!(mux.len(), 3);

        mux.cancel_all();

        assert!(mux.is_empty());
        assert!(cancel_token2.is_cancelled());
        assert!(rx1.await.is_err());
        assert!(rx3.await.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let mux = RequestMultiplexer::new();

        // Register multiple concurrent requests
        let rx1 = mux.register_single("req-1".to_string());
        let rx2 = mux.register_single("req-2".to_string());
        let (mut rx3, _) = mux.register_streaming("watch-3".to_string());

        assert_eq!(mux.len(), 3);

        // Dispatch responses out of order
        mux.dispatch(make_response("req-2", false, false))
            .await
            .expect("dispatch should succeed");
        mux.dispatch(make_response("watch-3", true, false))
            .await
            .expect("dispatch should succeed");
        mux.dispatch(make_response("req-1", false, false))
            .await
            .expect("dispatch should succeed");

        // All should receive correct response
        let r1 = rx1.await.expect("should receive");
        assert_eq!(r1.request_id, "req-1");

        let r2 = rx2.await.expect("should receive");
        assert_eq!(r2.request_id, "req-2");

        let r3 = rx3.recv().await.expect("should receive");
        assert_eq!(r3.request_id, "watch-3");
    }

    // Story: HTTP request lifecycle through multiplexer
    #[tokio::test]
    async fn story_http_request_lifecycle() {
        let mux = RequestMultiplexer::new();

        // Act 1: HTTP handler receives GET /api/v1/pods request
        let rx = mux.register_single("get-pods-123".to_string());
        assert!(mux.is_pending("get-pods-123"));

        // Act 2: KubernetesRequest sent to agent (not shown)

        // Act 3: Agent executes request and sends response
        let response = KubernetesResponse {
            request_id: "get-pods-123".to_string(),
            status_code: 200,
            body: br#"{"items":[]}"#.to_vec(),
            content_type: "application/json".to_string(),
            streaming: false,
            stream_end: false,
            error: String::new(),
        };

        // Act 4: gRPC handler dispatches response
        mux.dispatch(response)
            .await
            .expect("dispatch should succeed");

        // Act 5: HTTP handler receives response
        let received = rx.await.expect("should receive response");
        assert_eq!(received.status_code, 200);
        assert!(!mux.is_pending("get-pods-123"));
    }

    // Story: Watch request with events
    #[tokio::test]
    async fn story_watch_request_with_events() {
        let mux = RequestMultiplexer::new();

        // Act 1: HTTP handler receives watch request
        let (mut rx, cancel_token) = mux.register_streaming("watch-pods-456".to_string());

        // Act 2: Agent streams events
        let events = vec!["ADDED pod-1", "MODIFIED pod-1", "DELETED pod-1"];

        for (i, event) in events.iter().enumerate() {
            let is_last = i == events.len() - 1;
            let response = KubernetesResponse {
                request_id: "watch-pods-456".to_string(),
                status_code: 200,
                body: event.as_bytes().to_vec(),
                content_type: "application/json".to_string(),
                streaming: true,
                stream_end: is_last,
                error: String::new(),
            };
            mux.dispatch(response)
                .await
                .expect("dispatch should succeed");
        }

        // Act 3: HTTP handler receives all events
        for expected in &events {
            let received = rx.recv().await.expect("should receive event");
            assert_eq!(String::from_utf8_lossy(&received.body), *expected);
        }

        // Watch entry should be removed after stream_end
        assert!(!mux.is_pending("watch-pods-456"));
        assert!(!cancel_token.is_cancelled());
    }

    // Story: Client disconnect cancels watch
    #[tokio::test]
    async fn story_client_disconnect_cancels_watch() {
        let mux = RequestMultiplexer::new();

        let (_rx, cancel_token) = mux.register_streaming("watch-deploy-789".to_string());

        // Simulate client disconnect - HTTP handler calls cancel
        mux.cancel("watch-deploy-789");

        // Token should be triggered for agent to stop watch
        assert!(cancel_token.is_cancelled());
        assert!(!mux.is_pending("watch-deploy-789"));
    }

    // Story: Agent disconnect cancels all requests
    #[tokio::test]
    async fn story_agent_disconnect_cleanup() {
        let mux = RequestMultiplexer::new();

        // Multiple pending requests
        let _rx1 = mux.register_single("req-1".to_string());
        let (_, token2) = mux.register_streaming("watch-2".to_string());
        let (_, token3) = mux.register_streaming("watch-3".to_string());

        assert_eq!(mux.len(), 3);

        // Agent disconnects
        mux.cancel_all();

        // All cleaned up
        assert!(mux.is_empty());
        assert!(token2.is_cancelled());
        assert!(token3.is_cancelled());
    }

    // Test error display
    #[test]
    fn test_dispatch_error_display() {
        assert_eq!(
            format!("{}", DispatchError::NoPendingRequest),
            "no pending request with this ID"
        );
        assert_eq!(
            format!("{}", DispatchError::ReceiverDropped),
            "receiver dropped"
        );
        assert_eq!(
            format!("{}", DispatchError::ConsumerSlow),
            "consumer too slow"
        );
    }

    #[test]
    fn test_dispatch_error_is_error() {
        let err = DispatchError::NoPendingRequest;
        let _: &dyn std::error::Error = &err;
    }

    // Test with timeout - slow consumer scenario
    #[tokio::test]
    async fn test_streaming_receiver_dropped_mid_stream() {
        let mux = RequestMultiplexer::new();

        let (rx, _cancel_token) = mux.register_streaming("watch-1".to_string());

        // Drop receiver before sending
        drop(rx);

        // Dispatch should fail
        let response = make_response("watch-1", true, false);
        let result = mux.dispatch(response).await;

        assert!(matches!(result, Err(DispatchError::ReceiverDropped)));
    }
}
