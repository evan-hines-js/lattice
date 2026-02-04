//! WebSocket proxy for exec/attach/portforward
//!
//! Handles WebSocket upgrade for kubectl exec/attach/portforward requests
//! and bridges them to the gRPC tunnel or local K8s API.

mod handlers;
mod websocket;

pub use handlers::{handle_exec_websocket, has_websocket_upgrade_headers};
