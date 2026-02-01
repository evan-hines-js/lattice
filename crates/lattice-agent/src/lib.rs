//! Lattice Agent - Child cluster runtime
//!
//! This crate provides the client-side runtime for child/workload clusters:
//!
//! - **Agent Client**: gRPC client connecting to the parent cell
//! - **Pivot Execution**: Importing CAPI manifests, patching kubeconfig
//! - **K8s Request Execution**: Handling K8s API requests from parent
//!
//! # Architecture
//!
//! The agent runs on child clusters and maintains an **outbound** connection
//! to the parent cell. All communication is initiated by the agent.

use std::time::Duration;

pub mod client;
pub mod executor;
pub mod pivot;
pub mod subtree;
pub mod watch;

/// Default connection timeout for kube clients (5s is plenty for local API server)
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout for kube clients
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a Kubernetes client with proper timeouts
///
/// Uses in-cluster configuration with explicit timeouts (5s connect, 30s read)
/// instead of kube-rs defaults which may be too long and cause hangs.
pub async fn create_k8s_client() -> Result<kube::Client, kube::Error> {
    let mut config = kube::Config::infer()
        .await
        .map_err(kube::Error::InferConfig)?;
    config.connect_timeout = Some(DEFAULT_CONNECT_TIMEOUT);
    config.read_timeout = Some(DEFAULT_READ_TIMEOUT);
    kube::Client::try_from(config)
}

/// Create a Kubernetes client with logging, returning None on failure.
///
/// Helper for cases where client creation failure should be logged and handled
/// gracefully rather than propagated as an error.
pub async fn create_k8s_client_logged(purpose: &str) -> Option<kube::Client> {
    match create_k8s_client().await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create K8s client for {}", purpose);
            None
        }
    }
}

/// Macro for getting a K8s client or returning early from a function.
///
/// Use this in async functions that should return early if client creation fails.
/// The purpose string is used in the warning log message.
#[macro_export]
macro_rules! get_client_or_return {
    ($purpose:expr) => {
        match $crate::create_k8s_client().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create K8s client for {}", $purpose);
                return;
            }
        }
    };
}

pub use client::{AgentClient, AgentClientConfig, AgentCredentials, CertificateError, ClientState};

// Re-export protocol types from lattice_common
pub use executor::{execute_k8s_request, is_watch_request};
pub use lattice_common::{CsrRequest, CsrResponse};
pub use pivot::{
    apply_distributed_resources, patch_kubeconfig_for_self_management, DistributableResources,
    PivotError,
};
pub use subtree::SubtreeSender;
pub use watch::{build_k8s_error_response, execute_watch, WatchRegistry};

// Re-export proto types for convenience
pub use lattice_proto::{
    agent_message, cell_command, AgentMessage, AgentReady, AgentState, BootstrapComplete,
    CellCommand, ClusterDeleting, ClusterHealth, Heartbeat, KubernetesRequest, KubernetesResponse,
    StatusResponse,
};

// Re-export mTLS from infra
pub use lattice_infra::{ClientMtlsConfig, MtlsError, ServerMtlsConfig};
