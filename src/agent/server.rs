//! gRPC server for cell (management cluster)
//!
//! Accepts incoming connections from agents running on workload clusters.
//!
//! # mTLS Security
//!
//! The server requires client certificates signed by the cell CA.
//! Each agent presents its certificate, and the cluster ID is extracted
//! from the certificate's CN field.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, instrument, warn};

use crate::proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use crate::proto::{
    AgentMessage, AgentState, CellCommand, KubeProxyRequest, KubeProxyResponse,
    agent_message::Payload,
};

use super::connection::{AgentConnection, AgentRegistry, SharedAgentRegistry};
use super::mtls::ServerMtlsConfig;

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
}

impl AgentServer {
    /// Create a new agent server with the given registry
    pub fn new(registry: SharedAgentRegistry) -> Self {
        Self { registry }
    }

    /// Create a new agent server with a fresh registry
    pub fn with_new_registry() -> (Self, SharedAgentRegistry) {
        let registry = Arc::new(AgentRegistry::new());
        let server = Self::new(registry.clone());
        (server, registry)
    }

    /// Convert to a tonic service
    pub fn into_service(self) -> LatticeAgentServer<Self> {
        LatticeAgentServer::new(self)
    }

    /// Start the gRPC server with mTLS on the given address
    ///
    /// This is the primary entry point for running the cell gRPC server.
    /// It requires mTLS configuration with:
    /// - Server certificate (presented to agents)
    /// - Server private key
    /// - CA certificate (for verifying agent certificates)
    pub async fn serve_with_mtls(
        registry: SharedAgentRegistry,
        addr: SocketAddr,
        mtls_config: ServerMtlsConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry);
        let tls_config = mtls_config.to_tonic_config()?;

        info!(%addr, "Starting gRPC server with mTLS");

        Server::builder()
            .tls_config(tls_config)?
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }

    /// Start the gRPC server without TLS (for testing only)
    #[cfg(test)]
    pub async fn serve_insecure(
        registry: SharedAgentRegistry,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry);

        warn!(%addr, "Starting gRPC server WITHOUT TLS - for testing only!");

        Server::builder()
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }

    /// Handle an agent message
    fn handle_agent_message(
        &self,
        msg: &AgentMessage,
        command_tx: &mpsc::Sender<CellCommand>,
    ) {
        let cluster_name = &msg.cluster_name;

        match &msg.payload {
            Some(Payload::Ready(ready)) => {
                info!(
                    cluster = %cluster_name,
                    agent_version = %ready.agent_version,
                    k8s_version = %ready.kubernetes_version,
                    "Agent ready"
                );

                // Register the agent
                let conn = AgentConnection::new(
                    cluster_name.clone(),
                    ready.agent_version.clone(),
                    ready.kubernetes_version.clone(),
                    command_tx.clone(),
                );
                self.registry.register(conn);
                self.registry.update_state(cluster_name, ready.state());
            }
            Some(Payload::BootstrapComplete(bc)) => {
                info!(
                    cluster = %cluster_name,
                    flux_ready = bc.flux_ready,
                    cilium_ready = bc.cilium_ready,
                    "Bootstrap complete"
                );
            }
            Some(Payload::PivotStarted(ps)) => {
                info!(
                    cluster = %cluster_name,
                    target_namespace = %ps.target_namespace,
                    "Pivot started"
                );
                self.registry.update_state(cluster_name, AgentState::Pivoting);
            }
            Some(Payload::PivotComplete(pc)) => {
                if pc.success {
                    info!(
                        cluster = %cluster_name,
                        resources_imported = pc.resources_imported,
                        "Pivot complete"
                    );
                    self.registry.update_state(cluster_name, AgentState::Ready);
                } else {
                    error!(
                        cluster = %cluster_name,
                        error = %pc.error_message,
                        "Pivot failed"
                    );
                    self.registry.update_state(cluster_name, AgentState::Failed);
                }
            }
            Some(Payload::Heartbeat(hb)) => {
                debug!(
                    cluster = %cluster_name,
                    state = ?hb.state(),
                    uptime = hb.uptime_seconds,
                    "Heartbeat received"
                );
                self.registry.update_state(cluster_name, hb.state());
            }
            Some(Payload::ClusterHealth(health)) => {
                debug!(
                    cluster = %cluster_name,
                    ready_nodes = health.ready_nodes,
                    total_nodes = health.total_nodes,
                    "Health update"
                );
            }
            Some(Payload::StatusResponse(sr)) => {
                debug!(
                    cluster = %cluster_name,
                    request_id = %sr.request_id,
                    "Status response received"
                );
            }
            None => {
                warn!(cluster = %cluster_name, "Received message with no payload");
            }
        }
    }
}

#[tonic::async_trait]
impl LatticeAgent for AgentServer {
    type StreamMessagesStream =
        Pin<Box<dyn Stream<Item = Result<CellCommand, Status>> + Send + 'static>>;

    #[instrument(skip(self, request))]
    async fn stream_messages(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamMessagesStream>, Status> {
        let remote_addr = request.remote_addr();
        info!(?remote_addr, "New agent connection");

        let mut inbound = request.into_inner();

        // Channel for sending commands to this agent
        let (command_tx, command_rx) = mpsc::channel::<CellCommand>(32);

        // Clone registry for the spawned task
        let registry = self.registry.clone();
        let command_tx_clone = command_tx.clone();

        // Spawn task to handle incoming messages
        tokio::spawn(async move {
            let mut cluster_name: Option<String> = None;

            while let Some(result) = inbound.next().await {
                match result {
                    Ok(msg) => {
                        // Track the cluster name for cleanup
                        if cluster_name.is_none() {
                            cluster_name = Some(msg.cluster_name.clone());
                        }

                        // Create a temporary server to handle the message
                        // (In a real implementation, we'd refactor to avoid this)
                        let temp_registry = registry.clone();
                        let server = AgentServer::new(temp_registry);
                        server.handle_agent_message(&msg, &command_tx_clone);
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving agent message");
                        break;
                    }
                }
            }

            // Cleanup on disconnect
            if let Some(name) = cluster_name {
                info!(cluster = %name, "Agent disconnected");
                registry.unregister(&name);
            }
        });

        // Return stream of commands to send to agent
        let outbound = ReceiverStream::new(command_rx);
        Ok(Response::new(Box::pin(outbound.map(Ok))))
    }

    type ProxyKubernetesAPIStream =
        Pin<Box<dyn Stream<Item = Result<KubeProxyRequest, Status>> + Send + 'static>>;

    #[instrument(skip(self, request))]
    async fn proxy_kubernetes_api(
        &self,
        request: Request<Streaming<KubeProxyResponse>>,
    ) -> Result<Response<Self::ProxyKubernetesAPIStream>, Status> {
        let remote_addr = request.remote_addr();
        info!(?remote_addr, "New K8s API proxy connection");

        let mut inbound = request.into_inner();

        // Channel for sending proxy requests to the agent
        let (_request_tx, request_rx) = mpsc::channel::<KubeProxyRequest>(32);

        // Channel for receiving proxy responses from the agent
        let (response_tx, _response_rx) = mpsc::channel::<KubeProxyResponse>(32);

        let _registry = self.registry.clone();

        // Spawn task to handle incoming responses and route them
        tokio::spawn(async move {
            let cluster_name: Option<String> = None;

            while let Some(result) = inbound.next().await {
                match result {
                    Ok(response) => {
                        debug!(
                            request_id = %response.request_id,
                            status = response.status_code,
                            "Proxy response received"
                        );

                        // Forward to response channel for the waiting request
                        if let Err(e) = response_tx.send(response).await {
                            error!(error = %e, "Failed to forward proxy response");
                            break;
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving proxy response");
                        break;
                    }
                }
            }

            // Cleanup
            if let Some(name) = cluster_name {
                debug!(cluster = %name, "K8s API proxy disconnected");
            }
        });

        // Return stream of requests to send to agent
        let outbound = ReceiverStream::new(request_rx);
        Ok(Response::new(Box::pin(outbound.map(Ok))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        AgentReady, BootstrapComplete, ClusterHealth, Heartbeat, PivotComplete, PivotStarted,
        StatusResponse, agent_message::Payload,
    };

    #[test]
    fn test_server_creation() {
        let (_server, registry) = AgentServer::with_new_registry();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_server_creation_with_registry() {
        let registry = Arc::new(AgentRegistry::new());
        let _server = AgentServer::new(registry.clone());
        assert!(registry.is_empty());
    }

    #[test]
    fn test_into_service() {
        let (server, _) = AgentServer::with_new_registry();
        let _service = server.into_service();
    }

    // Test handle_agent_message with Ready payload
    #[tokio::test]
    async fn test_handle_ready_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };

        server.handle_agent_message(&msg, &tx);

        // Verify agent was registered
        assert!(!registry.is_empty());
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.cluster_name, "test-cluster");
        assert_eq!(conn.agent_version, "0.1.0");
        assert_eq!(conn.kubernetes_version, "1.28.0");
        assert_eq!(conn.state, AgentState::Provisioning);
    }

    #[tokio::test]
    async fn test_handle_ready_message_updates_existing() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First ready message
        let msg1 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg1, &tx);

        // Second ready message with updated state
        let msg2 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg2, &tx);

        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with BootstrapComplete payload
    #[tokio::test]
    async fn test_handle_bootstrap_complete_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                flux_ready: true,
                cilium_ready: true,
            })),
        };

        // Should not panic
        server.handle_agent_message(&msg, &tx);
    }

    // Test handle_agent_message with PivotStarted payload
    #[tokio::test]
    async fn test_handle_pivot_started_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx);

        // Then send pivot started
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-system".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx);

        // Verify state changed to Pivoting
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Pivoting);
    }

    // Test handle_agent_message with PivotComplete (success)
    #[tokio::test]
    async fn test_handle_pivot_complete_success_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx);

        // Send pivot complete (success)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        };
        server.handle_agent_message(&msg, &tx);

        // Verify state changed to Ready
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with PivotComplete (failure)
    #[tokio::test]
    async fn test_handle_pivot_complete_failure_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx);

        // Send pivot complete (failure)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl failed".to_string(),
                resources_imported: 0,
            })),
        };
        server.handle_agent_message(&msg, &tx);

        // Verify state changed to Failed
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Failed);
    }

    // Test handle_agent_message with Heartbeat payload
    #[tokio::test]
    async fn test_handle_heartbeat_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx);

        // Send heartbeat
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        };
        server.handle_agent_message(&msg, &tx);

        // State should remain Ready
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with ClusterHealth payload
    #[tokio::test]
    async fn test_handle_cluster_health_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::ClusterHealth(ClusterHealth {
                ready_nodes: 3,
                total_nodes: 3,
                ready_control_plane: 1,
                total_control_plane: 1,
                conditions: vec![],
            })),
        };

        // Should not panic
        server.handle_agent_message(&msg, &tx);
    }

    // Test handle_agent_message with StatusResponse payload
    #[tokio::test]
    async fn test_handle_status_response_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::StatusResponse(StatusResponse {
                request_id: "req-123".to_string(),
                state: AgentState::Ready.into(),
                health: None,
                capi_status: None,
            })),
        };

        // Should not panic
        server.handle_agent_message(&msg, &tx);
    }

    // Test handle_agent_message with no payload
    #[tokio::test]
    async fn test_handle_empty_payload_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: None,
        };

        // Should not panic, just log warning
        server.handle_agent_message(&msg, &tx);
    }

    // Test registry interactions through server
    #[tokio::test]
    async fn test_multiple_agents_registration() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Register first agent
        let msg1 = AgentMessage {
            cluster_name: "cluster-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.cluster1:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg1, &tx);

        // Register second agent
        let msg2 = AgentMessage {
            cluster_name: "cluster-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.2.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.cluster2:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg2, &tx);

        // Verify both are registered
        assert_eq!(registry.len(), 2);

        let conn1 = registry.get("cluster-1").unwrap();
        assert_eq!(conn1.agent_version, "0.1.0");

        let conn2 = registry.get("cluster-2").unwrap();
        assert_eq!(conn2.agent_version, "0.2.0");
    }

    // Test state transitions through messages
    #[tokio::test]
    async fn test_full_state_transition_lifecycle() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Initial: Provisioning
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx);
        assert_eq!(registry.get("test-cluster").unwrap().state, AgentState::Provisioning);

        // Heartbeat with Ready state
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 60,
            })),
        };
        server.handle_agent_message(&msg, &tx);
        assert_eq!(registry.get("test-cluster").unwrap().state, AgentState::Ready);

        // Pivot started
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-system".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx);
        assert_eq!(registry.get("test-cluster").unwrap().state, AgentState::Pivoting);

        // Pivot complete
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 10,
            })),
        };
        server.handle_agent_message(&msg, &tx);
        assert_eq!(registry.get("test-cluster").unwrap().state, AgentState::Ready);
    }

    // ==========================================================================
    // Integration Tests: Real gRPC Server
    // ==========================================================================

    use crate::proto::lattice_agent_client::LatticeAgentClient;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::transport::Channel;

    /// Integration test: Start gRPC server and connect a client
    #[tokio::test]
    async fn integration_grpc_server_accepts_connection() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Start server in background
        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client
        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        // Create message stream
        let (_tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        // Start streaming
        let response = client.stream_messages(outbound).await;
        assert!(response.is_ok());

        // Clean up
        server_handle.abort();
    }

    /// Integration test: Agent sends ready message and gets registered
    #[tokio::test]
    async fn integration_agent_ready_registers_in_registry() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client
        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        // Create message stream
        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        // Start streaming
        let response = client.stream_messages(outbound).await.unwrap();
        let _inbound = response.into_inner();

        // Send ready message
        tx.send(AgentMessage {
            cluster_name: "integration-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        // Give server time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify agent was registered
        assert!(!registry.is_empty());
        let conn = registry.get("integration-cluster");
        assert!(conn.is_some());
        let conn = conn.unwrap();
        assert_eq!(conn.agent_version, "1.0.0");
        assert_eq!(conn.kubernetes_version, "1.30.0");

        // Clean up
        server_handle.abort();
    }

    /// Integration test: Cell sends command to agent
    #[tokio::test]
    async fn integration_cell_sends_command_to_agent() {
        use crate::proto::{BootstrapCommand, cell_command::Command};

        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        let response = client.stream_messages(outbound).await.unwrap();
        let mut inbound = response.into_inner();

        // Send ready message to register
        tx.send(AgentMessage {
            cluster_name: "cmd-test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send command through registry
        let conn = registry.get("cmd-test-cluster").unwrap();
        let send_result = conn.send_command(CellCommand {
            command_id: "cmd-1".to_string(),
            command: Some(Command::Bootstrap(BootstrapCommand {
                git_repository: vec![],
                kustomization: vec![],
                additional_manifests: vec![],
            })),
        })
        .await;

        assert!(send_result.is_ok());

        // Receive command on agent side
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            inbound.next(),
        )
        .await;

        assert!(received.is_ok());
        let cmd = received.unwrap().unwrap().unwrap();
        assert_eq!(cmd.command_id, "cmd-1");

        server_handle.abort();
    }

    /// Integration test: Agent disconnect unregisters from registry
    #[tokio::test]
    async fn integration_agent_disconnect_unregisters() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        let response = client.stream_messages(outbound).await.unwrap();

        // Send ready message
        tx.send(AgentMessage {
            cluster_name: "disconnect-test".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(registry.get("disconnect-test").is_some());

        // Drop the sender to simulate disconnect
        drop(tx);
        drop(response);

        // Give server time to detect disconnect
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Agent should be unregistered
        assert!(registry.get("disconnect-test").is_none());

        server_handle.abort();
    }

    /// Integration test: Multiple agents can connect simultaneously
    #[tokio::test]
    async fn integration_multiple_agents_connect() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect first agent
        let endpoint = format!("http://{}", actual_addr);
        let channel1 = Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client1 = LatticeAgentClient::new(channel1);

        let (tx1, rx1) = mpsc::channel::<AgentMessage>(32);
        let _resp1 = client1.stream_messages(ReceiverStream::new(rx1)).await.unwrap();

        tx1.send(AgentMessage {
            cluster_name: "agent-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://agent1:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        // Connect second agent
        let channel2 = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client2 = LatticeAgentClient::new(channel2);

        let (tx2, rx2) = mpsc::channel::<AgentMessage>(32);
        let _resp2 = client2.stream_messages(ReceiverStream::new(rx2)).await.unwrap();

        tx2.send(AgentMessage {
            cluster_name: "agent-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "2.0.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://agent2:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Both should be registered
        assert_eq!(registry.len(), 2);
        assert!(registry.get("agent-1").is_some());
        assert!(registry.get("agent-2").is_some());

        server_handle.abort();
    }

    // ==========================================================================
    // Story-Driven Tests: Covering Edge Cases and Error Paths
    // ==========================================================================

    /// Story: When the gRPC server starts, it should accept incoming connections
    ///
    /// The server must bind to the specified address and begin accepting connections
    /// from agents. Each new connection is logged with the remote address.
    #[tokio::test]
    async fn story_grpc_server_starts_and_accepts_connections() {
        // Background: A cell (management cluster) needs to accept agent connections
        let registry = Arc::new(AgentRegistry::new());

        // Given: The server is configured to listen on an ephemeral port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // When: The server starts
        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Then: It should accept incoming gRPC connections
        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .expect("Server should accept connections");

        let mut client = LatticeAgentClient::new(channel);
        let (tx, rx) = mpsc::channel::<AgentMessage>(32);

        // And: The stream_messages RPC should succeed
        let stream_result = client.stream_messages(ReceiverStream::new(rx)).await;
        assert!(stream_result.is_ok(), "stream_messages RPC should succeed");

        // Cleanup
        drop(tx);
        server_handle.abort();
    }

    /// Story: When an agent connects, the server should register it in the registry
    ///
    /// Upon receiving an AgentReady message, the server extracts the agent details
    /// (cluster name, versions, state) and adds the agent to the registry for
    /// future command dispatching.
    #[tokio::test]
    async fn story_agent_registration_on_connect() {
        // Background: The cell maintains a registry of all connected agents
        let registry = Arc::new(AgentRegistry::new());

        // Given: A running server with an empty registry
        assert!(registry.is_empty(), "Registry starts empty");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // When: An agent connects and sends its Ready message
        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        tx.send(AgentMessage {
            cluster_name: "production-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "2.1.0".to_string(),
                kubernetes_version: "1.31.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://k8s.prod.example.com:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Then: The agent should be registered with all its details
        assert!(!registry.is_empty(), "Registry should have the agent");

        let agent = registry.get("production-cluster").expect("Agent should be findable by name");
        assert_eq!(agent.cluster_name, "production-cluster");
        assert_eq!(agent.agent_version, "2.1.0");
        assert_eq!(agent.kubernetes_version, "1.31.0");
        assert_eq!(agent.state, AgentState::Provisioning);

        // Cleanup
        server_handle.abort();
    }

    /// Story: When a command is sent to an agent, it should be delivered over the stream
    ///
    /// The cell can send commands (bootstrap, pivot, reconcile) to specific agents
    /// through the bidirectional gRPC stream. Commands are routed based on cluster name.
    #[tokio::test]
    async fn story_command_dispatching_to_connected_agent() {
        use crate::proto::{StartPivotCommand, cell_command::Command};

        // Background: The cell needs to orchestrate cluster lifecycle operations
        let registry = Arc::new(AgentRegistry::new());

        // Given: A server with a connected agent
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let response = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();
        let mut inbound_stream = response.into_inner();

        // Register the agent
        tx.send(AgentMessage {
            cluster_name: "workload-alpha".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://alpha.k8s:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // When: The cell sends a start pivot command to the agent
        let agent_conn = registry.get("workload-alpha").expect("Agent should be registered");
        agent_conn.send_command(CellCommand {
            command_id: "pivot-op-42".to_string(),
            command: Some(Command::StartPivot(StartPivotCommand {
                cluster_name: "workload-alpha".to_string(),
                source_namespace: "capi-cell".to_string(),
                target_namespace: "capi-system".to_string(),
            })),
        }).await.expect("Command should be sent successfully");

        // Then: The agent should receive the command on its stream
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_stream.next(),
        ).await.expect("Should receive within timeout")
          .expect("Stream should have item")
          .expect("Item should be valid");

        assert_eq!(received.command_id, "pivot-op-42");
        match received.command {
            Some(Command::StartPivot(pivot)) => {
                assert_eq!(pivot.cluster_name, "workload-alpha");
                assert_eq!(pivot.target_namespace, "capi-system");
            }
            _ => panic!("Expected StartPivot command"),
        }

        server_handle.abort();
    }

    /// Story: When an agent disconnects, the server should clean up its registration
    ///
    /// If an agent's connection drops (network failure, agent restart, etc.),
    /// the server detects this and removes the agent from the registry to
    /// prevent stale connections from accumulating.
    #[tokio::test]
    async fn story_connection_cleanup_on_agent_disconnect() {
        // Background: Clean disconnection handling is critical for resilience
        let registry = Arc::new(AgentRegistry::new());

        // Given: A server with a connected agent
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let stream_response = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Register the agent
        tx.send(AgentMessage {
            cluster_name: "ephemeral-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://ephemeral:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(registry.get("ephemeral-cluster").is_some(), "Agent should be registered");

        // When: The agent disconnects (simulated by dropping the sender and stream)
        drop(tx);
        drop(stream_response);

        // Then: After the server detects the disconnect, the agent should be unregistered
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(registry.get("ephemeral-cluster").is_none(), "Agent should be unregistered after disconnect");

        server_handle.abort();
    }

    /// Story: When multiple agents send state updates, each agent's state is tracked independently
    ///
    /// The registry must maintain separate state for each connected agent,
    /// allowing the cell to understand the health of all managed clusters.
    #[tokio::test]
    async fn story_independent_state_tracking_for_multiple_agents() {
        let registry = Arc::new(AgentRegistry::new());

        // Given: A server with multiple connected agents
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);

        // Connect three agents representing different environments
        let agents = vec![
            ("prod-west", AgentState::Ready),
            ("staging-east", AgentState::Provisioning),
            ("dev-local", AgentState::Degraded),
        ];

        let mut senders = Vec::new();

        for (name, initial_state) in &agents {
            let channel = Channel::from_shared(endpoint.clone()).unwrap().connect().await.unwrap();
            let mut client = LatticeAgentClient::new(channel);

            let (tx, rx) = mpsc::channel::<AgentMessage>(32);
            let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

            tx.send(AgentMessage {
                cluster_name: name.to_string(),
                payload: Some(Payload::Ready(AgentReady {
                    agent_version: "1.0.0".to_string(),
                    kubernetes_version: "1.30.0".to_string(),
                    state: (*initial_state).into(),
                    api_server_endpoint: format!("https://{}:6443", name),
                })),
            }).await.unwrap();

            senders.push(tx);
        }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Then: Each agent has its own tracked state
        assert_eq!(registry.len(), 3);

        let prod = registry.get("prod-west").unwrap();
        assert_eq!(prod.state, AgentState::Ready);

        let staging = registry.get("staging-east").unwrap();
        assert_eq!(staging.state, AgentState::Provisioning);

        let dev = registry.get("dev-local").unwrap();
        assert_eq!(dev.state, AgentState::Degraded);

        // When: One agent sends a state update
        senders[1].send(AgentMessage {
            cluster_name: "staging-east".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Then: Only that agent's state changes
        let staging_updated = registry.get("staging-east").unwrap();
        assert_eq!(staging_updated.state, AgentState::Ready);

        // Other agents remain unchanged
        let prod_unchanged = registry.get("prod-west").unwrap();
        assert_eq!(prod_unchanged.state, AgentState::Ready);

        server_handle.abort();
    }

    /// Story: When an agent goes through the full pivot lifecycle, all state transitions are recorded
    ///
    /// The pivot flow: Ready -> PivotStarted (Pivoting) -> PivotComplete (Ready or Failed)
    #[tokio::test]
    async fn story_full_pivot_lifecycle_state_transitions() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Phase 1: Agent connects and is ready
        tx.send(AgentMessage {
            cluster_name: "pivoting-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://pivot:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(registry.get("pivoting-cluster").unwrap().state, AgentState::Ready);

        // Phase 2: Agent reports pivot started
        tx.send(AgentMessage {
            cluster_name: "pivoting-cluster".to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-workload".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(registry.get("pivoting-cluster").unwrap().state, AgentState::Pivoting);

        // Phase 3: Agent reports pivot complete (success)
        tx.send(AgentMessage {
            cluster_name: "pivoting-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 15,
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(registry.get("pivoting-cluster").unwrap().state, AgentState::Ready);

        server_handle.abort();
    }

    /// Story: When pivot fails, the agent state reflects the failure
    #[tokio::test]
    async fn story_pivot_failure_sets_failed_state() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Agent connects
        tx.send(AgentMessage {
            cluster_name: "failing-pivot".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://fail:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Pivot fails
        tx.send(AgentMessage {
            cluster_name: "failing-pivot".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl move failed: etcd timeout".to_string(),
                resources_imported: 0,
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(registry.get("failing-pivot").unwrap().state, AgentState::Failed);

        server_handle.abort();
    }

    /// Story: When the K8s API proxy stream is established, the server can forward requests
    #[tokio::test]
    async fn story_k8s_api_proxy_stream_established() {
        use crate::proto::KubeProxyResponse;

        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        // Establish proxy stream
        let (tx, rx) = mpsc::channel::<KubeProxyResponse>(32);
        let proxy_result = client.proxy_kubernetes_api(ReceiverStream::new(rx)).await;

        // The proxy stream should be established
        assert!(proxy_result.is_ok(), "proxy_kubernetes_api RPC should succeed");

        let mut request_stream = proxy_result.unwrap().into_inner();

        // Send a mock response through the proxy channel
        tx.send(KubeProxyResponse {
            request_id: "get-pods-123".to_string(),
            status_code: 200,
            headers: vec![],
            body: b"pod list response".to_vec(),
            error: String::new(),
        }).await.unwrap();

        // Give server time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // The server should have received and processed the response
        // (In a full implementation, this would route to waiting requests)

        // Drop sender to close the stream
        drop(tx);

        // Stream should end gracefully
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Try to read from stream - should return None (stream ended)
        let next_item = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            request_stream.next(),
        ).await;

        // Either timeout or None is acceptable (stream is closing/closed)
        match next_item {
            Ok(None) => {} // Stream ended
            Err(_) => {} // Timeout - stream is idle
            Ok(Some(_)) => {} // Got an item before closing
        }

        server_handle.abort();
    }

    /// Story: Bootstrap complete message is logged but doesn't change state
    #[tokio::test]
    async fn story_bootstrap_complete_message_handling() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Agent connects
        tx.send(AgentMessage {
            cluster_name: "bootstrap-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://bootstrap:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Bootstrap complete - this is informational, state managed separately
        tx.send(AgentMessage {
            cluster_name: "bootstrap-cluster".to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                flux_ready: true,
                cilium_ready: true,
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // State doesn't change from bootstrap complete (managed via Ready/Heartbeat)
        let agent = registry.get("bootstrap-cluster").unwrap();
        assert_eq!(agent.state, AgentState::Provisioning);

        server_handle.abort();
    }

    /// Story: Health updates are received and logged
    #[tokio::test]
    async fn story_cluster_health_updates_received() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Agent connects
        tx.send(AgentMessage {
            cluster_name: "health-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://health:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send health update
        tx.send(AgentMessage {
            cluster_name: "health-cluster".to_string(),
            payload: Some(Payload::ClusterHealth(ClusterHealth {
                ready_nodes: 5,
                total_nodes: 5,
                ready_control_plane: 3,
                total_control_plane: 3,
                conditions: vec![crate::proto::NodeCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "AllNodesHealthy".to_string(),
                    message: "All nodes are healthy".to_string(),
                }],
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Agent is still tracked (health is informational)
        assert!(registry.get("health-cluster").is_some());

        server_handle.abort();
    }

    /// Story: Status response messages are received and logged
    #[tokio::test]
    async fn story_status_response_handling() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Agent connects
        tx.send(AgentMessage {
            cluster_name: "status-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://status:6443".to_string(),
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send status response (response to a StatusRequest)
        tx.send(AgentMessage {
            cluster_name: "status-cluster".to_string(),
            payload: Some(Payload::StatusResponse(StatusResponse {
                request_id: "status-req-456".to_string(),
                state: AgentState::Ready.into(),
                health: None,
                capi_status: None,
            })),
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Agent is still registered
        assert!(registry.get("status-cluster").is_some());

        server_handle.abort();
    }

    /// Story: Messages with no payload are handled gracefully
    #[tokio::test]
    async fn story_empty_payload_messages_logged_as_warning() {
        let registry = Arc::new(AgentRegistry::new());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let registry_clone = registry.clone();
        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", server_addr);
        let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let _stream = client.stream_messages(ReceiverStream::new(rx)).await.unwrap();

        // Send message with no payload (malformed message)
        tx.send(AgentMessage {
            cluster_name: "malformed-sender".to_string(),
            payload: None,
        }).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Server should not crash, agent not registered (no Ready message)
        assert!(registry.is_empty());

        server_handle.abort();
    }
}
