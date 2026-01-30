//! Agent startup and connection management
//!
//! Provides functions for starting and maintaining the agent connection to a parent cell.

use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{Api, PostParams};
use kube::Client;

use lattice_agent::{AgentClient, AgentClientConfig, AgentCredentials, ClientState};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

const AGENT_CREDENTIALS_SECRET: &str = "lattice-agent-credentials";

/// Supervise agent connection with automatic reconnection.
/// If a parent cell is configured, maintains connection indefinitely with retries.
/// The agent handles unpivot automatically by detecting deletion_timestamp on connect.
pub async fn start_agent_with_retry(client: &Client, cluster_name: &str) {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(30);

    loop {
        match start_agent_if_needed(client, cluster_name).await {
            Ok(Some(agent)) => {
                tracing::info!("Agent connection to parent cell established");
                retry_delay = Duration::from_secs(1);

                // Monitor connection health
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let state = agent.state().await;
                    if state == ClientState::Disconnected || state == ClientState::Failed {
                        tracing::warn!(state = ?state, "Agent disconnected, will reconnect...");
                        break;
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?retry_delay, "Failed to connect to parent cell, retrying...");
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

async fn start_agent_if_needed(
    client: &Client,
    cluster_name: &str,
) -> anyhow::Result<Option<AgentClient>> {
    // Check for lattice-parent-config secret - this is set by the bootstrap process
    // and indicates we were provisioned by a parent cell and need to connect back.
    // If a cluster has a cellRef, this secret will ALWAYS exist (created during bootstrap).
    let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let parent_config = match secrets.get("lattice-parent-config").await {
        Ok(config) => config,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            tracing::debug!("No parent config secret, this is a root cluster");
            return Ok(None);
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to get parent config secret: {}", e)),
    };

    tracing::info!(
        cluster = %cluster_name,
        "Found parent config secret, starting agent connection to parent cell"
    );

    let data = parent_config
        .data
        .ok_or_else(|| anyhow::anyhow!("Parent config secret has no data"))?;

    // Parse cell endpoint (format: "host:http_port:grpc_port")
    let cell_endpoint = data
        .get("cell_endpoint")
        .ok_or_else(|| anyhow::anyhow!("Missing cell_endpoint in parent config"))?;
    let cell_endpoint = String::from_utf8(cell_endpoint.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid cell_endpoint encoding: {}", e))?;

    let ca_cert = data
        .get("ca.crt")
        .ok_or_else(|| anyhow::anyhow!("Missing ca.crt in parent config"))?;
    let ca_cert_pem = String::from_utf8(ca_cert.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid CA cert encoding: {}", e))?;

    // Parse endpoint parts
    let parts: Vec<&str> = cell_endpoint.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "Invalid cell_endpoint format, expected host:http_port:grpc_port"
        ));
    }
    let host = parts[0];
    let http_port: u16 = parts[1]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid HTTP port: {}", e))?;
    let grpc_port: u16 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid gRPC port: {}", e))?;

    let http_endpoint = format!("https://{}:{}", host, http_port);
    let grpc_endpoint = format!("https://{}:{}", host, grpc_port);

    tracing::info!(
        http_endpoint = %http_endpoint,
        grpc_endpoint = %grpc_endpoint,
        "Connecting to parent cell"
    );

    // Try to load existing credentials from secret, or request new ones
    let credentials = match load_agent_credentials(&secrets).await {
        Ok(creds) => {
            tracing::info!("Using existing agent credentials from secret");
            creds
        }
        Err(_) => {
            tracing::info!("No existing credentials, requesting new certificate from cell");
            let creds =
                AgentClient::request_certificate(&http_endpoint, cluster_name, &ca_cert_pem)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get certificate: {}", e))?;

            // Store credentials for future restarts
            if let Err(e) = save_agent_credentials(&secrets, &creds).await {
                tracing::warn!(error = %e, "Failed to save agent credentials to secret");
            }
            creds
        }
    };

    // Create agent client config
    let config = AgentClientConfig {
        cluster_name: cluster_name.to_string(),
        cell_grpc_endpoint: grpc_endpoint,
        cell_http_endpoint: http_endpoint,
        ca_cert_pem: Some(ca_cert_pem),
        heartbeat_interval: Duration::from_secs(30),
        ..Default::default()
    };

    // Create and connect agent
    let mut agent = AgentClient::new(config);
    agent
        .connect_with_mtls(&credentials)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to cell: {}", e))?;

    tracing::info!("Agent connected to parent cell");
    Ok(Some(agent))
}

/// Load agent credentials from Kubernetes secret
async fn load_agent_credentials(secrets: &Api<Secret>) -> anyhow::Result<AgentCredentials> {
    let secret = secrets.get(AGENT_CREDENTIALS_SECRET).await?;
    let data = secret
        .data
        .ok_or_else(|| anyhow::anyhow!("credentials secret has no data"))?;

    let cert_pem = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("missing tls.crt"))?;
    let key_pem = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("missing tls.key"))?;
    let ca_pem = data
        .get("ca.crt")
        .ok_or_else(|| anyhow::anyhow!("missing ca.crt"))?;

    Ok(AgentCredentials {
        cert_pem: String::from_utf8(cert_pem.0.clone())?,
        key_pem: String::from_utf8(key_pem.0.clone())?,
        ca_cert_pem: String::from_utf8(ca_pem.0.clone())?,
    })
}

/// Save agent credentials to Kubernetes secret
async fn save_agent_credentials(
    secrets: &Api<Secret>,
    credentials: &AgentCredentials,
) -> anyhow::Result<()> {
    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        ByteString(credentials.cert_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_string(),
        ByteString(credentials.key_pem.as_bytes().to_vec()),
    );
    data.insert(
        "ca.crt".to_string(),
        ByteString(credentials.ca_cert_pem.as_bytes().to_vec()),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(AGENT_CREDENTIALS_SECRET.to_string()),
            namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(data),
        type_: Some("kubernetes.io/tls".to_string()),
        ..Default::default()
    };

    // Try to create, if exists then replace
    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            tracing::info!("Created agent credentials secret");
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            // Already exists, replace it
            secrets
                .replace(AGENT_CREDENTIALS_SECRET, &PostParams::default(), &secret)
                .await?;
            tracing::info!("Updated agent credentials secret");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
