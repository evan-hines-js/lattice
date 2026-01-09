//! Lattice Operator - Kubernetes multi-cluster lifecycle management

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, CustomResourceExt};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use lattice::agent::client::{AgentClient, AgentClientConfig};
use lattice::cell::{CellConfig, CellServers};
use lattice::controller::{error_policy, reconcile, Context};
use lattice::crd::LatticeCluster;

/// Lattice - CRD-driven Kubernetes operator for multi-cluster lifecycle management
#[derive(Parser, Debug)]
#[command(name = "lattice", version, about, long_about = None)]
struct Cli {
    /// Generate CRD manifests and exit
    #[arg(long)]
    crd: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as controller (default mode)
    /// Cell servers start automatically when Pending LatticeCluster CRDs are detected
    Controller,

    /// Run as agent on a workload cluster
    Agent(AgentArgs),
}

/// Agent mode arguments
#[derive(Parser, Debug)]
struct AgentArgs {
    /// Cluster ID (from ConfigMap or environment)
    #[arg(long, env = "CLUSTER_ID")]
    cluster_id: String,

    /// Cell HTTP endpoint for CSR signing (e.g., "https://cell.example.com:443")
    #[arg(long, env = "CELL_HTTP_ENDPOINT")]
    cell_http_endpoint: String,

    /// Cell gRPC endpoint for agent connection (e.g., "https://cell.example.com:50051")
    #[arg(long, env = "CELL_GRPC_ENDPOINT")]
    cell_grpc_endpoint: String,

    /// Path to CA certificate file
    #[arg(
        long,
        env = "CA_CERT_PATH",
        default_value = "/var/run/secrets/lattice/ca/ca.crt"
    )]
    ca_cert_path: String,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "30")]
    heartbeat_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.crd {
        // Generate CRD YAML
        let crd = serde_yaml::to_string(&LatticeCluster::crd())
            .map_err(|e| anyhow::anyhow!("Failed to serialize CRD: {}", e))?;
        println!("{crd}");
        return Ok(());
    }

    match cli.command {
        Some(Commands::Agent(args)) => run_agent(args).await,
        Some(Commands::Controller) | None => run_controller().await,
    }
}

/// Run in agent mode - connects to parent cell
async fn run_agent(args: AgentArgs) -> anyhow::Result<()> {
    tracing::info!(
        cluster_id = %args.cluster_id,
        cell_http = %args.cell_http_endpoint,
        cell_grpc = %args.cell_grpc_endpoint,
        "Lattice agent starting..."
    );

    // Read CA certificate from file (mounted from Secret)
    let ca_cert_pem = tokio::fs::read_to_string(&args.ca_cert_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read CA cert from {}: {}", args.ca_cert_path, e))?;

    tracing::info!("CA certificate loaded");

    // Step 1: Request CSR signing from cell
    tracing::info!("Requesting certificate from cell...");
    let credentials =
        AgentClient::request_certificate(&args.cell_http_endpoint, &args.cluster_id, &ca_cert_pem)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get certificate: {}", e))?;

    tracing::info!("Certificate received and validated");

    // Step 2: Create agent client with mTLS credentials
    let config = AgentClientConfig {
        cell_grpc_endpoint: args.cell_grpc_endpoint.clone(),
        cell_http_endpoint: args.cell_http_endpoint.clone(),
        cluster_name: args.cluster_id.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        heartbeat_interval: Duration::from_secs(args.heartbeat_interval_secs),
        connect_timeout: Duration::from_secs(10),
        ca_cert_pem: Some(ca_cert_pem),
    };

    let mut client = AgentClient::new(config);

    // Step 3: Connect to cell with mTLS
    tracing::info!("Connecting to cell with mTLS...");
    client
        .connect_with_mtls(&credentials)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to cell: {}", e))?;

    tracing::info!("Connected to cell, sending AgentReady");

    // The client automatically sends AgentReady and starts heartbeat/command handling
    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to listen for shutdown signal: {}", e))?;

    tracing::info!("Agent shutting down");
    client.shutdown().await;

    Ok(())
}

/// Run in controller mode - manages clusters
///
/// Cell servers (gRPC + bootstrap HTTP) start automatically when needed.
/// Cell endpoint configuration is read from the local LatticeCluster CRD's spec.cell.
async fn run_controller() -> anyhow::Result<()> {
    tracing::info!("Lattice controller starting...");

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}", e))?;

    // Create cell servers (starts on-demand when Pending CRDs detected)
    let cell_servers = Arc::new(
        CellServers::new(CellConfig::default())
            .map_err(|e| anyhow::anyhow!("Failed to create cell servers: {}", e))?,
    );

    // Create controller context with cell servers
    // Cell endpoint config is read from CRD spec.cell during reconciliation
    let ctx = Arc::new(Context::new_with_cell(client.clone(), cell_servers.clone()));

    // Create API for LatticeCluster (cluster-scoped)
    let clusters: Api<LatticeCluster> = Api::all(client);

    tracing::info!("Starting LatticeCluster controller...");
    tracing::info!("Cell config will be read from LatticeCluster CRD spec.cell");

    // Run the controller
    let controller = Controller::new(clusters, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx.clone())
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    tracing::debug!(?action, "Reconciliation completed");
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Reconciliation error");
                }
            }
        });

    // Run controller and wait for shutdown
    controller.await;

    // Shutdown cell servers
    cell_servers.shutdown().await;

    tracing::info!("Lattice controller shutting down");
    Ok(())
}
