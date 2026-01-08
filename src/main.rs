//! Lattice Operator - Kubernetes multi-cluster lifecycle management

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, CustomResourceExt};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use lattice::agent::client::{AgentClient, AgentClientConfig};
use lattice::agent::connection::AgentRegistry;
use lattice::agent::mtls::ServerMtlsConfig;
use lattice::agent::server::AgentServer;
use lattice::bootstrap::{bootstrap_router, BootstrapState, DefaultManifestGenerator};
use lattice::controller::{error_policy, reconcile, Context, RealClusterBootstrap};
use lattice::crd::LatticeCluster;
use lattice::pki::CertificateAuthority;

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
    /// Run as controller/cell (default mode)
    Controller(ControllerArgs),

    /// Run as agent on a workload cluster
    Agent(AgentArgs),
}

/// Controller mode arguments
#[derive(Parser, Debug)]
struct ControllerArgs {
    /// Bootstrap HTTPS server listen address
    #[arg(long, default_value = "0.0.0.0:443")]
    bootstrap_addr: SocketAddr,

    /// gRPC server listen address (TLS) - internal, agents connect via bootstrap_addr
    #[arg(long, default_value = "0.0.0.0:50051")]
    grpc_addr: SocketAddr,

    /// Bootstrap token TTL in seconds
    #[arg(long, default_value = "3600")]
    token_ttl_secs: u64,

    /// Cell endpoint (host:port) for workload clusters to connect to
    /// Required when running as a cell that provisions workload clusters
    #[arg(long)]
    cell_endpoint: Option<String>,
}

/// Agent mode arguments
#[derive(Parser, Debug)]
struct AgentArgs {
    /// Cluster ID (from ConfigMap or environment)
    #[arg(long, env = "CLUSTER_ID")]
    cluster_id: String,

    /// Cell HTTP endpoint for CSR signing (e.g., "http://cell.example.com:8080")
    #[arg(long, env = "CELL_HTTP_ENDPOINT")]
    cell_http_endpoint: String,

    /// Cell gRPC endpoint for agent connection (e.g., "https://cell.example.com:50051")
    #[arg(long, env = "CELL_GRPC_ENDPOINT")]
    cell_grpc_endpoint: String,

    /// Path to CA certificate file
    #[arg(long, env = "CA_CERT_PATH", default_value = "/var/run/secrets/lattice/ca/ca.crt")]
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
        Some(Commands::Controller(args)) => run_controller(args).await,
        None => {
            // Default to controller mode with default args
            run_controller(ControllerArgs {
                bootstrap_addr: "0.0.0.0:8080".parse().unwrap(),
                grpc_addr: "0.0.0.0:443".parse().unwrap(),
                token_ttl_secs: 3600,
                cell_endpoint: None,
            })
            .await
        }
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
    let credentials = AgentClient::request_certificate(&args.cell_http_endpoint, &args.cluster_id)
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
async fn run_controller(args: ControllerArgs) -> anyhow::Result<()> {
    tracing::info!("Lattice controller starting...");

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}", e))?;

    // Create Certificate Authority for signing agent certificates
    let ca = Arc::new(
        CertificateAuthority::new("Lattice CA")
            .map_err(|e| anyhow::anyhow!("Failed to create CA: {}", e))?,
    );
    tracing::info!("Certificate Authority initialized");

    // Create manifest generator with Cilium CNI
    let manifest_generator = DefaultManifestGenerator::new()
        .map_err(|e| anyhow::anyhow!("Failed to create manifest generator: {}", e))?;

    // Create bootstrap state
    let bootstrap_state = Arc::new(BootstrapState::new(
        manifest_generator,
        Duration::from_secs(args.token_ttl_secs),
        ca.clone(),
    ));

    // Create controller context with bootstrap if this is a cell
    let ctx = if let Some(ref cell_endpoint) = args.cell_endpoint {
        tracing::info!(endpoint = %cell_endpoint, "Running as cell - enabling workload cluster provisioning");
        let cluster_bootstrap = Arc::new(RealClusterBootstrap::new(
            bootstrap_state.clone(),
            cell_endpoint.clone(),
        ));
        Arc::new(Context::with_bootstrap(client.clone(), cluster_bootstrap))
    } else {
        tracing::info!("Running without cell endpoint - workload cluster provisioning disabled");
        Arc::new(Context::new(client.clone()))
    };

    // Create API for LatticeCluster (cluster-scoped)
    let clusters: Api<LatticeCluster> = Api::all(client);

    // Start bootstrap HTTPS server with TLS
    let bootstrap_router = bootstrap_router(bootstrap_state.clone());

    // Configure TLS using CA's certificate and key
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        ca.ca_cert_pem().as_bytes().to_vec(),
        ca.ca_key_pem().as_bytes().to_vec(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to configure TLS: {}", e))?;

    let bootstrap_addr = args.bootstrap_addr;
    tracing::info!(addr = %bootstrap_addr, "Bootstrap HTTPS server listening");

    let bootstrap_server = tokio::spawn(async move {
        axum_server::bind_rustls(bootstrap_addr, tls_config)
            .serve(bootstrap_router.into_make_service())
            .await
            .map_err(|e| tracing::error!(error = %e, "Bootstrap server error"))
    });

    // Start gRPC server for agent connections (only if running as cell)
    let _agent_registry = Arc::new(AgentRegistry::new());
    let grpc_server = if args.cell_endpoint.is_some() {
        // Create mTLS config using CA cert/key
        // In production, you'd want a separate server certificate signed by the CA
        let mtls_config = ServerMtlsConfig::new(
            ca.ca_cert_pem().to_string(),
            ca.ca_key_pem().to_string(),
            ca.ca_cert_pem().to_string(),
        );

        let registry_clone = _agent_registry.clone();
        let grpc_addr = args.grpc_addr;

        Some(tokio::spawn(async move {
            tracing::info!(addr = %grpc_addr, "Starting gRPC server for agent connections");
            if let Err(e) =
                AgentServer::serve_with_mtls(registry_clone, grpc_addr, mtls_config).await
            {
                tracing::error!(error = %e, "gRPC server error");
            }
        }))
    } else {
        tracing::info!("gRPC server disabled (not running as cell)");
        None
    };

    tracing::info!("Starting LatticeCluster controller...");

    // Run the controller
    let controller = Controller::new(clusters, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
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

    // Shutdown servers
    bootstrap_server.abort();
    if let Some(grpc) = grpc_server {
        grpc.abort();
    }

    tracing::info!("Lattice controller shutting down");
    Ok(())
}
