//! Uninstall command - Tear down a self-managing Lattice cluster
//!
//! Usage: lattice uninstall --kubeconfig <path>
//!
//! This command safely destroys a self-managing Lattice cluster by:
//! 1. Creating a temporary kind cluster
//! 2. Installing CAPI providers matching the target cluster
//! 3. Reverse-pivoting CAPI resources from target to kind
//! 4. Waiting for CAPI to reconcile (InfrastructureReady)
//! 5. Deleting the Cluster resource (triggers infrastructure cleanup)
//! 6. Waiting for infrastructure deletion
//! 7. Deleting the kind cluster

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use k8s_openapi::api::core::v1::Service;
use kube::api::{Api, DeleteParams};
use kube::Client;
use tokio::process::Command;
use tracing::{debug, info};

use super::kind_utils;

use lattice_common::clusterctl::{move_to_kubeconfig, teardown_cluster, TeardownConfig};
use lattice_common::kube_utils;
use lattice_common::AwsCredentials;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use lattice_operator::crd::{LatticeCluster, ProviderType};

use crate::{Error, Result};

/// Uninstall a self-managing Lattice cluster
#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Path to kubeconfig for the cluster to uninstall
    #[arg(short = 'k', long = "kubeconfig")]
    pub kubeconfig: PathBuf,

    /// Cluster name (if different from context)
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Skip confirmation prompt
    #[arg(short = 'y', long = "yes")]
    pub yes: bool,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    pub keep_bootstrap_on_failure: bool,
}

/// Fixed uninstall bootstrap cluster name
const UNINSTALL_CLUSTER_NAME: &str = "lattice-uninstall";

pub struct Uninstaller {
    kubeconfig: PathBuf,
    cluster_name: String,
    provider: ProviderType,
    capi_namespace: String,
    keep_bootstrap_on_failure: bool,
}

impl Uninstaller {
    pub async fn new(args: &UninstallArgs) -> Result<Self> {
        // Connect to target cluster
        let client = kube_utils::create_client(Some(&args.kubeconfig))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create client: {}", e)))?;

        // Find the LatticeCluster
        let clusters: Api<LatticeCluster> = Api::all(client);
        let cluster_list = clusters
            .list(&Default::default())
            .await
            .map_err(|e| Error::command_failed(format!("Failed to list clusters: {}", e)))?;

        let cluster = if let Some(name) = &args.name {
            cluster_list
                .items
                .into_iter()
                .find(|c| c.metadata.name.as_deref() == Some(name.as_str()))
                .ok_or_else(|| Error::command_failed(format!("Cluster '{}' not found", name)))?
        } else if cluster_list.items.len() == 1 {
            // Safe: we just checked len() == 1
            cluster_list
                .items
                .into_iter()
                .next()
                .expect("len() == 1 guarantees at least one item")
        } else if cluster_list.items.is_empty() {
            return Err(Error::command_failed("No LatticeCluster found"));
        } else {
            let names: Vec<&str> = cluster_list
                .items
                .iter()
                .filter_map(|c| c.metadata.name.as_deref())
                .collect();
            return Err(Error::command_failed(format!(
                "Multiple clusters found, specify --name: {}",
                names.join(", ")
            )));
        };

        let cluster_name = cluster
            .metadata
            .name
            .ok_or_else(|| Error::command_failed("Cluster has no name"))?;

        let provider = cluster.spec.provider.provider_type();
        let capi_namespace = format!("capi-{}", cluster_name);

        Ok(Self {
            kubeconfig: args.kubeconfig.clone(),
            cluster_name,
            provider,
            capi_namespace,
            keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        })
    }

    pub fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    pub fn provider(&self) -> ProviderType {
        self.provider
    }

    fn bootstrap_kubeconfig_path(&self) -> PathBuf {
        std::env::temp_dir().join("lattice-uninstall-bootstrap.kubeconfig")
    }

    async fn target_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.kubeconfig))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create target client: {}", e)))
    }

    async fn bootstrap_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.bootstrap_kubeconfig_path()))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create bootstrap client: {}", e)))
    }

    /// Delete the lattice-cell LoadBalancer service and wait for cleanup
    ///
    /// This prevents orphaning cloud LB resources when the cluster is deleted.
    async fn delete_cell_service(&self) -> Result<()> {
        let client = self.target_client().await?;
        let api: Api<Service> = Api::namespaced(client, LATTICE_SYSTEM_NAMESPACE);

        // Delete the service
        match api.delete("lattice-cell", &DeleteParams::default()).await {
            Ok(_) => {
                info!("Deleted lattice-cell LoadBalancer service");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!("lattice-cell service not found (already deleted)");
                return Ok(());
            }
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "Failed to delete lattice-cell service: {}",
                    e
                )));
            }
        }

        // Wait for the service to be fully deleted
        info!("Waiting for LoadBalancer cleanup...");
        let timeout = Duration::from_secs(60);
        let poll_interval = Duration::from_secs(2);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            match api.get("lattice-cell").await {
                Ok(_) => {
                    debug!("Cell service still exists, waiting...");
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    debug!("Cell service deleted");
                    return Ok(());
                }
                Err(e) => {
                    debug!(error = %e, "Error checking cell service, assuming deleted");
                    return Ok(());
                }
            }
            tokio::time::sleep(poll_interval).await;
        }

        tracing::warn!("Timeout waiting for cell service deletion, proceeding anyway");
        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            "Uninstalling cluster '{}' (provider: {})",
            self.cluster_name, self.provider
        );

        // Step 1: Create kind cluster
        info!("Creating temporary kind cluster...");
        kind_utils::create_kind_cluster(UNINSTALL_CLUSTER_NAME, &self.bootstrap_kubeconfig_path())
            .await?;

        let result = self.run_uninstall().await;

        // Cleanup kind cluster
        if result.is_err() && self.keep_bootstrap_on_failure {
            info!("Keeping kind cluster for debugging (--keep-bootstrap-on-failure)");
        } else {
            info!("Deleting temporary kind cluster...");
            if let Err(e) = kind_utils::delete_kind_cluster(UNINSTALL_CLUSTER_NAME).await {
                tracing::warn!("Failed to delete kind cluster: {}", e);
            }
        }

        result
    }

    async fn run_uninstall(&self) -> Result<()> {
        let bootstrap_client = self.bootstrap_client().await?;

        // Step 2: Install CAPI providers (clusterctl init waits for components to be ready)
        info!("Installing CAPI providers on kind cluster...");
        self.install_capi_providers().await?;

        // Step 3: Delete LoadBalancer service to clean up cloud LB resources
        // Must be done before move to give cloud provider time to cleanup
        info!("Cleaning up LoadBalancer service...");
        self.delete_cell_service().await?;

        // Step 4: Move CAPI resources directly from target to kind cluster
        // Uses --to-kubeconfig for single-step move (same approach as installer)
        info!("Moving CAPI resources from target to kind cluster...");
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        move_to_kubeconfig(
            &self.kubeconfig,
            &bootstrap_kubeconfig,
            &self.capi_namespace,
            &self.cluster_name,
        )
        .await
        .map_err(|e| Error::command_failed(e.to_string()))?;

        // Step 5: Teardown cluster (unpause → wait ready → delete → wait deletion)
        info!("Tearing down cluster...");
        teardown_cluster(
            &bootstrap_client,
            &self.capi_namespace,
            &self.cluster_name,
            &TeardownConfig::default(),
            Some(&bootstrap_kubeconfig),
        )
        .await
        .map_err(|e| Error::command_failed(e.to_string()))?;

        info!("Cluster '{}' successfully uninstalled", self.cluster_name);
        Ok(())
    }

    async fn install_capi_providers(&self) -> Result<()> {
        let kubeconfig = self.bootstrap_kubeconfig_path();
        let init_args = self.clusterctl_init_args();

        let mut cmd = Command::new("clusterctl");
        cmd.args(&init_args).env("KUBECONFIG", &kubeconfig);

        // Pass through provider credentials from environment
        if self.provider == ProviderType::Aws {
            if let Ok(creds) = AwsCredentials::from_env() {
                cmd.env("AWS_B64ENCODED_CREDENTIALS", creds.to_b64_encoded());
            }
        }

        let output = cmd.output().await?;

        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "clusterctl init failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn clusterctl_init_args(&self) -> Vec<String> {
        let mut args = vec!["init".to_string()];

        match self.provider {
            ProviderType::Docker => {
                args.extend(["--infrastructure".to_string(), "docker".to_string()]);
            }
            ProviderType::Proxmox => {
                args.extend([
                    "--infrastructure".to_string(),
                    "proxmox".to_string(),
                    "--ipam".to_string(),
                    "in-cluster".to_string(),
                ]);
            }
            ProviderType::Aws => {
                args.extend(["--infrastructure".to_string(), "aws".to_string()]);
            }
            ProviderType::OpenStack => {
                args.extend(["--infrastructure".to_string(), "openstack".to_string()]);
            }
            ProviderType::Gcp => {
                args.extend(["--infrastructure".to_string(), "gcp".to_string()]);
            }
            ProviderType::Azure => {
                args.extend(["--infrastructure".to_string(), "azure".to_string()]);
            }
        }

        args
    }
}

pub async fn run(args: UninstallArgs) -> Result<()> {
    let uninstaller = Uninstaller::new(&args).await?;

    if !args.yes {
        println!(
            "This will permanently delete cluster '{}' and all its resources.",
            uninstaller.cluster_name()
        );
        println!("Provider: {}", uninstaller.provider());
        println!();
        print!("Are you sure? [y/N] ");

        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        tokio::io::stdout()
            .flush()
            .await
            .expect("stdout flush failed");

        let mut input = String::new();
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
        reader
            .read_line(&mut input)
            .await
            .expect("stdin read failed");
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    uninstaller.run().await
}
