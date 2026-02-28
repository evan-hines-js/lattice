//! Kubernetes client creation utilities.

use std::path::Path;
use std::time::Duration;

use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};

use crate::Error;

/// Default connection timeout for kube clients (5s is plenty for local API server)
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout for kube clients
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a kube client from optional kubeconfig path.
///
/// Pass `None` for timeouts to use defaults (5s connect, 30s read).
pub async fn create_client(
    kubeconfig: Option<&Path>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
) -> Result<Client, Error> {
    let connect_timeout = connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
    let read_timeout = read_timeout.unwrap_or(DEFAULT_READ_TIMEOUT);
    match kubeconfig {
        Some(path) => {
            let kubeconfig = Kubeconfig::read_from(path).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to read kubeconfig: {}", e),
                )
            })?;
            let mut config =
                Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                    .await
                    .map_err(|e| {
                        Error::internal_with_context(
                            "create_client",
                            format!("failed to load kubeconfig: {}", e),
                        )
                    })?;
            config.connect_timeout = Some(connect_timeout);
            config.read_timeout = Some(read_timeout);
            Client::try_from(config).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to create client: {}", e),
                )
            })
        }
        None => {
            let mut config = Config::infer().await.map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to infer config: {}", e),
                )
            })?;
            config.connect_timeout = Some(connect_timeout);
            config.read_timeout = Some(read_timeout);
            Client::try_from(config).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to create client: {}", e),
                )
            })
        }
    }
}
