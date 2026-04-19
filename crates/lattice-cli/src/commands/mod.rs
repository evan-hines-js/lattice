//! CLI commands

use std::fmt::Display;
use std::future::Future;
use std::time::{Duration, Instant};

use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tracing::{debug, warn};

use crate::{Error, Result};

pub mod install;
pub mod kind_utils;
pub mod login;
pub mod logout;
pub mod port_forward;
pub mod proxy;
pub mod uninstall;

/// Extension trait to convert errors with Display to CLI Error::CommandFailed.
///
/// This reduces boilerplate for the common pattern of `.map_err(|e| Error::command_failed(e.to_string()))`.
pub trait CommandErrorExt<T> {
    /// Convert an error to `Error::CommandFailed` using its Display implementation.
    fn cmd_err(self) -> Result<T>;
}

impl<T, E: Display> CommandErrorExt<T> for std::result::Result<T, E> {
    fn cmd_err(self) -> Result<T> {
        self.map_err(|e| Error::command_failed(e.to_string()))
    }
}

/// Generate a short readable run ID (6 hex chars).
///
/// Used by install/uninstall commands to create unique kind cluster names
/// and temp files for parallel execution.
pub fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32;
    let pid = std::process::id();
    // Combine timestamp and pid, take 6 hex chars for readability
    format!("{:06x}", (timestamp ^ pid) & 0xFFFFFF)
}

/// Result type for polling check functions.
///
/// - `Ok(Some(value))` - Condition met, return the value
/// - `Ok(None)` - Condition not met yet, keep polling
/// - `Err(e)` - Fatal error, stop polling immediately
pub type PollResult<T> = std::result::Result<Option<T>, String>;

/// Generic timeout-based polling utility.
///
/// Polls a condition function at regular intervals until:
/// - The condition returns `Ok(Some(value))` - returns `Ok(value)`
/// - The timeout is exceeded - returns `Err` with timeout message
/// - The condition returns `Err` - returns that error immediately
///
/// # Arguments
/// * `timeout` - Maximum time to wait for the condition
/// * `interval` - Time between polls
/// * `description` - Human-readable description for error messages
/// * `check_fn` - Async function that returns `PollResult<T>`
///
/// # Example
/// ```ignore
/// let result = wait_with_timeout(
///     Duration::from_secs(60),
///     Duration::from_secs(2),
///     "API server ready",
///     || async {
///         match client.list::<Namespace>().await {
///             Ok(_) => Ok(Some(())),  // Ready
///             Err(e) if is_transient(&e) => Ok(None),  // Keep polling
///             Err(e) => Err(e.to_string()),  // Fatal error
///         }
///     },
/// ).await?;
/// ```
pub async fn wait_with_timeout<T, F, Fut>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    mut check_fn: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = PollResult<T>>,
{
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::command_failed(format!(
                "Timeout waiting for {}",
                description
            )));
        }

        match check_fn().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {
                debug!("Waiting for {}...", description);
                tokio::time::sleep(interval).await;
            }
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "Error waiting for {}: {}",
                    description, e
                )));
            }
        }
    }
}

/// Polls until a resource is deleted (returns 404).
///
/// Similar to `wait_with_timeout` but specifically for waiting on resource deletion.
/// Handles the common pattern of waiting for a Kubernetes resource to be fully removed.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for deletion
/// * `interval` - Time between polls
/// * `description` - Human-readable description for logging
/// * `check_exists` - Async function that returns `Ok(true)` if resource exists,
///   `Ok(false)` if deleted, or `Err` for fatal errors
///
/// # Returns
/// * `Ok(())` - Resource was deleted
/// * `Err` - Timeout or fatal error
pub async fn wait_for_deletion<F, Fut>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    mut check_exists: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<bool, String>>,
{
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            warn!(
                "Timeout waiting for {} deletion, proceeding anyway",
                description
            );
            return Ok(());
        }

        match check_exists().await {
            Ok(true) => {
                debug!("{} still exists, waiting...", description);
                tokio::time::sleep(interval).await;
            }
            Ok(false) => {
                debug!("{} deleted", description);
                return Ok(());
            }
            Err(_) => {
                // Treat errors as "deleted" since we can't determine state
                return Ok(());
            }
        }
    }
}

/// Load a [`Kubeconfig`] using the Lattice resolution chain and ensure the proxy is reachable.
///
/// Resolution priority:
/// 1. `explicit` — the `--kubeconfig` CLI flag
/// 2. `LATTICE_KUBECONFIG` env var
/// 3. `~/.lattice/kubeconfig` (from `lattice login`)
/// 4. kube defaults (`KUBECONFIG` env / `~/.kube/config`)
///
/// If the kubeconfig is a proxy kubeconfig with a dead port, a port-forward is
/// auto-started and the server URLs are rewritten. The caller must hold the
/// `PortForward` guard to keep it alive.
pub async fn load_kubeconfig(
    explicit: Option<&str>,
) -> Result<(Kubeconfig, Option<port_forward::PortForward>)> {
    let resolved = crate::config::resolve_kubeconfig(explicit);
    let mut kc = match resolved.as_deref() {
        Some(path) => Kubeconfig::read_from(path).map_err(|e| {
            Error::command_failed(format!("failed to read kubeconfig {}: {}", path, e))
        })?,
        None => Kubeconfig::read()
            .map_err(|e| Error::command_failed(format!("failed to read kubeconfig: {}", e)))?,
    };
    let pf = port_forward::ensure_proxy_reachable(&mut kc).await;
    Ok((kc, pf))
}

/// Build a kube [`Client`] from an already-loaded [`Kubeconfig`] with options.
pub async fn kube_client_from_kubeconfig(
    kubeconfig: Kubeconfig,
    options: &KubeConfigOptions,
) -> Result<Client> {
    let config = Config::from_custom_kubeconfig(kubeconfig, options)
        .await
        .cmd_err()?;
    Client::try_from(config).cmd_err()
}

/// Apply just the Lattice CRD manifests to `client`.
///
/// Used by `uninstall` to prep a fresh kind cluster that doesn't need the full
/// operator running, just the CRDs so copied `InfraProvider`/`ImageProvider`
/// resources have a schema to land against.
pub async fn apply_lattice_crds(client: &Client) -> Result<()> {
    let crd_manifests = lattice_operator::startup::all_crd_manifests();

    lattice_common::kube_utils::apply_manifests(
        client,
        &crd_manifests.iter().map(String::as_str).collect::<Vec<_>>(),
        &Default::default(),
    )
    .await
    .cmd_err()?;

    // Establish-wait for the two CRDs the uninstall flow actually writes to.
    // Everything else lands as a by-product and isn't on the critical path.
    for crd in ["infraproviders.lattice.dev", "imageproviders.lattice.dev"] {
        lattice_common::kube_utils::wait_for_crd(
            client,
            crd,
            std::time::Duration::from_secs(60),
        )
        .await
        .cmd_err()?;
    }

    Ok(())
}

/// Copy every Lattice CRD marked distributable (`InfraProvider`,
/// `ImageProvider`, `SecretProvider`, `CedarPolicy`, `OIDCProvider`,
/// `LatticePackage`) plus their backing Secrets from `source` to `target`.
///
/// Used in both directions:
/// - **install**: bootstrap kind → pivoted mgmt cluster (seeds what the user
///   authored in the install YAML onto the long-lived cluster).
/// - **uninstall**: target mgmt cluster → fresh kind cluster (so `lattice move`
///   can run CAPI providers that need private images).
///
/// `origin_cluster` tags inherited resources with their source cluster name.
pub async fn copy_lattice_resources(
    source: &Client,
    target: &Client,
    origin_cluster: &str,
) -> Result<()> {
    use lattice_agent::apply_distributed_resources;
    use lattice_cell::fetch_distributable_resources;

    let resources = fetch_distributable_resources(source, origin_cluster)
        .await
        .map_err(|e| Error::command_failed(format!("Failed to fetch resources: {e}")))?;

    if resources.is_empty() {
        debug!("No distributable resources to copy");
        return Ok(());
    }

    debug!(
        "Copying {} InfraProvider(s), {} ImageProvider(s), {} SecretProvider(s), \
         {} CedarPolicy(s), {} OIDCProvider(s), {} LatticePackage(s), {} secret(s)",
        resources.cloud_providers.len(),
        resources.image_providers.len(),
        resources.secrets_providers.len(),
        resources.cedar_policies.len(),
        resources.oidc_providers.len(),
        resources.packages.len(),
        resources.secrets.len()
    );

    apply_distributed_resources(target, &resources)
        .await
        .map_err(|e| Error::command_failed(format!("Failed to apply resources: {e}")))?;

    Ok(())
}

/// Ensure CAPI providers are installed for the given provider type.
///
/// cert-manager must be installed and ready before calling this function,
/// as CAPI manifests reference cert-manager CRDs (Certificate, Issuer).
///
/// Looks up the named `InfraProvider` in `lattice-system` when present and
/// materializes its declared `imagePullSecrets` into the CAPI provider
/// namespace via ESO so the provider Deployment can pull private images.
/// Shares the `ensure_capi_providers_for` entry point used by the in-cluster
/// operator startup — one install path, no drift.
pub async fn ensure_capi_providers(
    client: &Client,
    provider: lattice_crd::crd::ProviderType,
    provider_ref: &str,
) -> Result<()> {
    use kube::Api;
    use lattice_capi::installer::{ensure_capi_providers_for, NativeInstaller};
    use lattice_core::LATTICE_SYSTEM_NAMESPACE;
    use lattice_crd::crd::InfraProvider;

    let cps: Api<InfraProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let cp = match cps.get(provider_ref).await {
        Ok(cp) => Some(cp),
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => {
            return Err(Error::command_failed(format!(
                "failed to read InfraProvider '{provider_ref}': {e}"
            )));
        }
    };

    let installer = NativeInstaller::new();
    ensure_capi_providers_for(client, &installer, provider, cp.as_ref(), "lattice-cli")
        .await
        .cmd_err()
}
