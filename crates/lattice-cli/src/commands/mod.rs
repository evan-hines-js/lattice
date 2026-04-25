//! CLI commands

use std::fmt::Display;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant};

use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tracing::{debug, info, warn};

use lattice_cell::bootstrap::{DefaultManifestGenerator, ManifestGenerator};
use lattice_common::{kube_utils, OPERATOR_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::ProviderType;

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

/// Timeout waiting for kind's API server to register Lattice CRDs.
const CRD_REGISTER_TIMEOUT: Duration = Duration::from_secs(90);
/// Timeout waiting for the operator Deployment to report Available.
const OPERATOR_READY_TIMEOUT: Duration = Duration::from_secs(180);

/// Stand up a kind cluster running the Lattice operator in bootstrap mode.
///
/// Shared by `install` (to stage initial provisioning) and `uninstall` (to
/// host a reverse CAPI pivot). Both flows need the same thing: a kind cluster
/// whose operator is configured to install CAPI providers for `provider` /
/// `provider_ref`, register Lattice CRDs, and stand up cert-manager + ESO +
/// the local-secrets webhook. Diverging these setups invites exactly the
/// class of bugs this function exists to prevent.
///
/// Returns a [`Client`] connected to the new kind cluster. On success, the
/// operator Deployment is Available and `infraproviders.lattice.dev` is
/// registered — callers can immediately apply InfraProvider CRs.
pub async fn prepare_ephemeral_cluster(
    kind_name: &str,
    kubeconfig_path: &Path,
    image: &str,
    registry_credentials: Option<&str>,
    provider: ProviderType,
    provider_ref: &str,
) -> Result<Client> {
    info!(kind = kind_name, "Creating kind cluster");
    kind_utils::create_kind_cluster(kind_name, kubeconfig_path).await?;

    let client = kube_utils::create_client(Some(kubeconfig_path), None, None)
        .await
        .cmd_err()?;

    info!("Deploying Lattice operator on kind cluster");
    // The ephemeral kind cluster runs with kindnet + kube-proxy (kind
    // defaults), so the bundle is operator-only — no Cilium. Cilium with
    // DSR is wired into the production bundle generated by
    // `generate_bootstrap_bundle` for CAPI-provisioned clusters.
    let manifests = DefaultManifestGenerator::new()
        .generate(
            image,
            registry_credentials,
            Some("lattice-installer"),
            None,
        )
        .await
        .map_err(|e| Error::command_failed(format!("manifest generation failed: {e}")))?;

    // Inject bootstrap env vars on the operator Deployment doc so it runs
    // `ensure_capi_on_bootstrap` — waits for InfraProvider `provider_ref`,
    // then installs cert-manager + ESO + local-webhook + CAPI providers.
    // Pass YAML manifests (Cilium) through unchanged.
    let provider_str = provider.to_string();
    let injected_manifests: Vec<String> = manifests
        .iter()
        .map(|s| {
            if s.starts_with('{') && kube_utils::is_deployment_json(s) {
                add_bootstrap_env(s, &provider_str, provider_ref)
            } else {
                s.to_string()
            }
        })
        .collect();

    let refs: Vec<&str> = injected_manifests.iter().map(String::as_str).collect();
    kube_utils::apply_manifests(&client, &refs, &Default::default())
        .await
        .cmd_err()?;

    info!("Waiting for operator Deployment Available");
    kube_utils::wait_for_deployment(
        &client,
        OPERATOR_NAME,
        LATTICE_SYSTEM_NAMESPACE,
        OPERATOR_READY_TIMEOUT,
    )
    .await
    .cmd_err()?;

    info!("Waiting for Lattice CRDs to register");
    kube_utils::wait_for_crd(&client, "infraproviders.lattice.dev", CRD_REGISTER_TIMEOUT)
        .await
        .cmd_err()?;
    kube_utils::wait_for_crd(&client, "imageproviders.lattice.dev", CRD_REGISTER_TIMEOUT)
        .await
        .cmd_err()?;

    Ok(client)
}

/// Add LATTICE_BOOTSTRAP_CLUSTER + LATTICE_PROVIDER + LATTICE_PROVIDER_REF env
/// vars to a Deployment JSON, leaving everything else intact. No-op if the
/// input isn't a Deployment or if the variables already exist.
pub fn add_bootstrap_env(deployment_json: &str, provider: &str, provider_ref: &str) -> String {
    add_deployment_env(
        deployment_json,
        &[
            ("LATTICE_BOOTSTRAP_CLUSTER", "true"),
            ("LATTICE_PROVIDER", provider),
            ("LATTICE_PROVIDER_REF", provider_ref),
        ],
    )
}

fn add_deployment_env(deployment_json: &str, vars: &[(&str, &str)]) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(deployment_json) else {
        return deployment_json.to_string();
    };
    let Some(containers) = value
        .pointer_mut("/spec/template/spec/containers")
        .and_then(|c| c.as_array_mut())
    else {
        return deployment_json.to_string();
    };
    for container in containers {
        let Some(env) = container.as_object_mut().and_then(|c| {
            c.entry("env")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut()
        }) else {
            continue;
        };
        for (name, value_str) in vars {
            if !env
                .iter()
                .any(|e| e.get("name").and_then(|n| n.as_str()) == Some(*name))
            {
                env.push(serde_json::json!({ "name": name, "value": value_str }));
            }
        }
    }
    serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
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
