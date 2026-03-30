//! Polling and waiting utilities for Kubernetes resources.

use std::future::Future;
use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Node, Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ListParams};
use kube::Client;
use tracing::{info, trace};

use super::conditions::{has_condition, CONDITION_AVAILABLE, CONDITION_READY};
use crate::Error;

/// Default polling interval for wait operations
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Poll until a condition is met or timeout is reached
///
/// This is a generic polling function that repeatedly calls a check function
/// until it returns `Ok(true)` or the timeout is exceeded.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for the condition
/// * `poll_interval` - Time between polling attempts
/// * `timeout_msg` - Error message to use on timeout
/// * `check_fn` - Async function that returns `Ok(true)` when condition is met,
///   `Ok(false)` to continue polling, or `Err` on failure
///
/// # Returns
/// `Ok(())` if the condition was met, or `Err` on timeout or check failure
pub(crate) async fn poll_until<F, Fut>(
    timeout: Duration,
    poll_interval: Duration,
    timeout_msg: impl Into<String>,
    mut check_fn: F,
) -> Result<(), Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, Error>>,
{
    let start = std::time::Instant::now();
    let timeout_msg = timeout_msg.into();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::internal_with_context("poll_until", timeout_msg));
        }

        match check_fn().await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // Condition not met, continue polling
                trace!("Polling condition not yet met, retrying...");
            }
            Err(e) => {
                // Log at trace level since polling failures are expected
                trace!("Polling check returned error (retrying): {}", e);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Wait for all nodes to be ready
pub async fn wait_for_nodes_ready(client: &Client, timeout: Duration) -> Result<(), Error> {
    let nodes: Api<Node> = Api::all(client.clone());

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        "Timeout waiting for nodes to be ready",
        || async {
            let node_list = nodes.list(&ListParams::default()).await.map_err(|e| {
                Error::internal_with_context(
                    "wait_for_nodes_ready",
                    format!("Failed to list nodes: {}", e),
                )
            })?;

            if node_list.items.is_empty() {
                return Ok(false);
            }

            let all_ready = node_list.items.iter().all(|node| {
                let conditions = node.status.as_ref().and_then(|s| s.conditions.as_ref());
                has_condition(conditions.map(|c| c.as_slice()), CONDITION_READY)
            });

            Ok(all_ready)
        },
    )
    .await
}

/// Wait for a deployment to be available
pub async fn wait_for_deployment(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let name_owned = name.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for deployment {} to be available", name),
        || {
            let deployments = deployments.clone();
            let name = name_owned.clone();
            async move {
                match deployments.get(&name).await {
                    Ok(deployment) => {
                        let conditions = deployment
                            .status
                            .as_ref()
                            .and_then(|s| s.conditions.as_ref());
                        Ok(has_condition(
                            conditions.map(|c| c.as_slice()),
                            CONDITION_AVAILABLE,
                        ))
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => {
                        // Deployment doesn't exist yet, keep waiting
                        trace!("Deployment {} not found yet", name);
                        Ok(false)
                    }
                    Err(e) => Err(Error::internal_with_context(
                        "wait_for_deployment",
                        format!("Failed to get deployment {}: {}", name, e),
                    )),
                }
            }
        },
    )
    .await
}

/// Wait for all deployments in a namespace to be available
pub async fn wait_for_all_deployments(
    client: &Client,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let namespace_owned = namespace.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!(
            "Timeout waiting for deployments in {} to be available",
            namespace
        ),
        || {
            let deployments = deployments.clone();
            let namespace = namespace_owned.clone();
            async move {
                let deployment_list =
                    deployments
                        .list(&ListParams::default())
                        .await
                        .map_err(|e| {
                            Error::internal_with_context(
                                "wait_for_all_deployments",
                                format!("Failed to list deployments in {}: {}", namespace, e),
                            )
                        })?;

                if deployment_list.items.is_empty() {
                    return Ok(false);
                }

                let all_available = deployment_list.items.iter().all(|deployment| {
                    let conditions = deployment
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref());
                    has_condition(conditions.map(|c| c.as_slice()), CONDITION_AVAILABLE)
                });

                Ok(all_available)
            }
        },
    )
    .await
}

/// Check if a CRD exists
pub async fn crd_exists(client: &Client, crd_name: &str) -> Result<bool, Error> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    match crds.get(crd_name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::internal_with_context(
            "crd_exists",
            format!("Failed to check CRD {}: {}", crd_name, e),
        )),
    }
}

/// Wait for a CRD to be available
pub async fn wait_for_crd(client: &Client, crd_name: &str, timeout: Duration) -> Result<(), Error> {
    let client_clone = client.clone();
    let crd_name_owned = crd_name.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for CRD: {}", crd_name),
        || {
            let client = client_clone.clone();
            let crd_name = crd_name_owned.clone();
            async move {
                let exists = crd_exists(&client, &crd_name).await?;
                if exists {
                    info!("CRD ready: {}", crd_name);
                }
                Ok(exists)
            }
        },
    )
    .await
}

/// Get a secret data value
pub async fn get_secret_data(
    client: &Client,
    name: &str,
    namespace: &str,
    key: &str,
) -> Result<Vec<u8>, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let secret = secrets.get(name).await.map_err(|e| {
        Error::internal_with_context(
            "get_secret_data",
            format!("Failed to get secret {}/{}: {}", namespace, name, e),
        )
    })?;

    let data = secret
        .data
        .as_ref()
        .and_then(|d| d.get(key))
        .ok_or_else(|| {
            Error::internal_with_context(
                "get_secret_data",
                format!("Secret {}/{} missing key {}", namespace, name, key),
            )
        })?;

    Ok(data.0.clone())
}

/// Check if a secret exists
pub async fn secret_exists(client: &Client, name: &str, namespace: &str) -> Result<bool, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    match secrets.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::internal_with_context(
            "secret_exists",
            format!("Failed to check secret {}/{}: {}", namespace, name, e),
        )),
    }
}

/// Wait for a secret to exist using a K8s watch.
///
/// If the secret already exists, returns immediately. Otherwise sets up
/// a watch and waits for the ADDED event. Times out if the secret doesn't
/// appear within the given duration.
pub async fn wait_for_secret(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    use futures::{StreamExt, TryStreamExt};
    use kube::runtime::watcher::{self, Event};

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // Fast path: already exists
    match secrets.get(name).await {
        Ok(_) => return Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => {}
        Err(e) => {
            return Err(Error::internal_with_context(
                "wait_for_secret",
                format!("failed to check secret {namespace}/{name}: {e}"),
            ))
        }
    }

    info!(secret = %name, namespace = %namespace, "Watching for secret...");

    let field_selector = format!("metadata.name={name}");
    let watch_config = watcher::Config::default().fields(&field_selector);
    let mut stream = watcher::watcher(secrets, watch_config).boxed();

    let result = tokio::time::timeout(timeout, async {
        while let Some(event) = stream.try_next().await.map_err(|e| {
            Error::internal_with_context(
                "wait_for_secret",
                format!("watch error for {namespace}/{name}: {e}"),
            )
        })? {
            if let Event::Apply(secret) | Event::InitApply(secret) = event {
                if secret.metadata.name.as_deref() == Some(name) {
                    return Ok(());
                }
            }
        }
        Err(Error::internal_with_context(
            "wait_for_secret",
            format!("watch stream ended for {namespace}/{name}"),
        ))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(Error::internal_with_context(
            "wait_for_secret",
            format!("Timeout waiting for secret {namespace}/{name}"),
        )),
    }
}
