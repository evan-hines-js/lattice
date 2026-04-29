//! Polling and waiting utilities for Kubernetes resources.

use std::future::Future;
use std::time::Duration;

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Endpoints, Node, Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DynamicObject, GroupVersionKind, ListParams};
use kube::discovery::ApiResource;
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

/// Wait for a DaemonSet to have all desired pods ready.
///
/// Ready when `status.numberReady == status.desiredNumberScheduled` and
/// `desiredNumberScheduled > 0`. Missing DS (404) is treated as "not ready yet"
/// so callers can reconcile ahead of the DS being applied.
pub async fn wait_for_daemonset(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);
    let name_owned = name.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for DaemonSet {} to be ready", name),
        || {
            let daemonsets = daemonsets.clone();
            let name = name_owned.clone();
            async move {
                match daemonsets.get(&name).await {
                    Ok(ds) => {
                        let ready = ds
                            .status
                            .as_ref()
                            .map(|s| {
                                s.desired_number_scheduled > 0
                                    && s.number_ready == s.desired_number_scheduled
                            })
                            .unwrap_or(false);
                        Ok(ready)
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => {
                        trace!("DaemonSet {} not found yet", name);
                        Ok(false)
                    }
                    Err(e) => Err(Error::internal_with_context(
                        "wait_for_daemonset",
                        format!("Failed to get DaemonSet {}: {}", name, e),
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

/// Wait for a secret to exist by polling.
///
/// Returns immediately if the secret already exists. Otherwise polls at
/// [`DEFAULT_POLL_INTERVAL`] until the secret appears or `timeout` elapses.
///
/// Polling (not a watch) because callers hit this right after standing up
/// ESO / CAPI provider Deployments on fresh clusters, where the apiserver
/// routinely drops watch streams mid-connect. Watch error handling would
/// have to reconnect on every transient body-read error; a cheap periodic
/// GET is simpler and has the same latency characteristics.
pub async fn wait_for_secret(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    info!(secret = %name, namespace = %namespace, "Waiting for secret...");

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for secret {namespace}/{name}"),
        || async {
            match secrets.get(name).await {
                Ok(_) => Ok(true),
                Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
                Err(e) => {
                    // Treat transient API errors as "not yet"; poll_until logs
                    // at trace level so they surface in debug builds.
                    trace!("transient error checking {namespace}/{name}: {e}");
                    Ok(false)
                }
            }
        },
    )
    .await
}

/// GroupVersionKind + plural — the minimum a dynamic `Api<DynamicObject>`
/// needs. `plural` can't be derived reliably from `kind` (CephFS →
/// cephfilesystems, not cephfss), so callers pass it explicitly.
pub struct GvkPlural<'a> {
    /// API group (e.g. `"ceph.rook.io"`).
    pub group: &'a str,
    /// API version (e.g. `"v1"`).
    pub version: &'a str,
    /// Kind (e.g. `"CephCluster"`).
    pub kind: &'a str,
    /// Plural resource name used in REST paths (e.g. `"cephclusters"`).
    pub plural: &'a str,
}

/// Poll a named resource until `predicate(serde_json::Value)` returns true.
///
/// Used by Install controllers whose readiness signal lives on a CR's
/// `.status` — e.g. `CephCluster.status.ceph.health == "HEALTH_OK"` — and
/// isn't captured by a Deployment or DaemonSet check. The resource may not
/// exist when polling starts (just-applied CR, operator hasn't processed it
/// yet); 404 is treated as "not ready" and polling continues.
///
/// `description` appears in the timeout error message so the surfaced
/// failure points at the right invariant ("HEALTH_OK", not "timeout").
pub async fn wait_for_resource_status<F>(
    client: &Client,
    gvk: &GvkPlural<'_>,
    name: &str,
    namespace: Option<&str>,
    description: &str,
    timeout: Duration,
    predicate: F,
) -> Result<(), Error>
where
    F: Fn(&serde_json::Value) -> bool + Send + Sync + 'static,
{
    let ar = ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(gvk.group, gvk.version, gvk.kind),
        gvk.plural,
    );
    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &ar),
        None => Api::all_with(client.clone(), &ar),
    };
    let name_owned = name.to_string();
    let resource_ref = match namespace {
        Some(ns) => format!("{}/{}/{}", gvk.kind, ns, name),
        None => format!("{}/{}", gvk.kind, name),
    };

    info!(resource = %resource_ref, wait_for = %description, "Waiting for resource status");

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for {resource_ref} to reach {description}"),
        || {
            let api = api.clone();
            let name = name_owned.clone();
            let predicate = &predicate;
            async move {
                match api.get(&name).await {
                    Ok(obj) => {
                        let value = serde_json::to_value(&obj).map_err(|e| {
                            Error::internal_with_context(
                                "wait_for_resource_status",
                                format!("serialize dynamic object: {e}"),
                            )
                        })?;
                        Ok(predicate(&value))
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
                    Err(e) => {
                        trace!("transient error polling {name}: {e}");
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Non-blocking check: does this Service have at least one Ready Endpoint?
///
/// Returns `Ok(false)` when the Endpoints object is missing, has no subsets,
/// or every subset has only `not_ready_addresses`. Used by install controllers
/// to gate apply-of-CRs on the install's own admission webhook becoming
/// reachable — without that gate, a freshly-applied install pushes ~50 CRs
/// before its webhook pod is up, each one round-tripping through the
/// apiserver only to fail with `no endpoints available for service`.
///
/// Caller pattern: when this returns `false`, write a `Pending` status and
/// return `Action::requeue(short)` from the reconcile, instead of blocking.
pub async fn endpoints_ready(client: &Client, namespace: &str, name: &str) -> Result<bool, Error> {
    let api: Api<Endpoints> = Api::namespaced(client.clone(), namespace);
    match api.get(name).await {
        Ok(eps) => Ok(eps
            .subsets
            .as_deref()
            .map(|subsets| subsets.iter().any(|s| s.addresses.is_some()))
            .unwrap_or(false)),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::internal_with_context(
            "endpoints_ready",
            format!("Failed to get Endpoints {namespace}/{name}: {e}"),
        )),
    }
}
