//! ModelCache reconciliation controller
//!
//! Watches ModelArtifact CRDs and drives the download lifecycle:
//! - `Pending` → create pre-fetch Job → `Downloading`
//! - `Downloading` → poll Job status → `Ready` or `Failed`
//! - `Ready` → remove scheduling gates, periodic re-check
//! - `Failed` → reset to `Pending` for retry (infinite, with exponential backoff)
//!
//! Also provides `discover_models()` for use as a `.watches(LatticeService)` mapper
//! that ensures ModelArtifact CRDs exist for every `type: model` resource.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeService, ModelArtifact, ModelArtifactPhase, ModelArtifactSpec, ModelArtifactStatus,
    RETRY_BASE_DELAY_SECS, RETRY_MAX_DELAY_SECS,
};
use lattice_common::ReconcileError;

use crate::gate;
use crate::job;

/// Default model loader image
const DEFAULT_MODEL_LOADER_IMAGE: &str = "ghcr.io/lattice-cloud/model-loader:v1";

/// Context for the ModelCache controller
pub struct ModelCacheContext {
    /// Kubernetes client
    pub client: Client,
    /// Container image used for the model-loader Job
    pub model_loader_image: String,
}

impl ModelCacheContext {
    /// Create a new context with the default loader image
    pub fn new(client: Client) -> Self {
        Self {
            client,
            model_loader_image: DEFAULT_MODEL_LOADER_IMAGE.to_string(),
        }
    }
}

/// Error policy for the ModelCache controller.
///
/// Logs the error and requeues for retry after 30 seconds.
pub fn error_policy(
    _obj: Arc<ModelArtifact>,
    error: &ReconcileError,
    _ctx: Arc<ModelCacheContext>,
) -> Action {
    warn!(error = %error, "ModelCache reconcile error, will retry");
    Action::requeue(Duration::from_secs(30))
}

/// Reconcile a ModelArtifact through its download lifecycle.
///
/// Phase transitions:
/// - `Pending` → ensure PVC, create Job → `Downloading`
/// - `Downloading` → poll Job → `Ready` + remove gates, or `Failed`
/// - `Ready` → remove gates for new Deployments, periodic re-check
/// - `Failed` → delete old Job, reset to `Pending` with exponential backoff
pub async fn reconcile(
    artifact: Arc<ModelArtifact>,
    ctx: Arc<ModelCacheContext>,
) -> Result<Action, ReconcileError> {
    let name = artifact.name_any();
    let namespace = artifact
        .namespace()
        .ok_or_else(|| ReconcileError::Validation("ModelArtifact must be namespaced".into()))?;
    let client = &ctx.client;

    let phase = artifact
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or_default();

    info!(artifact = %name, ?phase, "Reconciling ModelArtifact");

    match phase {
        ModelArtifactPhase::Pending => {
            reconcile_pending(&artifact, &name, &namespace, ctx.as_ref()).await
        }
        ModelArtifactPhase::Downloading => {
            reconcile_downloading(&artifact, &name, &namespace, client).await
        }
        ModelArtifactPhase::Ready => reconcile_ready(&artifact, &name, &namespace, client).await,
        ModelArtifactPhase::Failed => reconcile_failed(&artifact, &name, &namespace, client).await,
    }
}

/// Pending: ensure PVC exists, create a pre-fetch Job if one doesn't exist,
/// then transition to Downloading.
async fn reconcile_pending(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    ctx: &ModelCacheContext,
) -> Result<Action, ReconcileError> {
    let client = &ctx.client;

    // Ensure the model cache PVC exists (owned by this ModelArtifact)
    ensure_pvc(artifact, namespace, client).await?;

    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let job_name = job::prefetch_job_name(name);

    // Check if a Job already exists (idempotent)
    match jobs.get_opt(&job_name).await {
        Ok(Some(_)) => {
            info!(artifact = %name, "Pre-fetch Job already exists, transitioning to Downloading");
            patch_status(client, name, namespace, |status| {
                status.phase = ModelArtifactPhase::Downloading;
            })
            .await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Ok(None) => {
            let uid = artifact
                .uid()
                .ok_or_else(|| ReconcileError::Internal("ModelArtifact has no UID".into()))?;

            let job_obj = job::build_prefetch_job(
                &artifact.spec,
                name,
                &uid,
                namespace,
                &ctx.model_loader_image,
            );

            info!(artifact = %name, job = %job_name, "Creating pre-fetch Job");
            jobs.create(&PostParams::default(), &job_obj)
                .await
                .map_err(|e| {
                    ReconcileError::Kube(format!("failed to create pre-fetch job: {}", e))
                })?;

            patch_status(client, name, namespace, |status| {
                status.phase = ModelArtifactPhase::Downloading;
            })
            .await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Err(e) => Err(ReconcileError::Kube(format!(
            "failed to check for existing job: {}",
            e
        ))),
    }
}

/// Ensure the model cache PVC exists, owned by the ModelArtifact via ownerReferences.
///
/// Uses server-side apply for idempotency — safe to call on every reconcile.
async fn ensure_pvc(
    artifact: &ModelArtifact,
    namespace: &str,
    client: &Client,
) -> Result<(), ReconcileError> {
    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let pvc_name = &artifact.spec.pvc_name;

    let uid = artifact
        .uid()
        .ok_or_else(|| ReconcileError::Internal("ModelArtifact has no UID".into()))?;

    let mut pvc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": pvc_name,
            "namespace": namespace,
            "ownerReferences": [{
                "apiVersion": "lattice.dev/v1alpha1",
                "kind": "ModelArtifact",
                "name": artifact.name_any(),
                "uid": uid,
                "controller": true,
                "blockOwnerDeletion": true,
            }],
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": artifact.spec.cache_size,
                }
            },
        }
    });

    // Only set storageClassName when explicitly specified.
    // Omitting it lets K8s use the default storage class;
    // setting it to null would mean "no storage class".
    if let Some(sc) = &artifact.spec.storage_class {
        pvc["spec"]["storageClassName"] = serde_json::json!(sc);
    }

    pvcs.patch(
        pvc_name,
        &PatchParams::apply("lattice-model-cache").force(),
        &Patch::Apply(&pvc),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to ensure PVC: {}", e)))?;

    debug!(pvc = %pvc_name, "Model cache PVC ensured via SSA");
    Ok(())
}

/// Downloading: poll Job status, transition to Ready or Failed
async fn reconcile_downloading(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let job_name = job::prefetch_job_name(name);

    match jobs.get_opt(&job_name).await {
        Ok(Some(job_obj)) => {
            if job::is_job_complete(&job_obj) {
                info!(artifact = %name, "Pre-fetch Job completed, model is ready");
                patch_status(client, name, namespace, |status| {
                    status.phase = ModelArtifactPhase::Ready;
                    status.completed_at = Some(chrono::Utc::now());
                })
                .await?;

                gate::remove_gates_for_pvc(client, namespace, &artifact.spec.pvc_name).await?;
                Ok(Action::requeue(Duration::from_secs(300)))
            } else if job::is_job_failed(&job_obj) {
                let msg = job::job_failure_message(&job_obj)
                    .unwrap_or_else(|| "unknown failure".to_string());
                warn!(artifact = %name, error = %msg, "Pre-fetch Job failed");
                patch_status(client, name, namespace, |status| {
                    status.phase = ModelArtifactPhase::Failed;
                    status.error = Some(msg);
                })
                .await?;
                Ok(Action::requeue(Duration::from_secs(30)))
            } else {
                debug!(artifact = %name, "Pre-fetch Job still running");
                Ok(Action::requeue(Duration::from_secs(15)))
            }
        }
        Ok(None) => {
            warn!(artifact = %name, "Pre-fetch Job not found, resetting to Pending");
            patch_status(client, name, namespace, |status| {
                status.phase = ModelArtifactPhase::Pending;
                status.error = Some("Pre-fetch Job not found, will retry".to_string());
            })
            .await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        Err(e) => Err(ReconcileError::Kube(format!(
            "failed to get job status: {}",
            e
        ))),
    }
}

/// Ready: remove scheduling gates for any new Deployments, periodic health check
async fn reconcile_ready(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    debug!(artifact = %name, "Model is Ready, checking for new Deployments needing gate removal");
    gate::remove_gates_for_pvc(client, namespace, &artifact.spec.pvc_name).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Failed: delete the old Job and reset to Pending with exponential backoff.
///
/// Retries forever — the backoff grows from 30s up to ~5 minutes.
async fn reconcile_failed(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    let retry_count = artifact.status.as_ref().map(|s| s.retry_count).unwrap_or(0);

    // Delete the old failed Job so Pending can create a fresh one
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let job_name = job::prefetch_job_name(name);
    if let Ok(Some(_)) = jobs.get_opt(&job_name).await {
        let dp = kube::api::DeleteParams {
            propagation_policy: Some(kube::api::PropagationPolicy::Background),
            ..Default::default()
        };
        let _ = jobs.delete(&job_name, &dp).await;
        debug!(artifact = %name, "Deleted failed Job for retry");
    }

    let new_count = retry_count.saturating_add(1);
    let delay = std::cmp::min(
        RETRY_BASE_DELAY_SECS.saturating_mul(2u64.saturating_pow(retry_count)),
        RETRY_MAX_DELAY_SECS,
    );

    info!(
        artifact = %name,
        retry_count = new_count,
        delay_secs = delay,
        "Resetting Failed artifact to Pending for retry"
    );

    patch_status(client, name, namespace, |status| {
        status.phase = ModelArtifactPhase::Pending;
        status.retry_count = new_count;
        status.error = None;
    })
    .await?;

    Ok(Action::requeue(Duration::from_secs(delay)))
}

// =============================================================================
// Status helpers
// =============================================================================

/// Read-modify-write the ModelArtifact status, preserving fields not touched
/// by the caller's closure. Uses JSON merge patch.
async fn patch_status(
    client: &Client,
    name: &str,
    namespace: &str,
    modify: impl FnOnce(&mut ModelArtifactStatus),
) -> Result<(), ReconcileError> {
    let api: Api<ModelArtifact> = Api::namespaced(client.clone(), namespace);

    let current = api
        .get_status(name)
        .await
        .map_err(|e| ReconcileError::Kube(format!("failed to read current status: {}", e)))?;
    let mut status = current.status.unwrap_or_default();

    modify(&mut status);

    let patch = serde_json::json!({ "status": status });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ReconcileError::Kube(format!("failed to update status: {}", e)))?;

    Ok(())
}

// =============================================================================
// Model discovery mapper
// =============================================================================

/// Watch mapper: discovers ModelArtifact refs from LatticeService changes.
///
/// For each `type: model` resource in the service spec, ensures a ModelArtifact
/// CRD exists (creates one if missing via server-side apply) and returns its
/// `ObjectRef` so the controller reconciles it.
pub fn discover_models(client: Client) -> impl Fn(LatticeService) -> Vec<ObjectRef<ModelArtifact>> {
    move |service: LatticeService| {
        let namespace = match service.metadata.namespace.as_deref() {
            Some(ns) => ns.to_string(),
            None => return vec![],
        };

        let mut refs = Vec::new();

        for resource in service.spec.resources.values() {
            let params = match resource.model_params() {
                Ok(Some(p)) => p,
                _ => continue,
            };

            let artifact_name = params.cache_pvc_name();

            // Spawn a background task to ensure the ModelArtifact exists.
            // We can't do async work in the mapper directly, so we spawn.
            // Uses server-side apply for idempotency — no race between
            // concurrent mapper invocations for the same service.
            let client = client.clone();
            let ns = namespace.clone();
            let name = artifact_name.clone();
            let spec = ModelArtifactSpec {
                uri: params.uri.clone(),
                revision: params.revision.clone(),
                pvc_name: artifact_name.clone(),
                cache_size: params.pvc_size().to_string(),
                storage_class: params.storage_class.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = ensure_model_artifact(&client, &name, &ns, spec).await {
                    warn!(
                        artifact = %name,
                        namespace = %ns,
                        error = %e,
                        "Failed to ensure ModelArtifact exists"
                    );
                }
            });

            refs.push(ObjectRef::<ModelArtifact>::new(&artifact_name).within(&namespace));
        }

        refs
    }
}

/// Ensure a ModelArtifact CRD exists for the given model using server-side apply.
///
/// Idempotent: if the artifact already exists, this is a no-op (SSA won't
/// overwrite fields owned by other managers). Safe for concurrent calls.
async fn ensure_model_artifact(
    client: &Client,
    name: &str,
    namespace: &str,
    spec: ModelArtifactSpec,
) -> Result<(), ReconcileError> {
    let api: Api<ModelArtifact> = Api::namespaced(client.clone(), namespace);

    let artifact = ModelArtifact::new(name, spec);
    let patch = serde_json::to_value(&artifact)
        .map_err(|e| ReconcileError::Internal(format!("failed to serialize artifact: {}", e)))?;

    api.patch(
        name,
        &PatchParams::apply("lattice-model-cache").force(),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to apply ModelArtifact: {}", e)))?;

    debug!(artifact = %name, namespace = %namespace, "ModelArtifact ensured via SSA");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_loader_image() {
        assert_eq!(
            DEFAULT_MODEL_LOADER_IMAGE,
            "ghcr.io/lattice-cloud/model-loader:v1"
        );
    }

    #[test]
    fn retry_backoff_caps_at_max_delay() {
        let backoff =
            |n: u32| -> u64 { RETRY_BASE_DELAY_SECS.saturating_mul(2u64.saturating_pow(n)) };

        assert_eq!(std::cmp::min(backoff(0), RETRY_MAX_DELAY_SECS), 30);
        assert_eq!(std::cmp::min(backoff(1), RETRY_MAX_DELAY_SECS), 60);
        assert_eq!(std::cmp::min(backoff(2), RETRY_MAX_DELAY_SECS), 120);
        assert_eq!(std::cmp::min(backoff(3), RETRY_MAX_DELAY_SECS), 240);
        // 30 * 2^4 = 480 → capped at 300
        assert_eq!(std::cmp::min(backoff(4), RETRY_MAX_DELAY_SECS), 300);
        // Large retry_count is safe (saturating arithmetic)
        assert_eq!(std::cmp::min(backoff(100), RETRY_MAX_DELAY_SECS), 300);
    }
}
