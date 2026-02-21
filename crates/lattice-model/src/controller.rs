//! LatticeModel controller implementation
//!
//! Reconciles LatticeModel resources through a state machine:
//! Pending → Loading → Serving | Failed
//!
//! Resources are applied in layers to prevent race conditions:
//! - Layer 0: Model download PVC + Job (only when modelSource is configured)
//! - Layer 1: ConfigMaps, Secrets, ExternalSecrets, PVCs, MeshMembers, TracingPolicies
//! - Layer 2: ModelServing (only after mesh/security is ready)
//! - Layer 3: Routing — ModelServer + ModelRoutes
//!
//! When `modelSource` is set, pods are created with a `lattice.dev/model-download`
//! scheduling gate that keeps them `SchedulingGated` (zero resource usage, no GPU
//! allocation) until the download Job completes. The Loading phase checks Job status
//! and removes the gate on success.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{error, info, warn};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{LatticeModel, LatticeModelStatus, ModelServingPhase, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::kube_utils::ApplyBatch;
use lattice_common::{CrdKind, CrdRegistry};

use crate::compiler::{compile_model, CompiledModel};
use crate::download::{CompiledDownload, SCHEDULING_GATE_MODEL_DOWNLOAD};
use crate::error::ModelError;

/// Shared context for the LatticeModel controller
pub struct ModelContext {
    pub client: Client,
    pub graph: Arc<ServiceGraph>,
    pub cluster_name: String,
    pub provider_type: ProviderType,
    pub cedar: Arc<PolicyEngine>,
    pub registry: Arc<CrdRegistry>,
}

impl ModelContext {
    pub fn new(
        client: Client,
        graph: Arc<ServiceGraph>,
        cluster_name: String,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        registry: Arc<CrdRegistry>,
    ) -> Self {
        Self {
            client,
            graph,
            cluster_name,
            provider_type,
            cedar,
            registry,
        }
    }
}

/// Reconcile a LatticeModel resource
pub async fn reconcile(
    model: Arc<LatticeModel>,
    ctx: Arc<ModelContext>,
) -> Result<Action, ModelError> {
    let name = model.name_any();
    let namespace = model
        .metadata
        .namespace
        .as_deref()
        .ok_or(ModelError::MissingNamespace)?;

    let generation = model.metadata.generation.unwrap_or(0);
    let phase = model
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ModelServingPhase::Pending);

    match phase {
        ModelServingPhase::Pending => {
            let compiled = compile_model(
                &model,
                &ctx.graph,
                &ctx.cluster_name,
                ctx.provider_type,
                &ctx.cedar,
            )
            .await;

            let compiled = match compiled {
                Ok(c) => c,
                Err(e) => {
                    cleanup_graph(&model, &ctx.graph, namespace);
                    return Err(e);
                }
            };

            register_graph(&model, &ctx.graph, namespace);

            apply_compiled_model(&ctx.client, namespace, &compiled, &ctx).await?;
            update_status(
                &ctx.client,
                &name,
                namespace,
                ModelServingPhase::Loading,
                None,
                Some(generation),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(15)))
        }
        ModelServingPhase::Loading => {
            // When modelSource is configured, check download Job before ModelServing
            if model.spec.model_source.is_some() {
                let job_name = format!("{}-download", name);
                match check_download_job_status(&ctx.client, &job_name, namespace).await {
                    Some(DownloadState::Succeeded) => {
                        info!(model = %name, "model download job completed");
                        remove_scheduling_gates(&ctx.client, &name, namespace).await?;
                    }
                    Some(DownloadState::Failed) => {
                        error!(model = %name, "model download job failed");
                        cleanup_graph(&model, &ctx.graph, namespace);
                        update_status(
                            &ctx.client,
                            &name,
                            namespace,
                            ModelServingPhase::Failed,
                            Some("Model download failed"),
                            Some(generation),
                        )
                        .await?;
                        return Ok(Action::await_change());
                    }
                    Some(DownloadState::Running) => {
                        info!(model = %name, "model download in progress");
                        return Ok(Action::requeue(Duration::from_secs(15)));
                    }
                    None => {
                        warn!(model = %name, "download job not found, requeuing");
                        return Ok(Action::requeue(Duration::from_secs(15)));
                    }
                }
            }

            let ms_api = match ctx.registry.resolve(CrdKind::ModelServing).await {
                Some(ar) => ar,
                None => {
                    warn!(model = %name, "cannot check ModelServing status: CRD not discovered");
                    return Ok(Action::requeue(Duration::from_secs(15)));
                }
            };

            match check_model_serving_status(&ctx.client, &name, namespace, &ms_api).await {
                Some(ModelServingState::Available) => {
                    info!(model = %name, "model serving is available");
                    update_status(
                        &ctx.client,
                        &name,
                        namespace,
                        ModelServingPhase::Serving,
                        Some("Model is serving inference requests"),
                        Some(generation),
                    )
                    .await?;
                    Ok(Action::requeue(Duration::from_secs(60)))
                }
                Some(ModelServingState::Failed) => {
                    error!(model = %name, "model serving failed");
                    cleanup_graph(&model, &ctx.graph, namespace);
                    update_status(
                        &ctx.client,
                        &name,
                        namespace,
                        ModelServingPhase::Failed,
                        Some("ModelServing failed"),
                        Some(generation),
                    )
                    .await?;
                    Ok(Action::await_change())
                }
                _ => Ok(Action::requeue(Duration::from_secs(15))),
            }
        }
        ModelServingPhase::Serving => {
            // Monitor health, detect spec changes for rolling update
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ModelServingPhase::Failed => Ok(Action::await_change()),
    }
}

/// Register all model roles in the service graph for bilateral agreements
fn register_graph(model: &LatticeModel, graph: &ServiceGraph, namespace: &str) {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    for (role_name, role_spec) in &model.spec.roles {
        graph.put_workload(
            namespace,
            &format!("{}-{}", name, role_name),
            &role_spec.entry_workload,
        );
    }
}

/// Remove model roles from the service graph on failure
fn cleanup_graph(model: &LatticeModel, graph: &ServiceGraph, namespace: &str) {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    for role_name in model.spec.roles.keys() {
        graph.delete_service(namespace, &format!("{}-{}", name, role_name));
    }
}

/// Error policy for LatticeModel reconciliation
pub fn error_policy(
    model: Arc<LatticeModel>,
    error: &ModelError,
    _ctx: Arc<ModelContext>,
) -> Action {
    error!(
        ?error,
        model = %model.name_any(),
        "model reconciliation failed"
    );
    Action::requeue(Duration::from_secs(30))
}

/// Apply compiled model resources in layers using ApplyBatch
async fn apply_compiled_model(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    ctx: &ModelContext,
) -> Result<(), ModelError> {
    let params = PatchParams::apply("lattice-model-controller").force();

    lattice_common::kube_utils::ensure_namespace_ssa(client, namespace, "lattice-model-controller")
        .await?;

    let ms_api = ctx
        .registry
        .resolve(CrdKind::ModelServing)
        .await
        .ok_or(ModelError::KthenaCrdMissing)?;

    apply_layers(client, namespace, compiled, &ctx.registry, &ms_api, &params).await
}

async fn apply_layers(
    client: &Client,
    namespace: &str,
    compiled: &CompiledModel,
    registry: &CrdRegistry,
    ms_api: &ApiResource,
    params: &PatchParams,
) -> Result<(), ModelError> {
    // Layer 0: Model download (PVC + Job) — only when modelSource is configured
    if let Some(ref download) = compiled.download {
        apply_download_resources(client, namespace, download, params).await?;
    }

    // Layer 1: Infrastructure (config, mesh, security, service accounts)
    let cm_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&());
    let secret_ar = ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&());
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let sa_ar = ApiResource::erase::<k8s_openapi::api::core::v1::ServiceAccount>(&());

    let mut layer1 = ApplyBatch::new(client.clone(), namespace, params);

    // Create a ServiceAccount for each role (entry + worker templates)
    for role in &compiled.model_serving.spec.template.roles {
        if let Some(sa_name) = role.entry_template["spec"]["serviceAccountName"].as_str() {
            let sa = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": sa_name,
                    "namespace": namespace
                },
                "automountServiceAccountToken": false
            });
            layer1.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
        }
        if let Some(ref wt) = role.worker_template {
            if let Some(sa_name) = wt["spec"]["serviceAccountName"].as_str() {
                let sa = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "name": sa_name,
                        "namespace": namespace
                    },
                    "automountServiceAccountToken": false
                });
                layer1.push("ServiceAccount", sa_name, &sa, &sa_ar)?;
            }
        }
    }

    for cm in &compiled.config.env_config_maps {
        layer1.push("ConfigMap", &cm.metadata.name, cm, &cm_ar)?;
    }
    for cm in &compiled.config.files_config_maps {
        layer1.push("ConfigMap", &cm.metadata.name, cm, &cm_ar)?;
    }
    for secret in &compiled.config.env_secrets {
        layer1.push("Secret", &secret.metadata.name, secret, &secret_ar)?;
    }
    for secret in &compiled.config.files_secrets {
        layer1.push("Secret", &secret.metadata.name, secret, &secret_ar)?;
    }
    let es_ar = registry.resolve(CrdKind::ExternalSecret).await;
    layer1.push_crd(
        "ExternalSecret",
        es_ar.as_ref(),
        &compiled.config.external_secrets,
        |es| &es.metadata.name,
    )?;
    for pvc in &compiled.config.pvcs {
        layer1.push("PersistentVolumeClaim", &pvc.metadata.name, pvc, &pvc_ar)?;
    }
    let mm_ar = registry.resolve(CrdKind::MeshMember).await;
    layer1.push_crd(
        "LatticeMeshMember",
        mm_ar.as_ref(),
        &compiled.mesh_members,
        |mm| mm.metadata.name.as_deref().unwrap_or("unknown"),
    )?;
    let tp_ar = registry.resolve(CrdKind::TracingPolicyNamespaced).await;
    layer1.push_crd(
        "TracingPolicyNamespaced",
        tp_ar.as_ref(),
        &compiled.tracing_policies,
        |tp| &tp.metadata.name,
    )?;

    layer1.run("layer-1-infrastructure").await?;

    // Layer 2: ModelServing (after mesh/security is ready)
    let mut layer2 = ApplyBatch::new(client.clone(), namespace, params);
    layer2.push(
        "ModelServing",
        &compiled.model_serving.metadata.name,
        &compiled.model_serving,
        ms_api,
    )?;
    layer2.run("layer-2-model-serving").await?;

    // Layer 3: Routing — ModelServer + ModelRoutes (after ModelServing pods are labeled)
    if let Some(ref routing) = compiled.routing {
        let mut layer3 = ApplyBatch::new(client.clone(), namespace, params);

        if let Some(ref ms_server_ar) = registry.resolve(CrdKind::KthenaModelServer).await {
            layer3.push(
                "ModelServer",
                &routing.model_server.metadata.name,
                &routing.model_server,
                ms_server_ar,
            )?;
        }

        if let Some(ref mr_ar) = registry.resolve(CrdKind::KthenaModelRoute).await {
            for route in &routing.model_routes {
                layer3.push("ModelRoute", &route.metadata.name, route, mr_ar)?;
            }
        }

        layer3.run("layer-3-routing").await?;
    }

    info!(
        namespace = %namespace,
        model_serving = %compiled.model_serving.metadata.name,
        mesh_members = compiled.mesh_members.len(),
        tracing_policies = compiled.tracing_policies.len(),
        has_routing = compiled.routing.is_some(),
        has_download = compiled.download.is_some(),
        "applied compiled model resources"
    );

    Ok(())
}

enum ModelServingState {
    Available,
    Failed,
    Progressing,
}

async fn check_model_serving_status(
    client: &Client,
    name: &str,
    namespace: &str,
    ms_api: &ApiResource,
) -> Option<ModelServingState> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, ms_api);

    match api.get(name).await {
        Ok(obj) => {
            let conditions = obj
                .data
                .get("status")
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array());

            if let Some(conditions) = conditions {
                for cond in conditions {
                    let type_ = cond.get("type").and_then(|t| t.as_str());
                    let status = cond.get("status").and_then(|s| s.as_str());
                    match (type_, status) {
                        (Some("Available"), Some("True")) => {
                            return Some(ModelServingState::Available);
                        }
                        (Some("Failed"), Some("True")) => {
                            return Some(ModelServingState::Failed);
                        }
                        _ => {}
                    }
                }
            }

            Some(ModelServingState::Progressing)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(model = %name, "ModelServing not found");
            None
        }
        Err(e) => {
            warn!(model = %name, error = %e, "failed to check ModelServing status");
            None
        }
    }
}

/// Apply model download resources (PVC + Job) as Layer 0
async fn apply_download_resources(
    client: &Client,
    namespace: &str,
    download: &CompiledDownload,
    params: &PatchParams,
) -> Result<(), ModelError> {
    let pvc_ar = ApiResource::erase::<k8s_openapi::api::core::v1::PersistentVolumeClaim>(&());
    let job_ar = ApiResource::erase::<k8s_openapi::api::batch::v1::Job>(&());

    let mut layer0 = ApplyBatch::new(client.clone(), namespace, params);
    layer0.push(
        "PersistentVolumeClaim",
        &download.pvc_name,
        &download.pvc,
        &pvc_ar,
    )?;

    let job_name = download.job["metadata"]["name"]
        .as_str()
        .unwrap_or("unknown");
    layer0.push("Job", job_name, &download.job, &job_ar)?;

    layer0.run("layer-0-model-download").await?;

    info!(
        pvc = %download.pvc_name,
        job = %job_name,
        mount_path = %download.mount_path,
        "applied model download resources (Layer 0)"
    );

    Ok(())
}

enum DownloadState {
    Succeeded,
    Failed,
    Running,
}

/// Check the status of a model download Job
async fn check_download_job_status(
    client: &Client,
    name: &str,
    namespace: &str,
) -> Option<DownloadState> {
    let jobs: Api<k8s_openapi::api::batch::v1::Job> = Api::namespaced(client.clone(), namespace);

    match jobs.get(name).await {
        Ok(job) => {
            let status = job.status.as_ref()?;
            if status.succeeded.unwrap_or(0) >= 1 {
                Some(DownloadState::Succeeded)
            } else if status.failed.unwrap_or(0) >= 3 {
                Some(DownloadState::Failed)
            } else {
                Some(DownloadState::Running)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(job = %name, "download Job not found");
            None
        }
        Err(e) => {
            warn!(job = %name, error = %e, "failed to check download Job status");
            None
        }
    }
}

/// Remove the model-download scheduling gate from all ModelServing pods.
///
/// Lists pods by the `modelserving.volcano.sh/name` label and patches each
/// one that has the `lattice.dev/model-download` gate to remove it, allowing
/// the kube-scheduler to schedule them.
async fn remove_scheduling_gates(
    client: &Client,
    model_name: &str,
    namespace: &str,
) -> Result<(), ModelError> {
    use kube::api::ListParams;

    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default()
        .labels(&format!("modelserving.volcano.sh/name={}", model_name));

    let pod_list = pods.list(&lp).await?;
    let mut removed = 0u32;

    for pod in &pod_list {
        let pod_name = pod.metadata.name.as_deref().unwrap_or_default();
        let has_gate = pod
            .spec
            .as_ref()
            .and_then(|s| s.scheduling_gates.as_ref())
            .map_or(false, |gates| {
                gates
                    .iter()
                    .any(|g| g.name == SCHEDULING_GATE_MODEL_DOWNLOAD)
            });

        if has_gate {
            // Remove the scheduling gate via JSON merge patch
            let new_gates: Vec<&k8s_openapi::api::core::v1::PodSchedulingGate> = pod
                .spec
                .as_ref()
                .and_then(|s| s.scheduling_gates.as_ref())
                .map(|gates| {
                    gates
                        .iter()
                        .filter(|g| g.name != SCHEDULING_GATE_MODEL_DOWNLOAD)
                        .collect()
                })
                .unwrap_or_default();

            let patch = if new_gates.is_empty() {
                serde_json::json!({ "spec": { "schedulingGates": null } })
            } else {
                serde_json::json!({ "spec": { "schedulingGates": new_gates } })
            };

            match pods
                .patch(
                    pod_name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await
            {
                Ok(_) => {
                    removed += 1;
                    info!(pod = %pod_name, "removed model-download scheduling gate");
                }
                Err(e) => {
                    warn!(pod = %pod_name, error = %e, "failed to remove scheduling gate");
                }
            }
        }
    }

    if removed > 0 {
        info!(model = %model_name, count = removed, "removed scheduling gates from pods");
    }

    Ok(())
}

async fn update_status(
    client: &Client,
    name: &str,
    namespace: &str,
    phase: ModelServingPhase,
    message: Option<&str>,
    observed_generation: Option<i64>,
) -> Result<(), ModelError> {
    let api: Api<LatticeModel> = Api::namespaced(client.clone(), namespace);
    let status = LatticeModelStatus {
        phase,
        message: message.map(|m| m.to_string()),
        observed_generation,
        conditions: None,
    };
    let status_patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("lattice-model-controller"),
        &Patch::Merge(&status_patch),
    )
    .await?;
    Ok(())
}
