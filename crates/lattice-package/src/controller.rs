//! LatticePackage reconciliation controller

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{ConditionStatus, LatticePackage, LatticePackageStatus, PackagePhase};
use lattice_common::{CrdKind, CrdRegistry, ReconcileError};

use crate::error::PackageError;
use crate::secrets;

const FIELD_MANAGER: &str = "lattice-package-controller";
const FINALIZER: &str = "lattice.dev/package-cleanup";
const REQUEUE_READY: Duration = Duration::from_secs(60);

/// Context for the package controller.
pub struct PackageContext {
    pub client: Client,
    pub cedar: Arc<PolicyEngine>,
    pub registry: Arc<CrdRegistry>,
    pub chart_cache_dir: String,
}

/// Reconcile a LatticePackage.
#[instrument(
    skip(package, ctx),
    fields(
        package = %package.name_any(),
        namespace = %package.namespace().unwrap_or_default(),
        phase = ?package.status.as_ref().map(|s| &s.phase),
    )
)]
pub async fn reconcile(
    package: Arc<LatticePackage>,
    ctx: Arc<PackageContext>,
) -> Result<Action, ReconcileError> {
    let name = package.name_any();
    let namespace = package.namespace().unwrap_or_default();

    // Handle deletion — uninstall Helm release and clean up ExternalSecrets
    if package.metadata.deletion_timestamp.is_some() {
        return handle_deletion(&package, &name, &namespace, &ctx).await;
    }

    // Ensure finalizer is present
    if !has_finalizer(&package) {
        add_finalizer(&name, &namespace, &ctx.client).await?;
        return Ok(Action::requeue(Duration::from_secs(1)));
    }

    // Skip if already Ready and generation hasn't changed
    if let Some(ref status) = package.status {
        if status.phase == PackagePhase::Ready
            && status.observed_generation == package.metadata.generation
        {
            return Ok(Action::requeue(REQUEUE_READY));
        }
    }

    info!("reconciling package");

    // Validate
    if let Err(e) = package.spec.validate() {
        update_status(
            &ctx.client,
            &name,
            &namespace,
            PackagePhase::Failed,
            Some(format!("Validation failed: {}", e)),
            package.metadata.generation,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    match compile_and_install(&package, &name, &namespace, &ctx).await {
        Ok(version) => {
            info!(version = %version, "package installed/upgraded");
            let mut status = LatticePackageStatus::with_phase(PackagePhase::Ready);
            status.chart_version = Some(version.clone());
            status.observed_generation = package.metadata.generation;
            status.message = Some(format!("{} {} installed", package.spec.chart.name, version,));
            status.set_condition(
                "Ready",
                ConditionStatus::True,
                "Installed",
                "Helm release installed",
            );
            patch_status(&ctx.client, &name, &namespace, &status).await?;
            Ok(Action::requeue(REQUEUE_READY))
        }
        Err(e) => {
            error!(error = %e, "package reconciliation failed");
            update_status(
                &ctx.client,
                &name,
                &namespace,
                PackagePhase::Failed,
                Some(e.to_string()),
                package.metadata.generation,
            )
            .await?;
            let requeue = if e.is_retryable() {
                Duration::from_secs(30)
            } else {
                Duration::from_secs(300)
            };
            Ok(Action::requeue(requeue))
        }
    }
}

async fn compile_and_install(
    package: &LatticePackage,
    name: &str,
    namespace: &str,
    ctx: &PackageContext,
) -> Result<String, PackageError> {
    let spec = &package.spec;
    let chart = &spec.chart;

    // Step 1: Expand values (collect mode) — find $secret directives
    let mut values = spec
        .values
        .clone()
        .unwrap_or(serde_json::Value::Object(Default::default()));
    let template_ctx = lattice_template::TemplateContext::builder()
        .set("metadata.name", name)
        .set("metadata.namespace", namespace)
        .build();
    let opts = lattice_template::ExpandOptions {
        secret_mode: lattice_template::SecretMode::Collect,
        name_prefix: name.to_string(),
    };
    let expansion = lattice_template::expand(&mut values, &template_ctx, &opts)
        .map_err(|e| PackageError::TemplateExpansion(e.to_string()))?;

    // Reject inline ${secret.X.Y} refs — packages only support $secret directives
    if !expansion.inline_refs.is_empty() {
        let refs: Vec<_> = expansion
            .inline_refs
            .iter()
            .map(|r| format!("${{secret.{}.{}}}", r.resource_name, r.key))
            .collect();
        return Err(PackageError::Validation(format!(
            "LatticePackage does not support inline ${{secret.X.Y}} refs. \
             Use $secret directives instead. Found: {}",
            refs.join(", ")
        )));
    }

    if !expansion.directives.is_empty() {
        // Step 2: Validate directive refs against resources block
        let referenced = secrets::validate_directive_refs(&expansion.directives, &spec.resources)?;

        // Step 3: Cedar authorize — only referenced resources
        secrets::authorize(&ctx.cedar, name, namespace, &referenced, &spec.resources).await?;

        // Step 4: Generate + apply ExternalSecrets
        let resolved = secrets::generate_external_secrets(
            name,
            namespace,
            &expansion.directives,
            &spec.resources,
        )?;

        if !resolved.is_empty() {
            let es_ar = ctx
                .registry
                .resolve(CrdKind::ExternalSecret)
                .await
                .map_err(|e| {
                    PackageError::Compilation(format!("resolve ExternalSecret CRD: {}", e))
                })?
                .ok_or_else(|| {
                    PackageError::Compilation("ExternalSecret CRD not installed".to_string())
                })?;
            let params = PatchParams::apply(FIELD_MANAGER).force();
            for r in &resolved {
                let es_json = serde_json::to_value(&r.external_secret).map_err(|e| {
                    PackageError::Compilation(format!("serialize ExternalSecret: {}", e))
                })?;
                let api: Api<kube::api::DynamicObject> =
                    Api::namespaced_with(ctx.client.clone(), namespace, &es_ar);
                let es_name = r.external_secret.metadata.name.as_str();
                api.patch(es_name, &params, &Patch::Apply(&es_json))
                    .await
                    .map_err(PackageError::Kube)?;
                debug!(external_secret = %es_name, "applied ExternalSecret");
            }
        }
    }

    // Step 5: Pull chart
    let chart_path = crate::helm::pull_chart(
        &chart.repository,
        &chart.name,
        &chart.version,
        std::path::Path::new(&ctx.chart_cache_dir),
    )?;

    let target_ns = spec.target_namespace.as_deref().unwrap_or(namespace);

    let values_json = serde_json::to_string_pretty(&values)
        .map_err(|e| PackageError::Compilation(format!("serialize values: {}", e)))?;

    // Step 6: Helm install/upgrade
    crate::helm::install_or_upgrade(
        name,
        &chart_path,
        target_ns,
        &values_json,
        spec.create_namespace,
        spec.skip_crds,
        spec.timeout.as_deref(),
    )?;

    // Step 7: Apply MeshMember if mesh config is set
    if let Some(ref mesh) = spec.mesh {
        let mm_ar = ctx
            .registry
            .resolve(CrdKind::MeshMember)
            .await
            .map_err(|e| PackageError::Compilation(format!("resolve MeshMember CRD: {}", e)))?
            .ok_or_else(|| {
                PackageError::Compilation("LatticeMeshMember CRD not installed".to_string())
            })?;
        let member = crate::mesh::build_mesh_member(name, target_ns, mesh);
        let member_json = serde_json::to_value(&member)
            .map_err(|e| PackageError::Compilation(format!("serialize MeshMember: {}", e)))?;
        let mm_api: Api<kube::api::DynamicObject> =
            Api::namespaced_with(ctx.client.clone(), target_ns, &mm_ar);
        let params = PatchParams::apply(FIELD_MANAGER).force();
        mm_api
            .patch(name, &params, &Patch::Apply(&member_json))
            .await
            .map_err(PackageError::Kube)?;
        debug!("applied MeshMember");
    }

    Ok(chart.version.clone())
}

// =============================================================================
// Deletion handling
// =============================================================================

async fn handle_deletion(
    package: &LatticePackage,
    name: &str,
    namespace: &str,
    ctx: &PackageContext,
) -> Result<Action, ReconcileError> {
    if !has_finalizer(package) {
        return Ok(Action::await_change());
    }

    info!("deleting package — uninstalling Helm release");

    let target_ns = package
        .spec
        .target_namespace
        .as_deref()
        .unwrap_or(namespace);

    // Uninstall Helm release (deletes all chart-managed resources)
    if let Err(e) = crate::helm::uninstall(name, target_ns) {
        error!(error = %e, "helm uninstall failed");
        // Don't block finalizer removal — the release may already be gone
    }

    // Delete ExternalSecrets owned by this package
    if let Ok(Some(es_ar)) = ctx.registry.resolve(CrdKind::ExternalSecret).await {
        delete_owned_resources(&ctx.client, namespace, name, &es_ar).await;
    }

    // Delete MeshMember if it exists
    if let Ok(Some(mm_ar)) = ctx.registry.resolve(CrdKind::MeshMember).await {
        delete_owned_resources(&ctx.client, target_ns, name, &mm_ar).await;
    }

    // Remove finalizer
    remove_finalizer(name, namespace, &ctx.client).await?;
    info!("package cleanup complete");

    Ok(Action::await_change())
}

/// Delete resources labeled with the package owner label.
async fn delete_owned_resources(
    client: &Client,
    namespace: &str,
    owner: &str,
    ar: &kube::discovery::ApiResource,
) {
    let api: Api<kube::api::DynamicObject> = Api::namespaced_with(client.clone(), namespace, ar);

    let label_selector = format!("{}={}", lattice_common::LABEL_SERVICE_OWNER, owner);
    let lp = kube::api::ListParams::default().labels(&label_selector);

    match api.list(&lp).await {
        Ok(list) => {
            for item in &list.items {
                if let Some(item_name) = &item.metadata.name {
                    let _ = api.delete(item_name, &Default::default()).await;
                    debug!(kind = %ar.kind, name = %item_name, "deleted owned resource");
                }
            }
        }
        Err(e) => {
            debug!(kind = %ar.kind, error = %e, "failed to list owned resources for cleanup (may not exist)");
        }
    }
}

// =============================================================================
// Finalizer helpers
// =============================================================================

fn has_finalizer(package: &LatticePackage) -> bool {
    package
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.contains(&FINALIZER.to_string()))
        .unwrap_or(false)
}

async fn add_finalizer(name: &str, namespace: &str, client: &Client) -> Result<(), ReconcileError> {
    let api: Api<LatticePackage> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": [FINALIZER]
        }
    });
    api.patch(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await?;
    debug!("added finalizer");
    Ok(())
}

async fn remove_finalizer(
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<(), ReconcileError> {
    let api: Api<LatticePackage> = Api::namespaced(client.clone(), namespace);
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": null
        }
    });
    api.patch(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await?;
    debug!("removed finalizer");
    Ok(())
}

// =============================================================================
// Status helpers
// =============================================================================

async fn update_status(
    client: &Client,
    name: &str,
    namespace: &str,
    phase: PackagePhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    let mut status = LatticePackageStatus::with_phase(phase);
    status.message = message;
    status.observed_generation = observed_generation;
    patch_status(client, name, namespace, &status).await
}

async fn patch_status(
    client: &Client,
    name: &str,
    namespace: &str,
    status: &LatticePackageStatus,
) -> Result<(), ReconcileError> {
    lattice_common::kube_utils::patch_resource_status::<LatticePackage>(
        client,
        name,
        namespace,
        status,
        FIELD_MANAGER,
    )
    .await?;
    Ok(())
}
