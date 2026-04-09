//! LatticePackage reconciliation controller

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    ConditionStatus, LatticePackage, LatticePackageStatus, PackagePhase,
};
use lattice_common::kube_utils::ApplyOptions;
use lattice_common::ReconcileError;

use crate::error::PackageError;
use crate::secrets;

const FIELD_MANAGER: &str = "lattice-package-controller";
const REQUEUE_READY: Duration = Duration::from_secs(60);
const REQUEUE_PENDING: Duration = Duration::from_secs(5);

/// Context for the package controller.
pub struct PackageContext {
    pub client: Client,
    pub cedar: Arc<PolicyEngine>,
    /// Directory for caching pulled helm charts
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
    info!("reconciling package");

    // Step 1: Validate
    if let Err(e) = package.spec.validate() {
        update_status(
            &ctx.client,
            &name,
            &namespace,
            PackagePhase::Failed,
            Some(format!("Validation failed: {}", e)),
            None,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    match compile_and_apply(&package, &name, &namespace, &ctx).await {
        Ok(applied) => {
            info!(
                resources = applied.resource_count,
                version = %applied.chart_version,
                "package applied"
            );
            let mut status = LatticePackageStatus::with_phase(PackagePhase::Ready);
            status.chart_version = Some(applied.chart_version);
            status.applied_hash = Some(applied.manifest_hash);
            status.resource_count = Some(applied.resource_count);
            status.observed_generation = package.metadata.generation;
            status.message = Some(format!(
                "{} {} applied ({} resources)",
                package.spec.chart.name,
                package.spec.chart.version,
                applied.resource_count,
            ));
            status.set_condition(
                "Ready",
                ConditionStatus::True,
                "Applied",
                "All manifests applied",
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

struct AppliedPackage {
    chart_version: String,
    manifest_hash: String,
    resource_count: u32,
}

async fn compile_and_apply(
    package: &LatticePackage,
    name: &str,
    namespace: &str,
    ctx: &PackageContext,
) -> Result<AppliedPackage, PackageError> {
    let spec = &package.spec;
    let chart = &spec.chart;

    // Step 2: Expand values (collect mode) — find $secret directives
    let mut values = spec.values.clone().unwrap_or(serde_json::Value::Object(Default::default()));
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
            "LatticePackage does not support inline ${{secret.X.Y}} refs in values strings. \
             Use $secret directives instead. Found: {}",
            refs.join(", ")
        )));
    }

    if !expansion.directives.is_empty() {
        // Step 3: Validate directive refs against resources block
        let referenced =
            secrets::validate_directive_refs(&expansion.directives, &spec.resources)?;

        // Step 4: Cedar authorize — only referenced resources
        secrets::authorize(&ctx.cedar, name, namespace, &referenced, &spec.resources).await?;

        // Step 5: Generate + apply ExternalSecrets
        let resolved = secrets::generate_external_secrets(
            name,
            namespace,
            &expansion.directives,
            &spec.resources,
        )?;

        if !resolved.is_empty() {
            update_status(
                &ctx.client,
                name,
                namespace,
                PackagePhase::Pending,
                Some("Applying ExternalSecrets".to_string()),
                None,
            )
            .await
            .ok();

            let params = PatchParams::apply(FIELD_MANAGER).force();
            for r in &resolved {
                let es_json = serde_json::to_value(&r.external_secret)
                    .map_err(|e| PackageError::Compilation(format!("serialize ExternalSecret: {}", e)))?;
                let api: Api<kube::api::DynamicObject> = Api::namespaced_with(
                    ctx.client.clone(),
                    namespace,
                    &lattice_common::kube_utils::build_api_resource(
                        "external-secrets.io/v1beta1",
                        "ExternalSecret",
                    ),
                );
                let name = r.external_secret.metadata.name.as_str();
                api.patch(name, &params, &Patch::Apply(&es_json))
                    .await
                    .map_err(|e| PackageError::Kube(e))?;
                debug!(external_secret = %name, "applied ExternalSecret");
            }
        }
    }

    // Step 6: Helm template
    update_status(
        &ctx.client,
        name,
        namespace,
        PackagePhase::Rendering,
        Some(format!("Rendering {} v{}", chart.name, chart.version)),
        None,
    )
    .await
    .ok();

    let chart_path = crate::helm::pull_chart(
        &chart.repository,
        &chart.name,
        &chart.version,
        std::path::Path::new(&ctx.chart_cache_dir),
    )?;

    let target_ns = spec
        .target_namespace
        .as_deref()
        .unwrap_or(namespace);

    let values_json = serde_json::to_string_pretty(&values)
        .map_err(|e| PackageError::Compilation(format!("serialize values: {}", e)))?;

    let rendered = crate::helm::template(
        name,
        &chart_path,
        target_ns,
        &values_json,
        spec.skip_crds,
    )?;

    // Compute manifest hash for drift detection
    let hash_bytes = lattice_common::kube_utils::sha256(rendered.as_bytes());
    let manifest_hash: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Check for drift — skip apply if unchanged
    if let Some(ref status) = package.status {
        if status.phase == PackagePhase::Ready {
            if let Some(ref existing_hash) = status.applied_hash {
                if *existing_hash == manifest_hash {
                    debug!("manifest hash unchanged, skipping apply");
                    return Ok(AppliedPackage {
                        chart_version: chart.version.clone(),
                        manifest_hash,
                        resource_count: status.resource_count.unwrap_or(0),
                    });
                }
            }
        }
    }

    // Step 7: Server-side apply rendered manifests
    update_status(
        &ctx.client,
        name,
        namespace,
        PackagePhase::Applying,
        Some("Applying rendered manifests".to_string()),
        None,
    )
    .await
    .ok();

    // Split multi-doc YAML into individual documents for apply_manifests
    let manifests: Vec<String> = rendered
        .split("\n---")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "---")
        .collect();

    if spec.create_namespace {
        lattice_common::kube_utils::ensure_namespace(
            &ctx.client,
            target_ns,
            None,
            FIELD_MANAGER,
        )
        .await?;
    }

    let apply_opts = ApplyOptions {
        skip_missing_crds: spec.skip_crds,
    };
    lattice_common::kube_utils::apply_manifests(&ctx.client, &manifests, &apply_opts)
        .await
        .map_err(PackageError::Common)?;

    let resource_count = manifests.len();
    info!(
        resources = resource_count,
        hash = %manifest_hash,
        "manifests applied"
    );

    // Step 8: Apply MeshMember if mesh config is set
    if let Some(ref mesh) = spec.mesh {
        let member = crate::mesh::build_mesh_member(name, target_ns, mesh);
        let member_json = serde_json::to_value(&member)
            .map_err(|e| PackageError::Compilation(format!("serialize MeshMember: {}", e)))?;
        let mm_api: Api<kube::api::DynamicObject> = Api::namespaced_with(
            ctx.client.clone(),
            target_ns,
            &lattice_common::kube_utils::build_api_resource(
                "lattice.dev/v1alpha1",
                "LatticeMeshMember",
            ),
        );
        let params = PatchParams::apply(FIELD_MANAGER).force();
        mm_api
            .patch(name, &params, &Patch::Apply(&member_json))
            .await
            .map_err(PackageError::Kube)?;
        debug!("applied MeshMember");
    }

    Ok(AppliedPackage {
        chart_version: chart.version.clone(),
        manifest_hash,
        resource_count: resource_count as u32,
    })
}

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
