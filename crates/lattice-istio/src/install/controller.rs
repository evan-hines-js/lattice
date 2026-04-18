//! IstioInstall reconciler — Phase 1: install-only.
//!
//! Phase 1 specifics beyond the common install pattern:
//! - Gated on the `lattice-ca` Secret existing. No CA → Pending, no manifests
//!   applied. Prevents istiod from starting with a self-signed CA that would
//!   later collide with the Lattice-issued intermediate.
//! - Derives the trust domain from the `lattice-ca` root CA fingerprint so
//!   every cluster sharing that CA lands on the same trust domain.
//! - Generates the `cacerts` Secret once on first install. On subsequent
//!   reconciles, `resolve_istio_ca` returns `root_ca: None` so the Secret is
//!   not regenerated — rotating the intermediate CA would break in-flight
//!   mTLS connections.
//! - Gates Ready on the `istiod` Deployment reporting Available.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{info, warn};

use lattice_common::install::patch_install_status;
use lattice_common::kube_utils::wait_for_deployment;
use lattice_common::{
    apply_manifests, status_check, ApplyOptions, ControllerContext, ReconcileError,
    REQUEUE_CRD_NOT_FOUND_SECS, REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};
use lattice_crd::crd::{InstallPhase, InstallStatus, IstioInstall};

use super::{manifests, trust_domain};

const FIELD_MANAGER: &str = "lattice-istio-install-controller";
const ISTIO_NAMESPACE: &str = "istio-system";
const ISTIOD_DEPLOYMENT: &str = "istiod";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<IstioInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = install.name_any();
    let generation = install.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("IstioInstall missing metadata.generation".into())
    })?;

    let ca = trust_domain::resolve_istio_ca(&ctx.client).await;
    let Some(td) = ca.trust_domain.clone() else {
        info!(install = %name, "lattice-ca not available yet; IstioInstall Pending");
        write_status(
            &ctx.client,
            &install,
            InstallPhase::Pending,
            Some("waiting for lattice-ca Secret".to_string()),
            generation,
            None,
            None,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(
            REQUEUE_CRD_NOT_FOUND_SECS,
        )));
    };

    if status_check::is_status_unchanged(
        install.status.as_ref(),
        &InstallPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(
        install = %name,
        version = %install.spec.base.version,
        cluster = %install.spec.cluster_name,
        trust_domain = %td,
        "Reconciling IstioInstall"
    );
    write_status(
        &ctx.client,
        &install,
        InstallPhase::Installing,
        None,
        generation,
        None,
        Some(&td),
    )
    .await?;

    let remote = install.spec.remote_networks.as_deref().unwrap_or(&[]);
    let mut mfs = vec![manifests::istio_namespace_yaml(&install.spec.cluster_name)];

    if let Some(ref root_ca) = ca.root_ca {
        let secret = manifests::generate_cacerts_manifest(root_ca, &install.spec.cluster_name)
            .map_err(|e| ReconcileError::Validation(format!("generate cacerts: {e}")))?;
        mfs.push(secret);
    }

    mfs.extend(manifests::render_istio_manifests(
        &install.spec.cluster_name,
        &td,
        remote,
    ));
    mfs.push(manifests::generate_eastwest_gateway(
        &install.spec.cluster_name,
    ));

    for policy in [
        serde_json::to_string_pretty(&manifests::generate_peer_authentication()),
        serde_json::to_string_pretty(&manifests::generate_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_waypoint_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_operator_allow_policy()),
        serde_json::to_string_pretty(&manifests::generate_eastwest_gateway_allow()),
    ] {
        mfs.push(
            policy
                .map_err(|e| ReconcileError::Validation(format!("serialize Istio policy: {e}")))?,
        );
    }

    if let Err(e) = apply_manifests(&ctx.client, &mfs, &ApplyOptions::default()).await {
        warn!(install = %name, error = %e, "IstioInstall apply failed");
        write_status(
            &ctx.client,
            &install,
            InstallPhase::Failed,
            Some(format!("apply failed: {e}")),
            generation,
            None,
            Some(&td),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    match wait_for_deployment(&ctx.client, ISTIOD_DEPLOYMENT, ISTIO_NAMESPACE, READY_TIMEOUT).await
    {
        Ok(()) => {
            info!(install = %name, version = %install.spec.base.version, "IstioInstall Ready");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Ready,
                None,
                generation,
                Some(&install.spec.base.version),
                Some(&td),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(install = %name, error = %e, "istiod not ready in time");
            write_status(
                &ctx.client,
                &install,
                InstallPhase::Failed,
                Some(format!("istiod not ready: {e}")),
                generation,
                None,
                Some(&td),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_status(
    client: &Client,
    install: &IstioInstall,
    phase: InstallPhase,
    message: Option<String>,
    observed_generation: i64,
    observed_version: Option<&str>,
    trust_domain: Option<&str>,
) -> Result<(), ReconcileError> {
    let status = InstallStatus {
        phase,
        observed_generation: Some(observed_generation),
        observed_version: observed_version.map(str::to_string),
        target_version: Some(install.spec.base.version.clone()),
        message,
        trust_domain: trust_domain.map(str::to_string),
        conditions: Vec::new(),
        last_upgrade: None,
    };
    patch_install_status::<IstioInstall>(
        client,
        &install.name_any(),
        install.status.as_ref(),
        status,
        FIELD_MANAGER,
    )
    .await
    .map_err(ReconcileError::Kube)
}
