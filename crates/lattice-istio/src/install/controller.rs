//! IstioInstall reconciler — Phase 1: install-only.
//!
//! Istio's install diverges from the simple `apply → wait` shape on two
//! axes:
//!
//! - **Pre-flight on `lattice-ca`.** istiod must boot with the
//!   Lattice-issued intermediate CA — a self-signed init would later collide
//!   with it. If the CA Secret is absent we publish `Pending` and requeue.
//! - **Trust-domain derivation.** The trust domain is derived from the root
//!   CA fingerprint so every cluster sharing that CA lands on the same value.
//!   It's stamped onto every status write via `SimpleInstallConfig::trust_domain`.
//!
//! Beyond those, the install is the standard "apply manifests, gate on
//! `istiod` Available" pattern and uses [`run_simple_install_reconcile`].

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{
    run_simple_install_reconcile, write_install_status, ReadinessCheck, SimpleInstallConfig,
    StatusUpdate,
};
use lattice_common::{ControllerContext, ReconcileError, REQUEUE_CRD_NOT_FOUND_SECS};
use lattice_crd::crd::IstioInstall;

use super::{manifests, trust_domain};

const FIELD_MANAGER: &str = "lattice-istio-install-controller";
const ISTIO_NAMESPACE: &str = "istio-system";
const ISTIOD_DEPLOYMENT: &str = "istiod";
const READY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn reconcile(
    install: Arc<IstioInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let ca = trust_domain::resolve_istio_ca(&ctx.client).await;
    let Some(td) = ca.trust_domain.clone() else {
        write_install_status(
            &ctx.client,
            install.as_ref(),
            FIELD_MANAGER,
            StatusUpdate::pending("waiting for lattice-ca Secret"),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(
            REQUEUE_CRD_NOT_FOUND_SECS,
        )));
    };

    let remote = install.spec.remote_networks.as_deref().unwrap_or(&[]);
    let mut manifests = vec![manifests::istio_namespace_yaml(&install.spec.cluster_name)];

    if let Some(ref root_ca) = ca.root_ca {
        let secret = manifests::generate_cacerts_manifest(root_ca, &install.spec.cluster_name)
            .map_err(|e| ReconcileError::Validation(format!("generate cacerts: {e}")))?;
        manifests.push(secret);
    }

    manifests.extend(manifests::render_istio_manifests(
        &install.spec.cluster_name,
        &td,
        remote,
    ));
    manifests.push(manifests::generate_eastwest_gateway(
        &install.spec.cluster_name,
    ));

    for policy in [
        serde_json::to_string_pretty(&manifests::generate_peer_authentication()),
        serde_json::to_string_pretty(&manifests::generate_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_waypoint_default_deny()),
        serde_json::to_string_pretty(&manifests::generate_operator_allow_policy()),
        serde_json::to_string_pretty(&manifests::generate_eastwest_gateway_allow()),
    ] {
        manifests.push(
            policy
                .map_err(|e| ReconcileError::Validation(format!("serialize Istio policy: {e}")))?,
        );
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "IstioInstall",
        manifests,
        readiness: ReadinessCheck::Deployment {
            name: ISTIOD_DEPLOYMENT,
            namespace: ISTIO_NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: Some(td),
    })
    .await
}
