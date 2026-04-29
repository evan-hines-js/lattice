//! VictoriaMetricsInstall reconciler — Phase 1: install-only.
//!
//! `spec.ha` selects between HA (VMCluster) and single-node (VMSingle) chart
//! renders embedded at build time. The readiness gate scans the `monitoring`
//! namespace — vmoperator, vmagent, and the VM workloads must all be
//! Available.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;

use lattice_common::install::{run_simple_install_reconcile, ReadinessCheck, SimpleInstallConfig};
use lattice_common::{ControllerContext, ReconcileError, MONITORING_NAMESPACE};
use lattice_crd::crd::VictoriaMetricsInstall;

use super::{manifests, policies};

const FIELD_MANAGER: &str = "lattice-victoria-metrics-install-controller";
const READY_TIMEOUT: Duration = Duration::from_secs(600);

pub async fn reconcile(
    install: Arc<VictoriaMetricsInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let ha = install.spec.ha;
    let mut manifests: Vec<String> = manifests::generate_victoria_metrics(ha).to_vec();
    for lmm in manifests::generate_monitoring_mesh_members(ha) {
        manifests.push(
            serde_json::to_string_pretty(&lmm)
                .map_err(|e| ReconcileError::Validation(format!("serialize mesh member: {e}")))?,
        );
    }
    manifests.push(
        serde_json::to_string_pretty(&policies::generate_vmagent_cedar_policy())
            .map_err(|e| ReconcileError::Validation(format!("serialize Cedar policy: {e}")))?,
    );

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "VictoriaMetricsInstall",
        manifests,
        readiness: ReadinessCheck::Deployments {
            namespace: MONITORING_NAMESPACE,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
        // VM operator owns vmrules / vmservicescrapes / vm{single,agent,…}
        // admission webhooks. Apply must wait for the operator pod, or
        // every CR push fails with `no endpoints available for service`.
        webhook_service: Some((MONITORING_NAMESPACE, "vm-victoria-metrics-operator")),
    })
    .await
}
