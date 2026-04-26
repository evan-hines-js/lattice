//! RookInstall reconciler — Phase 1: install-only.
//!
//! Two ways this diverges from the plain `apply → wait` shape:
//!
//! - **Pre-flight on node count.** `spec.required_storage_nodes()` folds in
//!   the mon quorum and the replication-vs-failure-domain requirement; if
//!   the cluster doesn't have enough schedulable worker nodes to satisfy
//!   both, we publish `Pending` and requeue rather than watching Rook
//!   spin on an unsatisfiable placement.
//! - **Readiness gate on CephCluster HEALTH_OK.** Waiting on the Rook
//!   operator Deployment alone would flip `Ready` before ceph had actually
//!   formed a cluster; instead the gate is `CephCluster.status.phase ==
//!   Ready` AND `status.ceph.health == HEALTH_OK`. That matches what a
//!   human operator would check with `kubectl -n rook-ceph get cephcluster`.
//!   The timeout is sized for a fresh install: mon quorum formation +
//!   per-OSD LUKS format + initial PG peering.
//!
//! Everything else is stock: apply the operator chart + `CephCluster` +
//! `CephBlockPool` + `StorageClass`, let the shared helper drive status.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use tracing::info;

use lattice_common::install::{
    run_simple_install_reconcile, write_install_status, ReadinessCheck, SimpleInstallConfig,
    StatusUpdate,
};
use lattice_common::kube_utils::GvkPlural;
use lattice_common::{ControllerContext, ReconcileError, REQUEUE_CRD_NOT_FOUND_SECS};
use lattice_core::system_namespaces::ROOK_CEPH_NAMESPACE;
use lattice_crd::crd::RookInstall;

use super::manifests;
use super::manifests::{BLOCK_POOL_NAME, DEFAULT_SC_ANNOTATION};

const FIELD_MANAGER: &str = "lattice-rook-install-controller";

/// 15 minutes covers: operator boot (~30s), mon quorum formation (~90s),
/// per-OSD LUKS format + prepare (~2-3 min, parallelisable), and initial
/// PG peering to HEALTH_OK (~1-2 min). Beyond this we'd rather surface a
/// clear timeout than wait forever on a stuck install.
const READY_TIMEOUT: Duration = Duration::from_secs(900);

/// Well-known control-plane taint. Nodes carrying this are excluded from
/// the storage-capable count — Rook won't place OSDs there under the
/// default tolerations, and even if it did we wouldn't want ceph sharing
/// the CP failure domain.
const CONTROL_PLANE_TAINT: &str = "node-role.kubernetes.io/control-plane";

pub async fn reconcile(
    install: Arc<RookInstall>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let required = install.spec.required_storage_nodes();
    let storage_nodes = count_storage_nodes(&ctx.client).await?;
    if storage_nodes < required {
        let message = format!(
            "need {required} storage nodes for this configuration (mons={}, replication={}, failureDomain={}), have {storage_nodes}",
            install.spec.mon_count,
            install.spec.replication,
            install.spec.failure_domain.as_ceph_str(),
        );
        write_install_status(
            &ctx.client,
            install.as_ref(),
            FIELD_MANAGER,
            StatusUpdate::pending(message),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(
            REQUEUE_CRD_NOT_FOUND_SECS,
        )));
    }

    // Kubernetes enforces at most one default StorageClass; if a prior
    // bootstrap addon (e.g. local-path-provisioner's `standard`) already
    // claims the default, demote it before applying ours so the cluster
    // ends up with exactly one default. Idempotent — patches only the
    // SCs whose annotation actually says "true".
    if install.spec.default_storage_class {
        demote_other_default_storage_classes(&ctx.client).await?;
    }

    let mut all_manifests: Vec<String> = Vec::new();
    all_manifests.push(manifests::rook_ceph_namespace_yaml());
    all_manifests.extend(manifests::operator_manifests().iter().cloned());

    for doc in [
        manifests::generate_ceph_cluster(&install.spec),
        manifests::generate_block_pool(&install.spec),
        manifests::generate_storage_class(&install.spec),
    ] {
        all_manifests
            .push(serde_json::to_string_pretty(&doc).map_err(|e| {
                ReconcileError::Validation(format!("serialize Rook manifest: {e}"))
            })?);
    }

    run_simple_install_reconcile(SimpleInstallConfig {
        install,
        ctx,
        field_manager: FIELD_MANAGER,
        log_kind: "RookInstall",
        manifests: all_manifests,
        readiness: ReadinessCheck::ResourceStatus {
            gvk: GvkPlural {
                group: "ceph.rook.io",
                version: "v1",
                kind: "CephCluster",
                plural: "cephclusters",
            },
            name: manifests::CEPH_CLUSTER_NAME,
            namespace: Some(ROOK_CEPH_NAMESPACE),
            description: "phase=Ready AND ceph.health=HEALTH_OK",
            ready_when: ceph_cluster_ready,
            timeout: READY_TIMEOUT,
        },
        trust_domain: None,
    })
    .await
}

/// Predicate matching a freshly-converged CephCluster: Rook has finished
/// creating cluster resources (`status.phase == Ready`) and ceph itself
/// is fully healthy (`status.ceph.health == HEALTH_OK`).
///
/// Accepting `HEALTH_WARN` here would let Ready trip during normal
/// rebalancing — correct for steady-state but not for the install gate,
/// where we want the stricter "everything green" signal before calling it
/// done.
fn ceph_cluster_ready(obj: &serde_json::Value) -> bool {
    let phase = obj
        .pointer("/status/phase")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let health = obj
        .pointer("/status/ceph/health")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    phase == "Ready" && health == "HEALTH_OK"
}

/// Schedulable, non-control-plane nodes. An approximation of "how many
/// hosts could run an OSD"; Rook's own discovery daemon does the real
/// per-device check at apply time.
async fn count_storage_nodes(client: &Client) -> Result<u32, ReconcileError> {
    let nodes: Api<Node> = Api::all(client.clone());
    let list = nodes
        .list(&ListParams::default())
        .await
        .map_err(ReconcileError::Kube)?;

    let count = list
        .items
        .iter()
        .filter(|n| !has_control_plane_taint(n) && !n.name_any().is_empty())
        .count();
    Ok(count as u32)
}

fn has_control_plane_taint(node: &Node) -> bool {
    node.spec
        .as_ref()
        .and_then(|s| s.taints.as_ref())
        .map(|taints| taints.iter().any(|t| t.key == CONTROL_PLANE_TAINT))
        .unwrap_or(false)
}

/// Patch every StorageClass other than `rook-ceph-block` whose
/// `is-default-class` annotation is `"true"` to `"false"`. Kubernetes
/// permits only one default; without this, applying the Rook SC on top
/// of an existing default (typically local-path-provisioner's
/// `standard`) leaves the cluster in a "two defaults, ambiguous" state.
async fn demote_other_default_storage_classes(client: &Client) -> Result<(), ReconcileError> {
    let api: Api<StorageClass> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await.map_err(ReconcileError::Kube)?;

    for sc in list.items {
        let name = sc.name_any();
        if name == BLOCK_POOL_NAME {
            continue;
        }
        let is_default = sc
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(DEFAULT_SC_ANNOTATION))
            .map(|v| v == "true")
            .unwrap_or(false);
        if !is_default {
            continue;
        }

        // Strategic-merge patch: setting the annotation to `"false"` (a
        // string, per kube convention) clears the default without
        // touching the rest of the SC. Server-side apply with a
        // separate field manager would conflict with whoever installed
        // it; a plain patch on this single annotation is the surgical
        // option.
        let patch = json!({
            "metadata": {
                "annotations": {
                    DEFAULT_SC_ANNOTATION: "false"
                }
            }
        });
        api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(ReconcileError::Kube)?;
        info!(
            storage_class = %name,
            "demoted prior default StorageClass so rook-ceph-block can take over"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{NodeSpec, Taint};
    use kube::api::ObjectMeta;

    fn node(name: &str, taints: Vec<Taint>) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: Some(NodeSpec {
                taints: if taints.is_empty() {
                    None
                } else {
                    Some(taints)
                },
                ..Default::default()
            }),
            status: None,
        }
    }

    fn cp_taint() -> Taint {
        Taint {
            key: CONTROL_PLANE_TAINT.to_string(),
            value: None,
            effect: "NoSchedule".to_string(),
            time_added: None,
        }
    }

    #[test]
    fn taint_filter_excludes_control_plane() {
        assert!(has_control_plane_taint(&node("cp-0", vec![cp_taint()])));
        assert!(!has_control_plane_taint(&node("worker-0", vec![])));
    }

    #[test]
    fn ceph_ready_requires_phase_and_health() {
        let ok = serde_json::json!({
            "status": { "phase": "Ready", "ceph": { "health": "HEALTH_OK" } }
        });
        assert!(ceph_cluster_ready(&ok));

        let warn = serde_json::json!({
            "status": { "phase": "Ready", "ceph": { "health": "HEALTH_WARN" } }
        });
        assert!(
            !ceph_cluster_ready(&warn),
            "HEALTH_WARN is not accepted at install time"
        );

        let creating = serde_json::json!({
            "status": { "phase": "Progressing", "ceph": { "health": "HEALTH_OK" } }
        });
        assert!(!ceph_cluster_ready(&creating));

        let empty = serde_json::json!({});
        assert!(
            !ceph_cluster_ready(&empty),
            "CR without status yet must not trip Ready"
        );
    }
}
