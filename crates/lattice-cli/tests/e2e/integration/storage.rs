//! Rook-Ceph storage integration test.
//!
//! Applies a `RookInstall` sized for the 2-worker Basis workload fixture
//! (one mon, replication 2 on host failure domain so each replica lands
//! on a different worker), waits for the controller to report
//! `phase=Ready` — which under the hood waits for
//! `CephCluster.status.ceph.health == HEALTH_OK` — then runs the only
//! assertion that ultimately matters for block storage: a PVC bound
//! against `rook-ceph-block`, data written in one pod, surviving the
//! pod's deletion, readable by its replacement.
//!
//! ## Running
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_storage_standalone \
//!     -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use kube::api::Api;
use lattice_crd::crd::{
    FailureDomain, InstallSpecBase, RookInstall, RookInstallSpec, UpgradePolicy,
};
use tracing::info;

use super::super::helpers::{
    client_from_kubeconfig, create_with_retry, ensure_namespace, run_kubectl, wait_for_condition,
    wait_for_pod_running,
};

const NAMESPACE: &str = "storage-test";
const PVC_NAME: &str = "storage-test-pvc";
const DEPLOYMENT_NAME: &str = "storage-writer";
const POD_LABEL_SELECTOR: &str = "app=storage-writer";
const ROOK_INSTALL_NAME: &str = "default";
/// Distinctive marker so a cache-hit on a stale file can't silently pass
/// the persistence check.
const MARKER_TEXT: &str = "rook-e2e-persistence-marker-v1";
const MARKER_PATH: &str = "/data/marker";

/// Minutes, not seconds: fresh Rook install has to boot the operator,
/// form mon quorum, LUKS-format each OSD, peer initial PGs, and reach
/// HEALTH_OK. 20 minutes is generous but leaves slack for slow disks.
const INSTALL_READY_TIMEOUT: Duration = Duration::from_secs(1200);

/// Whether the storage e2e should run against the active fixture.
///
/// Rook needs at least one raw block device per worker that ceph-osd can
/// claim — `dataDiskGibs` on a worker pool surfaces them. Only fixtures
/// that wire that up should run this test (basis today; proxmox VMs come
/// up with a single root disk, AWS/OpenStack rely on managed CSI). Gate
/// via env var so the test runner opts in explicitly per fixture rather
/// than entangling the test list with `InfraProvider` enum values.
pub fn storage_tests_enabled() -> bool {
    std::env::var("LATTICE_E2E_STORAGE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// End-to-end storage test: Rook install → PVC → persistence-through-pod-restart.
pub async fn run_storage_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Storage] Applying RookInstall (small-cluster config)...");
    apply_rook_install(kubeconfig).await?;

    info!(
        "[Storage] Waiting up to {:?} for RookInstall Ready (CephCluster HEALTH_OK)...",
        INSTALL_READY_TIMEOUT
    );
    wait_for_install_ready(kubeconfig, INSTALL_READY_TIMEOUT).await?;
    info!("[Storage] RookInstall is Ready");

    ensure_namespace(kubeconfig, NAMESPACE).await?;
    let client = client_from_kubeconfig(kubeconfig).await?;

    info!("[Storage] Creating PVC + writer Deployment...");
    create_pvc(&client).await?;
    create_writer_deployment(&client).await?;
    wait_for_pod_running(kubeconfig, NAMESPACE, POD_LABEL_SELECTOR).await?;

    info!("[Storage] Writing persistence marker...");
    write_marker(kubeconfig).await?;

    // Cordon the writer's node so the replacement pod is forced onto the
    // other worker. Without this the scheduler usually keeps the pod on
    // its original host (the RBD volume is already attached there), so a
    // successful read only proves "RBD detach/reattach works" — not that
    // the replica on the other host is consistent. By forcing CSI to
    // attach the RBD on a different host we exercise the cross-host read
    // path that replication=2/failure_domain=host is supposed to provide.
    let original_node = pod_node(kubeconfig).await?;
    info!("[Storage] Cordoning writer node {original_node} to force reschedule onto replica host...");
    cordon_node(kubeconfig, &original_node).await?;

    let persistence_result = run_persistence_check(kubeconfig, &original_node).await;

    // Always uncordon, even on failure — leaving a node cordoned would
    // poison whatever runs next on this fixture.
    if let Err(e) = uncordon_node(kubeconfig, &original_node).await {
        info!("[Storage] uncordon of {original_node} failed: {e}");
    }
    persistence_result?;

    // Leave the namespace behind if the whole test passed — the
    // unified_e2e teardown drops the cluster, and keeping it on failure
    // would require a DiagnosticContext wrapper; neither helps here.
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "namespace",
        NAMESPACE,
        "--ignore-not-found",
        "--wait=false",
    ])
    .await
    .ok();

    info!("[Storage] All storage tests passed");
    Ok(())
}

/// Apply the RookInstall sized for a 2-worker cluster. Each knob here is
/// a deliberate deviation from the production default, justified below.
async fn apply_rook_install(kubeconfig: &str) -> Result<(), String> {
    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<RookInstall> = Api::all(client);
    let install = RookInstall::new(
        ROOK_INSTALL_NAME,
        RookInstallSpec {
            base: InstallSpecBase {
                version: lattice_rook::install::manifests::rook_ceph_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: Vec::new(),
            },
            // 2 replicas spread across 2 worker hosts (failure_domain=host,
            // the production default). Enough to exercise the replication
            // path without the 3-node mon quorum footprint.
            replication: 2,
            // mon.count=1 keeps the test footprint small. Not production,
            // but sufficient to verify the install flow end-to-end on a
            // 2-worker fixture.
            mon_count: 1,
            allow_multiple_mons_per_node: false,
            failure_domain: FailureDomain::Host,
            // Exercise the LUKS path — if encryption breaks OSD prepare,
            // CI catches it here, not in production.
            encrypt_osds: true,
            default_storage_class: true,
        },
    );
    create_with_retry(&api, &install, ROOK_INSTALL_NAME).await?;
    Ok(())
}

async fn wait_for_install_ready(kubeconfig: &str, timeout: Duration) -> Result<(), String> {
    wait_for_condition(
        "RookInstall phase=Ready",
        timeout,
        Duration::from_secs(15),
        || async {
            let out = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "rookinstall",
                ROOK_INSTALL_NAME,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await;
            match out {
                Ok(phase) => {
                    let phase = phase.trim();
                    info!("[Storage] RookInstall phase: {phase}");
                    if phase == "Failed" {
                        return Err(format!("RookInstall entered Failed phase"));
                    }
                    Ok(phase == "Ready")
                }
                Err(e) => Err(e),
            }
        },
    )
    .await
}

async fn create_pvc(client: &kube::Client) -> Result<(), String> {
    let pvc: PersistentVolumeClaim = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": PVC_NAME, "namespace": NAMESPACE },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "rook-ceph-block",
            "resources": { "requests": { "storage": "1Gi" } }
        }
    }))
    .map_err(|e| format!("build PVC: {e}"))?;

    let api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), NAMESPACE);
    create_with_retry(&api, &pvc, PVC_NAME).await?;
    Ok(())
}

async fn create_writer_deployment(client: &kube::Client) -> Result<(), String> {
    let dep: Deployment = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": DEPLOYMENT_NAME,
            "namespace": NAMESPACE,
            "labels": { "app": DEPLOYMENT_NAME }
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": DEPLOYMENT_NAME } },
            "template": {
                "metadata": { "labels": { "app": DEPLOYMENT_NAME } },
                "spec": {
                    "containers": [{
                        "name": "writer",
                        "image": "busybox:1.36",
                        "command": ["sh", "-c", "sleep infinity"],
                        "volumeMounts": [{ "name": "data", "mountPath": "/data" }]
                    }],
                    "volumes": [{
                        "name": "data",
                        "persistentVolumeClaim": { "claimName": PVC_NAME }
                    }]
                }
            }
        }
    }))
    .map_err(|e| format!("build Deployment: {e}"))?;

    let api: Api<Deployment> = Api::namespaced(client.clone(), NAMESPACE);
    create_with_retry(&api, &dep, DEPLOYMENT_NAME).await?;
    Ok(())
}

async fn first_pod_name(kubeconfig: &str) -> Result<String, String> {
    let out = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        NAMESPACE,
        "-l",
        POD_LABEL_SELECTOR,
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;
    let name = out.trim();
    if name.is_empty() {
        return Err("no pod matched writer label selector".to_string());
    }
    Ok(name.to_string())
}

async fn write_marker(kubeconfig: &str) -> Result<(), String> {
    let pod = first_pod_name(kubeconfig).await?;
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "exec",
        "-n",
        NAMESPACE,
        &pod,
        "--",
        "sh",
        "-c",
        &format!("echo '{MARKER_TEXT}' > {MARKER_PATH}"),
    ])
    .await?;
    Ok(())
}

async fn delete_writer_pod(kubeconfig: &str) -> Result<(), String> {
    let pod = first_pod_name(kubeconfig).await?;
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "pod",
        "-n",
        NAMESPACE,
        &pod,
        "--wait=true",
    ])
    .await?;
    Ok(())
}

async fn pod_node(kubeconfig: &str) -> Result<String, String> {
    let out = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        NAMESPACE,
        "-l",
        POD_LABEL_SELECTOR,
        "-o",
        "jsonpath={.items[0].spec.nodeName}",
    ])
    .await?;
    let name = out.trim();
    if name.is_empty() {
        return Err("writer pod has no spec.nodeName yet".to_string());
    }
    Ok(name.to_string())
}

async fn cordon_node(kubeconfig: &str, node: &str) -> Result<(), String> {
    run_kubectl(&["--kubeconfig", kubeconfig, "cordon", node])
        .await
        .map(|_| ())
}

async fn uncordon_node(kubeconfig: &str, node: &str) -> Result<(), String> {
    run_kubectl(&["--kubeconfig", kubeconfig, "uncordon", node])
        .await
        .map(|_| ())
}

async fn run_persistence_check(kubeconfig: &str, original_node: &str) -> Result<(), String> {
    info!("[Storage] Deleting writer pod, waiting for replacement on a different host...");
    delete_writer_pod(kubeconfig).await?;
    wait_for_pod_running(kubeconfig, NAMESPACE, POD_LABEL_SELECTOR).await?;

    let new_node = pod_node(kubeconfig).await?;
    if new_node == original_node {
        return Err(format!(
            "replacement pod landed on the same node ({new_node}); cordon failed or fixture has only one schedulable worker — replication path was not exercised"
        ));
    }
    info!("[Storage] Replacement pod scheduled on {new_node} (was {original_node})");

    info!("[Storage] Verifying marker survived pod restart on different host...");
    verify_marker(kubeconfig).await?;
    Ok(())
}

async fn verify_marker(kubeconfig: &str) -> Result<(), String> {
    let pod = first_pod_name(kubeconfig).await?;
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "exec",
        "-n",
        NAMESPACE,
        &pod,
        "--",
        "cat",
        MARKER_PATH,
    ])
    .await?;
    let got = output.trim();
    if got != MARKER_TEXT {
        return Err(format!(
            "persistence check failed: expected {MARKER_TEXT:?}, got {got:?}"
        ));
    }
    Ok(())
}

/// Standalone storage test — assumes workload cluster exists and the
/// RookInstall CRD is registered.
#[tokio::test]
#[ignore]
async fn test_storage_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_storage_tests(&resolved.kubeconfig).await.unwrap();
}
