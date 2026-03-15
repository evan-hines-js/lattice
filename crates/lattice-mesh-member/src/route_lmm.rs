//! Auto-create LatticeMeshMember resources from LatticeClusterRoutes.
//!
//! When remote services are advertised via LatticeClusterRoutes, this
//! reconciler ensures a LatticeMeshMember exists in each target namespace
//! with FQDN egress rules for the advertised hostnames. The existing
//! mesh-member controller then generates ServiceEntries and deploys
//! waypoints through the standard compilation path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeClusterRoutes, LatticeMeshMember};
use lattice_common::Error;

const FIELD_MANAGER: &str = "lattice-route-lmm";
const LMM_PREFIX: &str = "route-";

/// Label marking auto-managed LMMs so we can find and clean them up.
const MANAGED_LABEL: &str = "lattice.dev/route-managed";

/// Context for the route LMM reconciler.
pub struct RouteLmmContext {
    pub client: Client,
}

/// Reconcile a LatticeClusterRoutes resource: ensure one LMM per namespace
/// with FQDN egress rules for each advertised route.
pub async fn reconcile(
    routes: Arc<LatticeClusterRoutes>,
    ctx: Arc<RouteLmmContext>,
) -> Result<Action, Error> {
    let source = routes.name_any();
    debug!(source = %source, "reconciling route LMMs");

    // Group routes by namespace
    let mut by_namespace: HashMap<String, Vec<&lattice_common::crd::ClusterRoute>> = HashMap::new();
    for route in &routes.spec.routes {
        by_namespace
            .entry(route.service_namespace.clone())
            .or_default()
            .push(route);
    }

    let params = PatchParams::apply(FIELD_MANAGER).force();

    // Ensure one LMM per namespace with routes
    for (namespace, ns_routes) in &by_namespace {
        let lmm_name = format!("{}{}", LMM_PREFIX, source);

        let egress: Vec<serde_json::Value> = ns_routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "target": { "fqdn": r.hostname },
                    "ports": [r.port]
                })
            })
            .collect();

        let lmm_manifest = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeMeshMember",
            "metadata": {
                "name": lmm_name,
                "namespace": namespace,
                "labels": {
                    MANAGED_LABEL: source,
                }
            },
            "spec": {
                "target": { "namespace": namespace },
                "ports": [],
                "egress": egress,
                "ambient": true
            }
        });

        let api: Api<LatticeMeshMember> = Api::namespaced(ctx.client.clone(), namespace);
        match api
            .patch(&lmm_name, &params, &Patch::Apply(&lmm_manifest))
            .await
        {
            Ok(_) => {
                debug!(
                    lmm = %lmm_name,
                    namespace = %namespace,
                    routes = ns_routes.len(),
                    "ensured route LMM"
                );
            }
            Err(e) => {
                warn!(
                    lmm = %lmm_name,
                    namespace = %namespace,
                    error = %e,
                    "failed to apply route LMM"
                );
            }
        }
    }

    // Clean up LMMs for namespaces that no longer have routes from this source
    cleanup_stale_lmms(&ctx.client, &source, &by_namespace).await;

    info!(
        source = %source,
        namespaces = by_namespace.len(),
        "route LMM reconciliation complete"
    );

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Delete route-managed LMMs that belong to this source but whose namespace
/// no longer has any routes.
async fn cleanup_stale_lmms(
    client: &Client,
    source: &str,
    active_namespaces: &HashMap<String, Vec<&lattice_common::crd::ClusterRoute>>,
) {
    let label_selector = format!("{}={}", MANAGED_LABEL, source);

    let api: Api<LatticeMeshMember> = Api::all(client.clone());
    let list = match api
        .list(&kube::api::ListParams::default().labels(&label_selector))
        .await
    {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "failed to list route-managed LMMs for cleanup");
            return;
        }
    };

    for lmm in list {
        let ns = match lmm.metadata.namespace.as_deref() {
            Some(ns) => ns,
            None => continue,
        };
        if active_namespaces.contains_key(ns) {
            continue;
        }
        let ns_api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), ns);
        if let Err(e) = ns_api
            .delete(&lmm.name_any(), &Default::default())
            .await
        {
            warn!(
                lmm = %lmm.name_any(),
                namespace = %ns,
                error = %e,
                "failed to delete stale route LMM"
            );
        } else {
            info!(
                lmm = %lmm.name_any(),
                namespace = %ns,
                "deleted stale route LMM"
            );
        }
    }
}

pub fn error_policy(
    _resource: Arc<LatticeClusterRoutes>,
    error: &Error,
    _ctx: Arc<RouteLmmContext>,
) -> Action {
    warn!(error = %error, "route LMM reconciliation failed");
    Action::requeue(Duration::from_secs(30))
}
