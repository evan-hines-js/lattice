//! Pivoting phase handler.
//!
//! Orchestrates the pivot from parent to child cluster.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, error, info, warn};

use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::{capi_namespace, Error};

use crate::controller::{
    determine_pivot_action, Context, PivotAction, PivotOperations, PivotOperationsImpl,
};
use crate::phases::{try_transition_to_ready, update_status};

/// Handle a cluster in the Pivoting phase.
///
/// This phase orchestrates the pivot from parent to child cluster:
/// - Self-clusters are already pivoted, transition to Ready
/// - Child clusters with pivot_complete in status transition to Pivoted
/// - Otherwise, use PivotOperations to trigger or wait for pivot
pub async fn handle_pivoting(
    cluster: &LatticeCluster,
    ctx: &Context,
    is_self: bool,
) -> Result<Action, Error> {
    let name = cluster.name_any();
    let capi_namespace = capi_namespace(&name);

    // Self-cluster: pivot already complete (we received this CRD post-pivot)
    if is_self {
        info!("reconciling self cluster, pivot already complete");
        return try_transition_to_ready(cluster, ctx, true).await;
    }

    // Child cluster with pivot already complete in status
    if cluster
        .status
        .as_ref()
        .map(|s| s.pivot_complete)
        .unwrap_or(false)
    {
        info!("pivot already complete (from status), child is self-managing");
        update_status(cluster, ctx, ClusterPhase::Pivoted, None, false).await?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // We're the parent cell, orchestrating pivot for a child cluster
    let pivot_ops = get_pivot_operations(ctx)?;

    match pivot_ops {
        Some(ops) => execute_pivot(&name, &capi_namespace, cluster, ctx, ops.as_ref()).await,
        None => {
            // No pivot operations - non-cell mode
            debug!("no pivot operations configured");
            try_transition_to_ready(cluster, ctx, false).await
        }
    }
}

/// Get pivot operations if parent servers are available and running.
fn get_pivot_operations(ctx: &Context) -> Result<Option<Arc<dyn PivotOperations>>, Error> {
    let (Some(ref parent_servers), Some(ref client)) = (&ctx.parent_servers, &ctx.client) else {
        warn!(
            parent_servers = ctx.parent_servers.is_some(),
            client = ctx.client.is_some(),
            "missing parent_servers or client, skipping pivot"
        );
        return Ok(None);
    };

    if !parent_servers.is_running() {
        warn!("parent_servers not running, skipping pivot");
        return Ok(None);
    }

    Ok(Some(Arc::new(PivotOperationsImpl::new(
        parent_servers.agent_registry(),
        client.clone(),
        ctx.self_cluster_name.clone(),
    ))))
}

/// Execute the pivot based on current state.
async fn execute_pivot(
    name: &str,
    capi_namespace: &str,
    cluster: &LatticeCluster,
    ctx: &Context,
    pivot_ops: &dyn PivotOperations,
) -> Result<Action, Error> {
    // Determine pivot action using pure function
    let action = determine_pivot_action(
        pivot_ops.is_pivot_complete(name),
        pivot_ops.is_agent_ready(name),
    );

    match action {
        PivotAction::Complete => {
            // Pivot complete - child cluster is now self-managing
            info!("pivot complete, child cluster is self-managing");
            update_status(cluster, ctx, ClusterPhase::Pivoted, None, true).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        PivotAction::TriggerPivot => {
            // Agent ready for pivot - set Pivoting phase and trigger
            info!("agent ready, triggering pivot");
            update_status(cluster, ctx, ClusterPhase::Pivoting, None, false).await?;

            match pivot_ops
                .trigger_pivot(name, capi_namespace, capi_namespace)
                .await
            {
                Ok(()) => {
                    info!("pivot completed successfully");
                }
                Err(e) => {
                    error!(cluster = %name, error = %e, "pivot failed, will retry");
                }
            }
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        PivotAction::WaitForAgent => {
            // No agent connected yet, wait
            debug!("waiting for agent to connect and be ready for pivot");
            Ok(Action::requeue(Duration::from_secs(10)))
        }
    }
}
