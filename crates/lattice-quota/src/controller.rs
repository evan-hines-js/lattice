//! LatticeQuota reconciliation controller
//!
//! Watches LatticeQuota CRDs, validates specs, and tracks resource usage
//! per principal in status. Requeues periodically to keep usage current.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeJob, LatticeModel, LatticeQuota, LatticeQuotaPhase, LatticeQuotaStatus,
    LatticeService, QuotaPrincipal,
};
use lattice_common::resources::{
    compute_workload_demand, parse_cpu_millis_str, parse_memory_bytes_str, GPU_RESOURCE,
    WorkloadResourceDemand,
};
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
};

const FIELD_MANAGER: &str = "lattice-quota-controller";
const REQUEUE_SECS: u64 = 30;

/// Reconcile a LatticeQuota
///
/// Validates the spec, computes current resource usage for the principal,
/// and updates status with usage and phase (Active vs Exceeded).
pub async fn reconcile(
    quota: Arc<LatticeQuota>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = quota.name_any();
    let client = &ctx.client;
    let generation = quota.metadata.generation.unwrap_or(0);

    // Validate spec
    if let Err(e) = quota.spec.validate() {
        warn!(quota = %name, error = %e, "LatticeQuota spec invalid");
        update_status(
            client,
            &quota,
            LatticeQuotaPhase::Invalid,
            BTreeMap::new(),
            0,
            Some(e.to_string()),
            Some(generation),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    if !quota.spec.enabled {
        debug!(quota = %name, "LatticeQuota disabled, skipping");
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS * 10)));
    }

    let principal = match QuotaPrincipal::parse(&quota.spec.principal) {
        Ok(p) => p,
        Err(e) => {
            update_status(
                client,
                &quota,
                LatticeQuotaPhase::Invalid,
                BTreeMap::new(),
                0,
                Some(e.to_string()),
                Some(generation),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    };

    // Compute usage
    let (usage, workload_count) = compute_usage(client, &principal).await;

    // Determine phase: check usage against soft limits
    let exceeded = is_exceeded(&usage, &quota.spec.soft);
    let phase = if exceeded {
        LatticeQuotaPhase::Exceeded
    } else {
        LatticeQuotaPhase::Active
    };

    let used_map = demand_to_map(&usage);

    update_status(
        client,
        &quota,
        phase,
        used_map,
        workload_count,
        None,
        Some(generation),
    )
    .await?;

    info!(
        quota = %name,
        principal = %quota.spec.principal,
        phase = %phase,
        workloads = workload_count,
        "Reconciled LatticeQuota"
    );

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS)))
}

/// Compute total resource usage for a principal across all workload types.
async fn compute_usage(
    client: &kube::Client,
    principal: &QuotaPrincipal,
) -> (WorkloadResourceDemand, u32) {
    let mut total = WorkloadResourceDemand::default();
    let mut count: u32 = 0;

    // Sum across LatticeServices
    if let Ok(services) = Api::<LatticeService>::all(client.clone())
        .list(&ListParams::default())
        .await
    {
        for svc in &services.items {
            let ns = svc.namespace().unwrap_or_default();
            let name = svc.name_any();
            let ns_labels = get_namespace_labels(client, &ns).await;
            let annotations = svc.metadata.annotations.as_ref().cloned().unwrap_or_default();

            if !principal.matches_workload(&ns, &name, &ns_labels, &annotations) {
                continue;
            }

            let replicas = svc.spec.replicas;
            if let Ok(demand) = compute_workload_demand(&svc.spec.workload, replicas) {
                add_demand(&mut total, &demand);
                count += 1;
            }
        }
    }

    // Sum across LatticeJobs
    if let Ok(jobs) = Api::<LatticeJob>::all(client.clone())
        .list(&ListParams::default())
        .await
    {
        for job in &jobs.items {
            let ns = job.namespace().unwrap_or_default();
            let name = job.name_any();
            let ns_labels = get_namespace_labels(client, &ns).await;
            let annotations = job.metadata.annotations.as_ref().cloned().unwrap_or_default();

            if !principal.matches_workload(&ns, &name, &ns_labels, &annotations) {
                continue;
            }

            // Jobs sum across all tasks
            for task in job.spec.tasks.values() {
                let replicas = task.replicas.unwrap_or(1);
                if let Ok(demand) = compute_workload_demand(&task.workload, replicas) {
                    add_demand(&mut total, &demand);
                }
            }
            count += 1;
        }
    }

    // Sum across LatticeModels
    if let Ok(models) = Api::<LatticeModel>::all(client.clone())
        .list(&ListParams::default())
        .await
    {
        for model in &models.items {
            let ns = model.namespace().unwrap_or_default();
            let name = model.name_any();
            let ns_labels = get_namespace_labels(client, &ns).await;
            let annotations = model
                .metadata
                .annotations
                .as_ref()
                .cloned()
                .unwrap_or_default();

            if !principal.matches_workload(&ns, &name, &ns_labels, &annotations) {
                continue;
            }

            // Models sum entry + worker workloads across all roles
            for role in model.spec.roles.values() {
                let entry_replicas = role.replicas.unwrap_or(1);
                if let Ok(demand) =
                    compute_workload_demand(&role.entry_workload, entry_replicas)
                {
                    add_demand(&mut total, &demand);
                }
                if let (Some(ref worker_workload), Some(worker_replicas)) =
                    (&role.worker_workload, role.worker_replicas)
                {
                    if let Ok(demand) =
                        compute_workload_demand(worker_workload, worker_replicas)
                    {
                        add_demand(&mut total, &demand);
                    }
                }
            }
            count += 1;
        }
    }

    (total, count)
}

fn add_demand(total: &mut WorkloadResourceDemand, demand: &WorkloadResourceDemand) {
    total.cpu_millis += demand.cpu_millis;
    total.memory_bytes += demand.memory_bytes;
    total.gpu_count += demand.gpu_count;
}

/// Check if usage exceeds any soft limit.
fn is_exceeded(usage: &WorkloadResourceDemand, soft: &BTreeMap<String, String>) -> bool {
    if let Some(cpu_limit) = soft.get("cpu") {
        if let Ok(limit_millis) = parse_cpu_millis_str(cpu_limit) {
            if usage.cpu_millis > limit_millis {
                return true;
            }
        }
    }
    if let Some(mem_limit) = soft.get("memory") {
        if let Ok(limit_bytes) = parse_memory_bytes_str(mem_limit) {
            if usage.memory_bytes > limit_bytes {
                return true;
            }
        }
    }
    if let Some(gpu_limit) = soft.get(GPU_RESOURCE) {
        if let Ok(limit) = gpu_limit.parse::<u32>() {
            if usage.gpu_count > limit {
                return true;
            }
        }
    }
    false
}

/// Convert a WorkloadResourceDemand into a status map with human-readable values.
fn demand_to_map(demand: &WorkloadResourceDemand) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if demand.cpu_millis > 0 {
        // Express as cores (e.g., "24" or "1500m")
        if demand.cpu_millis % 1000 == 0 {
            map.insert("cpu".to_string(), format!("{}", demand.cpu_millis / 1000));
        } else {
            map.insert("cpu".to_string(), format!("{}m", demand.cpu_millis));
        }
    }
    if demand.memory_bytes > 0 {
        // Express in the largest clean unit
        if demand.memory_bytes % (1024 * 1024 * 1024) == 0 {
            map.insert(
                "memory".to_string(),
                format!("{}Gi", demand.memory_bytes / (1024 * 1024 * 1024)),
            );
        } else if demand.memory_bytes % (1024 * 1024) == 0 {
            map.insert(
                "memory".to_string(),
                format!("{}Mi", demand.memory_bytes / (1024 * 1024)),
            );
        } else {
            map.insert("memory".to_string(), demand.memory_bytes.to_string());
        }
    }
    if demand.gpu_count > 0 {
        map.insert(GPU_RESOURCE.to_string(), demand.gpu_count.to_string());
    }
    map
}

/// Get namespace labels (cached per reconcile via simple fetch).
async fn get_namespace_labels(
    client: &kube::Client,
    namespace: &str,
) -> BTreeMap<String, String> {
    let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    match ns_api.get(namespace).await {
        Ok(ns) => ns.metadata.labels.unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
}

/// Update LatticeQuota status.
async fn update_status(
    client: &kube::Client,
    quota: &LatticeQuota,
    phase: LatticeQuotaPhase,
    used: BTreeMap<String, String>,
    workload_count: u32,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    let name = quota.name_any();
    let namespace = quota
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeQuotaStatus {
        phase,
        used,
        workload_count,
        message,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<LatticeQuota>(
        client,
        &name,
        &namespace,
        &status,
        FIELD_MANAGER,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_exceeded_within_limits() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 4000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu_count: 2,
        };
        let soft = BTreeMap::from([
            ("cpu".to_string(), "8".to_string()),
            ("memory".to_string(), "16Gi".to_string()),
            ("nvidia.com/gpu".to_string(), "4".to_string()),
        ]);
        assert!(!is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_cpu_over() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 10000,
            memory_bytes: 0,
            gpu_count: 0,
        };
        let soft = BTreeMap::from([("cpu".to_string(), "8".to_string())]);
        assert!(is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_gpu_over() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 0,
            memory_bytes: 0,
            gpu_count: 5,
        };
        let soft = BTreeMap::from([("nvidia.com/gpu".to_string(), "4".to_string())]);
        assert!(is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_empty_soft() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 100000,
            memory_bytes: 100000000000,
            gpu_count: 100,
        };
        assert!(!is_exceeded(&usage, &BTreeMap::new()));
    }

    #[test]
    fn demand_to_map_whole_cores() {
        let demand = WorkloadResourceDemand {
            cpu_millis: 4000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu_count: 2,
        };
        let map = demand_to_map(&demand);
        assert_eq!(map.get("cpu").unwrap(), "4");
        assert_eq!(map.get("memory").unwrap(), "8Gi");
        assert_eq!(map.get("nvidia.com/gpu").unwrap(), "2");
    }

    #[test]
    fn demand_to_map_fractional_cpu() {
        let demand = WorkloadResourceDemand {
            cpu_millis: 1500,
            memory_bytes: 512 * 1024 * 1024,
            gpu_count: 0,
        };
        let map = demand_to_map(&demand);
        assert_eq!(map.get("cpu").unwrap(), "1500m");
        assert_eq!(map.get("memory").unwrap(), "512Mi");
        assert!(map.get("nvidia.com/gpu").is_none());
    }

    #[test]
    fn demand_to_map_zero() {
        let demand = WorkloadResourceDemand::default();
        let map = demand_to_map(&demand);
        assert!(map.is_empty());
    }
}
