//! Quota enforcement for the workload compiler
//!
//! Called during `WorkloadCompiler::compile()` to reject workloads that would
//! exceed soft limits. Reads pre-computed usage from `LatticeQuotaStatus`.

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeQuota, QuotaPrincipal};
use lattice_common::resources::{
    compute_workload_demand, parse_cpu_millis_str, parse_memory_bytes_str, GPU_RESOURCE,
    WorkloadResourceDemand,
};
use lattice_common::crd::workload::spec::WorkloadSpec;

/// Enforce quota limits for a workload about to be compiled.
///
/// Checks all enabled quotas whose principal matches this workload.
/// For each matching quota:
/// - Rejects if any single resource exceeds `maxPerWorkload`
/// - Rejects if `status.used + demand` would exceed `soft` limits
///
/// Returns `Ok(())` if all quotas pass, or `Err(details)` with a
/// human-readable rejection message.
pub fn enforce_quotas(
    quotas: &[LatticeQuota],
    name: &str,
    namespace: &str,
    namespace_labels: &BTreeMap<String, String>,
    workload_annotations: &BTreeMap<String, String>,
    workload: &WorkloadSpec,
    replicas: u32,
) -> Result<(), String> {
    let demand = compute_workload_demand(workload, replicas)
        .map_err(|e| format!("failed to compute resource demand: {e}"))?;

    for quota in quotas {
        if !quota.spec.enabled {
            continue;
        }

        let principal = match QuotaPrincipal::parse(&quota.spec.principal) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !principal.matches_workload(namespace, name, namespace_labels, workload_annotations) {
            continue;
        }

        let quota_name = quota.metadata.name.as_deref().unwrap_or("unknown");

        // Check per-workload caps
        if let Some(ref max) = quota.spec.max_per_workload {
            check_per_workload_limit(&demand, max, quota_name)?;
        }

        // Check total: used + demand <= soft
        let used = quota
            .status
            .as_ref()
            .map(|s| &s.used)
            .cloned()
            .unwrap_or_default();

        check_soft_limit(&demand, &used, &quota.spec.soft, quota_name)?;
    }

    Ok(())
}

fn check_per_workload_limit(
    demand: &WorkloadResourceDemand,
    max: &BTreeMap<String, String>,
    quota_name: &str,
) -> Result<(), String> {
    if let Some(cpu_max) = max.get("cpu") {
        if let Ok(limit) = parse_cpu_millis_str(cpu_max) {
            if demand.cpu_millis > limit {
                return Err(format!(
                    "quota '{}': workload cpu ({}m) exceeds maxPerWorkload ({})",
                    quota_name, demand.cpu_millis, cpu_max,
                ));
            }
        }
    }
    if let Some(mem_max) = max.get("memory") {
        if let Ok(limit) = parse_memory_bytes_str(mem_max) {
            if demand.memory_bytes > limit {
                return Err(format!(
                    "quota '{}': workload memory exceeds maxPerWorkload ({})",
                    quota_name, mem_max,
                ));
            }
        }
    }
    if let Some(gpu_max) = max.get(GPU_RESOURCE) {
        if let Ok(limit) = gpu_max.parse::<u32>() {
            if demand.gpu_count > limit {
                return Err(format!(
                    "quota '{}': workload gpu ({}) exceeds maxPerWorkload ({})",
                    quota_name, demand.gpu_count, gpu_max,
                ));
            }
        }
    }
    Ok(())
}

fn check_soft_limit(
    demand: &WorkloadResourceDemand,
    used: &BTreeMap<String, String>,
    soft: &BTreeMap<String, String>,
    quota_name: &str,
) -> Result<(), String> {
    if let Some(cpu_soft) = soft.get("cpu") {
        if let Ok(limit) = parse_cpu_millis_str(cpu_soft) {
            let current = used
                .get("cpu")
                .and_then(|v| parse_cpu_millis_str(v).ok())
                .unwrap_or(0);
            if current + demand.cpu_millis > limit {
                return Err(format!(
                    "quota '{}': cpu would exceed soft limit ({} used + {}m requested > {} limit)",
                    quota_name,
                    used.get("cpu").unwrap_or(&"0".to_string()),
                    demand.cpu_millis,
                    cpu_soft,
                ));
            }
        }
    }
    if let Some(mem_soft) = soft.get("memory") {
        if let Ok(limit) = parse_memory_bytes_str(mem_soft) {
            let current = used
                .get("memory")
                .and_then(|v| parse_memory_bytes_str(v).ok())
                .unwrap_or(0);
            if current + demand.memory_bytes > limit {
                return Err(format!(
                    "quota '{}': memory would exceed soft limit",
                    quota_name,
                ));
            }
        }
    }
    if let Some(gpu_soft) = soft.get(GPU_RESOURCE) {
        if let Ok(limit) = gpu_soft.parse::<u32>() {
            let current = used
                .get(GPU_RESOURCE)
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            if current + demand.gpu_count > limit {
                return Err(format!(
                    "quota '{}': gpu would exceed soft limit ({} used + {} requested > {} limit)",
                    quota_name, current, demand.gpu_count, gpu_soft,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::workload::container::ContainerSpec;
    use lattice_common::crd::workload::resources::{ResourceQuantity, ResourceRequirements};
    use lattice_common::crd::{LatticeQuotaSpec, LatticeQuotaStatus, LatticeQuotaPhase};

    fn make_workload(cpu: &str, memory: &str) -> WorkloadSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                resources: Some(ResourceRequirements {
                    requests: Some(ResourceQuantity {
                        cpu: Some(cpu.to_string()),
                        memory: Some(memory.to_string()),
                        ..Default::default()
                    }),
                    limits: Some(ResourceQuantity {
                        cpu: Some(cpu.to_string()),
                        memory: Some(memory.to_string()),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
        );
        WorkloadSpec {
            containers,
            ..Default::default()
        }
    }

    fn make_quota(soft_cpu: &str, used_cpu: Option<&str>) -> LatticeQuota {
        let mut quota = LatticeQuota::new(
            "test-quota",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), soft_cpu.to_string())]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );
        quota.metadata.namespace = Some("lattice-system".to_string());

        if let Some(used) = used_cpu {
            quota.status = Some(LatticeQuotaStatus {
                phase: LatticeQuotaPhase::Active,
                used: BTreeMap::from([("cpu".to_string(), used.to_string())]),
                workload_count: 1,
                message: None,
                observed_generation: None,
            });
        }

        quota
    }

    #[test]
    fn enforce_within_limits() {
        let workload = make_workload("1", "1Gi");
        let quota = make_quota("10", Some("4"));
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_exceeds_soft() {
        let workload = make_workload("8", "1Gi");
        let quota = make_quota("10", Some("4"));
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceed soft limit"));
    }

    #[test]
    fn enforce_no_matching_quota() {
        let workload = make_workload("100", "1Gi");
        let quota = make_quota("1", None);
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "other".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_disabled_quota_ignored() {
        let workload = make_workload("100", "1Gi");
        let mut quota = make_quota("1", None);
        quota.spec.enabled = false;
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_per_workload_cap() {
        let workload = make_workload("16", "1Gi");
        let mut quota = make_quota("100", None);
        quota.spec.max_per_workload =
            Some(BTreeMap::from([("cpu".to_string(), "8".to_string())]));
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maxPerWorkload"));
    }

    #[test]
    fn enforce_replicas_multiply() {
        let workload = make_workload("2", "1Gi");
        let quota = make_quota("10", Some("4"));
        let ns_labels = BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]);

        // 2 CPU * 4 replicas = 8 CPU, 4 used + 8 = 12 > 10 soft limit
        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &ns_labels,
            &BTreeMap::new(),
            &workload,
            4,
        );
        assert!(result.is_err());
    }
}
