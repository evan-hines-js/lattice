//! Capacity solver — translates aggregate quota demands into pool node counts.
//!
//! Pure function: takes pool specs and quota sums, returns desired min/max
//! per pool. No I/O, no K8s client, fully testable.
//!
//! The solver:
//! - Sizes for GPU first (scarce resource), then CPU/memory come along for the ride
//! - Computes `min_nodes` from hard quotas (guaranteed reserved capacity)
//! - Computes `max_nodes` from soft quotas (autoscaler ceiling)
//! - Clamps by pool spec `min`/`max` — pool overrides always win

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeQuota, WorkerPoolSpec};
use lattice_common::resources::{
    parse_cpu_millis_str, parse_memory_bytes_str, parse_resource_by_key, CPU_RESOURCE,
    GPU_RESOURCE, MEMORY_RESOURCE,
};

/// Per-pool capacity plan computed by the solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolCapacityPlan {
    /// Pool identifier
    pub pool_id: String,
    /// Desired minimum nodes (from hard quotas, clamped by pool spec)
    pub min_nodes: u32,
    /// Desired maximum nodes (from soft quotas, clamped by pool spec)
    pub max_nodes: u32,
}

/// Node shape for a pool — what one node provides.
#[derive(Clone, Debug)]
pub struct NodeShape {
    /// CPU in millicores per node
    pub cpu_millis: i64,
    /// Memory in bytes per node
    pub memory_bytes: i64,
    /// GPU count per node (0 for non-GPU pools)
    pub gpu_count: u32,
}

impl NodeShape {
    /// Derive node shape from a WorkerPoolSpec.
    ///
    /// Returns `None` if the pool has no capacity information (named instance
    /// types without a `capacity` hint).
    pub fn from_pool_spec(spec: &WorkerPoolSpec) -> Option<Self> {
        // Try explicit capacity hint first
        if let Some(ref capacity) = spec.capacity {
            let cpu = parse_cpu_millis_str(&capacity.cpu).ok()?;
            let mem = parse_memory_bytes_str(&capacity.memory).ok()?;
            let gpu = spec
                .instance_type
                .as_ref()
                .and_then(|it| it.gpu.as_ref())
                .map(|g| g.count)
                .unwrap_or(0);
            return Some(Self {
                cpu_millis: cpu,
                memory_bytes: mem,
                gpu_count: gpu,
            });
        }

        // Try resource-based instance type (Proxmox)
        if let Some(ref it) = spec.instance_type {
            if let Some(res) = it.as_resources() {
                let gpu = it.gpu.as_ref().map(|g| g.count).unwrap_or(0);
                return Some(Self {
                    cpu_millis: res.cores as i64 * 1000,
                    memory_bytes: res.memory_gib as i64 * 1024 * 1024 * 1024,
                    gpu_count: gpu,
                });
            }
        }

        None
    }
}

/// Aggregate quota demand — sum of all quota limits for a resource type.
#[derive(Clone, Debug, Default)]
pub struct AggregateDemand {
    /// Sum of hard quota limits (guaranteed capacity)
    pub hard_cpu_millis: i64,
    /// Sum of hard quota memory
    pub hard_memory_bytes: i64,
    /// Sum of hard quota GPUs
    pub hard_gpu_count: u32,
    /// Sum of soft quota limits (burst ceiling)
    pub soft_cpu_millis: i64,
    /// Sum of soft quota memory
    pub soft_memory_bytes: i64,
    /// Sum of soft quota GPUs
    pub soft_gpu_count: u32,
}

/// Aggregate demands from all enabled quotas.
pub fn aggregate_quotas(quotas: &[LatticeQuota]) -> AggregateDemand {
    let mut demand = AggregateDemand::default();

    for quota in quotas {
        if !quota.spec.enabled {
            continue;
        }

        // Soft limits (always present)
        demand.soft_cpu_millis += parse_quantity(&quota.spec.soft, CPU_RESOURCE);
        demand.soft_memory_bytes += parse_quantity(&quota.spec.soft, MEMORY_RESOURCE);
        demand.soft_gpu_count += parse_quantity(&quota.spec.soft, GPU_RESOURCE) as u32;

        // Hard limits (optional — only set for reserved capacity)
        if let Some(ref hard) = quota.spec.hard {
            demand.hard_cpu_millis += parse_quantity(hard, CPU_RESOURCE);
            demand.hard_memory_bytes += parse_quantity(hard, MEMORY_RESOURCE);
            demand.hard_gpu_count += parse_quantity(hard, GPU_RESOURCE) as u32;
        }
    }

    demand
}

/// Solve pool capacity plans from aggregate demand and pool specs.
///
/// For each pool:
/// - Computes the number of nodes needed to satisfy hard quotas (min_nodes)
/// - Computes the number of nodes needed to satisfy soft quotas (max_nodes)
/// - Clamps by pool spec `min`/`max` — explicit pool bounds always win
///
/// GPU pools absorb GPU demand first. Remaining CPU/memory demand goes to
/// non-GPU pools.
pub fn solve(
    pools: &BTreeMap<String, WorkerPoolSpec>,
    demand: &AggregateDemand,
) -> Vec<PoolCapacityPlan> {
    let mut plans = Vec::new();

    // Separate GPU and non-GPU pools
    let mut remaining_hard_cpu = demand.hard_cpu_millis;
    let mut remaining_hard_mem = demand.hard_memory_bytes;
    let mut remaining_soft_cpu = demand.soft_cpu_millis;
    let mut remaining_soft_mem = demand.soft_memory_bytes;
    let mut remaining_hard_gpu = demand.hard_gpu_count;
    let mut remaining_soft_gpu = demand.soft_gpu_count;

    // Phase 1: GPU pools — size for GPU first, CPU/memory comes along
    for (pool_id, spec) in pools {
        let shape = match NodeShape::from_pool_spec(spec) {
            Some(s) if s.gpu_count > 0 => s,
            _ => continue,
        };

        let hard_gpu_nodes = nodes_for_resource(remaining_hard_gpu as i64, shape.gpu_count as i64);
        let soft_gpu_nodes = nodes_for_resource(remaining_soft_gpu as i64, shape.gpu_count as i64);

        // GPU nodes also provide CPU/memory — subtract what they contribute
        let hard_nodes = hard_gpu_nodes;
        let soft_nodes = soft_gpu_nodes;

        remaining_hard_gpu = remaining_hard_gpu.saturating_sub(hard_nodes * shape.gpu_count);
        remaining_soft_gpu = remaining_soft_gpu.saturating_sub(soft_nodes * shape.gpu_count);
        remaining_hard_cpu =
            (remaining_hard_cpu - hard_nodes as i64 * shape.cpu_millis).max(0);
        remaining_hard_mem =
            (remaining_hard_mem - hard_nodes as i64 * shape.memory_bytes).max(0);
        remaining_soft_cpu =
            (remaining_soft_cpu - soft_nodes as i64 * shape.cpu_millis).max(0);
        remaining_soft_mem =
            (remaining_soft_mem - soft_nodes as i64 * shape.memory_bytes).max(0);

        plans.push(clamp_plan(pool_id, spec, hard_nodes, soft_nodes));
    }

    // Phase 2: Non-GPU pools — absorb remaining CPU/memory
    for (pool_id, spec) in pools {
        let shape = match NodeShape::from_pool_spec(spec) {
            Some(s) if s.gpu_count == 0 => s,
            _ => continue,
        };

        let hard_cpu_nodes = nodes_for_resource(remaining_hard_cpu, shape.cpu_millis);
        let hard_mem_nodes = nodes_for_resource(remaining_hard_mem, shape.memory_bytes);
        let hard_nodes = hard_cpu_nodes.max(hard_mem_nodes);

        let soft_cpu_nodes = nodes_for_resource(remaining_soft_cpu, shape.cpu_millis);
        let soft_mem_nodes = nodes_for_resource(remaining_soft_mem, shape.memory_bytes);
        let soft_nodes = soft_cpu_nodes.max(soft_mem_nodes);

        remaining_hard_cpu =
            (remaining_hard_cpu - hard_nodes as i64 * shape.cpu_millis).max(0);
        remaining_hard_mem =
            (remaining_hard_mem - hard_nodes as i64 * shape.memory_bytes).max(0);
        remaining_soft_cpu =
            (remaining_soft_cpu - soft_nodes as i64 * shape.cpu_millis).max(0);
        remaining_soft_mem =
            (remaining_soft_mem - soft_nodes as i64 * shape.memory_bytes).max(0);

        plans.push(clamp_plan(pool_id, spec, hard_nodes, soft_nodes));
    }

    plans
}

/// Compute how many nodes are needed to provide `demand` units of a resource,
/// given each node provides `per_node` units. Returns 0 if demand <= 0.
fn nodes_for_resource(demand: i64, per_node: i64) -> u32 {
    if demand <= 0 || per_node <= 0 {
        return 0;
    }
    // ceil(demand / per_node)
    ((demand + per_node - 1) / per_node) as u32
}

/// Apply pool spec min/max clamping to computed node counts.
fn clamp_plan(
    pool_id: &str,
    spec: &WorkerPoolSpec,
    quota_min: u32,
    quota_max: u32,
) -> PoolCapacityPlan {
    // Pool spec overrides always win
    let min_nodes = match spec.min {
        Some(pool_min) => pool_min.max(quota_min),
        None => quota_min,
    };
    let max_nodes = match spec.max {
        Some(pool_max) => pool_max.min(quota_max).max(min_nodes),
        None => quota_max.max(min_nodes),
    };

    PoolCapacityPlan {
        pool_id: pool_id.to_string(),
        min_nodes,
        max_nodes,
    }
}

/// Parse a single quantity from a resource map, returning 0 on missing/invalid.
fn parse_quantity(map: &BTreeMap<String, String>, key: &str) -> i64 {
    map.get(key)
        .and_then(|v| parse_resource_by_key(key, v).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{GpuCapacity, InstanceType, LatticeQuotaSpec, NodeCapacityHint};

    fn gpu_pool(gpu_count: u32, cpu_cores: u32, mem_gib: u32) -> WorkerPoolSpec {
        WorkerPoolSpec {
            instance_type: Some(InstanceType {
                cores: Some(cpu_cores),
                memory_gib: Some(mem_gib),
                disk_gib: Some(100),
                gpu: Some(GpuCapacity {
                    count: gpu_count,
                    model: "NVIDIA-H100-SXM".to_string(),
                    memory_gib: Some(80),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn cpu_pool(cpu_cores: u32, mem_gib: u32) -> WorkerPoolSpec {
        WorkerPoolSpec {
            instance_type: Some(InstanceType {
                cores: Some(cpu_cores),
                memory_gib: Some(mem_gib),
                disk_gib: Some(100),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn nodes_for_resource_basic() {
        assert_eq!(nodes_for_resource(8000, 4000), 2); // 8 cores / 4 per node
        assert_eq!(nodes_for_resource(7000, 4000), 2); // ceil(7/4) = 2
        assert_eq!(nodes_for_resource(4000, 4000), 1);
        assert_eq!(nodes_for_resource(0, 4000), 0);
        assert_eq!(nodes_for_resource(-100, 4000), 0);
        assert_eq!(nodes_for_resource(4000, 0), 0);
    }

    #[test]
    fn node_shape_from_resource_type() {
        let spec = cpu_pool(16, 32);
        let shape = NodeShape::from_pool_spec(&spec).unwrap();
        assert_eq!(shape.cpu_millis, 16000);
        assert_eq!(shape.memory_bytes, 32 * 1024 * 1024 * 1024);
        assert_eq!(shape.gpu_count, 0);
    }

    #[test]
    fn node_shape_from_gpu_pool() {
        let spec = gpu_pool(8, 192, 2048);
        let shape = NodeShape::from_pool_spec(&spec).unwrap();
        assert_eq!(shape.cpu_millis, 192000);
        assert_eq!(shape.gpu_count, 8);
    }

    #[test]
    fn node_shape_from_capacity_hint() {
        let spec = WorkerPoolSpec {
            capacity: Some(NodeCapacityHint {
                cpu: "96".to_string(),
                memory: "768Gi".to_string(),
            }),
            instance_type: Some(InstanceType {
                name: Some("p5.48xlarge".to_string()),
                gpu: Some(GpuCapacity {
                    count: 8,
                    model: "H100".to_string(),
                    memory_gib: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let shape = NodeShape::from_pool_spec(&spec).unwrap();
        assert_eq!(shape.cpu_millis, 96000);
        assert_eq!(shape.memory_bytes, 768 * 1024 * 1024 * 1024);
        assert_eq!(shape.gpu_count, 8);
    }

    #[test]
    fn node_shape_named_without_capacity_returns_none() {
        let spec = WorkerPoolSpec {
            instance_type: Some(InstanceType::named("m5.xlarge")),
            ..Default::default()
        };
        assert!(NodeShape::from_pool_spec(&spec).is_none());
    }

    #[test]
    fn solve_gpu_first() {
        let mut pools = BTreeMap::new();
        pools.insert("gpu".to_string(), gpu_pool(8, 192, 2048));
        pools.insert("compute".to_string(), cpu_pool(32, 128));

        let demand = AggregateDemand {
            hard_gpu_count: 16,
            hard_cpu_millis: 100_000, // 100 cores
            hard_memory_bytes: 256 * 1024 * 1024 * 1024,
            soft_gpu_count: 32,
            soft_cpu_millis: 200_000,
            soft_memory_bytes: 512 * 1024 * 1024 * 1024,
        };

        let plans = solve(&pools, &demand);
        assert_eq!(plans.len(), 2);

        let gpu_plan = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        // 16 GPUs / 8 per node = 2 nodes min (hard)
        // 32 GPUs / 8 per node = 4 nodes max (soft)
        assert_eq!(gpu_plan.min_nodes, 2);
        assert_eq!(gpu_plan.max_nodes, 4);

        let cpu_plan = plans.iter().find(|p| p.pool_id == "compute").unwrap();
        // GPU nodes provide 2 * 192 = 384 cores, demand is 100 → remaining = 0
        // So compute pool needs 0 nodes from hard
        assert_eq!(cpu_plan.min_nodes, 0);
    }

    #[test]
    fn solve_cpu_only_demand() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand {
            soft_cpu_millis: 64_000, // 64 cores
            soft_memory_bytes: 128 * 1024 * 1024 * 1024,
            ..Default::default()
        };

        let plans = solve(&pools, &demand);
        let plan = &plans[0];
        // 64 cores / 16 per node = 4 nodes max
        // 128Gi / 64Gi per node = 2 nodes → cpu is the bottleneck → 4
        assert_eq!(plan.max_nodes, 4);
        assert_eq!(plan.min_nodes, 0); // no hard quotas
    }

    #[test]
    fn solve_pool_clamp_floor() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.min = Some(3); // pool floor
        pools.insert("compute".to_string(), spec);

        let demand = AggregateDemand {
            hard_cpu_millis: 16_000, // 1 node worth
            soft_cpu_millis: 32_000, // 2 nodes worth
            ..Default::default()
        };

        let plans = solve(&pools, &demand);
        let plan = &plans[0];
        // quota says min=1, but pool says min=3 → 3 wins
        assert_eq!(plan.min_nodes, 3);
        // quota says max=2, but min is 3, so max must be >= min → 3
        assert_eq!(plan.max_nodes, 3);
    }

    #[test]
    fn solve_pool_clamp_ceiling() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.max = Some(5); // pool ceiling
        pools.insert("compute".to_string(), spec);

        let demand = AggregateDemand {
            soft_cpu_millis: 160_000, // 10 nodes worth
            ..Default::default()
        };

        let plans = solve(&pools, &demand);
        let plan = &plans[0];
        // quota says max=10, pool says max=5 → 5 wins
        assert_eq!(plan.max_nodes, 5);
    }

    #[test]
    fn solve_no_demand() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand::default();
        let plans = solve(&pools, &demand);
        assert_eq!(plans[0].min_nodes, 0);
        assert_eq!(plans[0].max_nodes, 0);
    }

    #[test]
    fn aggregate_quotas_basic() {
        let q1 = LatticeQuota::new(
            "team-a",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-a\"".to_string(),
                soft: BTreeMap::from([
                    ("cpu".to_string(), "64".to_string()),
                    ("nvidia.com/gpu".to_string(), "8".to_string()),
                ]),
                hard: Some(BTreeMap::from([
                    ("cpu".to_string(), "32".to_string()),
                    ("nvidia.com/gpu".to_string(), "4".to_string()),
                ])),
                max_per_workload: None,
                enabled: true,
            },
        );
        let q2 = LatticeQuota::new(
            "team-b",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-b\"".to_string(),
                soft: BTreeMap::from([
                    ("cpu".to_string(), "32".to_string()),
                    ("nvidia.com/gpu".to_string(), "8".to_string()),
                ]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );

        let agg = aggregate_quotas(&[q1, q2]);
        assert_eq!(agg.soft_cpu_millis, 96_000); // (64 + 32) * 1000
        assert_eq!(agg.soft_gpu_count, 16); // 8 + 8
        assert_eq!(agg.hard_cpu_millis, 32_000); // only team-a has hard
        assert_eq!(agg.hard_gpu_count, 4);
    }

    #[test]
    fn aggregate_skips_disabled() {
        let mut q = LatticeQuota::new(
            "disabled",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"x\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), "100".to_string())]),
                hard: None,
                max_per_workload: None,
                enabled: false,
            },
        );
        q.spec.enabled = false;

        let agg = aggregate_quotas(&[q]);
        assert_eq!(agg.soft_cpu_millis, 0);
    }
}
