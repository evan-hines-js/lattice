//! Capacity solver — translates aggregate quota demands into pool node counts.
//!
//! Uses integer linear programming (ILP) to find the minimum-cost node
//! allocation that satisfies all quota constraints. The solver:
//!
//! - Minimizes total hourly cost across all pools
//! - Satisfies hard quota demands (guaranteed reserved capacity)
//! - Respects soft quota ceilings (autoscaler max)
//! - Respects per-pool min/max from the cluster spec (always wins)
//! - Handles hundreds of instance types efficiently

use std::collections::BTreeMap;

use good_lp::{constraint, variable, Expression, ProblemVariables, Solution, SolverModel};
use tracing::warn;

use lattice_common::crd::{LatticeQuota, WorkerPoolSpec};
use lattice_common::resources::{
    parse_cpu_millis_str, parse_memory_bytes_str, parse_resource_by_key, CPU_RESOURCE,
    GPU_RESOURCE, MEMORY_RESOURCE,
};
use lattice_cost::CostRates;

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
    /// Hourly cost per node (USD)
    pub hourly_cost: f64,
}

impl NodeShape {
    /// Derive node shape from a WorkerPoolSpec and cost rates.
    ///
    /// Returns `None` if the pool has no capacity information.
    pub fn from_pool_spec(spec: &WorkerPoolSpec, rates: &CostRates) -> Option<Self> {
        let (cpu_millis, memory_bytes, gpu_count) = extract_capacity(spec)?;

        let cpu_cost = (cpu_millis as f64 / 1000.0) * rates.cpu;
        let mem_cost = (memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * rates.memory;
        let gpu_cost: f64 = spec
            .instance_type
            .as_ref()
            .and_then(|it| it.gpu.as_ref())
            .and_then(|g| rates.gpu.get(&g.model))
            .map(|rate| rate * gpu_count as f64)
            .unwrap_or(0.0);

        Some(Self {
            cpu_millis,
            memory_bytes,
            gpu_count,
            hourly_cost: cpu_cost + mem_cost + gpu_cost,
        })
    }
}

/// Extract CPU (millis), memory (bytes), GPU count from a pool spec.
fn extract_capacity(spec: &WorkerPoolSpec) -> Option<(i64, i64, u32)> {
    let gpu = spec
        .instance_type
        .as_ref()
        .and_then(|it| it.gpu.as_ref())
        .map(|g| g.count)
        .unwrap_or(0);

    if let Some(ref capacity) = spec.capacity {
        let cpu = parse_cpu_millis_str(&capacity.cpu).ok()?;
        let mem = parse_memory_bytes_str(&capacity.memory).ok()?;
        return Some((cpu, mem, gpu));
    }

    if let Some(ref it) = spec.instance_type {
        if let Some(res) = it.as_resources() {
            return Some((
                res.cores as i64 * 1000,
                res.memory_gib as i64 * 1024 * 1024 * 1024,
                gpu,
            ));
        }
    }

    None
}

/// Aggregate quota demand — sum of all quota limits.
#[derive(Clone, Debug, Default)]
pub struct AggregateDemand {
    /// Sum of hard quota CPU (millis) — guaranteed reserved
    pub hard_cpu_millis: i64,
    /// Sum of hard quota memory (bytes)
    pub hard_memory_bytes: i64,
    /// Sum of hard quota GPUs
    pub hard_gpu_count: u32,
    /// Sum of hard quota hourly cost budget (USD, 0 = no cost constraint)
    pub hard_cost_budget: f64,
    /// Sum of soft quota CPU (millis) — burst ceiling
    pub soft_cpu_millis: i64,
    /// Sum of soft quota memory (bytes)
    pub soft_memory_bytes: i64,
    /// Sum of soft quota GPUs
    pub soft_gpu_count: u32,
    /// Sum of soft quota hourly cost budget (USD, 0 = no cost constraint)
    pub soft_cost_budget: f64,
}

/// Aggregate demands from all enabled quotas.
pub fn aggregate_quotas(quotas: &[LatticeQuota]) -> AggregateDemand {
    let mut demand = AggregateDemand::default();

    for quota in quotas {
        if !quota.spec.enabled {
            continue;
        }

        demand.soft_cpu_millis += parse_quantity(&quota.spec.soft, CPU_RESOURCE);
        demand.soft_memory_bytes += parse_quantity(&quota.spec.soft, MEMORY_RESOURCE);
        demand.soft_gpu_count += parse_quantity(&quota.spec.soft, GPU_RESOURCE) as u32;
        demand.soft_cost_budget += parse_cost(&quota.spec.soft);

        if let Some(ref hard) = quota.spec.hard {
            demand.hard_cpu_millis += parse_quantity(hard, CPU_RESOURCE);
            demand.hard_memory_bytes += parse_quantity(hard, MEMORY_RESOURCE);
            demand.hard_gpu_count += parse_quantity(hard, GPU_RESOURCE) as u32;
            demand.hard_cost_budget += parse_cost(hard);
        }
    }

    demand
}

/// Solve pool capacity plans from aggregate demand, pool specs, and cost rates.
///
/// Runs ILP twice:
/// - Once with hard demands → min_nodes (guaranteed reserved capacity)
/// - Once with soft demands → max_nodes (autoscaler ceiling)
///
/// Both solutions minimize total hourly cost. Pool spec `min`/`max` clamp the result.
pub fn solve(
    pools: &BTreeMap<String, WorkerPoolSpec>,
    demand: &AggregateDemand,
    rates: &CostRates,
) -> Vec<PoolCapacityPlan> {
    // Build pool shapes (skip pools without capacity info)
    let pool_shapes: Vec<(&str, &WorkerPoolSpec, NodeShape)> = pools
        .iter()
        .filter_map(|(id, spec)| {
            NodeShape::from_pool_spec(spec, rates).map(|shape| (id.as_str(), spec, shape))
        })
        .collect();

    if pool_shapes.is_empty() {
        return Vec::new();
    }

    // Solve for hard (min_nodes) and soft (max_nodes) separately
    let hard_solution = solve_ilp(
        &pool_shapes,
        demand.hard_cpu_millis,
        demand.hard_memory_bytes,
        demand.hard_gpu_count,
        demand.hard_cost_budget,
    );

    let soft_solution = solve_ilp(
        &pool_shapes,
        demand.soft_cpu_millis,
        demand.soft_memory_bytes,
        demand.soft_gpu_count,
        demand.soft_cost_budget,
    );

    // Build plans with clamping
    pool_shapes
        .iter()
        .enumerate()
        .map(|(i, (pool_id, spec, _))| {
            let quota_min = hard_solution.get(i).copied().unwrap_or(0);
            let quota_max = soft_solution.get(i).copied().unwrap_or(0);
            clamp_plan(pool_id, spec, quota_min, quota_max)
        })
        .collect()
}

/// Solve a single ILP: minimize cost subject to resource demand constraints.
///
/// Returns node count per pool (in the same order as `pools`).
fn solve_ilp(
    pools: &[(&str, &WorkerPoolSpec, NodeShape)],
    cpu_demand: i64,
    mem_demand: i64,
    gpu_demand: u32,
    cost_budget: f64,
) -> Vec<u32> {
    // No demand → zero nodes everywhere
    if cpu_demand <= 0 && mem_demand <= 0 && gpu_demand == 0 {
        return vec![0; pools.len()];
    }

    let mut vars = ProblemVariables::new();

    // One integer variable per pool: number of nodes.
    // Don't constrain by pool max here — clamping happens after the solve
    // so the ILP can find a feasible solution even when demand exceeds pool limits.
    let node_vars: Vec<_> = pools
        .iter()
        .map(|_| vars.add(variable().integer().min(0).max(10000)))
        .collect();

    // Objective: minimize total hourly cost
    let cost_expr: Expression = node_vars
        .iter()
        .zip(pools.iter())
        .map(|(var, (_, _, shape))| shape.hourly_cost * *var)
        .sum();

    let mut model = vars.minimise(&cost_expr).using(good_lp::solvers::microlp::microlp);

    // Constraint: meet CPU demand
    if cpu_demand > 0 {
        let cpu_expr: Expression = node_vars
            .iter()
            .zip(pools.iter())
            .map(|(var, (_, _, shape))| (shape.cpu_millis as f64) * *var)
            .sum();
        model = model.with(constraint!(cpu_expr >= cpu_demand as f64));
    }

    // Constraint: meet memory demand
    if mem_demand > 0 {
        let mem_expr: Expression = node_vars
            .iter()
            .zip(pools.iter())
            .map(|(var, (_, _, shape))| (shape.memory_bytes as f64) * *var)
            .sum();
        model = model.with(constraint!(mem_expr >= mem_demand as f64));
    }

    // Constraint: meet GPU demand
    if gpu_demand > 0 {
        let gpu_expr: Expression = node_vars
            .iter()
            .zip(pools.iter())
            .map(|(var, (_, _, shape))| (shape.gpu_count as f64) * *var)
            .sum();
        model = model.with(constraint!(gpu_expr >= gpu_demand as f64));
    }

    // Constraint: stay within cost budget (if set)
    if cost_budget > 0.0 {
        model = model.with(constraint!(cost_expr <= cost_budget));
    }

    match model.solve() {
        Ok(solution) => node_vars
            .iter()
            .map(|var| solution.value(*var).round() as u32)
            .collect(),
        Err(e) => {
            warn!(error = %e, "ILP solver failed, falling back to zero nodes");
            vec![0; pools.len()]
        }
    }
}

/// Apply pool spec min/max clamping to computed node counts.
fn clamp_plan(
    pool_id: &str,
    spec: &WorkerPoolSpec,
    quota_min: u32,
    quota_max: u32,
) -> PoolCapacityPlan {
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

/// Parse a cost value from a resource map.
fn parse_cost(map: &BTreeMap<String, String>) -> f64 {
    map.get("cost")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{GpuCapacity, InstanceType, LatticeQuotaSpec, NodeCapacityHint};

    fn test_rates() -> CostRates {
        CostRates {
            cpu: 0.031,
            memory: 0.004,
            gpu: BTreeMap::from([
                ("NVIDIA-H100-SXM".to_string(), 3.50),
                ("NVIDIA-L4".to_string(), 0.81),
            ]),
        }
    }

    fn gpu_pool(gpu_count: u32, cpu_cores: u32, mem_gib: u32, model: &str) -> WorkerPoolSpec {
        WorkerPoolSpec {
            instance_type: Some(InstanceType {
                cores: Some(cpu_cores),
                memory_gib: Some(mem_gib),
                disk_gib: Some(100),
                gpu: Some(GpuCapacity {
                    count: gpu_count,
                    model: model.to_string(),
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
    fn solve_no_demand() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand::default();
        let plans = solve(&pools, &demand, &test_rates());
        assert_eq!(plans[0].min_nodes, 0);
        assert_eq!(plans[0].max_nodes, 0);
    }

    #[test]
    fn solve_cpu_only() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand {
            soft_cpu_millis: 64_000,
            soft_memory_bytes: 128 * 1024 * 1024 * 1024,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        // 64 cores / 16 per node = 4, 128Gi / 64Gi = 2 → CPU bottleneck → 4
        assert_eq!(plans[0].max_nodes, 4);
        assert_eq!(plans[0].min_nodes, 0);
    }

    #[test]
    fn solve_gpu_demand() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "gpu".to_string(),
            gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"),
        );
        pools.insert("compute".to_string(), cpu_pool(32, 128));

        let demand = AggregateDemand {
            soft_gpu_count: 16,
            soft_cpu_millis: 100_000,
            soft_memory_bytes: 256 * 1024 * 1024 * 1024,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        let gpu_plan = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        // 16 GPUs / 8 per node = 2 nodes
        assert_eq!(gpu_plan.max_nodes, 2);

        // GPU nodes provide 2*192=384 cores and 2*2048Gi=4096Gi → covers all CPU/mem
        let cpu_plan = plans.iter().find(|p| p.pool_id == "compute").unwrap();
        assert_eq!(cpu_plan.max_nodes, 0);
    }

    #[test]
    fn solve_hard_vs_soft() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand {
            hard_cpu_millis: 32_000,
            soft_cpu_millis: 80_000,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        assert_eq!(plans[0].min_nodes, 2); // hard: 32/16
        assert_eq!(plans[0].max_nodes, 5); // soft: 80/16
    }

    #[test]
    fn solve_pool_clamp_floor() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.min = Some(3);
        pools.insert("compute".to_string(), spec);

        let demand = AggregateDemand {
            hard_cpu_millis: 16_000,
            soft_cpu_millis: 32_000,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        // quota min=1, pool min=3 → 3 wins
        assert_eq!(plans[0].min_nodes, 3);
    }

    #[test]
    fn solve_pool_clamp_ceiling() {
        let mut pools = BTreeMap::new();
        let mut spec = cpu_pool(16, 64);
        spec.max = Some(5);
        pools.insert("compute".to_string(), spec);

        let demand = AggregateDemand {
            soft_cpu_millis: 160_000,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        // quota max=10, pool max=5 → 5 wins
        assert_eq!(plans[0].max_nodes, 5);
    }

    #[test]
    fn solve_cost_optimizes_across_pool_types() {
        // Two compute pools: cheap small vs expensive large
        // Solver should prefer the cheaper option
        let mut pools = BTreeMap::new();
        pools.insert("small".to_string(), cpu_pool(4, 16)); // cheap per node
        pools.insert("large".to_string(), cpu_pool(64, 256)); // expensive per node

        let demand = AggregateDemand {
            soft_cpu_millis: 16_000, // 16 cores needed
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        let small = plans.iter().find(|p| p.pool_id == "small").unwrap();
        let large = plans.iter().find(|p| p.pool_id == "large").unwrap();

        // Solver minimizes cost: 4 small nodes (4*4=16 cores) cheaper than 1 large
        // 4 small: 4 * (4*0.031 + 16*0.004) = 4 * 0.188 = $0.752
        // 1 large: 1 * (64*0.031 + 256*0.004) = 1 * 3.008 = $3.008
        assert_eq!(small.max_nodes, 4);
        assert_eq!(large.max_nodes, 0);
    }

    #[test]
    fn solve_memory_bottleneck() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(32, 64));

        let demand = AggregateDemand {
            soft_cpu_millis: 32_000,
            soft_memory_bytes: 256 * 1024 * 1024 * 1024,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        // Memory bottleneck: 256Gi / 64Gi = 4 nodes
        assert_eq!(plans[0].max_nodes, 4);
    }

    #[test]
    fn solve_rounds_up() {
        let mut pools = BTreeMap::new();
        pools.insert("compute".to_string(), cpu_pool(16, 64));

        let demand = AggregateDemand {
            soft_cpu_millis: 17_000, // slightly more than 1 node
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        assert_eq!(plans[0].max_nodes, 2);
    }

    #[test]
    fn solve_empty_pools() {
        let plans = solve(&BTreeMap::new(), &AggregateDemand::default(), &test_rates());
        assert!(plans.is_empty());
    }

    #[test]
    fn solve_pool_without_shape_skipped() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "unknown".to_string(),
            WorkerPoolSpec {
                instance_type: Some(InstanceType::named("m5.xlarge")),
                ..Default::default()
            },
        );

        let demand = AggregateDemand {
            soft_cpu_millis: 100_000,
            ..Default::default()
        };
        let plans = solve(&pools, &demand, &test_rates());
        assert!(plans.is_empty());
    }

    #[test]
    fn solve_cost_budget_constraint() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "gpu".to_string(),
            gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"),
        );

        // Want 32 GPUs (4 nodes @ $28/hr each = $112/hr) but budget is $60/hr
        let demand = AggregateDemand {
            soft_gpu_count: 32,
            soft_cost_budget: 60.0,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        let gpu = plans.iter().find(|p| p.pool_id == "gpu").unwrap();
        // Cost constraint should limit to fewer nodes than GPU demand would require
        assert!(gpu.max_nodes < 4);
    }

    #[test]
    fn solve_prefers_cheaper_gpu() {
        let mut pools = BTreeMap::new();
        pools.insert(
            "h100".to_string(),
            gpu_pool(8, 192, 2048, "NVIDIA-H100-SXM"),
        );
        pools.insert("l4".to_string(), gpu_pool(4, 48, 256, "NVIDIA-L4"));

        // Need 4 GPUs — L4 nodes are much cheaper
        let demand = AggregateDemand {
            soft_gpu_count: 4,
            ..Default::default()
        };

        let plans = solve(&pools, &demand, &test_rates());
        let h100 = plans.iter().find(|p| p.pool_id == "h100").unwrap();
        let l4 = plans.iter().find(|p| p.pool_id == "l4").unwrap();

        // L4: 1 node * $3.24 = $3.24 vs H100: 1 node * $28+ → solver picks L4
        assert_eq!(l4.max_nodes, 1);
        assert_eq!(h100.max_nodes, 0);
    }

    #[test]
    fn aggregate_quotas_with_cost() {
        let q = LatticeQuota::new(
            "team-a",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team-a\"".to_string(),
                soft: BTreeMap::from([
                    ("cpu".to_string(), "64".to_string()),
                    ("cost".to_string(), "100".to_string()),
                ]),
                hard: Some(BTreeMap::from([("cost".to_string(), "50".to_string())])),
                max_per_workload: None,
                enabled: true,
            },
        );

        let agg = aggregate_quotas(&[q]);
        assert!((agg.soft_cost_budget - 100.0).abs() < f64::EPSILON);
        assert!((agg.hard_cost_budget - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn node_shape_includes_cost() {
        let spec = cpu_pool(16, 64);
        let shape = NodeShape::from_pool_spec(&spec, &test_rates()).unwrap();
        // 16 cores * $0.031 + 64Gi * $0.004 = $0.496 + $0.256 = $0.752
        assert!((shape.hourly_cost - 0.752).abs() < 0.001);
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
                    model: "NVIDIA-H100-SXM".to_string(),
                    memory_gib: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let shape = NodeShape::from_pool_spec(&spec, &test_rates()).unwrap();
        assert_eq!(shape.cpu_millis, 96000);
        assert_eq!(shape.memory_bytes, 768 * 1024 * 1024 * 1024);
        assert_eq!(shape.gpu_count, 8);
        assert!(shape.hourly_cost > 28.0); // 8 H100 @ $3.50 = $28 + CPU/mem
    }
}
