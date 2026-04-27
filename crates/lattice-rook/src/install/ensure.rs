//! Ensure a RookInstall singleton exists for the current cluster.
//!
//! The spec is sized from the cluster's worker pool shape so a single
//! `storage: true` flag on `LatticeCluster` produces a workable install
//! on dev fixtures (1–2 workers) and a production install (≥3 workers)
//! without further user input.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{
    FailureDomain, InstallSpecBase, LatticeCluster, RookInstall, RookInstallSpec, UpgradePolicy,
};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client, cluster: &LatticeCluster) -> Result<(), kube::Error> {
    let spec = sized_spec(cluster.spec.nodes.total_workers());
    let install = RookInstall::new(INSTALL_SINGLETON, spec);
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}

/// Pick a RookInstall shape that fits the worker count. Small clusters
/// drop replication and mon counts so the install can actually schedule;
/// once there are 3+ workers, production defaults take over.
fn sized_spec(worker_count: u32) -> RookInstallSpec {
    let base = InstallSpecBase {
        version: manifests::rook_ceph_version().to_string(),
        upgrade_policy: UpgradePolicy::default(),
        requires: super::install_requires(),
    };
    match worker_count {
        0 | 1 => RookInstallSpec {
            base,
            replication: 2,
            mon_count: 1,
            allow_multiple_mons_per_node: true,
            failure_domain: FailureDomain::Osd,
            encrypt_osds: true,
            default_storage_class: true,
        },
        2 => RookInstallSpec {
            base,
            replication: 2,
            mon_count: 1,
            allow_multiple_mons_per_node: false,
            failure_domain: FailureDomain::Host,
            encrypt_osds: true,
            default_storage_class: true,
        },
        _ => RookInstallSpec {
            base,
            replication: 3,
            mon_count: 3,
            allow_multiple_mons_per_node: false,
            failure_domain: FailureDomain::Host,
            encrypt_osds: true,
            default_storage_class: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_worker_collapses_to_osd_failure_domain_with_stacked_mon() {
        let spec = sized_spec(1);
        assert_eq!(spec.mon_count, 1);
        assert_eq!(spec.replication, 2);
        assert_eq!(spec.failure_domain, FailureDomain::Osd);
        assert!(spec.allow_multiple_mons_per_node);
        assert_eq!(spec.required_storage_nodes(), 1);
    }

    #[test]
    fn two_workers_use_host_domain_with_single_mon() {
        let spec = sized_spec(2);
        assert_eq!(spec.mon_count, 1);
        assert_eq!(spec.replication, 2);
        assert_eq!(spec.failure_domain, FailureDomain::Host);
        assert!(!spec.allow_multiple_mons_per_node);
        assert_eq!(spec.required_storage_nodes(), 2);
    }

    #[test]
    fn three_or_more_workers_use_production_defaults() {
        for n in [3u32, 5, 10] {
            let spec = sized_spec(n);
            assert_eq!(spec.mon_count, 3);
            assert_eq!(spec.replication, 3);
            assert_eq!(spec.failure_domain, FailureDomain::Host);
            assert!(!spec.allow_multiple_mons_per_node);
            assert_eq!(spec.required_storage_nodes(), 3);
        }
    }
}
