//! Ensure a VictoriaMetricsInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::apply_cluster_resource;
use lattice_crd::crd::{
    InstallSpecBase, UpgradePolicy, VictoriaMetricsInstall, VictoriaMetricsInstallSpec,
};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

/// Create-or-update the singleton `VictoriaMetricsInstall` for this cluster.
///
/// `ha` is wired through from `LatticeCluster.spec.monitoring.ha`; the
/// controller reads it back off the CR spec to pick the chart variant.
pub async fn ensure_install(client: &Client, ha: bool) -> Result<(), kube::Error> {
    let install = VictoriaMetricsInstall::new(
        DEFAULT_INSTALL_NAME,
        VictoriaMetricsInstallSpec {
            base: InstallSpecBase {
                version: manifests::victoria_metrics_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
            },
            ha,
        },
    );
    apply_cluster_resource(client, &install, DEFAULT_INSTALL_NAME, FIELD_MANAGER).await
}
