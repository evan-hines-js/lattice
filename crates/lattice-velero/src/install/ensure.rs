//! Ensure a VeleroInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::apply_cluster_resource;
use lattice_crd::crd::{InstallSpecBase, UpgradePolicy, VeleroInstall, VeleroInstallSpec};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = VeleroInstall::new(
        DEFAULT_INSTALL_NAME,
        VeleroInstallSpec {
            base: InstallSpecBase {
                version: manifests::velero_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: Vec::new(),
            },
        },
    );
    apply_cluster_resource(client, &install, DEFAULT_INSTALL_NAME, FIELD_MANAGER).await
}
