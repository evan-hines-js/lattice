//! Ensure a VeleroInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{InstallSpecBase, UpgradePolicy, VeleroInstall, VeleroInstallSpec};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = VeleroInstall::new(
        INSTALL_SINGLETON,
        VeleroInstallSpec {
            base: InstallSpecBase {
                version: manifests::velero_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: super::install_requires(),
            },
        },
    );
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}
