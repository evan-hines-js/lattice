//! Ensure a VolcanoInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{InstallSpecBase, UpgradePolicy, VolcanoInstall, VolcanoInstallSpec};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = VolcanoInstall::new(
        INSTALL_SINGLETON,
        VolcanoInstallSpec {
            base: InstallSpecBase {
                version: manifests::volcano_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: super::install_requires(),
            },
        },
    );
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}
