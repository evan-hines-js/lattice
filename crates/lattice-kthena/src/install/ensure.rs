//! Ensure a KthenaInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{InstallSpecBase, KthenaInstall, KthenaInstallSpec, UpgradePolicy};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = KthenaInstall::new(
        INSTALL_SINGLETON,
        KthenaInstallSpec {
            base: InstallSpecBase {
                version: manifests::kthena_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: super::install_requires(),
            },
        },
    );
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}
