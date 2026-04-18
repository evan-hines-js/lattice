//! Ensure a VolcanoInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::apply_cluster_resource;
use lattice_crd::crd::{InstallSpecBase, UpgradePolicy, VolcanoInstall, VolcanoInstallSpec};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = VolcanoInstall::new(
        DEFAULT_INSTALL_NAME,
        VolcanoInstallSpec {
            base: InstallSpecBase {
                version: manifests::volcano_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
            },
        },
    );
    apply_cluster_resource(client, &install, DEFAULT_INSTALL_NAME, FIELD_MANAGER).await
}
