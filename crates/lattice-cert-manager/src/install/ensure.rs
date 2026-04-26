//! Ensure a CertManagerInstall singleton exists for the current cluster.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{
    CertManagerInstall, CertManagerInstallSpec, InstallSpecBase, UpgradePolicy,
};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let install = CertManagerInstall::new(
        INSTALL_SINGLETON,
        CertManagerInstallSpec {
            base: InstallSpecBase {
                version: manifests::cert_manager_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: super::install_requires(),
            },
        },
    );
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}
