//! Ensure an IstioInstall singleton exists for the current cluster.
//!
//! Takes cluster-identity fields (cluster name, remote networks) from the
//! caller because they're derived from `LatticeCluster` + `LatticeClusterRoutes`.
//! The trust domain itself is derived at apply time inside the controller.

use kube::Client;

use lattice_common::install::{apply_cluster_resource, INSTALL_SINGLETON};
use lattice_crd::crd::{InstallSpecBase, IstioInstall, IstioInstallSpec, UpgradePolicy};

use super::manifests;

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(
    client: &Client,
    cluster_name: &str,
    remote_networks: Option<Vec<String>>,
) -> Result<(), kube::Error> {
    let install = IstioInstall::new(
        INSTALL_SINGLETON,
        IstioInstallSpec {
            base: InstallSpecBase {
                version: manifests::istio_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                requires: super::install_requires(),
            },
            cluster_name: cluster_name.to_string(),
            remote_networks,
        },
    );
    apply_cluster_resource(client, &install, INSTALL_SINGLETON, FIELD_MANAGER).await
}
