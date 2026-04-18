//! Ensure an IstioInstall singleton exists for the current cluster.
//!
//! Takes cluster-identity fields (cluster name, remote networks) from the
//! caller because they're cluster-specific and derived from `LatticeCluster`
//! + `LatticeClusterRoutes`. The trust domain itself is derived at apply
//! time inside the controller.

use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use lattice_crd::crd::{IstioInstall, IstioInstallSpec, UpgradePolicy};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(
    client: &Client,
    cluster_name: &str,
    remote_networks: Option<Vec<String>>,
) -> Result<(), kube::Error> {
    let api: Api<IstioInstall> = Api::all(client.clone());
    let install = IstioInstall::new(
        DEFAULT_INSTALL_NAME,
        IstioInstallSpec {
            version: manifests::istio_version().to_string(),
            cluster_name: cluster_name.to_string(),
            remote_networks,
            upgrade_policy: UpgradePolicy::default(),
        },
    );
    api.patch(
        DEFAULT_INSTALL_NAME,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Apply(&install),
    )
    .await?;
    Ok(())
}
