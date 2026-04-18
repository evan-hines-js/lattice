//! Ensure a CiliumInstall singleton exists for the current cluster.

use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use lattice_crd::crd::{CiliumInstall, CiliumInstallSpec, UpgradePolicy};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let api: Api<CiliumInstall> = Api::all(client.clone());
    let install = CiliumInstall::new(
        DEFAULT_INSTALL_NAME,
        CiliumInstallSpec {
            version: manifests::cilium_version().to_string(),
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
