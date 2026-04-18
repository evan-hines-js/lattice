//! Ensure a TetragonInstall singleton exists for the current cluster.
//!
//! Called by the LatticeCluster reconciler during the Ready phase. Server-side
//! applies a TetragonInstall CR whose `spec.version` matches the bundled chart
//! version. On new Lattice releases with a bumped `TETRAGON_VERSION`, this
//! patches the spec and the TetragonInstall controller picks up the change.

use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use lattice_crd::crd::{TetragonInstall, TetragonInstallSpec, UpgradePolicy};

use super::manifests;

/// Singleton name. Cluster-scoped CRD, one per cluster.
pub const DEFAULT_INSTALL_NAME: &str = "default";

/// Field manager used by the LatticeCluster orchestrator when it owns the spec.
const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

/// Server-side apply the TetragonInstall singleton at the bundled version.
pub async fn ensure_install(client: &Client) -> Result<(), kube::Error> {
    let api: Api<TetragonInstall> = Api::all(client.clone());
    let install = TetragonInstall::new(
        DEFAULT_INSTALL_NAME,
        TetragonInstallSpec {
            version: manifests::tetragon_version().to_string(),
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
