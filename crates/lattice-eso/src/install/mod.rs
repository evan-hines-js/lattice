//! ESO install — manifests, mesh enrollment, reconciler, ensure.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use std::time::Duration;

use kube::Client;

use lattice_common::kube_utils::wait_for_all_deployments;
use lattice_common::{apply_manifests, ApplyOptions, Error};

/// Namespace the ESO chart renders into.
pub const NAMESPACE: &str = "external-secrets";

const READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Synchronously apply ESO manifests and block until every Deployment in
/// `external-secrets` reports Available.
///
/// Used by pre-CAPI bootstrap (operator startup) — the CAPI credential-sync
/// flow needs ESO healthy before provider Deployments start, and the
/// controller loop can't service that because the full operator isn't
/// running yet.
pub async fn install_blocking(client: &Client) -> Result<(), Error> {
    apply_manifests(
        client,
        manifests::generate_eso(),
        &ApplyOptions::default(),
    )
    .await?;
    wait_for_all_deployments(client, NAMESPACE, READY_TIMEOUT).await
}
