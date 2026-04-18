//! cert-manager install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use std::time::Duration;

use kube::Client;

use lattice_common::kube_utils::wait_for_all_deployments;
use lattice_common::{apply_manifests, ApplyOptions, Error};

/// Namespace the cert-manager chart renders into.
pub const NAMESPACE: &str = "cert-manager";

/// Same time budget the controller uses — covers the startupapicheck Job's
/// wait for the webhook to be reachable.
const READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Synchronously apply cert-manager manifests and block until every
/// Deployment in `cert-manager` reports Available.
///
/// Used by pre-CAPI bootstrap paths (operator startup and `lattice uninstall`)
/// that need cert-manager's webhooks up before the rest of the flow proceeds
/// — the controller loop can't service those callers because the full
/// operator isn't running yet.
pub async fn install_blocking(client: &Client) -> Result<(), Error> {
    apply_manifests(
        client,
        manifests::generate_cert_manager(),
        &ApplyOptions::default(),
    )
    .await?;
    wait_for_all_deployments(client, NAMESPACE, READY_TIMEOUT).await
}
