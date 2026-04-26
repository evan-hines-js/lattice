//! cert-manager install module.

pub mod controller;
pub mod ensure;
pub mod manifests;

pub use controller::reconcile;
pub use ensure::{ensure_install, DEFAULT_INSTALL_NAME};

use lattice_crd::crd::{Dependency, Subsystem};

/// `CertManagerInstall.spec.requires`. Webhooks + the startup-apicheck
/// Job need pod networking, so the CNI must be up.
pub fn install_requires() -> Vec<Dependency> {
    vec![Dependency::new(Subsystem::Cilium, ">=1.18, <2")]
}

use std::time::Duration;

use kube::Client;

use lattice_common::kube_utils::wait_for_all_deployments;
use lattice_common::retry::RetryConfig;
use lattice_common::{apply_manifests_with_retry, ApplyOptions, Error};

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
    apply_manifests_with_retry(
        client,
        manifests::generate_cert_manager(),
        &ApplyOptions::default(),
        &RetryConfig::install(),
        "cert-manager install",
    )
    .await?;
    wait_for_all_deployments(client, NAMESPACE, READY_TIMEOUT).await
}
