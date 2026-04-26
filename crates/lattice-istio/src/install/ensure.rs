//! Ensure an IstioInstall singleton exists for the current cluster.
//!
//! Takes cluster-identity fields (cluster name, remote networks) from the
//! caller because they're derived from `LatticeCluster` + `LatticeClusterRoutes`.
//! The trust domain itself is derived at apply time inside the controller.

use kube::Client;

use lattice_common::install::apply_cluster_resource;
use lattice_crd::crd::{
    Dependency, InstallSpecBase, IstioInstall, IstioInstallSpec, Subsystem, UpgradePolicy,
};

use super::manifests;

pub const DEFAULT_INSTALL_NAME: &str = "default";

const FIELD_MANAGER: &str = "lattice-cluster-orchestrator";

pub async fn ensure_install(
    client: &Client,
    cluster_name: &str,
    remote_networks: Option<Vec<String>>,
) -> Result<(), kube::Error> {
    let install = IstioInstall::new(
        DEFAULT_INSTALL_NAME,
        IstioInstallSpec {
            base: InstallSpecBase {
                version: manifests::istio_version().to_string(),
                upgrade_policy: UpgradePolicy::default(),
                // Istio's ambient dataplane runs on top of Cilium's eBPF
                // routing — istiod can't program endpoints until the CNI
                // is observed-Ready. Permissive constraint for now;
                // tighten once the compatibility matrix is encoded.
                requires: vec![Dependency {
                    subsystem: Subsystem::Cilium,
                    version_constraint: ">=1.0".into(),
                }],
            },
            cluster_name: cluster_name.to_string(),
            remote_networks,
        },
    );
    apply_cluster_resource(client, &install, DEFAULT_INSTALL_NAME, FIELD_MANAGER).await
}
