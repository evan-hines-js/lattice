//! IstioInstall CRD — desired state for the Istio ambient install.
//!
//! Carries cluster-identity fields (`cluster_name`, `remote_networks`)
//! because istiod's rendered config is per-cluster and multi-cluster-aware;
//! the trust domain itself is derived at apply time from the `lattice-ca`
//! Secret and reported back on `status.trust_domain`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallResource, InstallSpecBase, InstallStatus};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "IstioInstall",
    plural = "istioinstalls",
    shortname = "ii",
    status = "InstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterName"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IstioInstallSpec {
    #[serde(flatten)]
    pub base: InstallSpecBase,

    /// This cluster's name — used for istiod `multiCluster.clusterName`,
    /// `global.network`, and the `topology.istio.io/network` namespace label.
    pub cluster_name: String,

    /// Names of peer clusters whose east-west gateways should appear in this
    /// cluster's `meshNetworks`. `None` preserves existing `meshNetworks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_networks: Option<Vec<String>>,
}

impl InstallResource for IstioInstall {
    fn spec_base(&self) -> &InstallSpecBase {
        &self.spec.base
    }
    fn install_status(&self) -> Option<&InstallStatus> {
        self.status.as_ref()
    }
}
