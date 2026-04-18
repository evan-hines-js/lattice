//! IstioInstall CRD — desired state for the Istio ambient install.
//!
//! Singleton cluster-scoped CRD. The `lattice-istio` crate owns the
//! controller. Carries cluster-identity fields (`cluster_name`,
//! `remote_networks`) because istiod's rendered config is per-cluster and
//! multi-cluster-aware; the trust domain itself is derived at apply time
//! from the `lattice-ca` Secret.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallPhase, UpgradeAttempt, UpgradePolicy};
use crate::crd::types::Condition;

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "IstioInstall",
    plural = "istioinstalls",
    shortname = "ii",
    status = "IstioInstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterName"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IstioInstallSpec {
    /// Desired Istio version.
    pub version: String,

    /// This cluster's name — used for istiod `multiCluster.clusterName`,
    /// `global.network`, and the `topology.istio.io/network` namespace label.
    pub cluster_name: String,

    /// Names of peer clusters whose east-west gateways should appear in this
    /// cluster's `meshNetworks`. `None` preserves existing `meshNetworks` (no
    /// change); `Some(vec![])` explicitly clears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_networks: Option<Vec<String>>,

    /// Upgrade strategy overrides.
    #[serde(default)]
    pub upgrade_policy: UpgradePolicy,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IstioInstallStatus {
    #[serde(default)]
    pub phase: InstallPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    /// Trust domain currently in use, derived from the `lattice-ca` root CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upgrade: Option<UpgradeAttempt>,
}
