//! VictoriaMetricsInstall CRD — desired state for the monitoring stack.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallResource, InstallSpecBase, InstallStatus};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "VictoriaMetricsInstall",
    plural = "victoriametricsinstalls",
    shortname = "vmi",
    status = "InstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"HA","type":"boolean","jsonPath":".spec.ha"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct VictoriaMetricsInstallSpec {
    #[serde(flatten)]
    pub base: InstallSpecBase,

    /// HA mode (VMCluster with replicated storage) vs single-node (VMSingle).
    #[serde(default)]
    pub ha: bool,
}

impl InstallResource for VictoriaMetricsInstall {
    fn spec_base(&self) -> &InstallSpecBase {
        &self.spec.base
    }
    fn install_status(&self) -> Option<&InstallStatus> {
        self.status.as_ref()
    }
}
