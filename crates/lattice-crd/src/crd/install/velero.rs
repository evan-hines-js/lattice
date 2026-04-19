//! VeleroInstall CRD — desired state for the Velero install.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallResource, InstallSpecBase, InstallStatus};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "VeleroInstall",
    plural = "veleroinstalls",
    shortname = "vei",
    status = "InstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct VeleroInstallSpec {
    #[serde(flatten)]
    pub base: InstallSpecBase,
}

impl InstallResource for VeleroInstall {
    fn spec_base(&self) -> &InstallSpecBase {
        &self.spec.base
    }
    fn install_status(&self) -> Option<&InstallStatus> {
        self.status.as_ref()
    }
}
