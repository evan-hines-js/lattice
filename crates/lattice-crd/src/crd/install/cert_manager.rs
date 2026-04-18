//! CertManagerInstall CRD — desired state for the cert-manager install.
//!
//! Distinct from `CertIssuer`, the user-facing CRD that represents issuers
//! (ACME, CA, Vault, self-signed) cert-manager should honor.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallSpecBase, InstallStatus};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "CertManagerInstall",
    plural = "certmanagerinstalls",
    shortname = "cmi",
    status = "InstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CertManagerInstallSpec {
    #[serde(flatten)]
    pub base: InstallSpecBase,
}
