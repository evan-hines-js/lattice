//! Namespace creation utilities.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

/// Pod Security Standards labels applied to every Lattice-managed namespace.
///
/// Audit and warn at `restricted` level so PSS violations appear in audit
/// logs and kubectl warnings, but enforcement is left to Cedar (authorization)
/// and Tetragon (runtime). This avoids conflicts with Cedar-approved security
/// overrides (e.g., NET_ADMIN capabilities) that would be rejected by PSS
/// `restricted` enforce mode.
fn pss_labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "pod-security.kubernetes.io/audit".to_string(),
            "restricted".to_string(),
        ),
        (
            "pod-security.kubernetes.io/warn".to_string(),
            "restricted".to_string(),
        ),
    ])
}

/// Ensure a namespace exists, optionally with extra labels (idempotent).
///
/// Pod Security Standards labels (`restricted` audit/warn) are always
/// applied. Caller-provided labels are merged on top.
///
/// Uses server-side apply so it never fails on "already exists" and doesn't
/// race with concurrent creators.
pub async fn ensure_namespace(
    client: &Client,
    name: &str,
    labels: Option<&BTreeMap<String, String>>,
    field_manager: &str,
) -> Result<(), kube::Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let mut merged = pss_labels();
    if let Some(extra) = labels {
        merged.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": merged
        }
    });
    api.patch(name, &PatchParams::apply(field_manager), &Patch::Apply(&ns))
        .await?;
    Ok(())
}
