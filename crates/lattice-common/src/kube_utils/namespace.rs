//! Namespace creation utilities.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

/// Ensure a namespace exists, optionally with labels (idempotent).
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
    let metadata = match labels {
        Some(l) => serde_json::json!({ "name": name, "labels": l }),
        None => serde_json::json!({ "name": name }),
    };
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": metadata
    });
    api.patch(name, &PatchParams::apply(field_manager), &Patch::Apply(&ns))
        .await?;
    Ok(())
}
