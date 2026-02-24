//! Namespace creation utilities.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use crate::Error;

/// Ensure a namespace exists (idempotent).
///
/// Uses server-side apply so it never fails on "already exists" and doesn't
/// race with concurrent creators.
pub async fn ensure_namespace(
    client: &Client,
    name: &str,
    field_manager: &str,
) -> Result<(), kube::Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": name }
    });
    api.patch(name, &PatchParams::apply(field_manager), &Patch::Apply(&ns))
        .await?;
    Ok(())
}

/// Ensure a namespace exists with specific labels (idempotent).
///
/// Same as [`ensure_namespace`] but also applies the given labels via
/// server-side apply.
pub async fn ensure_namespace_with_labels(
    client: &Client,
    name: &str,
    labels: &BTreeMap<String, String>,
    field_manager: &str,
) -> Result<(), kube::Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": labels
        }
    });
    api.patch(name, &PatchParams::apply(field_manager), &Patch::Apply(&ns))
        .await?;
    Ok(())
}

/// Ensure a namespace exists using server-side apply (idempotent, with field manager).
pub async fn ensure_namespace_ssa(client: &Client, name: &str, manager: &str) -> Result<(), Error> {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": name }
    });
    api.patch(name, &PatchParams::apply(manager), &Patch::Apply(&ns))
        .await
        .map_err(|e| {
            Error::internal_with_context("ensure_namespace", format!("failed for {}: {}", name, e))
        })?;
    Ok(())
}
