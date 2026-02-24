//! Dynamic resource utilities for untyped Kubernetes resource access.

use kube::api::{Api, DynamicObject, ListParams};
use kube::discovery::ApiResource;
use kube::Client;

use super::api_resource::build_api_resource_with_discovery;
use crate::Error;

/// Get a dynamic resource field value
pub async fn get_dynamic_resource_status_field(
    client: &Client,
    ar: &ApiResource,
    name: &str,
    namespace: Option<&str>,
    field: &str,
) -> Result<Option<String>, Error> {
    let result = if let Some(ns) = namespace {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, ar);
        api.get(name).await
    } else {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
        api.get(name).await
    };

    match result {
        Ok(obj) => {
            let value = obj
                .data
                .get("status")
                .and_then(|s| s.get(field))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(value)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
        Err(e) => Err(Error::internal_with_context(
            "get_dynamic_resource_status_field",
            format!("Failed to get {}/{}: {}", ar.kind, name, e),
        )),
    }
}

/// Get machine phases in a namespace
pub async fn get_machine_phases(client: &Client, namespace: &str) -> Result<Vec<String>, Error> {
    let ar = build_api_resource_with_discovery(client, "cluster.x-k8s.io", "Machine").await?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let machines = api.list(&ListParams::default()).await.map_err(|e| {
        Error::internal_with_context(
            "get_machine_phases",
            format!("Failed to list machines: {}", e),
        )
    })?;

    let phases: Vec<String> = machines
        .items
        .iter()
        .filter_map(|m| {
            m.data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    Ok(phases)
}
