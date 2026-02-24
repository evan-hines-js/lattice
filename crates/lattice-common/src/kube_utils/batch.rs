//! ApplyBatch -- parallel server-side-apply for Kubernetes resources.

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{debug, warn};

use crate::Error;

type ApplyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>;

/// Collects server-side-apply operations and runs them in parallel.
///
/// All resources (native K8s types and discovered CRDs) are applied via
/// `DynamicObject` with an explicit `ApiResource`. For native types, construct
/// the `ApiResource` with `ApiResource::erase::<T>(&())`. For discovered CRDs,
/// use the `ApiResource` from API discovery.
pub struct ApplyBatch<'a> {
    client: Client,
    futures: Vec<ApplyFuture>,
    namespace: &'a str,
    params: &'a PatchParams,
}

impl<'a> ApplyBatch<'a> {
    /// Create a new batch targeting `namespace` with the given `PatchParams`.
    pub fn new(client: Client, namespace: &'a str, params: &'a PatchParams) -> Self {
        Self {
            client,
            futures: Vec::new(),
            namespace,
            params,
        }
    }

    /// Serialize a typed resource and queue a server-side-apply patch.
    pub fn push(
        &mut self,
        kind: &str,
        name: &str,
        resource: &impl serde::Serialize,
        ar: &ApiResource,
    ) -> Result<(), Error> {
        let json = serde_json::to_value(resource)
            .map_err(|e| Error::serialization(format!("{}: {}", kind, e)))?;
        self.push_json(kind, name, json, ar)
    }

    /// Queue a server-side-apply patch from raw JSON.
    ///
    /// Overrides `apiVersion` from the `ApiResource` so CRD versions always
    /// match what the server actually serves.
    pub fn push_json(
        &mut self,
        kind: &str,
        name: &str,
        mut json: serde_json::Value,
        ar: &ApiResource,
    ) -> Result<(), Error> {
        if let Some(obj) = json.as_object_mut() {
            obj.insert(
                "apiVersion".to_string(),
                serde_json::Value::String(ar.api_version.clone()),
            );
        }

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), self.namespace, ar);
        let params = self.params.clone();
        let name = name.to_string();
        let kind = kind.to_string();
        self.futures.push(Box::pin(async move {
            debug!(name = %name, kind = %kind, "applying resource");
            api.patch(&name, &params, &Patch::Apply(&json)).await?;
            Ok(())
        }));
        Ok(())
    }

    /// Push a list of CRD-backed resources if the CRD is discovered, warn if not.
    pub fn push_crd<T: serde::Serialize>(
        &mut self,
        kind: &str,
        crd: Option<&ApiResource>,
        resources: &[T],
        name_fn: impl Fn(&T) -> &str,
    ) -> Result<(), Error> {
        if let Some(ar) = crd {
            for resource in resources {
                self.push(kind, name_fn(resource), resource, ar)?;
            }
        } else if !resources.is_empty() {
            warn!(
                count = resources.len(),
                kind = kind,
                "CRD not installed, skipping"
            );
        }
        Ok(())
    }

    /// Push a single optional CRD-backed resource if both it and the CRD exist.
    pub fn push_optional_crd<T: serde::Serialize>(
        &mut self,
        kind: &str,
        crd: Option<&ApiResource>,
        resource: Option<&T>,
        name_fn: impl Fn(&T) -> &str,
    ) -> Result<(), Error> {
        let Some(resource) = resource else {
            return Ok(());
        };
        if let Some(ar) = crd {
            self.push(kind, name_fn(resource), resource, ar)?;
        } else {
            warn!(kind = kind, "CRD not installed, skipping");
        }
        Ok(())
    }

    /// Execute all queued patches in parallel, returning the count applied.
    pub async fn run(self, layer: &str) -> Result<usize, Error> {
        use futures::future::join_all;

        let count = self.futures.len();
        if count == 0 {
            return Ok(0);
        }

        debug!(count, layer, "applying resources in parallel");
        let results = join_all(self.futures).await;

        let mut errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();
        if !errors.is_empty() {
            for (i, err) in errors.iter().enumerate() {
                tracing::error!(error = %err, index = i, layer, "resource application failed");
            }
            return Err(errors.swap_remove(0));
        }

        Ok(count)
    }
}
