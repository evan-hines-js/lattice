//! CAPI (Cluster API) client for applying and managing CAPI resources
//!
//! Provides a trait-based abstraction for CAPI operations, allowing tests to mock
//! Kubernetes interactions while production code uses real API calls.

use async_trait::async_trait;
use kube::api::{Api, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{debug, info};

#[cfg(test)]
use mockall::automock;

use crate::provider::{pool_resource_suffix, CAPIManifest, CAPI_CLUSTER_API_VERSION};
use lattice_common::crd::BootstrapProvider;
use lattice_common::Error;

/// Trait abstracting CAPI resource operations
///
/// This trait allows mocking CAPI operations in tests while using the
/// real Kubernetes client for applying manifests in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CAPIClient: Send + Sync {
    /// Apply CAPI manifests to provision cluster infrastructure
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error>;

    /// Check if CAPI infrastructure is ready for a cluster
    ///
    /// Returns true when:
    /// - CAPI Cluster object is Provisioned/Ready
    /// - ControlPlane is initialized
    /// - No machines are still provisioning
    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<bool, Error>;

    /// Get the current replica count of a pool's MachineDeployment
    async fn get_pool_replicas(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error>;

    /// Scale a pool's MachineDeployment to the desired replica count
    async fn scale_pool(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error>;

    /// Delete a CAPI Cluster resource
    async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error>;

    /// Check if a CAPI Cluster resource exists
    async fn capi_cluster_exists(&self, cluster_name: &str, namespace: &str)
        -> Result<bool, Error>;

    /// Get the underlying kube Client for advanced operations
    fn kube_client(&self) -> Client;
}

/// Real CAPI client implementation using DynamicObject for untyped resources
pub struct CAPIClientImpl {
    client: Client,
}

impl CAPIClientImpl {
    /// Create a new CAPIClientImpl
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Discover the ApiResource for a given API version and kind using kube-rs discovery
    async fn discover_api_resource(
        &self,
        api_version: &str,
        kind: &str,
    ) -> Result<ApiResource, Error> {
        use kube::discovery::Discovery;

        let (group, version) = parse_api_version(api_version);

        // Run discovery to find the resource
        let discovery = Discovery::new(self.client.clone())
            .run()
            .await
            .map_err(|e| Error::serialization(format!("API discovery failed: {}", e)))?;

        // Search for the matching kind in the discovered resources
        for api_group in discovery.groups() {
            if api_group.name() != group {
                continue;
            }
            for (ar, _caps) in api_group.recommended_resources() {
                if ar.kind == kind && ar.version == version {
                    return Ok(ar.clone());
                }
            }
        }

        // Fallback to constructing manually if not found in discovery cache
        debug!(
            api_version = %api_version,
            kind = %kind,
            "Resource not found in discovery, using fallback pluralization"
        );

        Ok(ApiResource {
            group: group.to_string(),
            version: version.to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: pluralize_kind(kind),
        })
    }

    /// Get API for CAPI Cluster resources
    fn capi_cluster_api(&self, namespace: &str) -> Api<DynamicObject> {
        let ar = ApiResource {
            group: "cluster.x-k8s.io".to_string(),
            version: "v1beta2".to_string(),
            api_version: CAPI_CLUSTER_API_VERSION.to_string(),
            kind: "Cluster".to_string(),
            plural: "clusters".to_string(),
        };
        Api::namespaced_with(self.client.clone(), namespace, &ar)
    }
}

#[async_trait]
impl CAPIClient for CAPIClientImpl {
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error> {
        for manifest in manifests {
            let ar = self
                .discover_api_resource(&manifest.api_version, &manifest.kind)
                .await?;

            // Build dynamic object from manifest
            let mut obj_value = serde_json::json!({
                "apiVersion": manifest.api_version,
                "kind": manifest.kind,
                "metadata": {
                    "name": manifest.metadata.name,
                    "namespace": namespace,
                    "labels": manifest.metadata.labels,
                },
            });

            if let Some(ref data) = manifest.data {
                obj_value["data"] = data.clone();
            }
            if let Some(ref spec) = manifest.spec {
                obj_value["spec"] = spec.clone();
            }

            let obj: DynamicObject = serde_json::from_value(obj_value)
                .map_err(|e| Error::serialization(e.to_string()))?;

            let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);
            api.patch(
                &manifest.metadata.name,
                &PatchParams::apply("lattice-controller").force(),
                &Patch::Apply(&obj),
            )
            .await?;

            info!(
                kind = %manifest.kind,
                name = %manifest.metadata.name,
                namespace = %namespace,
                "Applied CAPI manifest"
            );
        }

        Ok(())
    }

    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<bool, Error> {
        // Check 1: CAPI Cluster object is Ready/Provisioned
        let cluster_api = self.capi_cluster_api(namespace);
        let cluster_ready = match cluster_api.get(cluster_name).await {
            Ok(cluster) => {
                let mut ready = false;
                if let Some(status) = cluster.data.get("status") {
                    if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                        if phase == "Provisioned" {
                            ready = true;
                        }
                    }
                    if !ready {
                        if let Some(conditions) =
                            status.get("conditions").and_then(|c| c.as_array())
                        {
                            for condition in conditions {
                                if condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                                    && condition.get("status").and_then(|s| s.as_str())
                                        == Some("True")
                                {
                                    ready = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                ready
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => false,
            Err(e) => return Err(e.into()),
        };

        if !cluster_ready {
            debug!(cluster = %cluster_name, "CAPI Cluster not ready yet");
            return Ok(false);
        }

        // Check 2: Control plane is Initialized
        let (cp_kind, cp_group, cp_version) = match bootstrap {
            BootstrapProvider::Kubeadm => (
                "KubeadmControlPlane",
                "controlplane.cluster.x-k8s.io",
                "v1beta2",
            ),
            BootstrapProvider::Rke2 => (
                "RKE2ControlPlane",
                "controlplane.cluster.x-k8s.io",
                "v1beta1",
            ),
        };

        let cp_api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: cp_group.to_string(),
                version: cp_version.to_string(),
                kind: cp_kind.to_string(),
            }),
        );

        let cp_name = format!("{}-control-plane", cluster_name);
        let cp_initialized = match cp_api.get(&cp_name).await {
            Ok(cp) => {
                if let Some(status) = cp.data.get("status") {
                    status
                        .get("initialization")
                        .and_then(|init| init.get("controlPlaneInitialized"))
                        .and_then(|i| i.as_bool())
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, cp_kind = %cp_kind, "ControlPlane not found");
                false
            }
            Err(e) => return Err(e.into()),
        };

        if !cp_initialized {
            debug!(cluster = %cluster_name, cp_kind = %cp_kind, "ControlPlane not initialized yet");
            return Ok(false);
        }

        // Check 3: No machines are still provisioning
        let machine_api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta2".to_string(),
                kind: "Machine".to_string(),
            }),
        );

        let machines = machine_api
            .list(
                &ListParams::default()
                    .labels(&format!("cluster.x-k8s.io/cluster-name={}", cluster_name)),
            )
            .await?;

        for machine in &machines.items {
            if let Some(status) = machine.data.get("status") {
                if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                    if phase == "Provisioning" || phase == "Pending" {
                        debug!(
                            cluster = %cluster_name,
                            machine = ?machine.metadata.name,
                            phase = %phase,
                            "Machine still provisioning"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        info!(
            cluster = %cluster_name,
            cp_kind = %cp_kind,
            "Infrastructure fully ready (Cluster ready, ControlPlane initialized, all machines running)"
        );
        Ok(true)
    }

    async fn get_pool_replicas(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error> {
        let api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta2".to_string(),
                kind: "MachineDeployment".to_string(),
            }),
        );

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));

        match api.get(&md_name).await {
            Ok(md) => {
                let replicas = md
                    .data
                    .get("spec")
                    .and_then(|s| s.get("replicas"))
                    .and_then(|r| r.as_i64())
                    .map(|r| r as u32);
                debug!(
                    cluster = %cluster_name,
                    pool = %pool_id,
                    replicas = ?replicas,
                    "Got MachineDeployment replicas for pool"
                );
                Ok(replicas)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, pool = %pool_id, "MachineDeployment not found for pool");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn scale_pool(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error> {
        let api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta2".to_string(),
                kind: "MachineDeployment".to_string(),
            }),
        );

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));
        let patch = serde_json::json!({ "spec": { "replicas": replicas } });

        api.patch(&md_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        info!(
            cluster = %cluster_name,
            pool = %pool_id,
            replicas = replicas,
            "Scaled MachineDeployment for pool"
        );
        Ok(())
    }

    async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error> {
        let api = self.capi_cluster_api(namespace);
        match api.delete(cluster_name, &Default::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, "CAPI Cluster not found (already deleted)");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn capi_cluster_exists(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<bool, Error> {
        let api = self.capi_cluster_api(namespace);
        match api.get(cluster_name).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn kube_client(&self) -> Client {
        self.client.clone()
    }
}

/// Parse API version into (group, version) tuple
fn parse_api_version(api_version: &str) -> (&str, &str) {
    if let Some(idx) = api_version.rfind('/') {
        (&api_version[..idx], &api_version[idx + 1..])
    } else {
        ("", api_version)
    }
}

/// Known CAPI resource pluralizations
const CAPI_KIND_PLURALS: &[(&str, &str)] = &[
    // Core CAPI types
    ("cluster", "clusters"),
    ("machine", "machines"),
    ("machinedeployment", "machinedeployments"),
    ("machineset", "machinesets"),
    ("machinepool", "machinepools"),
    // Control plane providers
    ("kubeadmcontrolplane", "kubeadmcontrolplanes"),
    (
        "kubeadmcontrolplanetemplate",
        "kubeadmcontrolplanetemplates",
    ),
    // Bootstrap providers
    ("kubeadmconfig", "kubeadmconfigs"),
    ("kubeadmconfigtemplate", "kubeadmconfigtemplates"),
    // Docker provider
    ("dockercluster", "dockerclusters"),
    ("dockerclustertemplate", "dockerclustertemplates"),
    ("dockermachine", "dockermachines"),
    ("dockermachinetemplate", "dockermachinetemplates"),
    ("dockermachinepool", "dockermachinepools"),
    ("dockermachinepooltemplate", "dockermachinepooltemplates"),
    // AWS provider
    ("awscluster", "awsclusters"),
    ("awsmachine", "awsmachines"),
    ("awsmachinetemplate", "awsmachinetemplates"),
    ("awsmanagedcluster", "awsmanagedclusters"),
    ("awsmanagedmachinepool", "awsmanagedmachinepools"),
    // GCP provider
    ("gcpcluster", "gcpclusters"),
    ("gcpmachine", "gcpmachines"),
    ("gcpmachinetemplate", "gcpmachinetemplates"),
    // Azure provider
    ("azurecluster", "azureclusters"),
    ("azuremachine", "azuremachines"),
    ("azuremachinetemplate", "azuremachinetemplates"),
    ("azuremanagedcluster", "azuremanagedclusters"),
    ("azuremanagedmachinepool", "azuremanagedmachinepools"),
    // IPAM
    ("ipaddress", "ipaddresses"),
    ("ipaddressclaim", "ipaddressclaims"),
];

/// Convert a Kind to its plural form for Kubernetes API resources
fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();

    // Look up in known CAPI kinds
    for (singular, plural) in CAPI_KIND_PLURALS {
        if *singular == lower {
            return (*plural).to_string();
        }
    }

    // Fallback: simple pluralization
    if lower.ends_with('s') || lower.ends_with("ch") || lower.ends_with("sh") {
        format!("{}es", lower)
    } else if lower.ends_with('y') && !lower.ends_with("ay") && !lower.ends_with("ey") {
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_api_version_with_group() {
        let (group, version) = parse_api_version("cluster.x-k8s.io/v1beta2");
        assert_eq!(group, "cluster.x-k8s.io");
        assert_eq!(version, "v1beta2");
    }

    #[test]
    fn parse_api_version_core() {
        let (group, version) = parse_api_version("v1");
        assert_eq!(group, "");
        assert_eq!(version, "v1");
    }

    #[test]
    fn pluralize_known_kinds() {
        assert_eq!(pluralize_kind("Cluster"), "clusters");
        assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");
        assert_eq!(
            pluralize_kind("KubeadmControlPlane"),
            "kubeadmcontrolplanes"
        );
        assert_eq!(
            pluralize_kind("DockerMachineTemplate"),
            "dockermachinetemplates"
        );
    }

    #[test]
    fn pluralize_fallback() {
        assert_eq!(pluralize_kind("Pod"), "pods");
        assert_eq!(pluralize_kind("Service"), "services");
        assert_eq!(pluralize_kind("Policy"), "policies");
        assert_eq!(pluralize_kind("Ingress"), "ingresses");
    }
}
