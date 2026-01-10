//! Infrastructure provider abstraction layer
//!
//! This module provides a trait-based abstraction for infrastructure providers
//! that generate CAPI (Cluster API) manifests. Each provider implements the
//! [`Provider`] trait to generate the appropriate manifests for its infrastructure.
//!
//! # Supported Providers
//!
//! - [`DockerProvider`] - Docker/Kind provider for local development
//!
//! # Example
//!
//! ```ignore
//! use lattice::provider::{Provider, DockerProvider};
//! use lattice::crd::LatticeCluster;
//!
//! let provider = DockerProvider::new();
//! let cluster: LatticeCluster = /* ... */;
//! let manifests = provider.generate_capi_manifests(&cluster).await?;
//! ```

mod docker;

pub use docker::DockerProvider;

use async_trait::async_trait;

use crate::crd::{LatticeCluster, ProviderSpec};
use crate::Result;

/// A CAPI manifest represented as an untyped Kubernetes resource
///
/// This struct holds a generic Kubernetes manifest with its API version,
/// kind, metadata, and spec. It can be serialized to YAML for applying
/// to a cluster.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CAPIManifest {
    /// API version (e.g., "cluster.x-k8s.io/v1beta1")
    pub api_version: String,
    /// Kind of resource (e.g., "Cluster", "MachineDeployment")
    pub kind: String,
    /// Resource metadata
    pub metadata: ManifestMetadata,
    /// Resource spec (untyped)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
}

impl CAPIManifest {
    /// Create a new CAPI manifest
    pub fn new(
        api_version: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            api_version: api_version.into(),
            kind: kind.into(),
            metadata: ManifestMetadata {
                name: name.into(),
                namespace: Some(namespace.into()),
                labels: None,
                annotations: None,
            },
            spec: None,
        }
    }

    /// Set the spec for this manifest
    pub fn with_spec(mut self, spec: serde_json::Value) -> Self {
        self.spec = Some(spec);
        self
    }

    /// Add labels to the manifest
    pub fn with_labels(mut self, labels: std::collections::BTreeMap<String, String>) -> Self {
        self.metadata.labels = Some(labels);
        self
    }

    /// Serialize the manifest to YAML
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(|e| crate::Error::serialization(e.to_string()))
    }
}

/// Bootstrap information for workload clusters
///
/// This struct contains the information needed for a workload cluster to
/// bootstrap and connect to its parent cell.
#[derive(Clone, Debug, Default)]
pub struct BootstrapInfo {
    /// The parent cell's bootstrap endpoint URL (HTTPS)
    pub bootstrap_endpoint: Option<String>,
    /// One-time bootstrap token for authentication
    pub bootstrap_token: Option<String>,
    /// CA certificate PEM for verifying the cell's TLS certificate
    pub ca_cert_pem: Option<String>,
}

impl BootstrapInfo {
    /// Create new bootstrap info for a workload cluster
    pub fn new(bootstrap_endpoint: String, token: String, ca_cert_pem: String) -> Self {
        Self {
            bootstrap_endpoint: Some(bootstrap_endpoint),
            bootstrap_token: Some(token),
            ca_cert_pem: Some(ca_cert_pem),
        }
    }

    /// Check if bootstrap info is present
    pub fn is_some(&self) -> bool {
        self.bootstrap_token.is_some()
    }
}

/// Metadata for a CAPI manifest
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ManifestMetadata {
    /// Name of the resource
    pub name: String,
    /// Namespace (optional for cluster-scoped resources)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    /// Annotations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
}

/// CAPI Cluster API version (shared across all providers)
/// Updated to v1beta2 as of CAPI v1.11+ (August 2025)
pub const CAPI_CLUSTER_API_VERSION: &str = "cluster.x-k8s.io/v1beta2";
/// CAPI Bootstrap API version for KubeadmConfigTemplate (shared across all providers)
pub const CAPI_BOOTSTRAP_API_VERSION: &str = "bootstrap.cluster.x-k8s.io/v1beta2";
/// CAPI Control Plane API version for KubeadmControlPlane (shared across all providers)
pub const CAPI_CONTROLPLANE_API_VERSION: &str = "controlplane.cluster.x-k8s.io/v1beta2";

/// Generate a MachineDeployment manifest
///
/// This is shared across ALL providers. MachineDeployment is always created with
/// replicas=0 during initial provisioning. After pivot, the cluster's local
/// controller scales up to match spec.nodes.workers.
pub fn generate_machine_deployment(
    cluster_name: &str,
    namespace: &str,
    k8s_version: &str,
    infrastructure_api_version: &str,
    infrastructure_kind: &str,
    labels: std::collections::BTreeMap<String, String>,
) -> CAPIManifest {
    let deployment_name = format!("{}-md-0", cluster_name);

    let spec = serde_json::json!({
        "clusterName": cluster_name,
        "replicas": 0,  // ALWAYS 0 - scaling happens after pivot
        "selector": {
            "matchLabels": {}
        },
        "template": {
            "spec": {
                "clusterName": cluster_name,
                "version": format!("v{}", k8s_version.trim_start_matches('v')),
                "bootstrap": {
                    "configRef": {
                        "apiVersion": CAPI_BOOTSTRAP_API_VERSION,
                        "kind": "KubeadmConfigTemplate",
                        "name": format!("{}-md-0", cluster_name),
                        "namespace": namespace
                    }
                },
                "infrastructureRef": {
                    "apiVersion": infrastructure_api_version,
                    "kind": infrastructure_kind,
                    "name": format!("{}-md-0", cluster_name),
                    "namespace": namespace
                }
            }
        }
    });

    CAPIManifest::new(
        CAPI_CLUSTER_API_VERSION,
        "MachineDeployment",
        &deployment_name,
        namespace,
    )
    .with_labels(labels)
    .with_spec(spec)
}

/// Generate a KubeadmConfigTemplate manifest for workers
///
/// This is shared across ALL providers since worker kubeadm config is provider-agnostic.
pub fn generate_kubeadm_config_template(
    cluster_name: &str,
    namespace: &str,
    labels: std::collections::BTreeMap<String, String>,
) -> CAPIManifest {
    let template_name = format!("{}-md-0", cluster_name);

    let spec = serde_json::json!({
        "template": {
            "spec": {
                "joinConfiguration": {
                    "nodeRegistration": {
                        "criSocket": "/var/run/containerd/containerd.sock",
                        "kubeletExtraArgs": {
                            "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                        }
                    }
                }
            }
        }
    });

    CAPIManifest::new(
        CAPI_BOOTSTRAP_API_VERSION,
        "KubeadmConfigTemplate",
        &template_name,
        namespace,
    )
    .with_labels(labels)
    .with_spec(spec)
}

/// Generate the main CAPI Cluster resource
///
/// This is shared across ALL providers. The only provider-specific part is the
/// infrastructureRef which points to the provider's infrastructure cluster resource
/// (DockerCluster, AWSCluster, etc.)
pub fn generate_cluster(
    cluster_name: &str,
    namespace: &str,
    infrastructure_api_version: &str,
    infrastructure_kind: &str,
    labels: std::collections::BTreeMap<String, String>,
) -> CAPIManifest {
    let spec = serde_json::json!({
        "clusterNetwork": {
            "pods": {
                "cidrBlocks": ["192.168.0.0/16"]
            },
            "services": {
                "cidrBlocks": ["10.128.0.0/12"]
            }
        },
        "controlPlaneRef": {
            "apiVersion": CAPI_CONTROLPLANE_API_VERSION,
            "kind": "KubeadmControlPlane",
            "name": format!("{}-control-plane", cluster_name),
            "namespace": namespace
        },
        "infrastructureRef": {
            "apiVersion": infrastructure_api_version,
            "kind": infrastructure_kind,
            "name": cluster_name,
            "namespace": namespace
        }
    });

    CAPIManifest::new(CAPI_CLUSTER_API_VERSION, "Cluster", cluster_name, namespace)
        .with_labels(labels)
        .with_spec(spec)
}

/// Generate the KubeadmControlPlane resource
///
/// This is shared across ALL providers. The only provider-specific part is the
/// machineTemplate.infrastructureRef which points to the provider's machine template
/// (DockerMachineTemplate, AWSMachineTemplate, etc.)
pub fn generate_control_plane(
    cluster_name: &str,
    namespace: &str,
    k8s_version: &str,
    replicas: u32,
    cert_sans: Vec<String>,
    post_kubeadm_commands: Vec<String>,
    infrastructure_api_version: &str,
    infrastructure_machine_template_kind: &str,
    labels: std::collections::BTreeMap<String, String>,
) -> CAPIManifest {
    let cp_name = format!("{}-control-plane", cluster_name);

    let mut kubeadm_config_spec = serde_json::json!({
        "clusterConfiguration": {
            "apiServer": {
                "certSANs": cert_sans
            },
            "controllerManager": {
                "extraArgs": {
                    "bind-address": "0.0.0.0"
                }
            },
            "scheduler": {
                "extraArgs": {
                    "bind-address": "0.0.0.0"
                }
            }
        },
        "initConfiguration": {
            "nodeRegistration": {
                "criSocket": "/var/run/containerd/containerd.sock",
                "kubeletExtraArgs": {
                    "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                }
            }
        },
        "joinConfiguration": {
            "nodeRegistration": {
                "criSocket": "/var/run/containerd/containerd.sock",
                "kubeletExtraArgs": {
                    "eviction-hard": "nodefs.available<0%,imagefs.available<0%"
                }
            }
        }
    });

    if !post_kubeadm_commands.is_empty() {
        kubeadm_config_spec["postKubeadmCommands"] = serde_json::json!(post_kubeadm_commands);
    }

    let spec = serde_json::json!({
        "replicas": replicas,
        "version": format!("v{}", k8s_version.trim_start_matches('v')),
        "machineTemplate": {
            "infrastructureRef": {
                "apiVersion": infrastructure_api_version,
                "kind": infrastructure_machine_template_kind,
                "name": format!("{}-control-plane", cluster_name),
                "namespace": namespace
            }
        },
        "kubeadmConfigSpec": kubeadm_config_spec
    });

    CAPIManifest::new(
        CAPI_CONTROLPLANE_API_VERSION,
        "KubeadmControlPlane",
        &cp_name,
        namespace,
    )
    .with_labels(labels)
    .with_spec(spec)
}

/// Build postKubeadmCommands for agent bootstrap
///
/// This is shared across ALL providers. These are the shell commands that run
/// after kubeadm completes on each control plane node.
pub fn build_post_kubeadm_commands(cluster_name: &str, bootstrap: &BootstrapInfo) -> Vec<String> {
    let mut commands = Vec::new();

    // Untaint control plane so pods can schedule (all clusters need this)
    commands.push(
        r#"kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane:NoSchedule-"#
            .to_string(),
    );

    // If cluster has bootstrap info, fetch and apply manifests from parent
    if let (Some(ref endpoint), Some(ref token), Some(ref ca_cert)) = (
        &bootstrap.bootstrap_endpoint,
        &bootstrap.bootstrap_token,
        &bootstrap.ca_cert_pem,
    ) {
        commands.push(format!(
            r#"echo "Bootstrapping cluster {cluster_name} from {endpoint}""#
        ));

        // Write CA cert to verify TLS connection to parent
        commands.push(format!(
            r#"cat > /tmp/cell-ca.crt << 'CACERT'
{ca_cert}
CACERT"#
        ));

        // Retry fetching manifests until success (with backoff)
        commands.push(format!(
            r#"echo "Fetching bootstrap manifests from parent..."
MANIFEST_FILE=/tmp/bootstrap-manifests.yaml
RETRY_DELAY=5
while true; do
  if curl -sf --cacert /tmp/cell-ca.crt "{endpoint}/api/clusters/{cluster_name}/manifests" \
    -H "Authorization: Bearer {token}" \
    -o "$MANIFEST_FILE"; then
    echo "Successfully fetched bootstrap manifests"
    break
  fi
  echo "Failed to fetch manifests, retrying in ${{RETRY_DELAY}}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#,
        ));

        // Apply manifests with retry
        commands.push(
            r#"echo "Applying bootstrap manifests..."
RETRY_DELAY=5
while true; do
  if kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /tmp/bootstrap-manifests.yaml; then
    echo "Successfully applied bootstrap manifests"
    break
  fi
  echo "Failed to apply manifests, retrying in ${RETRY_DELAY}s..."
  sleep $RETRY_DELAY
  RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
done"#
                .to_string(),
        );

        // Clean up temp files
        commands.push(r#"rm -f /tmp/cell-ca.crt /tmp/bootstrap-manifests.yaml"#.to_string());
    }

    commands
}

/// Infrastructure provider trait for generating CAPI manifests
///
/// Implementations of this trait generate Cluster API manifests for their
/// specific infrastructure provider (Docker, AWS, GCP, Azure, etc.).
///
/// # Example Implementation
///
/// ```ignore
/// use async_trait::async_trait;
/// use lattice::provider::{Provider, CAPIManifest, BootstrapInfo};
/// use lattice::crd::{LatticeCluster, ProviderSpec};
/// use lattice::Result;
///
/// struct MyProvider;
///
/// #[async_trait]
/// impl Provider for MyProvider {
///     async fn generate_capi_manifests(
///         &self,
///         cluster: &LatticeCluster,
///         bootstrap: &BootstrapInfo,
///     ) -> Result<Vec<CAPIManifest>> {
///         // Generate manifests for your infrastructure
///         todo!()
///     }
///
///     async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
///         // Validate provider-specific configuration
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait Provider: Send + Sync {
    /// Generate CAPI manifests for the given cluster
    ///
    /// This method should generate all necessary Cluster API resources to
    /// provision the cluster, including:
    /// - Cluster resource
    /// - Infrastructure-specific cluster resource (e.g., DockerCluster)
    /// - KubeadmControlPlane
    /// - Infrastructure-specific machine templates
    /// - MachineDeployment for workers
    /// - KubeadmConfigTemplate for workers
    ///
    /// # Arguments
    ///
    /// * `cluster` - The LatticeCluster CRD to generate manifests for
    /// * `bootstrap` - Bootstrap information for workload clusters (endpoint, token, etc.)
    ///
    /// # Returns
    ///
    /// A vector of CAPI manifests that can be applied to provision the cluster
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>>;

    /// Validate the provider specification
    ///
    /// This method validates that the provider-specific configuration is valid
    /// for this provider type. For example, a Docker provider might validate
    /// that no cloud-specific fields are set.
    ///
    /// # Arguments
    ///
    /// * `spec` - The provider specification to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if the spec is valid, or an error describing what's wrong
    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    mod capi_manifest {
        use super::*;

        #[test]
        fn test_new_creates_manifest_with_metadata() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            );

            assert_eq!(manifest.api_version, "cluster.x-k8s.io/v1beta1");
            assert_eq!(manifest.kind, "Cluster");
            assert_eq!(manifest.metadata.name, "test-cluster");
            assert_eq!(manifest.metadata.namespace, Some("default".to_string()));
            assert!(manifest.spec.is_none());
        }

        #[test]
        fn test_with_spec_adds_spec() {
            let spec = serde_json::json!({
                "clusterNetwork": {
                    "pods": { "cidrBlocks": ["192.168.0.0/16"] }
                }
            });

            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(spec.clone());

            assert_eq!(manifest.spec, Some(spec));
        }

        #[test]
        fn test_with_labels_adds_labels() {
            let mut labels = std::collections::BTreeMap::new();
            labels.insert("app".to_string(), "lattice".to_string());

            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_labels(labels.clone());

            assert_eq!(manifest.metadata.labels, Some(labels));
        }

        #[test]
        fn test_to_yaml_produces_valid_yaml() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(serde_json::json!({
                "clusterNetwork": {
                    "pods": { "cidrBlocks": ["192.168.0.0/16"] }
                }
            }));

            let yaml = manifest.to_yaml().expect("should serialize to YAML");
            assert!(yaml.contains("apiVersion: cluster.x-k8s.io/v1beta1"));
            assert!(yaml.contains("kind: Cluster"));
            assert!(yaml.contains("name: test-cluster"));
            assert!(yaml.contains("namespace: default"));
        }

        #[test]
        fn test_manifest_serialization_roundtrip() {
            let manifest = CAPIManifest::new(
                "cluster.x-k8s.io/v1beta1",
                "Cluster",
                "test-cluster",
                "default",
            )
            .with_spec(serde_json::json!({
                "controlPlaneRef": {
                    "apiVersion": "controlplane.cluster.x-k8s.io/v1beta1",
                    "kind": "KubeadmControlPlane",
                    "name": "test-cluster-control-plane"
                }
            }));

            let yaml = manifest.to_yaml().expect("should serialize");
            let parsed: CAPIManifest = serde_yaml::from_str(&yaml).expect("should deserialize");

            assert_eq!(manifest, parsed);
        }
    }
}
