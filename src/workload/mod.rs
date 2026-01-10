//! Workload generation for Lattice services
//!
//! This module generates Kubernetes workload resources from LatticeService specs:
//! - Deployment: Container orchestration
//! - Service: Network exposure
//! - ServiceAccount: SPIFFE identity for mTLS
//! - HorizontalPodAutoscaler: Auto-scaling (when replicas.max is set)
//!
//! # Architecture
//!
//! The workload compiler takes a LatticeService and produces standard Kubernetes
//! resources that can be applied to the cluster. Combined with the policy module,
//! this gives a complete deployment with network security.
//!
//! ```text
//! LatticeService
//!       │
//!       ▼
//! WorkloadCompiler.compile()
//!       │
//!       ├──► Deployment
//!       ├──► Service
//!       ├──► ServiceAccount
//!       └──► HorizontalPodAutoscaler (optional)
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crd::{DeployStrategy, LatticeService, LatticeServiceSpec};

// =============================================================================
// Kubernetes Resource Types
// =============================================================================

/// Standard Kubernetes ObjectMeta
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ObjectMeta {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), name.clone());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        Self {
            name,
            namespace: namespace.into(),
            labels,
            annotations: BTreeMap::new(),
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Add an annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// Deployment
// =============================================================================

/// Kubernetes Deployment
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: DeploymentSpec,
}

/// Deployment spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    /// Number of replicas
    pub replicas: u32,
    /// Label selector
    pub selector: LabelSelector,
    /// Pod template
    pub template: PodTemplateSpec,
    /// Deployment strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DeploymentStrategy>,
}

/// Label selector
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Deployment strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    /// Strategy type: RollingUpdate or Recreate
    #[serde(rename = "type")]
    pub type_: String,
    /// Rolling update config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfig>,
}

/// Rolling update configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfig {
    /// Max unavailable pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    /// Max surge pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<String>,
}

/// Pod template spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplateSpec {
    /// Pod metadata
    pub metadata: PodMeta,
    /// Pod spec
    pub spec: PodSpec,
}

/// Pod metadata (subset of ObjectMeta)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodMeta {
    /// Labels
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Pod spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// Service account name
    pub service_account_name: String,
    /// Containers
    pub containers: Vec<Container>,
    /// Volumes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
}

/// Container spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Container name
    pub name: String,
    /// Image
    pub image: String,
    /// Command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Args
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Environment variables
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ContainerPort>,
    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// Liveness probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<ProbeSpec>,
    /// Readiness probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<ProbeSpec>,
    /// Volume mounts
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
}

/// Environment variable
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Container port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub container_port: u16,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Resource requirements
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRequirements {
    /// Requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ResourceQuantity>,
    /// Limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceQuantity>,
}

/// Resource quantity
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceQuantity {
    /// CPU
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Memory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// Probe specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSpec {
    /// HTTP GET probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetAction>,
    /// Exec probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecAction>,
    /// Initial delay seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<u32>,
    /// Period seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<u32>,
}

/// HTTP GET action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetAction {
    /// Path
    pub path: String,
    /// Port
    pub port: u16,
    /// Scheme
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// Exec action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecAction {
    /// Command
    pub command: Vec<String>,
}

/// Volume
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// Volume name
    pub name: String,
    /// ConfigMap source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<ConfigMapVolumeSource>,
    /// Secret source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretVolumeSource>,
    /// EmptyDir source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<EmptyDirVolumeSource>,
}

/// ConfigMap volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapVolumeSource {
    /// ConfigMap name
    pub name: String,
}

/// Secret volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretVolumeSource {
    /// Secret name
    pub secret_name: String,
}

/// EmptyDir volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmptyDirVolumeSource {}

/// Volume mount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// Volume name
    pub name: String,
    /// Mount path
    pub mount_path: String,
    /// Read only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

// =============================================================================
// Service
// =============================================================================

/// Kubernetes Service
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ServiceSpec,
}

/// Service spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Selector
    pub selector: BTreeMap<String, String>,
    /// Ports
    pub ports: Vec<ServicePort>,
    /// Service type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Service port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub port: u16,
    /// Target port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

// =============================================================================
// ServiceAccount
// =============================================================================

/// Kubernetes ServiceAccount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
}

// =============================================================================
// HorizontalPodAutoscaler
// =============================================================================

/// Kubernetes HorizontalPodAutoscaler (v2)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalPodAutoscaler {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: HpaSpec,
}

/// HPA spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HpaSpec {
    /// Scale target ref
    pub scale_target_ref: ScaleTargetRef,
    /// Min replicas
    pub min_replicas: u32,
    /// Max replicas
    pub max_replicas: u32,
    /// Metrics
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricSpec>,
}

/// Scale target reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaleTargetRef {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
}

/// Metric specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricSpec {
    /// Metric type
    #[serde(rename = "type")]
    pub type_: String,
    /// Resource metric
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceMetricSource>,
}

/// Resource metric source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetricSource {
    /// Resource name (cpu, memory)
    pub name: String,
    /// Target
    pub target: MetricTarget,
}

/// Metric target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricTarget {
    /// Target type
    #[serde(rename = "type")]
    pub type_: String,
    /// Average utilization percentage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_utilization: Option<u32>,
}

// =============================================================================
// Generated Workloads Container
// =============================================================================

/// Collection of all workload resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedWorkloads {
    /// Kubernetes Deployment
    pub deployment: Option<Deployment>,
    /// Kubernetes Service
    pub service: Option<Service>,
    /// Kubernetes ServiceAccount
    pub service_account: Option<ServiceAccount>,
    /// Kubernetes HorizontalPodAutoscaler
    pub hpa: Option<HorizontalPodAutoscaler>,
}

impl GeneratedWorkloads {
    /// Create empty workload collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any workloads were generated
    pub fn is_empty(&self) -> bool {
        self.deployment.is_none()
            && self.service.is_none()
            && self.service_account.is_none()
            && self.hpa.is_none()
    }
}

// =============================================================================
// Workload Compiler
// =============================================================================

/// Workload compiler that generates Kubernetes resources from LatticeService specs
pub struct WorkloadCompiler {
    namespace: String,
}

impl WorkloadCompiler {
    /// Create a new workload compiler
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    /// Compile all workload resources for a LatticeService
    pub fn compile(&self, service: &LatticeService) -> GeneratedWorkloads {
        let name = service
            .metadata
            .name
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let mut workloads = GeneratedWorkloads::new();

        // Always generate ServiceAccount for SPIFFE identity
        workloads.service_account = Some(self.compile_service_account(name));

        // Always generate Deployment
        workloads.deployment = Some(self.compile_deployment(name, &service.spec));

        // Generate Service if ports are defined
        if service.spec.service.is_some() {
            workloads.service = Some(self.compile_service(name, &service.spec));
        }

        // Generate HPA if max replicas is set
        if service.spec.replicas.max.is_some() {
            workloads.hpa = Some(self.compile_hpa(name, &service.spec));
        }

        workloads
    }

    /// Compile ServiceAccount
    fn compile_service_account(&self, name: &str) -> ServiceAccount {
        ServiceAccount {
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            metadata: ObjectMeta::new(name, &self.namespace),
        }
    }

    /// Compile Deployment
    fn compile_deployment(&self, name: &str, spec: &LatticeServiceSpec) -> Deployment {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), name.to_string());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );

        // Convert containers
        let containers: Vec<Container> = spec
            .containers
            .iter()
            .map(|(container_name, container_spec)| {
                let env: Vec<EnvVar> = container_spec
                    .variables
                    .iter()
                    .map(|(k, v)| EnvVar {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect();

                // Get ports from service spec
                let ports: Vec<ContainerPort> = spec
                    .service
                    .as_ref()
                    .map(|svc| {
                        svc.ports
                            .iter()
                            .map(|(port_name, port_spec)| ContainerPort {
                                name: Some(port_name.clone()),
                                container_port: port_spec.target_port.unwrap_or(port_spec.port),
                                protocol: port_spec.protocol.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Convert resources
                let resources = container_spec.resources.as_ref().map(|r| {
                    ResourceRequirements {
                        requests: r.requests.as_ref().map(|req| ResourceQuantity {
                            cpu: req.cpu.clone(),
                            memory: req.memory.clone(),
                        }),
                        limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                            cpu: lim.cpu.clone(),
                            memory: lim.memory.clone(),
                        }),
                    }
                });

                // Convert probes
                let liveness_probe = container_spec.liveness_probe.as_ref().map(|p| {
                    ProbeSpec {
                        http_get: p.http_get.as_ref().map(|h| HttpGetAction {
                            path: h.path.clone(),
                            port: h.port,
                            scheme: h.scheme.clone(),
                        }),
                        exec: p.exec.as_ref().map(|e| ExecAction {
                            command: e.command.clone(),
                        }),
                        initial_delay_seconds: None,
                        period_seconds: None,
                    }
                });

                let readiness_probe = container_spec.readiness_probe.as_ref().map(|p| {
                    ProbeSpec {
                        http_get: p.http_get.as_ref().map(|h| HttpGetAction {
                            path: h.path.clone(),
                            port: h.port,
                            scheme: h.scheme.clone(),
                        }),
                        exec: p.exec.as_ref().map(|e| ExecAction {
                            command: e.command.clone(),
                        }),
                        initial_delay_seconds: None,
                        period_seconds: None,
                    }
                });

                Container {
                    name: container_name.clone(),
                    image: container_spec.image.clone(),
                    command: container_spec.command.clone(),
                    args: container_spec.args.clone(),
                    env,
                    ports,
                    resources,
                    liveness_probe,
                    readiness_probe,
                    volume_mounts: vec![], // TODO: implement file mounts
                }
            })
            .collect();

        // Determine deployment strategy
        let strategy = match spec.deploy.strategy {
            DeployStrategy::Rolling => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("25%".to_string()),
                    max_surge: Some("25%".to_string()),
                }),
            }),
            DeployStrategy::Canary => {
                // Canary is handled by Flagger, use RollingUpdate as base
                Some(DeploymentStrategy {
                    type_: "RollingUpdate".to_string(),
                    rolling_update: Some(RollingUpdateConfig {
                        max_unavailable: Some("0".to_string()),
                        max_surge: Some("100%".to_string()),
                    }),
                })
            }
        };

        Deployment {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            metadata: ObjectMeta::new(name, &self.namespace),
            spec: DeploymentSpec {
                replicas: spec.replicas.min,
                selector: LabelSelector {
                    match_labels: labels.clone(),
                },
                template: PodTemplateSpec {
                    metadata: PodMeta {
                        labels,
                        annotations: BTreeMap::new(),
                    },
                    spec: PodSpec {
                        service_account_name: name.to_string(),
                        containers,
                        volumes: vec![],
                    },
                },
                strategy,
            },
        }
    }

    /// Compile Service
    fn compile_service(&self, name: &str, spec: &LatticeServiceSpec) -> Service {
        let mut selector = BTreeMap::new();
        selector.insert("app.kubernetes.io/name".to_string(), name.to_string());

        let ports: Vec<ServicePort> = spec
            .service
            .as_ref()
            .map(|svc| {
                svc.ports
                    .iter()
                    .map(|(port_name, port_spec)| ServicePort {
                        name: Some(port_name.clone()),
                        port: port_spec.port,
                        target_port: port_spec.target_port,
                        protocol: port_spec.protocol.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Service {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: ObjectMeta::new(name, &self.namespace),
            spec: ServiceSpec {
                selector,
                ports,
                type_: None, // ClusterIP by default
            },
        }
    }

    /// Compile HorizontalPodAutoscaler
    fn compile_hpa(&self, name: &str, spec: &LatticeServiceSpec) -> HorizontalPodAutoscaler {
        HorizontalPodAutoscaler {
            api_version: "autoscaling/v2".to_string(),
            kind: "HorizontalPodAutoscaler".to_string(),
            metadata: ObjectMeta::new(name, &self.namespace),
            spec: HpaSpec {
                scale_target_ref: ScaleTargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                min_replicas: spec.replicas.min,
                max_replicas: spec.replicas.max.unwrap_or(spec.replicas.min),
                metrics: vec![MetricSpec {
                    type_: "Resource".to_string(),
                    resource: Some(ResourceMetricSource {
                        name: "cpu".to_string(),
                        target: MetricTarget {
                            type_: "Utilization".to_string(),
                            average_utilization: Some(80),
                        },
                    }),
                }],
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DeploySpec, PortSpec, ReplicaSpec, ServicePortsSpec,
    };

    fn make_service(name: &str, spec: LatticeServiceSpec) -> LatticeService {
        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn make_basic_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        LatticeServiceSpec {
            containers,
            resources: BTreeMap::new(),
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
        }
    }

    // =========================================================================
    // Story: Basic Deployment Generation
    // =========================================================================

    #[test]
    fn story_generates_deployment_from_spec() {
        let spec = make_basic_spec();
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let deployment = workloads.deployment.expect("should have deployment");
        assert_eq!(deployment.metadata.name, "my-app");
        assert_eq!(deployment.metadata.namespace, "default");
        assert_eq!(deployment.spec.replicas, 1);
        assert_eq!(deployment.spec.template.spec.containers.len(), 1);
        assert_eq!(deployment.spec.template.spec.containers[0].image, "nginx:latest");
    }

    // =========================================================================
    // Story: Service Account for SPIFFE Identity
    // =========================================================================

    #[test]
    fn story_generates_service_account() {
        let spec = make_basic_spec();
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let sa = workloads.service_account.expect("should have service account");
        assert_eq!(sa.metadata.name, "my-app");
        assert_eq!(sa.kind, "ServiceAccount");
    }

    // =========================================================================
    // Story: Kubernetes Service Generation
    // =========================================================================

    #[test]
    fn story_generates_service_when_ports_defined() {
        let spec = make_basic_spec();
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let svc = workloads.service.expect("should have service");
        assert_eq!(svc.metadata.name, "my-app");
        assert_eq!(svc.spec.ports.len(), 1);
        assert_eq!(svc.spec.ports[0].port, 80);
    }

    #[test]
    fn story_no_service_without_ports() {
        let mut spec = make_basic_spec();
        spec.service = None;
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        assert!(workloads.service.is_none());
    }

    // =========================================================================
    // Story: HPA Generation
    // =========================================================================

    #[test]
    fn story_generates_hpa_when_max_replicas_set() {
        let mut spec = make_basic_spec();
        spec.replicas = ReplicaSpec {
            min: 2,
            max: Some(10),
        };
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let hpa = workloads.hpa.expect("should have HPA");
        assert_eq!(hpa.spec.min_replicas, 2);
        assert_eq!(hpa.spec.max_replicas, 10);
        assert_eq!(hpa.spec.scale_target_ref.name, "my-app");
    }

    #[test]
    fn story_no_hpa_without_max_replicas() {
        let spec = make_basic_spec();
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        assert!(workloads.hpa.is_none());
    }

    // =========================================================================
    // Story: Container Environment Variables
    // =========================================================================

    #[test]
    fn story_container_env_vars_mapped() {
        let mut spec = make_basic_spec();
        spec.containers.get_mut("main").unwrap().variables = {
            let mut vars = BTreeMap::new();
            vars.insert("LOG_LEVEL".to_string(), "debug".to_string());
            vars.insert("PORT".to_string(), "8080".to_string());
            vars
        };
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let deployment = workloads.deployment.expect("should have deployment");
        let env = &deployment.spec.template.spec.containers[0].env;
        assert_eq!(env.len(), 2);
    }

    // =========================================================================
    // Story: Deployment Strategy
    // =========================================================================

    #[test]
    fn story_rolling_strategy() {
        let mut spec = make_basic_spec();
        spec.deploy.strategy = DeployStrategy::Rolling;
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let deployment = workloads.deployment.expect("should have deployment");
        let strategy = deployment.spec.strategy.expect("should have strategy");
        assert_eq!(strategy.type_, "RollingUpdate");
    }

    // =========================================================================
    // Story: YAML Serialization
    // =========================================================================

    #[test]
    fn story_workloads_serialize_to_yaml() {
        let spec = make_basic_spec();
        let service = make_service("my-app", spec);

        let compiler = WorkloadCompiler::new("default");
        let workloads = compiler.compile(&service);

        let deployment = workloads.deployment.expect("should have deployment");
        let yaml = serde_yaml::to_string(&deployment).expect("should serialize");

        assert!(yaml.contains("apiVersion: apps/v1"));
        assert!(yaml.contains("kind: Deployment"));
        assert!(yaml.contains("name: my-app"));
    }
}
