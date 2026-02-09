//! `WorkloadSpec` — the shared core specification for LatticeService, LatticeJob, and LatticeModel.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::types::ServiceRef;

use super::backup::ServiceBackupSpec;
use super::container::{ContainerSpec, SidecarSpec};
use super::gpu::GPUSpec;
use super::ports::ServicePortsSpec;
use super::resources::{ResourceSpec, ResourceType};
use super::scaling::ReplicaSpec;

/// Shared workload specification (Score core + Lattice extensions)
///
/// Contains the container/resource/service core shared across all Lattice
/// workload types: LatticeService, LatticeJob, LatticeModel.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSpec {
    /// Named container specifications (Score-compatible)
    pub containers: BTreeMap<String, ContainerSpec>,

    /// External dependencies (service, route, postgres, redis, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,

    /// Service port configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServicePortsSpec>,

    /// Replica scaling configuration
    #[serde(default)]
    pub replicas: ReplicaSpec,

    /// Sidecar containers (VPN, logging, metrics, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sidecars: BTreeMap<String, SidecarSpec>,

    /// Pod-level sysctls (e.g., net.ipv4.conf.all.src_valid_mark)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctls: BTreeMap<String, String>,

    /// Use host network namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,

    /// Share PID namespace between containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,

    /// Backup configuration (Velero hooks and volume policies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<ServiceBackupSpec>,

    /// GPU resource specification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GPUSpec>,

    /// Image pull secrets — resource names referencing `type: secret` resources
    ///
    /// Each entry is a resource name from `resources` that must have `type: secret`.
    /// The compiled K8s Secret name is resolved at compile time and added to the
    /// pod's `imagePullSecrets` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<String>,
}

impl WorkloadSpec {
    /// Extract all service dependencies (outbound) with namespace resolution
    ///
    /// Returns ServiceRefs for both internal and external services.
    /// If a resource doesn't specify a namespace, it defaults to `own_namespace`.
    pub fn dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.direction.is_outbound() && spec.type_.is_service_like())
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract services allowed to call this service (inbound) with namespace resolution
    ///
    /// Returns ServiceRefs for callers. If a resource doesn't specify a namespace,
    /// it defaults to `own_namespace`.
    pub fn allowed_callers(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_inbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract external service dependencies with namespace resolution
    pub fn external_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::ExternalService)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract internal service dependencies with namespace resolution
    pub fn internal_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Get the primary container image
    pub fn primary_image(&self) -> Option<&str> {
        self.containers
            .get("main")
            .or_else(|| self.containers.values().next())
            .map(|c| c.image.as_str())
    }

    /// Get shared volume IDs that this workload owns (has size defined)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn owned_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_owner() && spec.id.is_some())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get shared volume IDs that this workload references (no size, just id)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn referenced_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_reference())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get the ports this workload exposes
    pub fn ports(&self) -> BTreeMap<&str, u16> {
        self.service
            .as_ref()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(name, spec)| (name.as_str(), spec.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validate the workload specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.containers.is_empty() {
            return Err(crate::Error::validation(
                "service must have at least one container",
            ));
        }

        // Validate replica counts
        if let Some(max) = self.replicas.max {
            if self.replicas.min > max {
                return Err(crate::Error::validation(
                    "min replicas cannot exceed max replicas",
                ));
            }
        }

        // Validate autoscaling metrics
        if !self.replicas.autoscaling.is_empty() && self.replicas.max.is_none() {
            return Err(crate::Error::validation(
                "autoscaling metrics require max replicas to be set",
            ));
        }
        for m in &self.replicas.autoscaling {
            if m.target == 0 {
                return Err(crate::Error::validation(format!(
                    "autoscaling metric '{}' target must be greater than 0",
                    m.metric
                )));
            }
            if (m.metric == "cpu" || m.metric == "memory") && m.target > 100 {
                return Err(crate::Error::validation(format!(
                    "autoscaling metric '{}' target cannot exceed 100%",
                    m.metric
                )));
            }
        }

        // Validate containers
        for (name, container) in &self.containers {
            container.validate(name)?;
        }

        // Validate service ports
        if let Some(ref svc) = self.service {
            svc.validate()?;
        }

        // Validate GPU spec
        if let Some(ref gpu) = self.gpu {
            gpu.validate().map_err(crate::Error::validation)?;
        }

        Ok(())
    }
}

// No methods on LatticeServiceSpec — all shared behavior lives on WorkloadSpec.
// Mesh methods (dependencies, allowed_callers, etc.) operate on WorkloadSpec.resources.
// Validation lives on WorkloadSpec::validate().
// Callers access via spec.workload.dependencies(), spec.workload.validate(), etc.

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::resources::{DependencyDirection, ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType};
    use super::super::scaling::{AutoscalingMetric, ReplicaSpec};
    use super::super::container::ContainerSpec;

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    memory: Some("256Mi".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sample_workload() -> WorkloadSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());
        WorkloadSpec {
            containers,
            ..Default::default()
        }
    }

    #[test]
    fn story_valid_service_passes_validation() {
        let spec = sample_workload();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn story_service_without_containers_fails() {
        let spec = WorkloadSpec {
            containers: BTreeMap::new(),
            ..Default::default()
        };
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one container"));
    }

    #[test]
    fn story_invalid_replicas_fails() {
        let mut spec = sample_workload();
        spec.replicas = ReplicaSpec {
            min: 5,
            max: Some(3),
            autoscaling: vec![],
        };
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("min replicas"));
    }

    #[test]
    fn test_primary_image() {
        let spec = sample_workload();
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_primary_image_without_main() {
        let mut containers = BTreeMap::new();
        containers.insert("worker".to_string(), simple_container());
        let spec = WorkloadSpec {
            containers,
            ..Default::default()
        };
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn story_service_declares_outbound_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "redis".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
        resources.insert(
            "api-gateway".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let deps = spec.dependencies("test");
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|r| r.name == "redis"));
        assert!(deps.iter().any(|r| r.name == "api-gateway"));
    }

    #[test]
    fn story_service_declares_allowed_callers() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "curl-tester".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );
        resources.insert(
            "frontend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let callers = spec.allowed_callers("test");
        assert_eq!(callers.len(), 2);
        assert!(callers.iter().any(|r| r.name == "curl-tester"));
        assert!(callers.iter().any(|r| r.name == "frontend"));
    }

    #[test]
    fn story_bidirectional_relationships() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "cache".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Both,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        assert!(spec.dependencies("test").iter().any(|r| r.name == "cache"));
        assert!(spec
            .allowed_callers("test")
            .iter()
            .any(|r| r.name == "cache"));
    }

    #[test]
    fn story_external_vs_internal_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "google".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
        resources.insert(
            "backend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );

        let mut spec = sample_workload();
        spec.resources = resources;

        let external = spec.external_dependencies("test");
        let internal = spec.internal_dependencies("test");

        assert_eq!(external.len(), 1);
        assert_eq!(external[0].name, "google");
        assert_eq!(internal.len(), 1);
        assert_eq!(internal[0].name, "backend");
    }

    #[test]
    fn test_volume_owner_detection() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("shared-data".to_string()),
                params: Some(BTreeMap::from([(
                    "size".to_string(),
                    serde_json::json!("10Gi"),
                )])),
                ..Default::default()
            },
        );
        let owned = spec.owned_volume_ids();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0], ("data", "shared-data"));
    }

    #[test]
    fn test_volume_reference_detection() {
        let mut spec = sample_workload();
        spec.resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                id: Some("shared-data".to_string()),
                ..Default::default()
            },
        );
        let refs = spec.referenced_volume_ids();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ("data", "shared-data"));
    }

    #[test]
    fn autoscaling_target_zero_fails() {
        let mut spec = sample_workload();
        spec.replicas.max = Some(10);
        spec.replicas.autoscaling = vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 0,
        }];
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("greater than 0"));
    }

    #[test]
    fn autoscaling_cpu_over_100_fails() {
        let mut spec = sample_workload();
        spec.replicas.max = Some(10);
        spec.replicas.autoscaling = vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 120,
        }];
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot exceed 100%"));
    }

    #[test]
    fn autoscaling_memory_over_100_fails() {
        let mut spec = sample_workload();
        spec.replicas.max = Some(10);
        spec.replicas.autoscaling = vec![AutoscalingMetric {
            metric: "memory".to_string(),
            target: 150,
        }];
        assert!(spec.validate().is_err());
    }

    #[test]
    fn autoscaling_without_max_fails() {
        let mut spec = sample_workload();
        spec.replicas.autoscaling = vec![AutoscalingMetric {
            metric: "cpu".to_string(),
            target: 80,
        }];
        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max replicas"));
    }

    #[test]
    fn autoscaling_custom_metric_over_100_allowed() {
        let mut spec = sample_workload();
        spec.replicas.max = Some(10);
        spec.replicas.autoscaling = vec![AutoscalingMetric {
            metric: "vllm_num_requests_waiting".to_string(),
            target: 200,
        }];
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn gpu_validation_wired_into_spec() {
        let mut spec = sample_workload();
        spec.gpu = Some(super::super::gpu::GPUSpec {
            count: 0,
            ..Default::default()
        });
        assert!(spec.validate().is_err());
    }
}
