//! LatticeClusterBackup Custom Resource Definition
//!
//! The LatticeClusterBackup CRD defines cluster-wide backup schedules.
//! It references a BackupStore for storage and specifies scope (which resource
//! types to back up) and retention policy. Translates to a Velero Schedule.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::service_policy::NamespaceSelector;
use super::types::Condition;

/// Backup scope configuration — what platform resources to back up
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupScopeSpec {
    /// Backup Lattice control plane CRDs
    #[serde(default)]
    pub control_plane: bool,

    /// Backup GPU PaaS CRDs (GPUPool, InferenceEndpoint, ModelCache, GPUTenantQuota)
    #[serde(default)]
    pub gpu_paas_resources: bool,

    /// Select workload namespaces by labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_namespaces: Option<NamespaceSelector>,

    /// Explicitly include these namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_namespaces: Vec<String>,

    /// Explicitly exclude these namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_namespaces: Vec<String>,
}

/// Backup retention configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupRetentionSpec {
    /// Number of daily backups to retain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,

    /// Time-to-live for backups (e.g., "720h" for 30 days)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// Phase of a LatticeClusterBackup
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ClusterBackupPhase {
    /// Backup is pending configuration
    #[default]
    Pending,
    /// Backup schedule is active
    Active,
    /// Backup schedule is paused
    Paused,
    /// Backup has an error
    Failed,
}

impl std::fmt::Display for ClusterBackupPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Status of a LatticeClusterBackup
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterBackupStatus {
    /// Current phase
    #[serde(default)]
    pub phase: ClusterBackupPhase,

    /// Name of the generated Velero Schedule
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velero_schedule_name: Option<String>,

    /// Resolved BackupStore name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_store: Option<String>,

    /// Status conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Observed generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Specification for a LatticeClusterBackup
///
/// Defines when and what platform resources get backed up. References a
/// BackupStore for storage configuration and generates a Velero Schedule.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeClusterBackup",
    plural = "latticeclusterbackups",
    shortname = "lcb",
    namespaced,
    status = "LatticeClusterBackupStatus",
    printcolumn = r#"{"name":"Schedule","type":"string","jsonPath":".spec.schedule"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterBackupSpec {
    /// Cron schedule for backups (e.g., "0 2 * * *" for daily at 2am)
    pub schedule: String,

    /// Reference to a BackupStore by name (omit to use default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_ref: Option<String>,

    /// Backup scope (what to back up)
    #[serde(default)]
    pub scope: BackupScopeSpec,

    /// Retention configuration
    #[serde(default)]
    pub retention: BackupRetentionSpec,

    /// Pause backup creation
    #[serde(default)]
    pub paused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_spec(yaml: &str) -> LatticeClusterBackupSpec {
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        serde_json::from_value(value).expect("parse spec")
    }

    #[test]
    fn test_cluster_backup_roundtrip() {
        let spec = parse_spec(
            r#"
schedule: "0 2 * * *"
storeRef: production-s3
scope:
  controlPlane: true
  gpuPaasResources: true
retention:
  daily: 30
  ttl: "720h"
paused: false
"#,
        );

        assert_eq!(spec.schedule, "0 2 * * *");
        assert_eq!(spec.store_ref, Some("production-s3".to_string()));
        assert!(spec.scope.control_plane);
        assert!(spec.scope.gpu_paas_resources);
        assert_eq!(spec.retention.daily, Some(30));
        assert_eq!(spec.retention.ttl, Some("720h".to_string()));
        assert!(!spec.paused);
    }

    #[test]
    fn test_cluster_backup_defaults() {
        let spec = parse_spec(
            r#"
schedule: "0 3 * * *"
"#,
        );

        assert!(!spec.paused);
        assert!(spec.store_ref.is_none());
        assert!(!spec.scope.control_plane);
        assert!(!spec.scope.gpu_paas_resources);
        assert!(spec.scope.include_namespaces.is_empty());
        assert!(spec.scope.exclude_namespaces.is_empty());
        assert!(spec.retention.daily.is_none());
    }

    #[test]
    fn test_cluster_backup_phase_display() {
        assert_eq!(ClusterBackupPhase::Pending.to_string(), "Pending");
        assert_eq!(ClusterBackupPhase::Active.to_string(), "Active");
        assert_eq!(ClusterBackupPhase::Paused.to_string(), "Paused");
        assert_eq!(ClusterBackupPhase::Failed.to_string(), "Failed");
    }
}
