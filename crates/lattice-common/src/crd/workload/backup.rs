//! Backup configuration shared across all Lattice workload CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error action for backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum HookErrorAction {
    /// Continue backup even if hook fails (default)
    #[default]
    Continue,
    /// Fail the backup if hook fails
    Fail,
}

/// A single backup hook (pre or post)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupHook {
    /// Hook name (used in Velero annotation suffix)
    pub name: String,

    /// Target container name
    pub container: String,

    /// Command to execute
    pub command: Vec<String>,

    /// Timeout for hook execution (e.g., "600s", "10m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Action on hook failure
    #[serde(default)]
    pub on_error: HookErrorAction,
}

/// Pre and post backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct BackupHooksSpec {
    /// Hooks to run before backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre: Vec<BackupHook>,

    /// Hooks to run after backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post: Vec<BackupHook>,
}

/// Default volume backup behavior
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeBackupDefault {
    /// All volumes are backed up unless explicitly excluded (default)
    #[default]
    OptOut,
    /// Only explicitly included volumes are backed up
    OptIn,
}

/// Volume backup configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeBackupSpec {
    /// Volumes to explicitly include in backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Volumes to explicitly exclude from backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// Default backup policy for volumes not in include/exclude lists
    #[serde(default)]
    pub default_policy: VolumeBackupDefault,
}

/// Service-level backup configuration
///
/// Defines Velero backup hooks and volume backup policies for a service.
/// This spec is shared between `LatticeService.spec.backup` (inline) and
/// `LatticeServicePolicy.spec.backup` (policy overlay).
///
/// When `schedule` is set, the service controller generates a dedicated Velero
/// Schedule scoped to this service's namespace and labels. When `schedule` is
/// None, the service relies on cluster-wide backup schedules.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceBackupSpec {
    /// Cron schedule for service-level backups (e.g., "0 */1 * * *" for hourly)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// Reference to a BackupStore by name (omit to use default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_ref: Option<String>,

    /// Retention configuration for service-level backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<super::super::cluster_backup::BackupRetentionSpec>,

    /// Pre/post backup hooks for application-aware backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<BackupHooksSpec>,

    /// Volume backup configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<VolumeBackupSpec>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_error_action_serde() {
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Continue).unwrap(),
            r#""Continue""#
        );
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Fail).unwrap(),
            r#""Fail""#
        );
    }

    #[test]
    fn test_volume_backup_default_serde() {
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptOut).unwrap(),
            r#""opt-out""#
        );
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptIn).unwrap(),
            r#""opt-in""#
        );
    }
}
