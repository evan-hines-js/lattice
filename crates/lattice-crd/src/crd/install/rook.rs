//! RookInstall CRD — desired state for the Rook-Ceph storage operator
//! and its managed CephCluster / CephBlockPool / StorageClass.
//!
//! Opinionated defaults: `replication: 3`, `mon.count: 3`, `failureDomain:
//! host`, LUKS-encrypted OSDs, RBD-backed default StorageClass. The exposed
//! knobs exist so small clusters (homelab, dev) can drop to values the
//! production defaults would refuse to schedule; they are not meant as a
//! long menu of ceph tuning.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallResource, InstallSpecBase, InstallStatus};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "RookInstall",
    plural = "rookinstalls",
    shortname = "rki",
    status = "InstallStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.observedVersion"}"#,
    printcolumn = r#"{"name":"Desired","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Replication","type":"integer","jsonPath":".spec.replication"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct RookInstallSpec {
    #[serde(flatten)]
    pub base: InstallSpecBase,

    /// RBD pool replica count. Production default 3; minimum 2 (size:1 pools
    /// are rejected). Must not exceed the number of schedulable storage
    /// targets implied by `failureDomain`.
    #[serde(default = "default_replication")]
    pub replication: u32,

    /// Ceph mon quorum size. Odd numbers only; 3 for production, 1 for
    /// single-node dev.
    #[serde(default = "default_mon_count")]
    pub mon_count: u32,

    /// Allow multiple mons on the same Kubernetes node. Stacking collapses
    /// the mon failure domain onto one host — acceptable for dev clusters,
    /// never for production.
    #[serde(default)]
    pub allow_multiple_mons_per_node: bool,

    /// Failure domain for the default block pool. `host` keeps replicas on
    /// separate nodes (production). `osd` packs replicas onto separate OSDs
    /// on the same host (single-node dev only).
    #[serde(default = "default_failure_domain")]
    pub failure_domain: FailureDomain,

    /// Encrypt OSDs with LUKS. Keys are stored in a Kubernetes Secret in
    /// the `rook-ceph` namespace by default.
    #[serde(default = "super::super::default_true")]
    pub encrypt_osds: bool,

    /// Mark `rook-ceph-block` as the cluster default StorageClass, clearing
    /// the default annotation from any existing default first.
    #[serde(default = "super::super::default_true")]
    pub default_storage_class: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FailureDomain {
    /// Replicas must sit on separate Kubernetes nodes. Production default.
    #[default]
    Host,
    /// Replicas may share a node across separate OSDs. Dev / single-node only.
    Osd,
}

impl FailureDomain {
    pub fn as_ceph_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Osd => "osd",
        }
    }
}

fn default_replication() -> u32 {
    3
}

fn default_mon_count() -> u32 {
    3
}

fn default_failure_domain() -> FailureDomain {
    FailureDomain::Host
}

impl InstallResource for RookInstall {
    fn spec_base(&self) -> &InstallSpecBase {
        &self.spec.base
    }
    fn install_status(&self) -> Option<&InstallStatus> {
        self.status.as_ref()
    }
}

impl RookInstallSpec {
    /// Nodes required to satisfy this spec: the max of the mon quorum
    /// requirement (skipped when stacking is allowed) and the replication
    /// requirement (skipped when `failureDomain: osd`).
    pub fn required_storage_nodes(&self) -> u32 {
        let mon_req = if self.allow_multiple_mons_per_node {
            1
        } else {
            self.mon_count
        };
        let replica_req = match self.failure_domain {
            FailureDomain::Host => self.replication,
            FailureDomain::Osd => 1,
        };
        mon_req.max(replica_req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec_requires_three_nodes() {
        let spec = serde_json::from_value::<RookInstallSpec>(serde_json::json!({
            "version": "1.18.0"
        }))
        .unwrap();
        assert_eq!(spec.replication, 3);
        assert_eq!(spec.mon_count, 3);
        assert_eq!(spec.failure_domain, FailureDomain::Host);
        assert!(spec.encrypt_osds);
        assert!(spec.default_storage_class);
        assert!(!spec.allow_multiple_mons_per_node);
        assert_eq!(spec.required_storage_nodes(), 3);
    }

    #[test]
    fn stacking_mons_drops_node_requirement_to_replication_only() {
        let spec = serde_json::from_value::<RookInstallSpec>(serde_json::json!({
            "version": "1.18.0",
            "allowMultipleMonsPerNode": true
        }))
        .unwrap();
        // Still need 3 nodes because failureDomain: host + replication: 3.
        assert_eq!(spec.required_storage_nodes(), 3);
    }

    #[test]
    fn osd_failure_domain_drops_node_requirement_to_mon_only() {
        let spec = serde_json::from_value::<RookInstallSpec>(serde_json::json!({
            "version": "1.18.0",
            "failureDomain": "osd"
        }))
        .unwrap();
        // mon.count=3 still needs 3 nodes because stacking is off.
        assert_eq!(spec.required_storage_nodes(), 3);
    }

    #[test]
    fn single_node_spec_collapses_to_one() {
        let spec = serde_json::from_value::<RookInstallSpec>(serde_json::json!({
            "version": "1.18.0",
            "monCount": 1,
            "allowMultipleMonsPerNode": true,
            "failureDomain": "osd",
            "replication": 2
        }))
        .unwrap();
        assert_eq!(spec.required_storage_nodes(), 1);
    }

    #[test]
    fn failure_domain_serializes_lowercase() {
        let json = serde_json::to_string(&FailureDomain::Host).expect("serialize host");
        assert_eq!(json, "\"host\"");
        let parsed: FailureDomain = serde_json::from_str("\"osd\"").expect("parse osd");
        assert_eq!(parsed, FailureDomain::Osd);
    }
}
