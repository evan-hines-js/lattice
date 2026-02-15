//! Compiled workload output types

use std::collections::BTreeMap;

use lattice_common::crd::LatticeMeshMember;
use lattice_secret_provider::eso::ExternalSecret;

use crate::k8s::{ConfigMap, Secret};
use crate::pipeline::pod_template::CompiledPodTemplate;
use crate::pipeline::secrets::SecretRef;
use crate::pipeline::volumes::PersistentVolumeClaim;

/// Complete compiled workload output.
///
/// Contains everything needed by CRD-specific compilers to build their
/// final Kubernetes resources (Deployment, VCJob, SparkApplication, etc.).
#[derive(Debug)]
pub struct CompiledWorkload {
    /// Compiled pod template — containers, volumes, security, scheduling
    pub pod_template: CompiledPodTemplate,
    /// Configuration resources generated during compilation
    pub config: CompiledConfig,
    /// SHA-256 hash of config data for triggering rollouts
    pub config_hash: String,
    /// LatticeMeshMember CR for mesh policy delegation (if workload participates in mesh)
    pub mesh_member: Option<LatticeMeshMember>,
}

/// Configuration resources generated during compilation.
///
/// Collects all ConfigMaps, Secrets, PVCs, and ExternalSecrets that were
/// created by the pipeline stages.
#[derive(Clone, Debug, Default)]
pub struct CompiledConfig {
    /// ConfigMaps for non-sensitive env vars (one per container)
    pub env_config_maps: Vec<ConfigMap>,
    /// Secrets for sensitive env vars (one per container)
    pub env_secrets: Vec<Secret>,
    /// ConfigMaps for file mounts — text content (one per container)
    pub files_config_maps: Vec<ConfigMap>,
    /// Secrets for file mounts — binary content (one per container)
    pub files_secrets: Vec<Secret>,
    /// PersistentVolumeClaims for owned volumes
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// ExternalSecrets for syncing secrets from SecretProvider (Vault)
    pub external_secrets: Vec<ExternalSecret>,
    /// Secret references for template resolution (resource_name -> SecretRef)
    pub secret_refs: BTreeMap<String, SecretRef>,
}

impl CompiledConfig {
    /// Merge another CompiledConfig into this one.
    ///
    /// Used for multi-task compilation (Job tasks, Kthena driver+executor).
    /// Appends all vecs and merges secret_refs map.
    pub fn merge(&mut self, other: CompiledConfig) {
        self.env_config_maps.extend(other.env_config_maps);
        self.env_secrets.extend(other.env_secrets);
        self.files_config_maps.extend(other.files_config_maps);
        self.files_secrets.extend(other.files_secrets);
        self.pvcs.extend(other.pvcs);
        self.external_secrets.extend(other.external_secrets);
        self.secret_refs.extend(other.secret_refs);
    }
}
