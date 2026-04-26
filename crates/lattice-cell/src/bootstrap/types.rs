//! Bootstrap type definitions
//!
//! Core types for the bootstrap protocol: responses, registrations,
//! manifest generator trait, and bundle configuration.

use lattice_common::ApiServerEndpoint;
use lattice_crd::crd::{LatticeCluster, ProviderType};
use serde::{Deserialize, Serialize};

/// Bootstrap response containing manifests for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Cluster ID
    pub cluster_id: String,
    /// Cell endpoint for gRPC connection (after CSR is signed)
    pub cell_endpoint: String,
    /// CA certificate in PEM format (for verifying cell)
    pub ca_certificate: String,
    /// Kubernetes manifests to apply (YAML)
    pub manifests: Vec<String>,
}

/// Per-cluster facts shared by [`ClusterRegistration`] and
/// [`BootstrapBundleConfig`]. Single source of truth for the bits
/// derived from a `LatticeCluster`.
#[derive(Debug, Clone)]
pub struct ClusterFacts {
    pub cluster_name: String,
    pub provider: ProviderType,
    pub bootstrap: lattice_crd::crd::BootstrapProvider,
    pub k8s_version: String,
    pub autoscaling_enabled: bool,
    /// CIDR for the workload cluster's `CiliumLoadBalancerIPPool`,
    /// resolved by the provider trait (`Provider::lb_cidr`). `None`
    /// for cloud providers using native LBs, or for any provider
    /// whose spec doesn't request one.
    pub lb_cidr: Option<String>,
    /// Pod CIDR — pinned into Cilium's `ipv4NativeRoutingCIDR` so
    /// pod-egress to LAN destinations gets masqueraded to the node
    /// IP instead of leaking the pod IP.
    pub pod_cidr: String,
    pub cluster_manifest: String,
}

impl ClusterFacts {
    /// Derive facts from a cluster CR plus its serialized manifest
    /// and the provider-resolved LB CIDR. Each provider answers
    /// `lb_cidr` for itself via the [`Provider::lb_cidr`] trait
    /// method — synchronous spec lookups for static configs
    /// (Docker, Proxmox), CR fetches for dynamic ones (basis).
    pub fn from_cluster(
        cluster: &LatticeCluster,
        cluster_manifest: String,
        lb_cidr: Option<String>,
    ) -> Self {
        Self {
            cluster_name: cluster.metadata.name.clone().unwrap_or_default(),
            provider: cluster.spec.provider.config.provider_type(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            k8s_version: cluster.spec.provider.kubernetes.version.clone(),
            autoscaling_enabled: cluster
                .spec
                .nodes
                .worker_pools
                .values()
                .any(|p| p.is_autoscaling_enabled()),
            lb_cidr,
            pod_cidr: cluster
                .spec
                .provider
                .kubernetes
                .cluster_network
                .pod_cidr
                .clone(),
            cluster_manifest,
        }
    }
}

/// Configuration for registering a cluster for bootstrap.
#[derive(Debug, Clone)]
pub struct ClusterRegistration {
    pub facts: ClusterFacts,
    pub cell_endpoint: String,
    pub ca_certificate: String,
}

impl ClusterRegistration {
    pub fn cluster_id(&self) -> &str {
        &self.facts.cluster_name
    }
}

/// Bootstrap manifest generator
#[async_trait::async_trait]
pub trait ManifestGenerator: Send + Sync {
    /// Generate CNI and operator manifests for a cluster
    ///
    /// Returns Cilium CNI manifests and operator deployment (namespace, RBAC,
    /// ServiceAccount, Deployment). Called by `generate_bootstrap_bundle()` which
    /// adds LB-IPAM, provider addons, and LatticeCluster CRD/instance on top.
    ///
    /// This is an async function to avoid blocking the tokio runtime during
    /// helm template execution for Cilium manifests.
    async fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, super::errors::BootstrapError>;
}

/// Configuration for generating a complete bootstrap bundle
///
/// The bootstrap bundle includes only what's essential for the cluster to start:
/// - CNI (Cilium)
/// - Operator deployment + namespace + RBAC
/// - LB-IPAM resources (if configured)
/// - Provider addons (CCM, CSI, local-path-provisioner, cluster-autoscaler)
/// - LatticeCluster CRD definition + instance
///
/// Infrastructure components (Istio, ESO, Velero, VictoriaMetrics, KEDA, GPU stack)
/// are deferred to operator startup via `ensure_infrastructure()`.
#[derive(Debug, Clone)]
pub struct BootstrapBundleConfig<'a> {
    pub facts: &'a ClusterFacts,
    pub image: &'a str,
    pub registry_credentials: Option<&'a str>,
    pub api_server_endpoint: &'a ApiServerEndpoint,
}
