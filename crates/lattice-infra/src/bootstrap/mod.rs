//! Phased infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests.
//! Generates a sequence of [`InfraPhase`]s, each containing one or more
//! [`InfraComponent`]s with an optional health gate (namespace whose
//! deployments must be ready before the next phase starts).
//!
//! Used by:
//! - Operator startup: applies phases sequentially with health gates
//! - Cluster controller reconciliation: applies all manifests at once (infra already exists)
//!
//! All Helm charts are pre-rendered at build time and embedded into the binary.

pub mod prometheus;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use kube::ResourceExt;
use tracing::debug;

use lattice_common::kube_utils::split_yaml_documents;
use lattice_common::mesh::{kube_apiserver_egress, mesh_member, namespace_yaml_ambient};
use lattice_common::{
    DEFAULT_AUTH_PROXY_PORT, DEFAULT_WEBHOOK_PORT, LOCAL_SECRETS_PORT, MONITORING_NAMESPACE,
    OPERATOR_NAME, VMAGENT_SA_NAME,
};
use lattice_core::{
    DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT, DEFAULT_PROXY_PORT, LATTICE_SYSTEM_NAMESPACE,
};
use lattice_crd::crd::{
    BackupsConfig, BootstrapProvider, CedarPolicy, CedarPolicySpec, EgressRule, EgressTarget,
    LatticeCluster, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort, MeshMemberTarget,
    MonitoringConfig, NetworkTopologyConfig, PeerAuth, ProviderType, ServiceRef,
};

/// A single infrastructure component with its name, version, and manifests.
#[derive(Debug, Clone)]
pub struct InfraComponent {
    /// Human-readable name (e.g., "istio", "cilium", "cert-manager").
    pub name: &'static str,
    /// Pinned version from versions.toml (embedded at build time).
    pub version: &'static str,
    /// YAML/JSON manifests to apply via server-side apply.
    pub manifests: Vec<String>,
    /// Namespace to health-gate on after apply.
    /// When set, the phase runner waits for all Deployments in this namespace
    /// to be available before moving to the next phase.
    pub health_namespace: Option<&'static str>,
}

/// A group of components applied together.
///
/// All components in a phase are applied (manifests sent to the API server),
/// then all health gates are checked before the next phase begins.
#[derive(Debug, Clone)]
pub struct InfraPhase {
    /// Phase name for logging and status reporting.
    pub name: &'static str,
    /// Components in this phase.
    pub components: Vec<InfraComponent>,
}

impl InfraPhase {
    /// Collect all manifests across all components in this phase.
    pub fn all_manifests(&self) -> Vec<String> {
        self.components
            .iter()
            .flat_map(|c| c.manifests.iter().cloned())
            .collect()
    }

    /// Collect the unique namespaces that need health-gating in this phase.
    pub fn health_namespaces(&self) -> Vec<&'static str> {
        let mut ns: Vec<&'static str> = self
            .components
            .iter()
            .filter_map(|c| c.health_namespace)
            .collect();
        ns.dedup();
        ns
    }
}

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Cluster name used for Istio clusterName / network identity.
    pub cluster_name: String,
    /// Skip Istio, Gateway API CRDs, and mesh-related policies entirely.
    /// True for bootstrap / kind clusters without service workloads.
    pub skip_service_mesh: bool,
    /// Parent cell hostname (None for root/management clusters)
    pub parent_host: Option<String>,
    /// Parent cell gRPC port (used with parent_host)
    pub parent_grpc_port: u16,
    /// Enable GPU infrastructure (NFD + NVIDIA device plugin)
    pub gpu: bool,
    /// Monitoring infrastructure configuration (VictoriaMetrics + KEDA for autoscaling).
    pub monitoring: MonitoringConfig,
    /// Backup infrastructure configuration (Velero).
    pub backups: BackupsConfig,
    /// Network topology configuration for topology-aware scheduling.
    pub network_topology: Option<NetworkTopologyConfig>,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            provider: ProviderType::default(),
            bootstrap: BootstrapProvider::default(),
            cluster_name: String::new(),
            skip_service_mesh: false,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
        }
    }
}

impl From<&LatticeCluster> for InfrastructureConfig {
    /// Create an InfrastructureConfig from a LatticeCluster.
    ///
    /// NOTE: Does NOT set parent_host — that comes from the
    /// `lattice-parent-config` Secret (the upstream parent this cluster
    /// connects to), not from `parent_config` (which is for this cluster's
    /// own cell server endpoints).
    fn from(cluster: &LatticeCluster) -> Self {
        Self {
            provider: cluster.spec.provider.provider_type(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            cluster_name: cluster.name_any(),
            skip_service_mesh: !cluster.spec.services,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
            gpu: cluster.spec.gpu,
            monitoring: cluster.spec.monitoring.clone(),
            backups: cluster.spec.backups.clone(),
            network_topology: cluster.spec.network_topology.clone(),
        }
    }
}

/// Read remote network names from LatticeClusterRoutes CRDs.
///
/// Returns `Some(names)` on success, `None` if CRDs can't be listed
/// (e.g., CRD not registered during startup). When `None`, callers
/// should leave `remote_networks` unset so SSA preserves existing
/// meshNetworks in the ConfigMap.
pub async fn discover_remote_networks(client: &kube::Client) -> Option<Vec<String>> {
    use lattice_crd::crd::LatticeClusterRoutes;

    let routes_api: kube::Api<LatticeClusterRoutes> = kube::Api::all(client.clone());
    match routes_api.list(&kube::api::ListParams::default()).await {
        Ok(routes_list) => Some(
            routes_list
                .items
                .iter()
                .filter(|r| !r.spec.routes.is_empty())
                .filter_map(|r| r.metadata.name.clone())
                .collect(),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "failed to list LatticeClusterRoutes, preserving existing meshNetworks");
            None
        }
    }
}

/// Generate infrastructure as a sequence of phases.
///
/// Each phase contains components that can be applied together, with health
/// gates checked between phases. The ordering ensures dependencies are met:
///
/// - Phase 0 "cert-manager": must be ready before CAPI and webhook-dependent components
/// - Phase 1 "service-mesh": Istio + Cilium + Gateway API CRDs
/// - Phase 2 "core": ESO, Volcano, Kthena, Tetragon (always installed)
/// - Phase 3 "monitoring": VictoriaMetrics + KEDA + metrics-server (conditional)
/// - Phase 4 "gpu": GPU operator (conditional)
/// - Phase 5 "backup": Velero (conditional)
pub fn generate_phases(config: &InfrastructureConfig) -> Result<Vec<InfraPhase>, String> {
    let mut phases = Vec::new();

    // Phase 1: service mesh (Istio + Cilium policies + Gateway API CRDs)
    if !config.skip_service_mesh {
        let gw_api = generate_gateway_api_crds();
        debug!(count = gw_api.len(), "generated Gateway API CRDs");

        let mut operator_manifests = vec![namespace_yaml_ambient(LATTICE_SYSTEM_NAMESPACE)];
        operator_manifests.extend(serialize_lmms(vec![generate_operator_mesh_member()])?);

        phases.push(InfraPhase {
            name: "service-mesh",
            components: vec![
                InfraComponent {
                    name: "gateway-api",
                    version: env!("GATEWAY_API_VERSION"),
                    manifests: gw_api.to_vec(),
                    health_namespace: None,
                },
                InfraComponent {
                    name: "operator-mesh-enrollment",
                    version: "1",
                    manifests: operator_manifests,
                    health_namespace: None,
                },
            ],
        });
    }

    // cluster-access Cedar policy (for peer route proxy) rides along with the
    // service-mesh phase when mesh is enabled.
    if !config.skip_service_mesh {
        phases.push(InfraPhase {
            name: "cluster-access-policy",
            components: vec![InfraComponent {
                name: "cluster-access-policy",
                version: "1",
                manifests: vec![serde_json::to_string_pretty(
                    &generate_cluster_access_cedar_policy(),
                )
                .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?],
                health_namespace: None,
            }],
        });
    }

    // Phase 3: monitoring (conditional)
    if config.monitoring.enabled {
        let mut components = vec![InfraComponent {
            name: "victoria-metrics",
            version: prometheus::victoria_metrics_version(),
            manifests: prometheus::generate_prometheus(config.monitoring.ha).to_vec(),
            health_namespace: Some("monitoring"),
        }];

        // Mesh policies for the VictoriaMetrics stack (vmagent wildcard Cedar +
        // LMMs for vmagent/vm-read-target). KEDA's LMMs moved to its install crate.
        if !config.skip_service_mesh {
            let mut mesh_manifests = Vec::new();
            mesh_manifests.extend(serialize_lmms(
                prometheus::generate_monitoring_mesh_members(config.monitoring.ha),
            )?);
            mesh_manifests.push(
                serde_json::to_string_pretty(&generate_vmagent_cedar_policy())
                    .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?,
            );

            components.push(InfraComponent {
                name: "monitoring-mesh-policies",
                version: prometheus::victoria_metrics_version(),
                manifests: mesh_manifests,
                health_namespace: None,
            });
        }

        phases.push(InfraPhase {
            name: "monitoring",
            components,
        });
    }

    Ok(phases)
}

/// Flatten all phases into a single manifest list.
///
/// Used by the cluster controller for reconciliation (infra already exists,
/// just ensuring desired state — no need for phased application).
pub fn flatten_manifests(phases: &[InfraPhase]) -> Vec<String> {
    phases.iter().flat_map(|p| p.all_manifests()).collect()
}

/// Generate all infrastructure manifests as a flat list.
///
/// Convenience wrapper around [`generate_phases`] + [`flatten_manifests`]
/// for call sites that don't need phased application.
pub fn generate_all_manifests(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let phases = generate_phases(config)?;
    Ok(flatten_manifests(&phases))
}

// ---- Phase application ----

/// Timeout for deployment health gates between phases.
const HEALTH_GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Apply a single phase: send manifests to the API server, then wait for health gates.
pub async fn apply_phase(client: &kube::Client, phase: &InfraPhase) -> anyhow::Result<()> {
    use lattice_common::kube_utils;
    use lattice_common::retry::{retry_with_backoff, RetryConfig};
    use lattice_common::{apply_manifests, ApplyOptions};

    let manifests = phase.all_manifests();
    tracing::info!(
        phase = phase.name,
        components = phase.components.len(),
        manifests = manifests.len(),
        "Applying infrastructure phase"
    );

    let retry = RetryConfig {
        initial_delay: std::time::Duration::from_secs(2),
        ..RetryConfig::default()
    };
    retry_with_backoff(&retry, phase.name, || {
        let client = client.clone();
        let manifests = manifests.clone();
        async move { apply_manifests(&client, &manifests, &ApplyOptions::default()).await }
    })
    .await?;

    for ns in phase.health_namespaces() {
        tracing::info!(phase = phase.name, namespace = ns, "Waiting for deployments");
        kube_utils::wait_for_all_deployments(client, ns, HEALTH_GATE_TIMEOUT)
            .await
            .map_err(|e| anyhow::anyhow!("{} health gate failed ({}): {}", phase.name, ns, e))?;
    }

    tracing::info!(phase = phase.name, "Phase complete");
    Ok(())
}

/// Apply all phases sequentially, waiting for health gates between each phase.
pub async fn apply_all_phases(client: &kube::Client, phases: &[InfraPhase]) -> anyhow::Result<()> {
    for phase in phases {
        apply_phase(client, phase).await?;
    }
    Ok(())
}

// ---- Helpers ----

/// Pre-rendered Gateway API CRDs embedded at build time.
static GATEWAY_API_CRDS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gateway-api-crds.yaml"
    )))
});

/// Generate Gateway API CRDs
pub fn generate_gateway_api_crds() -> &'static [String] {
    &GATEWAY_API_CRDS
}

/// Generate a LatticeMeshMember for the lattice-operator itself.
///
/// Enrolls the operator in the ambient mesh so ESO (also ambient) can reach
/// the local-secrets webhook via proper HBONE/mTLS instead of an FQDN egress
/// hack. Ports 8443 (bootstrap webhook) and 50051 (agent gRPC) use Webhook
/// PeerAuth because their callers lack mesh identity.
pub fn generate_operator_mesh_member() -> LatticeMeshMember {
    mesh_member(
        OPERATOR_NAME,
        LATTICE_SYSTEM_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                OPERATOR_NAME.to_string(),
            )])),
            ports: vec![
                MeshMemberPort {
                    port: DEFAULT_WEBHOOK_PORT,
                    service_port: None,
                    name: "validation-webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_BOOTSTRAP_PORT,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_GRPC_PORT,
                    service_port: None,
                    name: "grpc".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_PROXY_PORT,
                    service_port: None,
                    name: "proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_AUTH_PROXY_PORT,
                    service_port: None,
                    name: "auth-proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: LOCAL_SECRETS_PORT,
                    service_port: None,
                    name: "local-secrets".to_string(),
                    peer_auth: PeerAuth::Strict,
                },
            ],
            allowed_callers: vec![ServiceRef::new("external-secrets", "external-secrets")],
            dependencies: vec![ServiceRef::new(MONITORING_NAMESPACE, "vm-read-target")],
            egress: vec![
                kube_apiserver_egress(),
                // Agent connects outbound to parent cell's gRPC and bootstrap ports
                EgressRule::tcp(
                    EgressTarget::Entity("world".to_string()),
                    vec![DEFAULT_GRPC_PORT, DEFAULT_BOOTSTRAP_PORT],
                ),
                // Helm pulls OCI charts from container registries (HTTPS)
                EgressRule::tcp(EgressTarget::Entity("world".to_string()), vec![443]),
            ],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true,
            advertise: None,
        },
    )
}

/// Generate the CedarPolicy that permits vmagent's wildcard outbound.
///
/// vmagent uses `depends_all: true` to scrape metrics from any service that
/// exposes a "metrics" port. This Cedar policy authorizes that wildcard.
fn generate_vmagent_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "vmagent-wildcard-outbound",
        CedarPolicySpec {
            description: Some("Allow vmagent wildcard outbound for metrics scraping".to_string()),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{}/{}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);"#,
                MONITORING_NAMESPACE, VMAGENT_SA_NAME,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Generate the CedarPolicy that grants cluster access for peer route sync.
/// Child clusters use tokens minted as lattice-operator to access the
/// parent's auth proxy for multi-cluster routing.
pub fn generate_cluster_access_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "proxy-cluster-access",
        CedarPolicySpec {
            description: Some("Cluster access for lattice-operator peer route proxy".to_string()),
            policies: r#"permit(
    principal == Lattice::User::"system:serviceaccount:lattice-system:lattice-operator",
    action == Lattice::Action::"AccessCluster",
    resource
);"#
            .to_string(),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Generate the CedarPolicy that grants full admin access to the lattice-admin SA.
pub fn generate_admin_access_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "lattice-admin-access",
        CedarPolicySpec {
            description: Some("Full admin access for lattice-admin SA".to_string()),
            policies: r#"permit(
    principal == Lattice::User::"system:serviceaccount:lattice-system:lattice-admin",
    action,
    resource
);"#
            .to_string(),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Serialize a vec of LMMs to JSON manifests.
fn serialize_lmms(members: Vec<LatticeMeshMember>) -> Result<Vec<String>, String> {
    members
        .iter()
        .map(|m| {
            serde_json::to_string_pretty(m)
                .map_err(|e| format!("Failed to serialize LatticeMeshMember: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_api_crds() {
        let crds = generate_gateway_api_crds();
        assert!(!crds.is_empty());
        assert!(crds.iter().any(|c| c.contains("CustomResourceDefinition")));
    }

    #[test]
    fn generate_phases_default_config() {
        let config = InfrastructureConfig::default();
        let phases = generate_phases(&config).expect("should generate phases");

        for phase in &phases {
            assert!(
                !phase.components.is_empty(),
                "phase {} is empty",
                phase.name
            );
            for comp in &phase.components {
                assert!(
                    !comp.manifests.is_empty(),
                    "component {} has no manifests",
                    comp.name
                );
                assert!(
                    !comp.version.is_empty(),
                    "component {} has no version",
                    comp.name
                );
            }
        }
    }

    #[test]
    fn generate_phases_with_monitoring() {
        let config = InfrastructureConfig {
            monitoring: MonitoringConfig {
                enabled: true,
                ha: false,
            },
            ..Default::default()
        };
        let phases = generate_phases(&config).expect("should generate phases");
        assert!(
            phases.iter().any(|p| p.name == "monitoring"),
            "should include monitoring phase"
        );
    }

    #[test]
    fn generate_phases_without_monitoring() {
        let config = InfrastructureConfig {
            monitoring: MonitoringConfig {
                enabled: false,
                ha: false,
            },
            ..Default::default()
        };
        let phases = generate_phases(&config).expect("should generate phases");
        assert!(
            !phases.iter().any(|p| p.name == "monitoring"),
            "should not include monitoring phase"
        );
    }

    #[test]
    fn generate_all_manifests_matches_flatten() {
        let config = InfrastructureConfig::default();
        let all = generate_all_manifests(&config).expect("should generate");
        let phases = generate_phases(&config).expect("should generate");
        let flattened = flatten_manifests(&phases);
        assert_eq!(all.len(), flattened.len());
    }

    #[test]
    fn operator_mesh_member_generated() {
        let member = generate_operator_mesh_member();
        assert_eq!(member.metadata.name.as_deref(), Some("lattice-operator"));
        assert_eq!(
            member.metadata.namespace.as_deref(),
            Some(LATTICE_SYSTEM_NAMESPACE)
        );
        assert!(member.spec.validate().is_ok());
        assert!(member.spec.ambient);

        // 6 ports: validation-webhook (9443), webhook (8443), grpc (50051), proxy (8081), auth-proxy (8082), local-secrets (8787)
        assert_eq!(member.spec.ports.len(), 6);

        let webhook = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "webhook")
            .expect("webhook port");
        assert_eq!(webhook.port, DEFAULT_BOOTSTRAP_PORT);
        assert_eq!(webhook.peer_auth, PeerAuth::Webhook);

        let grpc = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "grpc")
            .expect("grpc port");
        assert_eq!(grpc.port, DEFAULT_GRPC_PORT);
        assert_eq!(grpc.peer_auth, PeerAuth::Webhook);

        let proxy = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "proxy")
            .expect("proxy port");
        assert_eq!(proxy.port, DEFAULT_PROXY_PORT);
        assert_eq!(proxy.peer_auth, PeerAuth::Webhook);

        let auth_proxy = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "auth-proxy")
            .expect("auth-proxy port");
        assert_eq!(auth_proxy.port, DEFAULT_AUTH_PROXY_PORT);
        assert_eq!(auth_proxy.peer_auth, PeerAuth::Webhook);

        let secrets = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "local-secrets")
            .expect("local-secrets port");
        assert_eq!(secrets.port, LOCAL_SECRETS_PORT);
        assert_eq!(secrets.peer_auth, PeerAuth::Strict);

        // ESO is the only allowed caller
        assert_eq!(member.spec.allowed_callers.len(), 1);
        assert_eq!(member.spec.allowed_callers[0].name, "external-secrets");
        assert_eq!(
            member.spec.allowed_callers[0].namespace.as_deref(),
            Some("external-secrets")
        );
    }

    #[test]
    fn service_mesh_phase_includes_operator_enrollment() {
        let config = InfrastructureConfig::default();
        let phases = generate_phases(&config).expect("should generate phases");

        let mesh_phase = phases
            .iter()
            .find(|p| p.name == "service-mesh")
            .expect("service-mesh phase should exist");
        assert!(
            mesh_phase
                .components
                .iter()
                .any(|c| c.name == "operator-mesh-enrollment"),
            "service-mesh phase should include operator mesh enrollment"
        );
    }

}
