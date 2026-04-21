//! Basis infrastructure provider
//!
//! Generates Cluster API manifests for Kubernetes clusters backed by
//! Basis, our minimal bare-metal VM scheduler. The cluster-creation
//! flow is two-stage because Basis allocates the API-server VIP
//! server-side:
//!
//! 1. First reconcile pass — `BootstrapInfo.control_plane_endpoint` is
//!    `None`. Emit the infrastructure graph (`Cluster`, `BasisCluster`,
//!    `BasisMachineTemplate`, `MachineDeployment`,
//!    `KubeadmConfigTemplate`). Applying `BasisCluster` is what
//!    triggers basis-capi-provider to call `Basis.CreateCluster`, which
//!    allocates the VIP and writes it back to
//!    `BasisCluster.spec.controlPlaneEndpoint`.
//! 2. Second reconcile pass — the LatticeCluster reconciler picks up
//!    the endpoint and populates `bootstrap.control_plane_endpoint`.
//!    This generator now also emits `KubeadmControlPlane` with a
//!    kube-vip static pod wired to that address and the VIP in
//!    `certSANs`. Server-Side Apply lands the KCP; the rest of the
//!    graph is byte-identical to pass 1, so no churn.
//!
//! kube-vip itself is unchanged: a static pod inside each control-
//! plane guest that claims the VIP via ARP leader election, same as
//! Proxmox / OpenStack. The only difference is who picks the address.

use async_trait::async_trait;

use super::{
    build_cert_sans, build_post_kubeadm_commands, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix,
    validate_k8s_version, BootstrapInfo, CAPIManifest, ClusterConfig, ControlPlaneConfig,
    InfrastructureRef, Provider, VipConfig, WorkerPoolConfig,
};
use crate::constants::{BASIS_API_VERSION, DEFAULT_VIP_INTERFACE_BASIS, INFRASTRUCTURE_API_GROUP};
use lattice_common::{Error, Result, BASIS_CREDENTIALS_SECRET, LOCAL_SECRETS_NAMESPACE};
use lattice_crd::crd::{BasisConfig, InstanceType, LatticeCluster, ProviderSpec, ProviderType};

/// VM sizing for a BasisMachineTemplate.
struct MachineSizing {
    cpu: u32,
    memory_mib: u32,
    disk_gib: u32,
}

impl MachineSizing {
    fn from_instance_type(instance_type: &Option<InstanceType>, default_disk_gib: u32) -> Self {
        instance_type
            .as_ref()
            .and_then(|it| it.as_resources())
            .map(|r| Self {
                cpu: r.cores,
                memory_mib: r.memory_gib * 1024,
                disk_gib: r.disk_gib,
            })
            .unwrap_or(Self {
                cpu: 4,
                memory_mib: 8192,
                disk_gib: default_disk_gib,
            })
    }
}

/// Derive the VM rootfs image from the cluster's Kubernetes version.
///
/// Lattice publishes a matching node image per K8s version, so there is
/// nothing for users to configure — the provider picks the right image
/// automatically.
fn node_image_for(k8s_version: &str) -> String {
    let v = k8s_version.trim_start_matches('v');
    format!("ghcr.io/evan-hines-js/lattice-node:v{}", v)
}

/// Basis infrastructure provider
#[derive(Clone, Debug)]
pub struct BasisProvider {
    namespace: String,
}

impl BasisProvider {
    /// Create a new Basis provider with the given CAPI namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: INFRASTRUCTURE_API_GROUP,
            api_version: BASIS_API_VERSION,
            cluster_kind: "BasisCluster",
            machine_template_kind: "BasisMachineTemplate",
        }
    }

    fn get_config(cluster: &LatticeCluster) -> Option<&BasisConfig> {
        cluster.spec.provider.config.basis.as_ref()
    }

    /// Generate the BasisCluster manifest.
    ///
    /// The spec carries exactly what the user-facing config declares:
    /// the IP pool and the credentials Secret reference. The control-
    /// plane endpoint is absent — the basis-capi-provider reconciler
    /// allocates a VIP from the pool's vip sub-range and writes it
    /// back to `spec.controlPlaneEndpoint`. A separate Lattice
    /// reconciler patches the `KubeadmControlPlane` once that value
    /// appears, injecting kube-vip files and the VIP cert SAN.
    fn generate_basis_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("basis config required"))?;

        Ok(
            CAPIManifest::new(BASIS_API_VERSION, "BasisCluster", name, &self.namespace).with_spec(
                serde_json::json!({
                    "ipPool": &cfg.ipv4_pool,
                    "credentialsRef": {
                        "name": BASIS_CREDENTIALS_SECRET,
                        "namespace": LOCAL_SECRETS_NAMESPACE,
                    },
                }),
            ),
        )
    }

    /// Generate a BasisMachineTemplate manifest (used for both CP and workers).
    fn generate_machine_template(
        &self,
        cluster_name: &str,
        sizing: MachineSizing,
        image: &str,
        suffix: &str,
    ) -> CAPIManifest {
        CAPIManifest::new(
            BASIS_API_VERSION,
            "BasisMachineTemplate",
            format!("{}-{}", cluster_name, suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({
            "template": {
                "spec": {
                    "cpu": sizing.cpu,
                    "memoryMib": sizing.memory_mib,
                    "diskGib": sizing.disk_gib,
                    "image": image,
                }
            }
        }))
    }
}

#[async_trait]
impl Provider for BasisProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = get_cluster_name(cluster)?;
        let spec = &cluster.spec;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("basis config required"))?;

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version: &spec.provider.kubernetes.version,
            labels: create_cluster_labels(name),
            bootstrap: spec.provider.kubernetes.bootstrap.clone(),
            provider_type: ProviderType::Basis,
            registry_mirrors: bootstrap.registry_mirrors.clone(),
        };

        let infra = self.infra_ref();
        let image = node_image_for(&spec.provider.kubernetes.version);
        let cp_sizing =
            MachineSizing::from_instance_type(&spec.nodes.control_plane.instance_type, 40);

        // Pre-control-plane manifests — safe to apply without knowing
        // the API-server VIP. BasisCluster is what triggers basis-capi-
        // provider to call `Basis.CreateCluster`, which allocates the
        // VIP and writes it back to `BasisCluster.spec.controlPlaneEndpoint`.
        let mut manifests = vec![
            generate_cluster(&config, &infra),
            self.generate_basis_cluster(cluster)?,
            self.generate_machine_template(name, cp_sizing, &image, "control-plane"),
        ];

        // KubeadmControlPlane carries kube-vip's static pod manifest
        // and the VIP cert SAN. Emit it only once we know the endpoint
        // (populated by the reconciler after basis allocates). On
        // first-pass reconcile this branch is skipped; the requeue
        // picks it up on the next pass and SSA lands the KCP without
        // disturbing the rest of the graph.
        if let Some(endpoint) = bootstrap.control_plane_endpoint.as_deref() {
            let mut cert_sans = build_cert_sans(cluster);
            if !cert_sans.iter().any(|s| s == endpoint) {
                cert_sans.push(endpoint.to_string());
            }
            let vip = Some(VipConfig::new(
                endpoint.to_string(),
                Some(
                    cfg.virtual_ip_network_interface
                        .clone()
                        .unwrap_or_else(|| DEFAULT_VIP_INTERFACE_BASIS.to_string()),
                ),
                cfg.kube_vip_image.clone(),
            ));
            let cp_config = ControlPlaneConfig {
                replicas: spec.nodes.control_plane.replicas,
                cert_sans,
                post_kubeadm_commands: build_post_kubeadm_commands(name, bootstrap)?,
                vip,
                ssh_authorized_keys: Vec::new(),
                registry_mirrors: bootstrap.registry_mirrors.clone(),
            };
            manifests.push(generate_control_plane(&config, &infra, &cp_config)?);
        }

        for (pool_id, pool_spec) in &spec.nodes.worker_pools {
            let pool_config = WorkerPoolConfig {
                pool_id,
                spec: pool_spec,
            };
            let suffix = pool_resource_suffix(pool_id);
            let worker_sizing = MachineSizing::from_instance_type(&pool_spec.instance_type, 80);

            manifests.push(generate_machine_deployment_for_pool(
                &config,
                &infra,
                &pool_config,
            ));
            manifests.push(self.generate_machine_template(name, worker_sizing, &image, &suffix));
            manifests.push(generate_bootstrap_config_template_for_pool(
                &config,
                &pool_config,
            ));
        }

        Ok(manifests)
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        validate_k8s_version(&spec.kubernetes.version)?;
        let cfg = spec
            .config
            .basis
            .as_ref()
            .ok_or_else(|| Error::validation("basis config required"))?;
        if cfg.ipv4_pool.trim().is_empty() {
            return Err(Error::validation("basis.ipv4Pool must not be empty"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_crd::crd::{
        BackupsConfig, BootstrapProvider, ControlPlaneSpec, KubernetesSpec, LatticeClusterSpec,
        MonitoringConfig, NodeResourceSpec, NodeSpec, ProviderConfig, WorkerPoolSpec,
    };

    fn test_basis_config() -> BasisConfig {
        BasisConfig {
            ipv4_pool: "default".to_string(),
            virtual_ip_network_interface: None,
            kube_vip_image: None,
            lb_cidr: None,
        }
    }

    /// Populate a BootstrapInfo with the simulated basis-allocated VIP
    /// so `generate_capi_manifests` emits the KCP branch under test.
    fn test_bootstrap_with_endpoint() -> BootstrapInfo {
        BootstrapInfo {
            control_plane_endpoint: Some("10.0.0.210".to_string()),
            ..Default::default()
        }
    }

    fn test_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "basis".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::basis(test_basis_config()),
                },
                nodes: NodeSpec {
                    control_plane: ControlPlaneSpec {
                        replicas: 1,
                        instance_type: Some(InstanceType::resources(NodeResourceSpec {
                            cores: 4,
                            memory_gib: 8,
                            disk_gib: 40,
                            sockets: 1,
                        })),
                        root_volume: None,
                    },
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 2,
                            instance_type: Some(InstanceType::resources(NodeResourceSpec {
                                cores: 4,
                                memory_gib: 8,
                                disk_gib: 80,
                                sockets: 1,
                            })),
                            ..Default::default()
                        },
                    )]),
                },
                parent_config: None,

                services: true,
                gpu: false,
                monitoring: MonitoringConfig::default(),
                backups: BackupsConfig::default(),
                network_topology: None,
                registry_mirrors: None,
                issuers: std::collections::BTreeMap::new(),
                lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
                cascade_upgrade: false,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn first_reconcile_pass_omits_control_plane() {
        // Before basis-capi-provider allocates the VIP, BootstrapInfo
        // carries no endpoint — generator emits the infrastructure
        // graph but not the KubeadmControlPlane. The reconciler's next
        // pass (after the endpoint appears) fills it in via SSA.
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("homelab"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let kinds: Vec<_> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"BasisCluster"));
        assert!(kinds.contains(&"BasisMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
        assert!(
            !kinds.contains(&"KubeadmControlPlane"),
            "KCP must wait for the basis-allocated endpoint; it's emitted on the next reconcile pass"
        );
    }

    #[tokio::test]
    async fn second_reconcile_pass_emits_control_plane_with_kube_vip() {
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("homelab"), &test_bootstrap_with_endpoint())
            .await
            .expect("manifest generation should succeed");

        let cp = manifests
            .iter()
            .find(|m| m.kind == "KubeadmControlPlane")
            .expect("KubeadmControlPlane should exist once endpoint is known");
        let cp_json = serde_json::to_string(&cp.spec).expect("serialize cp spec");
        assert!(
            cp_json.contains("kube-vip"),
            "KCP must carry the kube-vip static pod manifest"
        );
        assert!(
            cp_json.contains("10.0.0.210"),
            "kube-vip manifest must carry the basis-allocated endpoint"
        );
    }

    #[tokio::test]
    async fn basis_cluster_carries_pool_and_credentials_ref() {
        // BasisCluster is emitted on the very first reconcile — that's
        // what triggers basis-capi-provider to allocate the VIP. The
        // endpoint is NOT on Lattice's generated spec; the provider
        // reconciler writes it after `Basis.CreateCluster` returns.
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("homelab"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let basis_cluster = manifests
            .iter()
            .find(|m| m.kind == "BasisCluster")
            .expect("BasisCluster should exist");
        let spec = basis_cluster.spec.as_ref().expect("spec should exist");
        assert_eq!(spec["ipPool"], "default");
        assert_eq!(spec["credentialsRef"]["name"], "basis-credentials");
        assert_eq!(spec["credentialsRef"]["namespace"], "lattice-secrets");
        assert!(
            spec.get("controlPlaneEndpoint").is_none(),
            "endpoint is written by basis-capi-provider, not Lattice"
        );
    }

    #[tokio::test]
    async fn machine_template_uses_derived_image_and_resources() {
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("homelab"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");

        let template = manifests
            .iter()
            .find(|m| m.kind == "BasisMachineTemplate")
            .expect("BasisMachineTemplate should exist");
        let spec = &template.spec.as_ref().expect("spec should exist")["template"]["spec"];
        assert_eq!(spec["cpu"], 4);
        assert_eq!(spec["memoryMib"], 8192);
        assert_eq!(spec["diskGib"], 40);
        assert_eq!(spec["image"], "ghcr.io/evan-hines-js/lattice-node:v1.32.0");
    }

    #[tokio::test]
    async fn validate_rejects_empty_ip_pool() {
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::basis(BasisConfig {
                ipv4_pool: "".to_string(),
                virtual_ip_network_interface: None,
                kube_vip_image: None,
                lb_cidr: None,
            }),
        };
        assert!(provider.validate_spec(&spec).await.is_err());
    }

    #[tokio::test]
    async fn validate_rejects_bad_k8s_version() {
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "nonsense".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::basis(test_basis_config()),
        };
        assert!(provider.validate_spec(&spec).await.is_err());
    }
}
