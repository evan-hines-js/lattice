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
//!    allocates the VIP from the cluster's `apiserverVipPool` and
//!    writes it back to `BasisCluster.spec.controlPlaneEndpoint`.
//! 2. Second reconcile pass — the LatticeCluster reconciler picks up
//!    the endpoint and populates `bootstrap.control_plane_endpoint`.
//!    This generator now also emits `KubeadmControlPlane` with a
//!    kube-vip static pod (BGP mode, peering with the basis controller)
//!    and the VIP in `certSANs`.

use async_trait::async_trait;

use super::{
    build_cert_sans, build_post_kubeadm_commands, create_cluster_labels,
    generate_bootstrap_config_template_for_pool, generate_cluster, generate_control_plane,
    generate_machine_deployment_for_pool, get_cluster_name, pool_resource_suffix,
    validate_k8s_version, BootstrapInfo, CAPIManifest, ClusterConfig, ControlPlaneConfig,
    InfrastructureRef, Provider, VipConfig, WorkerPoolConfig,
};
use crate::constants::{BASIS_API_VERSION, BASIS_VIP_INTERFACE, INFRASTRUCTURE_API_GROUP};
use lattice_common::{Error, Result, BASIS_CREDENTIALS_SECRET, LOCAL_SECRETS_NAMESPACE};
use lattice_crd::crd::{BasisConfig, InstanceType, LatticeCluster, ProviderSpec, ProviderType};

/// VM sizing for a BasisMachineTemplate.
struct MachineSizing {
    cpu: u32,
    memory_mib: u32,
    disk_gib: u32,
    /// Raw data disks (GiB each) attached at stable indexes
    /// (`/dev/vdc`, `/dev/vdd`, …) in declaration order.
    data_disk_gibs: Vec<u32>,
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
                data_disk_gibs: r.data_disk_gibs,
            })
            .unwrap_or(Self {
                cpu: 4,
                memory_mib: 8192,
                disk_gib: default_disk_gib,
                data_disk_gibs: Vec::new(),
            })
    }
}

/// Derive the VM rootfs image from the cluster's Kubernetes version.
fn node_image_for(k8s_version: &str) -> String {
    let v = k8s_version.trim_start_matches('v');
    format!("ghcr.io/evan-hines-js/lattice-node:v{}", v)
}

#[derive(Clone, Debug)]
pub struct BasisProvider {
    namespace: String,
}

impl BasisProvider {
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

    /// Render the `BasisCluster` CR. Forwards `apiserverVipPool` so the
    /// allocator knows which pool to draw the VIP from.
    fn generate_basis_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("basis config required"))?;

        let pool = cfg.apiserver_vip_pool.as_deref().unwrap_or("cell-internal");
        let spec = serde_json::json!({
            "credentialsRef": {
                "name": BASIS_CREDENTIALS_SECRET,
                "namespace": LOCAL_SECRETS_NAMESPACE,
            },
            "apiserverVipPool": pool,
        });

        Ok(
            CAPIManifest::new(BASIS_API_VERSION, "BasisCluster", name, &self.namespace)
                .with_spec(spec),
        )
    }

    /// Render a `BasisMachineTemplate`. Basis VMs are single-homed on
    /// the per-cluster VXLAN overlay; the host-side BGP reflector
    /// advertises VIPs and LB /32s with itself as next-hop, so the
    /// guest doesn't need a LAN NIC.
    fn generate_machine_template(
        &self,
        cluster_name: &str,
        sizing: MachineSizing,
        image: &str,
        suffix: &str,
    ) -> CAPIManifest {
        let mut spec = serde_json::json!({
            "cpu": sizing.cpu,
            "memoryMib": sizing.memory_mib,
            "diskGib": sizing.disk_gib,
            "image": image,
        });
        if !sizing.data_disk_gibs.is_empty() {
            spec["extraDiskGibs"] = serde_json::json!(sizing.data_disk_gibs);
        }
        CAPIManifest::new(
            BASIS_API_VERSION,
            "BasisMachineTemplate",
            format!("{}-{}", cluster_name, suffix),
            &self.namespace,
        )
        .with_spec(serde_json::json!({ "template": { "spec": spec } }))
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

        // Pre-control-plane manifests — safe to apply without the VIP.
        // Applying `BasisCluster` is what triggers basis-capi-provider
        // to call `Basis.CreateCluster`, which allocates the VIP.
        let mut manifests = vec![
            generate_cluster(&config, &infra),
            self.generate_basis_cluster(cluster)?,
            self.generate_machine_template(name, cp_sizing, &image, "control-plane"),
        ];

        // KubeadmControlPlane carries kube-vip's static pod manifest
        // (BGP mode, peering with the basis controller) and the VIP
        // cert SAN. Emit it only once we know the endpoint.
        if let Some(endpoint) = bootstrap.control_plane_endpoint.as_deref() {
            let mut cert_sans = build_cert_sans(cluster);
            if !cert_sans.iter().any(|s| s == endpoint) {
                cert_sans.push(endpoint.to_string());
            }
            let vip = Some(VipConfig::bgp(
                endpoint.to_string(),
                cfg.bgp_peer.asn,
                cfg.bgp_peer.asn,
                cfg.bgp_peer.address.clone(),
                BASIS_VIP_INTERFACE.to_string(),
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
        spec.config
            .basis
            .as_ref()
            .ok_or_else(|| Error::validation("basis config required"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_crd::crd::{
        AddressPoolBinding, BackupsConfig, BgpPeer, BootstrapProvider, ControlPlaneSpec,
        KubernetesSpec, LatticeClusterSpec, MonitoringConfig, NodeResourceSpec, NodeSpec,
        ProviderConfig, WorkerPoolSpec,
    };

    fn test_basis_config() -> BasisConfig {
        BasisConfig {
            bgp_peer: BgpPeer {
                address: "10.0.0.1".to_string(),
                asn: 64500,
            },
            address_pools: vec![AddressPoolBinding {
                name: "cell-internal".to_string(),
                cidr: "10.255.4.16/28".to_string(),
            }],
            apiserver_vip_pool: None,
            kube_vip_image: None,
        }
    }

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
                            data_disk_gibs: Vec::new(),
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
                                data_disk_gibs: Vec::new(),
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
        let provider = BasisProvider::with_namespace("capi-basis-system");
        let manifests = provider
            .generate_capi_manifests(&test_cluster("homelab"), &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");
        let kinds: Vec<_> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"BasisCluster"));
        assert!(kinds.contains(&"BasisMachineTemplate"));
        assert!(!kinds.contains(&"KubeadmControlPlane"));
    }

    #[tokio::test]
    async fn second_reconcile_pass_emits_control_plane_with_kube_vip() {
        let provider = BasisProvider::with_namespace("default");
        let cluster = test_cluster("basis-mgmt");
        let bootstrap = test_bootstrap_with_endpoint();
        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .expect("manifest generation should succeed");
        assert!(manifests.iter().any(|m| m.kind == "KubeadmControlPlane"));
        let kcp = manifests
            .iter()
            .find(|m| m.kind == "KubeadmControlPlane")
            .unwrap();
        let json = serde_json::to_string(&kcp.spec).unwrap();
        assert!(json.contains("bgp_enable"), "kube-vip in BGP mode: {json}");
        assert!(json.contains("bgp_as"));
        assert!(json.contains("bgp_peeraddress"));
        assert!(json.contains("64500"));
        assert!(!json.contains("vip_arp"), "no ARP path on basis: {json}");
    }

    #[tokio::test]
    async fn basis_cluster_carries_apiserver_vip_pool() {
        let provider = BasisProvider::with_namespace("default");
        let cluster = test_cluster("basis-wkr");
        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");
        let bc = manifests
            .iter()
            .find(|m| m.kind == "BasisCluster")
            .unwrap();
        let json = serde_json::to_string(&bc.spec).unwrap();
        assert!(json.contains(r#""apiserverVipPool":"cell-internal""#));
        assert!(!json.contains("controlPlaneEdge"));
    }
}
