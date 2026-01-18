//! Proxmox VE infrastructure provider (CAPMOX)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Proxmox Virtual Environment using the CAPMOX provider.
//!
//! CAPMOX API: infrastructure.cluster.x-k8s.io/v1alpha1

use async_trait::async_trait;
use std::collections::BTreeMap;

use super::{
    build_post_kubeadm_commands, generate_bootstrap_config_template, generate_cluster,
    generate_control_plane, generate_machine_deployment, BootstrapInfo, CAPIManifest,
    ClusterConfig, ControlPlaneConfig, InfrastructureRef, Provider, VipConfig,
};
use crate::crd::{LatticeCluster, ProviderSpec, ProviderType, ProxmoxConfig};
use crate::{Error, Result};

/// CAPMOX API version
const PROXMOX_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1alpha1";

/// Default network interface for Proxmox VMs with virtio
const DEFAULT_VIP_INTERFACE: &str = "ens18";

/// Proxmox VE infrastructure provider
///
/// Generates CAPI manifests for Proxmox using the CAPMOX provider.
/// Supports both kubeadm and RKE2 bootstrap providers.
#[derive(Clone, Debug)]
pub struct ProxmoxProvider {
    /// Namespace for CAPI resources
    namespace: String,
}

impl ProxmoxProvider {
    /// Create a new Proxmox provider with the given namespace
    pub fn with_namespace(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    /// Get infrastructure reference for Proxmox
    fn infra_ref(&self) -> InfrastructureRef<'static> {
        InfrastructureRef {
            api_group: "infrastructure.cluster.x-k8s.io",
            api_version: PROXMOX_API_VERSION,
            cluster_kind: "ProxmoxCluster",
            machine_template_kind: "ProxmoxMachineTemplate",
        }
    }

    /// Extract ProxmoxConfig from the cluster's provider config
    fn get_proxmox_config(cluster: &LatticeCluster) -> Option<&ProxmoxConfig> {
        cluster.spec.provider.config.proxmox.as_ref()
    }

    /// Generate ProxmoxCluster manifest
    ///
    /// IP addresses are configured in ipv4Config with a range string (e.g., "10.0.0.101-10.0.0.120").
    /// CAPMOX handles IP allocation from this range internally.
    fn generate_proxmox_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let cfg = Self::get_proxmox_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required".to_string()))?;

        // DNS servers
        let dns_servers = cfg
            .dns_servers
            .clone()
            .unwrap_or_else(|| vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]);

        // Allowed nodes (Proxmox cluster nodes that can host VMs)
        let allowed_nodes = cfg.allowed_nodes.clone().unwrap_or_default();

        let control_plane_endpoint = serde_json::json!({
            "host": &cfg.control_plane_endpoint,
            "port": 6443
        });

        // Build spec with ipv4Config - CAPMOX handles IP allocation from this range
        // Format: "start-end" range string (e.g., "10.0.0.101-10.0.0.120")
        let ip_range = format!("{}-{}", cfg.ipv4_pool.start, cfg.ipv4_pool.end);
        let mut spec_json = serde_json::json!({
            "controlPlaneEndpoint": control_plane_endpoint,
            "dnsServers": dns_servers,
            "allowedNodes": allowed_nodes,
            "ipv4Config": {
                "addresses": [ip_range],
                "prefix": cfg.ipv4_pool.prefix,
                "gateway": &cfg.ipv4_pool.gateway
            },
            "credentialsRef": {
                "name": cfg.secret_ref.as_ref().map(|s| s.name.clone())
                    .unwrap_or_else(|| "proxmox-credentials".to_string()),
                "namespace": &self.namespace
            }
        });

        // Add scheduler hints if memory adjustment is specified
        if let Some(memory_adj) = cfg.memory_adjustment {
            spec_json["schedulerHints"] = serde_json::json!({
                "memoryAdjustment": memory_adj
            });
        }

        Ok(
            CAPIManifest::new(PROXMOX_API_VERSION, "ProxmoxCluster", name, &self.namespace)
                .with_spec(spec_json),
        )
    }

    /// Generate ProxmoxMachineTemplate for control plane nodes
    fn generate_cp_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let cfg = Self::get_proxmox_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required".to_string()))?;

        let storage = cfg.storage.clone().unwrap_or_else(|| "local-lvm".to_string());
        let bridge = cfg.bridge.clone().unwrap_or_else(|| "vmbr0".to_string());
        let format = cfg.format.clone().unwrap_or_else(|| "qcow2".to_string());
        let full_clone = cfg.full_clone.unwrap_or(true);
        let network_model = cfg.network_model.clone().unwrap_or_else(|| "virtio".to_string());
        let cp_sockets = cfg.cp_sockets.unwrap_or(1);

        // Build network config - CAPMOX assigns IPs from ProxmoxCluster's ipv4Config
        let mut network_default = serde_json::json!({
            "bridge": bridge,
            "model": network_model
        });

        // Add VLAN if specified
        if let Some(vlan) = cfg.vlan {
            network_default["vlan"] = serde_json::json!(vlan);
        }

        // Build template spec
        let mut template_spec = serde_json::json!({
            "format": format,
            "full": full_clone,
            "storage": storage,
            "numSockets": cp_sockets,
            "numCores": cfg.cp_cores,
            "memoryMiB": cfg.cp_memory_mib,
            "disks": {
                "bootVolume": {
                    "disk": "scsi0",
                    "sizeGb": cfg.cp_disk_size_gb
                }
            },
            "network": {
                "default": network_default
            }
        });

        // sourceNode is optional - only needed if template is on local storage
        if let Some(ref node) = cfg.source_node {
            template_spec["sourceNode"] = serde_json::json!(node);
        }

        // Add templateID or templateSelector
        if let Some(ref tags) = cfg.template_tags {
            template_spec["templateSelector"] = serde_json::json!({
                "matchTags": tags
            });
        } else {
            template_spec["templateID"] = serde_json::json!(cfg.template_id.unwrap_or(9000));
        }

        // Optional fields
        if let Some(ref snap) = cfg.snap_name {
            template_spec["snapName"] = serde_json::json!(snap);
        }
        if let Some(ref target) = cfg.target_node {
            template_spec["target"] = serde_json::json!(target);
        }
        if let Some(ref pool) = cfg.pool {
            template_spec["pool"] = serde_json::json!(pool);
        }
        if let Some(ref desc) = cfg.description {
            template_spec["description"] = serde_json::json!(desc);
        }
        if let Some(ref tags) = cfg.tags {
            template_spec["tags"] = serde_json::json!(tags);
        }

        // VMID range
        if cfg.vmid_min.is_some() || cfg.vmid_max.is_some() {
            let mut vmid_range = serde_json::Map::new();
            if let Some(min) = cfg.vmid_min {
                vmid_range.insert("start".to_string(), serde_json::json!(min));
            }
            if let Some(max) = cfg.vmid_max {
                vmid_range.insert("end".to_string(), serde_json::json!(max));
            }
            template_spec["vmIDRange"] = serde_json::Value::Object(vmid_range);
        }

        // Health checks
        if cfg.skip_cloud_init_status.is_some() || cfg.skip_qemu_guest_agent.is_some() {
            let mut checks = serde_json::Map::new();
            if let Some(skip) = cfg.skip_cloud_init_status {
                checks.insert("skipCloudInitStatus".to_string(), serde_json::json!(skip));
            }
            if let Some(skip) = cfg.skip_qemu_guest_agent {
                checks.insert("skipQemuGuestAgent".to_string(), serde_json::json!(skip));
            }
            template_spec["checks"] = serde_json::Value::Object(checks);
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": template_spec
            }
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-control-plane", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }

    /// Generate ProxmoxMachineTemplate for worker nodes
    fn generate_worker_machine_template(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let cfg = Self::get_proxmox_config(cluster)
            .ok_or_else(|| Error::validation("proxmox config required".to_string()))?;

        let storage = cfg.storage.clone().unwrap_or_else(|| "local-lvm".to_string());
        let bridge = cfg.bridge.clone().unwrap_or_else(|| "vmbr0".to_string());
        let format = cfg.format.clone().unwrap_or_else(|| "qcow2".to_string());
        let full_clone = cfg.full_clone.unwrap_or(true);
        let network_model = cfg.network_model.clone().unwrap_or_else(|| "virtio".to_string());
        let worker_sockets = cfg.worker_sockets.unwrap_or(1);

        // Build network config - CAPMOX assigns IPs from ProxmoxCluster's ipv4Config
        let mut network_default = serde_json::json!({
            "bridge": bridge,
            "model": network_model
        });

        // Add VLAN if specified
        if let Some(vlan) = cfg.vlan {
            network_default["vlan"] = serde_json::json!(vlan);
        }

        // Build template spec
        let mut template_spec = serde_json::json!({
            "format": format,
            "full": full_clone,
            "storage": storage,
            "numSockets": worker_sockets,
            "numCores": cfg.worker_cores,
            "memoryMiB": cfg.worker_memory_mib,
            "disks": {
                "bootVolume": {
                    "disk": "scsi0",
                    "sizeGb": cfg.worker_disk_size_gb
                }
            },
            "network": {
                "default": network_default
            }
        });

        // sourceNode is optional - only needed if template is on local storage
        if let Some(ref node) = cfg.source_node {
            template_spec["sourceNode"] = serde_json::json!(node);
        }

        // Add templateID or templateSelector
        if let Some(ref tags) = cfg.template_tags {
            template_spec["templateSelector"] = serde_json::json!({
                "matchTags": tags
            });
        } else {
            template_spec["templateID"] = serde_json::json!(cfg.template_id.unwrap_or(9000));
        }

        // Optional fields
        if let Some(ref snap) = cfg.snap_name {
            template_spec["snapName"] = serde_json::json!(snap);
        }
        if let Some(ref target) = cfg.target_node {
            template_spec["target"] = serde_json::json!(target);
        }
        if let Some(ref pool) = cfg.pool {
            template_spec["pool"] = serde_json::json!(pool);
        }
        if let Some(ref desc) = cfg.description {
            template_spec["description"] = serde_json::json!(format!("{} (worker)", desc));
        }
        if let Some(ref tags) = cfg.tags {
            template_spec["tags"] = serde_json::json!(tags);
        }

        // VMID range
        if cfg.vmid_min.is_some() || cfg.vmid_max.is_some() {
            let mut vmid_range = serde_json::Map::new();
            if let Some(min) = cfg.vmid_min {
                vmid_range.insert("start".to_string(), serde_json::json!(min));
            }
            if let Some(max) = cfg.vmid_max {
                vmid_range.insert("end".to_string(), serde_json::json!(max));
            }
            template_spec["vmIDRange"] = serde_json::Value::Object(vmid_range);
        }

        // Health checks
        if cfg.skip_cloud_init_status.is_some() || cfg.skip_qemu_guest_agent.is_some() {
            let mut checks = serde_json::Map::new();
            if let Some(skip) = cfg.skip_cloud_init_status {
                checks.insert("skipCloudInitStatus".to_string(), serde_json::json!(skip));
            }
            if let Some(skip) = cfg.skip_qemu_guest_agent {
                checks.insert("skipQemuGuestAgent".to_string(), serde_json::json!(skip));
            }
            template_spec["checks"] = serde_json::Value::Object(checks);
        }

        let spec_json = serde_json::json!({
            "template": {
                "spec": template_spec
            }
        });

        Ok(CAPIManifest::new(
            PROXMOX_API_VERSION,
            "ProxmoxMachineTemplate",
            format!("{}-md-0", name),
            &self.namespace,
        )
        .with_spec(spec_json))
    }
}

#[async_trait]
impl Provider for ProxmoxProvider {
    async fn generate_capi_manifests(
        &self,
        cluster: &LatticeCluster,
        bootstrap: &BootstrapInfo,
    ) -> Result<Vec<CAPIManifest>> {
        let name = cluster
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| crate::Error::validation("cluster name required".to_string()))?;

        let spec = &cluster.spec;
        let k8s_version = &spec.provider.kubernetes.version;
        let bootstrap_provider = &spec.provider.kubernetes.bootstrap;

        // Build cluster config
        let mut labels = BTreeMap::new();
        labels.insert("cluster.x-k8s.io/cluster-name".to_string(), name.clone());
        labels.insert("lattice.dev/cluster".to_string(), name.clone());

        let config = ClusterConfig {
            name,
            namespace: &self.namespace,
            k8s_version,
            labels,
            bootstrap: bootstrap_provider.clone(),
            provider_type: ProviderType::Proxmox,
        };

        let infra = self.infra_ref();

        // Build control plane config
        let post_commands = build_post_kubeadm_commands(name, bootstrap);
        let mut cert_sans = spec
            .provider
            .kubernetes
            .cert_sans
            .clone()
            .unwrap_or_default();

        // Auto-add endpoints.host to certSANs so users don't have to specify it twice
        if let Some(ref endpoints) = cluster.spec.endpoints {
            if !cert_sans.contains(&endpoints.host) {
                cert_sans.push(endpoints.host.clone());
            }
        }

        let proxmox_cfg = Self::get_proxmox_config(cluster);

        // Configure kube-vip for management clusters (those with endpoints)
        let vip = cluster.spec.endpoints.as_ref().map(|e| {
            let interface = proxmox_cfg
                .and_then(|c| c.virtual_ip_network_interface.clone())
                .unwrap_or_else(|| DEFAULT_VIP_INTERFACE.to_string());
            VipConfig::new(
                e.host.clone(),
                Some(interface),
                proxmox_cfg.and_then(|c| c.kube_vip_image.clone()),
            )
        });

        // SSH authorized keys for node access
        let ssh_authorized_keys = proxmox_cfg
            .and_then(|c| c.ssh_authorized_keys.clone())
            .unwrap_or_default();

        let cp_config = ControlPlaneConfig {
            replicas: spec.nodes.control_plane,
            cert_sans,
            post_kubeadm_commands: post_commands,
            vip,
            ssh_authorized_keys,
        };

        // Generate manifests - extract fallible operations first
        let proxmox_cluster = self.generate_proxmox_cluster(cluster)?;
        let cp_machine_template = self.generate_cp_machine_template(cluster)?;
        let worker_machine_template = self.generate_worker_machine_template(cluster)?;

        let manifests = vec![
            generate_cluster(&config, &infra),              // 1. CAPI Cluster
            proxmox_cluster,                                // 2. ProxmoxCluster
            generate_control_plane(&config, &infra, &cp_config), // 3. Control Plane
            cp_machine_template,                            // 4. CP Machine Template
            generate_machine_deployment(&config, &infra),   // 5. MachineDeployment
            worker_machine_template,                        // 6. Worker Machine Template
            generate_bootstrap_config_template(&config),    // 7. Bootstrap Config Template
        ];

        Ok(manifests)
    }

    async fn validate_spec(&self, spec: &ProviderSpec) -> Result<()> {
        // Validate Kubernetes version format
        let version = &spec.kubernetes.version;
        if !version.starts_with("1.") && !version.starts_with("v1.") {
            return Err(crate::Error::validation(format!(
                "invalid kubernetes version: {version}, expected format: 1.x.x or v1.x.x"
            )));
        }

        // Required fields are enforced at the type level - no runtime validation needed
        Ok(())
    }

    fn required_secrets(&self, cluster: &LatticeCluster) -> Vec<(String, String)> {
        let proxmox_config = cluster.spec.provider.config.proxmox.as_ref();
        let secret_ref = proxmox_config.and_then(|c| c.secret_ref.as_ref());
        let secret_name = secret_ref
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "proxmox-credentials".to_string());
        let source_namespace = secret_ref
            .map(|s| s.namespace.clone())
            .unwrap_or_else(|| "capmox-system".to_string());

        vec![(secret_name, source_namespace)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BootstrapProvider, KubernetesSpec, NodeSpec, ProviderConfig, ProviderSpec};
    use kube::api::ObjectMeta;
    use lattice_common::crd::{Ipv4PoolConfig, LatticeClusterSpec};

    fn make_test_proxmox_config() -> ProxmoxConfig {
        ProxmoxConfig {
            // Required fields
            control_plane_endpoint: "10.0.0.100".to_string(),
            ipv4_pool: Ipv4PoolConfig {
                start: "10.0.0.101".to_string(),
                end: "10.0.0.120".to_string(),
                prefix: 24,
                gateway: "10.0.0.1".to_string(),
            },
            cp_cores: 4,
            cp_memory_mib: 8192,
            cp_disk_size_gb: 50,
            worker_cores: 4,
            worker_memory_mib: 8192,
            worker_disk_size_gb: 100,
            // Optional fields
            source_node: None,
            template_id: None,
            template_tags: None,
            snap_name: None,
            storage: None,
            format: None,
            full_clone: None,
            target_node: None,
            pool: None,
            description: None,
            tags: None,
            allowed_nodes: None,
            dns_servers: None,
            ssh_authorized_keys: None,
            virtual_ip_network_interface: None,
            kube_vip_image: None,
            secret_ref: None,
            ipv6_pool: None,
            bridge: None,
            vlan: None,
            network_model: None,
            memory_adjustment: None,
            vmid_min: None,
            vmid_max: None,
            skip_cloud_init_status: None,
            skip_qemu_guest_agent: None,
            cp_sockets: None,
            worker_sockets: None,
        }
    }

    fn make_test_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::proxmox(make_test_proxmox_config()),
                },
                nodes: NodeSpec {
                    control_plane: 3,
                    workers: 5,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn test_generates_seven_manifests_for_kubeadm() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        // 7 manifests: Cluster, ProxmoxCluster, ControlPlane, 2x MachineTemplate, MachineDeployment, BootstrapConfigTemplate
        assert_eq!(manifests.len(), 7);

        // Verify manifest kinds
        let kinds: Vec<&str> = manifests.iter().map(|m| m.kind.as_str()).collect();
        assert!(kinds.contains(&"Cluster"));
        assert!(kinds.contains(&"ProxmoxCluster"));
        assert!(kinds.contains(&"KubeadmControlPlane"));
        assert!(kinds.contains(&"ProxmoxMachineTemplate"));
        assert!(kinds.contains(&"MachineDeployment"));
        assert!(kinds.contains(&"KubeadmConfigTemplate"));
    }

    #[tokio::test]
    async fn test_proxmox_cluster_has_correct_api_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        assert_eq!(
            proxmox_cluster.api_version,
            "infrastructure.cluster.x-k8s.io/v1alpha1"
        );
    }

    #[tokio::test]
    async fn test_machine_deployment_starts_with_zero_replicas() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("test-cluster");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let md = manifests
            .iter()
            .find(|m| m.kind == "MachineDeployment")
            .unwrap();

        let replicas = md.spec.as_ref().unwrap()["replicas"].as_i64().unwrap();
        assert_eq!(replicas, 0, "MachineDeployment must start with replicas=0");
    }

    #[tokio::test]
    async fn test_validate_spec_accepts_valid_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(make_test_proxmox_config()),
        };

        assert!(provider.validate_spec(&spec).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_spec_rejects_invalid_version() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let spec = ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "invalid".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm,
            },
            config: ProviderConfig::proxmox(make_test_proxmox_config()),
        };

        assert!(provider.validate_spec(&spec).await.is_err());
    }

    #[tokio::test]
    async fn test_proxmox_cluster_has_ipv4_config() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let cluster = make_test_cluster("ip-test");
        let bootstrap = BootstrapInfo::default();

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .expect("ProxmoxCluster should be generated");

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        let ipv4_config = &spec["ipv4Config"];

        // Verify ipv4Config has the correct range format
        assert_eq!(ipv4_config["addresses"][0], "10.0.0.101-10.0.0.120");
        assert_eq!(ipv4_config["prefix"], 24);
        assert_eq!(ipv4_config["gateway"], "10.0.0.1");
    }

    #[tokio::test]
    async fn test_optional_network_fields() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let mut config = make_test_proxmox_config();
        config.bridge = Some("vmbr1".to_string());
        config.vlan = Some(100);
        config.dns_servers = Some(vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]);

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("network-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        assert_eq!(spec["dnsServers"][0], "1.1.1.1");
        assert_eq!(spec["dnsServers"][1], "1.0.0.1");
    }

    #[tokio::test]
    async fn test_allowed_nodes_configuration() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();

        let mut config = make_test_proxmox_config();
        config.allowed_nodes = Some(vec!["pve1".to_string(), "pve2".to_string(), "pve3".to_string()]);

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("nodes-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Kubeadm,
                    },
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let proxmox_cluster = manifests
            .iter()
            .find(|m| m.kind == "ProxmoxCluster")
            .unwrap();

        let spec = proxmox_cluster.spec.as_ref().unwrap();
        let allowed = &spec["allowedNodes"];
        assert!(allowed.is_array());
        assert_eq!(allowed.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_rke2_bootstrap_provider() {
        let provider = ProxmoxProvider::with_namespace("capi-system");
        let bootstrap = BootstrapInfo::default();
        let config = make_test_proxmox_config();

        let cluster = LatticeCluster {
            metadata: ObjectMeta {
                name: Some("rke2-test".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::Rke2,
                    },
                    config: ProviderConfig::proxmox(config),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 1,
                },
                endpoints: None,
                networking: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        };

        let manifests = provider
            .generate_capi_manifests(&cluster, &bootstrap)
            .await
            .unwrap();

        let control_plane = manifests
            .iter()
            .find(|m| m.kind.contains("ControlPlane"))
            .unwrap();
        assert!(control_plane.kind.contains("RKE2"));
    }
}
