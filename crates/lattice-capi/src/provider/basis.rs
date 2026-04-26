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
//!    allocates the VIP from the cluster's `externalIpPool` and
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
use lattice_crd::crd::{
    BasisConfig, BootstrapProvider, InstanceType, LatticeCluster, PlacementSpec, ProviderSpec,
    ProviderType,
};

/// Hardcoded debug SSH key, appended to `ubuntu`'s `authorized_keys` on
/// every basis-provisioned VM. Basis is private lab infra; this is for
/// in-VM inspection (kube-vip state, kubelet logs, cilium pods), not a
/// security boundary.
const DEBUG_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID1f8eVKp5YCAtis77YO/oHhWvzAiimDzlDqhtD+85YR evan.hines.dev@gmail.com";

/// Password set on the `ubuntu` user, paired with `PasswordAuthentication
/// yes` in sshd. Lets us drop into a VM from a console session even when
/// agent-side key forwarding isn't set up.
const DEBUG_USER_PASSWORD: &str = "basis";

/// Two shell snippets to run as root after the bootstrap unit finishes.
/// Plain post-commands — not cloud-init's `users:` / `chpasswd:`
/// modules — because Kubeadm/RKE2 already own the cloud-init document
/// for these manifests; appending into the post-bootstrap command list
/// is the lowest-blast-radius hook. Both snippets are idempotent so
/// reapply / machine rollover is safe.
fn debug_post_commands() -> Vec<String> {
    vec![
        format!(
            "mkdir -p /home/ubuntu/.ssh && \
             grep -qF '{key}' /home/ubuntu/.ssh/authorized_keys 2>/dev/null || \
             echo '{key}' >> /home/ubuntu/.ssh/authorized_keys && \
             chown -R ubuntu:ubuntu /home/ubuntu/.ssh && \
             chmod 700 /home/ubuntu/.ssh && \
             chmod 600 /home/ubuntu/.ssh/authorized_keys",
            key = DEBUG_SSH_KEY,
        ),
        // sshd's `Include` reads sshd_config.d/*.conf alphabetically and
        // first match wins — so cloud-init's 50-cloud-init.conf
        // (`PasswordAuthentication no`) clobbers anything later. We
        // both drop a `00-` snippet (first in alphabetical order, so
        // sshd reads it before cloud-init's) AND patch
        // 50-cloud-init.conf in place, so a future reload that re-reads
        // both files still ends up with password auth on.
        format!(
            "echo 'ubuntu:{pw}' | chpasswd && \
             printf 'PasswordAuthentication yes\\nKbdInteractiveAuthentication yes\\n' \
                 > /etc/ssh/sshd_config.d/00-basis-debug.conf && \
             if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then \
                 sed -i 's/^[[:space:]]*PasswordAuthentication[[:space:]]\\+no/PasswordAuthentication yes/' \
                     /etc/ssh/sshd_config.d/50-cloud-init.conf; \
             fi && \
             (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true)",
            pw = DEBUG_USER_PASSWORD,
        ),
    ]
}

/// Append the debug-access shell commands to a bootstrap-config-template
/// manifest's post-bootstrap command list. Picks the right key — Kubeadm
/// uses `postKubeadmCommands`, RKE2 uses `postRKE2Commands` — based on
/// the cluster's bootstrap provider. Worker pool generators in
/// `provider/mod.rs` don't take a post-commands argument, so this
/// mutation runs in place after the manifest is built.
fn inject_debug_post_commands(manifest: &mut CAPIManifest, bootstrap: &BootstrapProvider) {
    let key = match bootstrap {
        BootstrapProvider::Rke2 => "postRKE2Commands",
        _ => "postKubeadmCommands",
    };
    let Some(spec) = manifest.spec.as_mut() else {
        return;
    };
    let target = &mut spec["template"]["spec"];
    let cmds = debug_post_commands();
    if let Some(arr) = target.get_mut(key).and_then(|v| v.as_array_mut()) {
        for c in cmds {
            arr.push(serde_json::Value::String(c));
        }
    } else {
        target[key] = serde_json::json!(cmds);
    }
}

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

    /// Render the `BasisCluster` CR. Forwards the cluster's external
    /// IP pool name (apiserver VIP + LB Service block come from the
    /// same pool) and an optional override for the per-cluster
    /// service IP count.
    fn generate_basis_cluster(&self, cluster: &LatticeCluster) -> Result<CAPIManifest> {
        let name = get_cluster_name(cluster)?;
        let cfg =
            Self::get_config(cluster).ok_or_else(|| Error::validation("basis config required"))?;

        let pool = cfg.external_ip_pool.as_deref().ok_or_else(|| {
            Error::validation(
                "basis.externalIpPool is required and must name a pool defined in the controller's network.pools",
            )
        })?;
        let mut spec = serde_json::json!({
            "credentialsRef": {
                "name": BASIS_CREDENTIALS_SECRET,
                "namespace": LOCAL_SECRETS_NAMESPACE,
            },
            "externalIpPool": pool,
        });
        if let Some(count) = cfg.external_service_ips {
            spec["externalServiceIps"] = serde_json::json!(count);
        }

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
        placement: Option<&PlacementSpec>,
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
        if let Some(p) = placement.filter(|p| !p.requires.is_empty() || !p.prefers.is_empty()) {
            // Lattice's `PlacementSpec` is field-for-field identical to
            // BasisMachine's, so a direct serde round-trip is the
            // canonical mapping — no per-field copy that would drift
            // when basis adds an op-type or weight knob.
            spec["placement"] =
                serde_json::to_value(p).expect("PlacementSpec serializes to JSON infallibly");
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
            cluster_network: spec.provider.kubernetes.cluster_network.clone(),
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
            self.generate_machine_template(
                name,
                cp_sizing,
                &image,
                "control-plane",
                spec.nodes.control_plane.placement.as_ref(),
            ),
        ];

        // KubeadmControlPlane carries kube-vip's static pod manifest
        // and the VIP cert SAN. Emit it only once we know the endpoint.
        //
        // kube-vip runs in ARP mode: external advertisement of the
        // VIP is the basis layer's job (every host carrying the tree
        // advertises the VIP /32 via the cell BGP reflector with
        // itself as next-hop, plus proxy-ARP on the underlay).
        // Inside the cluster, kube-vip just claims the VIP locally
        // on the tree NIC and runs leader-election so a single CP
        // node owns it at any time.
        if let Some(endpoint) = bootstrap.control_plane_endpoint.as_deref() {
            let mut cert_sans = build_cert_sans(cluster);
            if !cert_sans.iter().any(|s| s == endpoint) {
                cert_sans.push(endpoint.to_string());
            }
            let vip = Some(VipConfig::arp(
                endpoint.to_string(),
                BASIS_VIP_INTERFACE.to_string(),
                cfg.kube_vip_image.clone(),
            ));
            let mut post_kubeadm_commands = build_post_kubeadm_commands(name, bootstrap)?;
            // Append the debug-access shell snippets so CP nodes are
            // ssh-able the same way workers are. Goes into
            // postKubeadmCommands / postRKE2Commands inside the CP
            // generator depending on bootstrap provider.
            post_kubeadm_commands.extend(debug_post_commands());

            let cp_config = ControlPlaneConfig {
                replicas: spec.nodes.control_plane.replicas,
                cert_sans,
                post_kubeadm_commands,
                vip,
                // Existing CP plumbing writes these to root's
                // authorized_keys (kubeadm `users[name=root]` /
                // RKE2 `/root/.ssh/authorized_keys`). Harmless — root
                // login is locked on Ubuntu cloud images so this is
                // belt-and-suspenders behind the ubuntu user that
                // debug_post_commands actually wires up.
                ssh_authorized_keys: vec![DEBUG_SSH_KEY.to_string()],
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
            manifests.push(self.generate_machine_template(
                name,
                worker_sizing,
                &image,
                &suffix,
                pool_spec.placement.as_ref(),
            ));
            let mut wp_template =
                generate_bootstrap_config_template_for_pool(&config, &pool_config);
            inject_debug_post_commands(&mut wp_template, &spec.provider.kubernetes.bootstrap);
            manifests.push(wp_template);
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

    /// Resolve the Cilium LB Service block by reading
    /// `BasisCluster.spec.serviceBlockCidr` — populated by
    /// basis-capi-provider after `Basis.CreateCluster` returns. If
    /// the field hasn't been written yet (eager reconcile, basis
    /// hasn't allocated), we return a retryable provider error so
    /// the cluster reconciler requeues until it appears.
    async fn lb_cidr(
        &self,
        cluster: &LatticeCluster,
        kube: &kube::Client,
    ) -> Result<Option<String>> {
        use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};

        let name = cluster
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| Error::validation("LatticeCluster missing metadata.name"))?;
        let namespace = lattice_common::capi_namespace(name);
        let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "infrastructure.cluster.x-k8s.io",
            "v1alpha1",
            "BasisCluster",
        ));
        let api: Api<DynamicObject> = Api::namespaced_with(kube.clone(), &namespace, &ar);
        let cidr = api
            .get_opt(name)
            .await
            .map_err(|e| Error::provider_for(name, "basis", e.to_string()))?
            .and_then(|obj| {
                obj.data
                    .pointer("/spec/serviceBlockCidr")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            });
        match cidr {
            Some(c) => Ok(Some(c)),
            None => Err(Error::provider_for(
                name,
                "basis",
                "BasisCluster.spec.serviceBlockCidr not populated yet — \
                 waiting for basis-capi-provider to allocate",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use lattice_crd::crd::{
        BackupsConfig, BootstrapProvider, ClusterNetworkSpec, ControlPlaneSpec, KubernetesSpec,
        LatticeClusterSpec, MonitoringConfig, NodeResourceSpec, NodeSpec, ProviderConfig,
        WorkerPoolSpec,
    };

    fn test_basis_config() -> BasisConfig {
        BasisConfig {
            external_ip_pool: Some("cell-public".to_string()),
            external_service_ips: None,
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
                        cluster_network: ClusterNetworkSpec::default(),
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
                        ..Default::default()
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
        // kube-vip on basis runs in ARP mode — basis-side BGP is what
        // gets the VIP routed externally, so kube-vip's job here is
        // just intra-tree leader election + ARP for the VIP.
        assert!(json.contains("vip_arp"), "kube-vip in ARP mode: {json}");
        assert!(
            !json.contains("bgp_enable"),
            "kube-vip should NOT enable its BGP path on basis (basis advertises): {json}"
        );
    }

    #[tokio::test]
    async fn basis_cluster_carries_external_ip_pool() {
        let provider = BasisProvider::with_namespace("default");
        let cluster = test_cluster("basis-wkr");
        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");
        let bc = manifests.iter().find(|m| m.kind == "BasisCluster").unwrap();
        let json = serde_json::to_string(&bc.spec).unwrap();
        assert!(json.contains(r#""externalIpPool":"cell-public""#));
        // externalServiceIps is omitted in the default case so basis
        // applies its cell-wide default — only present when the
        // config explicitly overrides.
        assert!(!json.contains("externalServiceIps"));
    }

    #[tokio::test]
    async fn basis_cluster_forwards_external_service_ips_override() {
        let mut basis_cfg = test_basis_config();
        basis_cfg.external_service_ips = Some(32);
        let mut cluster = test_cluster("basis-svc");
        cluster.spec.provider.config = ProviderConfig::basis(basis_cfg);

        let provider = BasisProvider::with_namespace("default");
        let manifests = provider
            .generate_capi_manifests(&cluster, &BootstrapInfo::default())
            .await
            .expect("manifest generation should succeed");
        let bc = manifests.iter().find(|m| m.kind == "BasisCluster").unwrap();
        let json = serde_json::to_string(&bc.spec).unwrap();
        assert!(json.contains(r#""externalServiceIps":32"#));
    }
}
