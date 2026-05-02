//! kube-vip wiring for control planes.
//!
//! Given a [`VipConfig`] and the bootstrap flavor (kubeadm vs RKE2),
//! [`bundle`] returns everything CAPI needs to drop the kube-vip static
//! pod onto every CP machine: the cloud-init file entries and the
//! pre-bootstrap shell commands.
//!
//! ## Kubeadm 1.29+ kubeconfig path: per-machine
//!
//! kubeadm 1.29 split admin authentication into two kubeconfigs:
//! - `super-admin.conf` — written only by `kubeadm init`, carries
//!   `system:masters` from byte zero. The init CP needs this for
//!   kube-vip's leader-election to authenticate before the
//!   cluster-admin RoleBinding has been written.
//! - `admin.conf` — written by both `kubeadm init` and
//!   `kubeadm join --control-plane`, but starts unbound. Once init
//!   completes, the binding lands and `admin.conf` becomes usable.
//!
//! So joined CPs need `admin.conf` (super-admin doesn't exist there),
//! and the init CP needs `super-admin.conf` (admin.conf isn't yet
//! authoritative). CAPI gives every CP the same `kubeadmConfigSpec`,
//! so we resolve the path *per machine* in `preKubeadmCommands`:
//!
//! - The cloud-init `files` block stages a placeholder template at
//!   `/etc/kubernetes/kube-vip.yaml.tmpl` (deliberately outside the
//!   `manifests/` directory so kubelet's static-pod watcher doesn't
//!   parse it).
//! - `preKubeadmCommands` checks for `/run/kubeadm/kubeadm.yaml`
//!   (CAPI writes this only on init machines; join machines get
//!   `kubeadm-join-config.yaml` instead), substitutes the right
//!   kubeconfig path, and atomically renames the result into
//!   `/etc/kubernetes/manifests/kube-vip.yaml`.
//! - HostPath `type: File` (not `FileOrCreate`) so kubelet retries the
//!   mount until kubeadm writes the kubeconfig instead of bind-mounting
//!   an empty inode that the kubeadm-side `rename(2)` won't update.
//!
//! See <https://github.com/kube-vip/kube-vip/issues/684>.
//!
//! ## RKE2
//!
//! RKE2's kubeconfig (`/etc/rancher/rke2/rke2.yaml`) has no admin/super
//! split, so the manifest is written directly to the static-pod
//! directory with no preKubeadm staging.

use k8s_openapi::api::core::v1::{
    Capabilities, Container, EnvVar, HostAlias, HostPathVolumeSource, Pod, PodSpec,
    SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use lattice_common::{Error, Result};
use lattice_crd::crd::BootstrapProvider;

use crate::constants::KUBERNETES_API_SERVER_PORT;

use super::VipConfig;

/// Where kube-vip looks for its kubeconfig inside the container —
/// matches the `--k8sConfigPath` default. The host file mounted here
/// can have a different name; only the in-pod path needs to be this.
const CONTAINER_KUBECONFIG_PATH: &str = "/etc/kubernetes/admin.conf";

/// Placeholder substituted at `preKubeadmCommands` time for the right
/// per-machine host kubeconfig path.
const KUBECONFIG_HOSTPATH_PLACEHOLDER: &str = "__KUBECONFIG_HOSTPATH__";

const KUBEADM_TEMPLATE_PATH: &str = "/etc/kubernetes/kube-vip.yaml.tmpl";
const KUBEADM_MANIFEST_PATH: &str = "/etc/kubernetes/manifests/kube-vip.yaml";
const RKE2_MANIFEST_PATH: &str = "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml";
const RKE2_KUBECONFIG_PATH: &str = "/etc/rancher/rke2/rke2.yaml";
const KUBEADM_INIT_KUBECONFIG: &str = "/etc/kubernetes/super-admin.conf";
const KUBEADM_JOIN_KUBECONFIG: &str = "/etc/kubernetes/admin.conf";

/// Everything a CP generator needs to wire kube-vip into a cluster.
#[derive(Debug)]
pub(super) struct Bundle {
    /// Cloud-init `files` entry — for kubeadm this is the staged
    /// template at `/etc/kubernetes/kube-vip.yaml.tmpl`; for RKE2 it's
    /// the final static-pod manifest.
    pub file: serde_json::Value,
    /// Commands to run before bootstrap (kubeadm/RKE2). Includes the
    /// node-ip fixup (#741); for kubeadm also the per-machine
    /// template materialization.
    pub pre_bootstrap: Vec<String>,
}

/// Build the full kube-vip wiring for a CP.
pub(super) fn bundle(vip: &VipConfig, bootstrap: &BootstrapProvider) -> Result<Bundle> {
    let mut pre_bootstrap = vec![node_ip_command(vip, bootstrap)?];

    let (file_path, host_kubeconfig) = match bootstrap {
        BootstrapProvider::Kubeadm => {
            pre_bootstrap.push(materialize_kubeadm_manifest_command());
            (KUBEADM_TEMPLATE_PATH, KUBECONFIG_HOSTPATH_PLACEHOLDER)
        }
        BootstrapProvider::Rke2 => (RKE2_MANIFEST_PATH, RKE2_KUBECONFIG_PATH),
        other => {
            return Err(Error::provider(format!(
                "unsupported bootstrap provider: {other}"
            )))
        }
    };

    let manifest = render_manifest(vip, host_kubeconfig)?;
    Ok(Bundle {
        file: serde_json::json!({
            "content": manifest,
            "owner": "root:root",
            "path": file_path,
            "permissions": "0644"
        }),
        pre_bootstrap,
    })
}

/// preKubeadmCommands snippet that picks the right kubeconfig path
/// per machine and atomically materializes the static pod manifest.
///
/// CAPI's bootstrap controller writes `/run/kubeadm/kubeadm.yaml` only
/// on the init machine (join machines get `kubeadm-join-config.yaml`
/// instead) — that file's existence is the init/join discriminator.
/// Staging the rendered manifest at `<dest>.staged` and `mv`ing into
/// place keeps kubelet's static-pod watcher from ever seeing the
/// half-written file.
fn materialize_kubeadm_manifest_command() -> String {
    format!(
        "if [ -f /run/kubeadm/kubeadm.yaml ]; then HOSTPATH={init_kubeconfig}; else HOSTPATH={join_kubeconfig}; fi && \
         mkdir -p /etc/kubernetes/manifests && \
         sed \"s|{placeholder}|$HOSTPATH|\" {tmpl} > {manifest}.staged && \
         mv {manifest}.staged {manifest}",
        init_kubeconfig = KUBEADM_INIT_KUBECONFIG,
        join_kubeconfig = KUBEADM_JOIN_KUBECONFIG,
        placeholder = KUBECONFIG_HOSTPATH_PLACEHOLDER,
        tmpl = KUBEADM_TEMPLATE_PATH,
        manifest = KUBEADM_MANIFEST_PATH,
    )
}

/// Pin kubelet's `--node-ip` to the primary NIC's IP before bootstrap
/// runs, so kubelet doesn't register against the VIP once kube-vip
/// claims it. https://github.com/kube-vip/kube-vip/issues/741
fn node_ip_command(vip: &VipConfig, bootstrap: &BootstrapProvider) -> Result<String> {
    let iface = vip.node_interface();
    let ip_lookup =
        format!("ip -4 -o addr show {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -1");
    match bootstrap {
        BootstrapProvider::Kubeadm => Ok(format!(
            r#"NODE_IP=$({ip_lookup}) && echo "KUBELET_EXTRA_ARGS=\"--node-ip=$NODE_IP\"" > /etc/default/kubelet"#,
        )),
        BootstrapProvider::Rke2 => Ok(format!(
            r#"NODE_IP=$({ip_lookup}) && mkdir -p /etc/rancher/rke2 && echo "node-ip: $NODE_IP" >> /etc/rancher/rke2/config.yaml"#,
        )),
        other => Err(Error::provider(format!(
            "unsupported bootstrap provider: {other}"
        ))),
    }
}

fn render_manifest(vip: &VipConfig, host_path: &str) -> Result<String> {
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some("kube-vip".to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            host_network: Some(true),
            host_aliases: Some(vec![HostAlias {
                hostnames: Some(vec!["kubernetes".to_string()]),
                ip: "127.0.0.1".to_string(),
            }]),
            containers: vec![Container {
                name: "kube-vip".to_string(),
                image: Some(vip.image.clone()),
                image_pull_policy: Some("IfNotPresent".to_string()),
                args: Some(vec!["manager".to_string()]),
                env: Some(env_vars(vip)),
                security_context: Some(SecurityContext {
                    capabilities: Some(Capabilities {
                        add: Some(vec!["NET_ADMIN".to_string(), "NET_RAW".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                volume_mounts: Some(vec![VolumeMount {
                    name: "kubeconfig".to_string(),
                    mount_path: CONTAINER_KUBECONFIG_PATH.to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "kubeconfig".to_string(),
                host_path: Some(HostPathVolumeSource {
                    path: host_path.to_string(),
                    // `File` (not `FileOrCreate`): if kubelet sees the
                    // static pod before kubeadm has written the
                    // kubeconfig, retrying the mount is correct;
                    // creating an empty placeholder + bind-mounting it
                    // strands the pod against an inode kubeadm's
                    // later `rename(2)` will swap out underneath.
                    type_: Some("File".to_string()),
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    serde_json::to_string(&pod).map_err(|e| Error::serialization(format!("kube-vip pod: {e}")))
}

fn env_vars(vip: &VipConfig) -> Vec<EnvVar> {
    let pairs: &[(&str, String)] = &[
        ("cp_enable", "true".into()),
        ("address", vip.address.clone()),
        ("port", KUBERNETES_API_SERVER_PORT.to_string()),
        ("vip_leaderelection", "true".into()),
        ("vip_leaseduration", "60".into()),
        ("vip_renewdeadline", "40".into()),
        ("vip_retryperiod", "5".into()),
        ("vip_interface", vip.mode.interface.clone()),
        ("vip_arp", "true".into()),
        // Tetragon's host-network DaemonSet binds :2112 on every node;
        // moving kube-vip's prometheus listener avoids the bind clash
        // on joined CPs where Tetragon comes up first.
        ("prometheus_server", ":2113".into()),
    ];
    pairs
        .iter()
        .map(|(name, value)| EnvVar {
            name: (*name).to_string(),
            value: Some(value.clone()),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::VipConfig;

    fn vip() -> VipConfig {
        VipConfig::arp("10.0.0.100".to_string(), "eth0".to_string(), None)
    }

    #[test]
    fn kubeadm_bundle_stages_template_outside_manifests_dir() {
        let b = bundle(&vip(), &BootstrapProvider::Kubeadm).unwrap();
        assert_eq!(
            b.file["path"].as_str().unwrap(),
            "/etc/kubernetes/kube-vip.yaml.tmpl",
            "template must NOT live under /etc/kubernetes/manifests/ — kubelet's static-pod watcher would parse it"
        );
        let content = b.file["content"].as_str().unwrap();
        assert!(
            content.contains(KUBECONFIG_HOSTPATH_PLACEHOLDER),
            "kubeadm template must carry the per-machine placeholder: {content}"
        );
        assert!(
            content.contains(r#""mountPath":"/etc/kubernetes/admin.conf""#),
            "in-container path must match kube-vip's --k8sConfigPath default"
        );
        assert!(
            content.contains(r#""type":"File""#),
            "hostPath must be `File` (not FileOrCreate) to avoid bind-mounting an empty inode"
        );
    }

    #[test]
    fn kubeadm_pre_bootstrap_picks_init_or_join_kubeconfig() {
        let b = bundle(&vip(), &BootstrapProvider::Kubeadm).unwrap();
        assert_eq!(b.pre_bootstrap.len(), 2);
        assert!(b.pre_bootstrap[0].contains("--node-ip"));
        let materialize = &b.pre_bootstrap[1];
        assert!(materialize.contains("/run/kubeadm/kubeadm.yaml"));
        assert!(materialize.contains("/etc/kubernetes/super-admin.conf"));
        assert!(materialize.contains("/etc/kubernetes/admin.conf"));
        assert!(materialize.contains(".staged"));
        assert!(materialize.contains("/etc/kubernetes/manifests/kube-vip.yaml"));
    }

    #[test]
    fn rke2_bundle_writes_directly_to_manifests_dir() {
        let b = bundle(&vip(), &BootstrapProvider::Rke2).unwrap();
        let content = b.file["content"].as_str().unwrap();
        assert!(content.contains(r#""path":"/etc/rancher/rke2/rke2.yaml""#));
        assert!(!content.contains("super-admin.conf"));
        assert!(!content.contains(KUBECONFIG_HOSTPATH_PLACEHOLDER));
        assert_eq!(
            b.file["path"].as_str().unwrap(),
            "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml"
        );
        assert_eq!(b.pre_bootstrap.len(), 1);
        assert!(b.pre_bootstrap[0].contains("node-ip"));
    }

    #[test]
    fn manifest_carries_vip_address_image_and_prometheus_offset() {
        let content = render_manifest(&vip(), KUBEADM_INIT_KUBECONFIG).unwrap();
        assert!(content.contains("10.0.0.100"));
        assert!(content.contains("eth0"));
        assert!(content.contains(crate::constants::DEFAULT_KUBE_VIP_IMAGE));
        assert!(content.contains(":2113"), "prometheus offset missing");
    }
}
