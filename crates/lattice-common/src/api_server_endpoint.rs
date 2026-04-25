//! Single source of truth for resolving a cluster's API server endpoint.
//!
//! Cilium with `kubeProxyReplacement` needs an explicit `host:port` baked
//! into its install manifests so agents can dial kube before service
//! networking exists. The endpoint lives in two places — the CAPI
//! `Cluster` CR (parent's view) and the cluster's own `kubeadm-config`
//! ConfigMap (in-cluster view) — but both carry the same value kubeadm
//! originally chose, so the bundle-time render and the post-pivot
//! reconciler render are byte-identical.
//!
//! - [`ApiServerEndpoint::from_capi_cluster`] — reads the CAPI `Cluster`
//!   CR's `spec.controlPlaneEndpoint`. Used by the parent operator's
//!   bootstrap webhook resolver and by `lattice-cli` for kubeconfig
//!   patching during uninstall.
//! - [`ApiServerEndpoint::from_kubeadm_config`] — reads the
//!   `kube-system/kubeadm-config` ConfigMap. Used by `lattice-cli` for the
//!   kind/management bootstrap (kubeconfig on disk has the host-side
//!   port-forward, not the internal endpoint Cilium agents need) and by
//!   in-cluster reconcilers re-applying their install for idempotency.

use k8s_openapi::api::core::v1::{ConfigMap, Endpoints};
use kube::api::{Api, DynamicObject};
use kube::Client;
use serde::Deserialize;

use crate::error::Error;
use crate::kube_utils::build_api_resource_with_discovery;

/// A Kubernetes API server endpoint as `host:port`.
///
/// Cilium, kubeadm, and CAPI all express this as separate host + port,
/// not a URL — keep the same shape so we don't have to re-split downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiServerEndpoint {
    /// DNS name or IP literal (no scheme, no path).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl ApiServerEndpoint {
    /// Parse `host:port` into a typed endpoint.
    fn parse_host_port(host_port: &str, source: &str) -> Result<Self, Error> {
        let (host, port_str) = host_port.rsplit_once(':').ok_or_else(|| {
            Error::internal(format!("{source} has no port: {host_port}"))
        })?;
        let port: u16 = port_str.parse().map_err(|e| {
            Error::internal(format!("{source} port is not a u16: {port_str}: {e}"))
        })?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Read a CAPI `Cluster` CR and extract `spec.controlPlaneEndpoint`.
    ///
    /// This is the canonical source on the parent: CAPI populates it from
    /// whatever the provider allocated (basis VIP, kube-vip, kind node IP,
    /// etc.), and it's not affected by any kubeconfig rewriting we do for
    /// proxy access.
    pub async fn from_capi_cluster(
        client: &Client,
        cluster_name: &str,
        capi_namespace: &str,
    ) -> Result<Self, Error> {
        let api_resource =
            build_api_resource_with_discovery(client, "cluster.x-k8s.io", "Cluster")
                .await
                .map_err(|e| Error::internal(format!("CAPI Cluster discovery failed: {}", e)))?;

        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), capi_namespace, &api_resource);

        let cluster = api.get(cluster_name).await.map_err(|e| {
            Error::internal(format!(
                "failed to get CAPI Cluster {}/{}: {}",
                capi_namespace, cluster_name, e
            ))
        })?;

        let endpoint = cluster
            .data
            .get("spec")
            .and_then(|s| s.get("controlPlaneEndpoint"))
            .ok_or_else(|| Error::internal("CAPI Cluster has no spec.controlPlaneEndpoint"))?;

        let host = endpoint
            .get("host")
            .and_then(|h| h.as_str())
            .ok_or_else(|| Error::internal("controlPlaneEndpoint has no host"))?;

        let port = endpoint
            .get("port")
            .and_then(|p| p.as_i64())
            .ok_or_else(|| Error::internal("controlPlaneEndpoint has no port"))?;

        let port = u16::try_from(port).map_err(|_| {
            Error::internal(format!("controlPlaneEndpoint port {} out of range", port))
        })?;

        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Resolve the API server endpoint from inside the cluster.
    ///
    /// Tries `kube-system/kubeadm-config.ClusterConfiguration.controlPlaneEndpoint`
    /// first (HA / production setups stamp this; matches the parent's view),
    /// falling back to the first address of the `default/kubernetes`
    /// Endpoints resource (single-node clusters like kind don't write
    /// `controlPlaneEndpoint`, but the apiserver always populates its own
    /// Endpoints).
    pub async fn from_kubeadm_config(client: &Client) -> Result<Self, Error> {
        if let Some(ep) = Self::try_from_kubeadm_control_plane_endpoint(client).await? {
            return Ok(ep);
        }
        Self::from_kubernetes_endpoints(client).await
    }

    /// Read `controlPlaneEndpoint` from `kube-system/kubeadm-config`.
    /// Returns `Ok(None)` when the field is absent (kind, single-node setups);
    /// errors only on actual I/O or parse failures.
    async fn try_from_kubeadm_control_plane_endpoint(
        client: &Client,
    ) -> Result<Option<Self>, Error> {
        let cms: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");
        let cm = cms.get("kubeadm-config").await.map_err(|e| {
            Error::internal(format!("failed to get kube-system/kubeadm-config: {e}"))
        })?;

        let Some(cluster_config_yaml) = cm
            .data
            .as_ref()
            .and_then(|d| d.get("ClusterConfiguration"))
        else {
            return Ok(None);
        };

        #[derive(Deserialize)]
        struct ClusterConfiguration {
            #[serde(rename = "controlPlaneEndpoint")]
            control_plane_endpoint: Option<String>,
        }

        let value = lattice_core::yaml::parse_yaml(cluster_config_yaml).map_err(|e| {
            Error::internal(format!("failed to parse ClusterConfiguration YAML: {e}"))
        })?;
        let cfg: ClusterConfiguration = serde_json::from_value(value).map_err(|e| {
            Error::internal(format!("failed to deserialize ClusterConfiguration: {e}"))
        })?;

        match cfg.control_plane_endpoint {
            Some(endpoint) => {
                Self::parse_host_port(&endpoint, "controlPlaneEndpoint").map(Some)
            }
            None => Ok(None),
        }
    }

    /// Read the first address of the `default/kubernetes` Endpoints resource.
    /// The apiserver writes this on startup; it's the canonical "where am I"
    /// entry for single-node clusters that don't set `controlPlaneEndpoint`.
    async fn from_kubernetes_endpoints(client: &Client) -> Result<Self, Error> {
        let eps: Api<Endpoints> = Api::namespaced(client.clone(), "default");
        let ep = eps.get("kubernetes").await.map_err(|e| {
            Error::internal(format!("failed to get default/kubernetes Endpoints: {e}"))
        })?;

        let subset = ep.subsets.as_ref().and_then(|s| s.first()).ok_or_else(|| {
            Error::internal("default/kubernetes Endpoints has no subsets")
        })?;
        let address = subset
            .addresses
            .as_ref()
            .and_then(|a| a.first())
            .ok_or_else(|| Error::internal("default/kubernetes Endpoints subset has no addresses"))?;
        let port = subset
            .ports
            .as_ref()
            .and_then(|p| p.first())
            .ok_or_else(|| Error::internal("default/kubernetes Endpoints subset has no ports"))?;

        let port_u16 = u16::try_from(port.port).map_err(|_| {
            Error::internal(format!("kubernetes Endpoints port {} out of range", port.port))
        })?;

        Ok(Self {
            host: address.ip.clone(),
            port: port_u16,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_ip() {
        let ep = ApiServerEndpoint::parse_host_port("172.18.0.5:6443", "test").unwrap();
        assert_eq!(ep.host, "172.18.0.5");
        assert_eq!(ep.port, 6443);
    }

    #[test]
    fn parses_host_port_dns() {
        let ep = ApiServerEndpoint::parse_host_port("api.example.com:6443", "test").unwrap();
        assert_eq!(ep.host, "api.example.com");
        assert_eq!(ep.port, 6443);
    }

    #[test]
    fn rejects_missing_port() {
        assert!(ApiServerEndpoint::parse_host_port("api.example.com", "test").is_err());
    }

    #[test]
    fn rejects_non_numeric_port() {
        assert!(ApiServerEndpoint::parse_host_port("api.example.com:abc", "test").is_err());
    }
}
