//! Apiserver-endpoint readers.
//!
//! Cilium with `kubeProxyReplacement` needs an explicit `host:port` baked
//! into its install manifests so agents can dial kube before service
//! networking exists. There are exactly two places this address lives,
//! and each has one reader here:
//!
//! - [`ApiServerEndpoint::from_capi_cluster`] reads the CAPI `Cluster`
//!   CR's `spec.controlPlaneEndpoint` — the canonical post-provisioning
//!   value, written by the per-provider infra controller (basis VIP,
//!   kube-vip, AWS NLB DNS, kind LB) and copied up by CAPI core. This is
//!   what every CAPI-provisioned cluster exposes.
//! - [`ApiServerEndpoint::from_kubeadm_config`] reads
//!   `kube-system/kubeadm-config.ClusterConfiguration.controlPlaneEndpoint`
//!   — only meaningful on the management kind cluster, which is
//!   bootstrapped by kubeadm directly and never gets a CAPI Cluster CR.
//!
//! Both return `Result<Option<Self>, _>`: `None` is "this source isn't
//! populated yet" (CAPI hasn't reconciled, or this isn't a kubeadm
//! cluster). Callers that need a strict value `.ok_or_else()` themselves.
//!
//! In-cluster reconcilers (cilium controller, etc.) do **not** call
//! these directly — they read the canonical
//! [`LatticeClusterStatus::endpoint`](lattice_crd::crd::LatticeClusterStatus)
//! field, populated by the cluster controller. There is no Endpoints
//! fallback: picking an apiserver node IP from `default/kubernetes` is
//! unsafe for HA (a single CP node restart would break Cilium agent
//! re-bootstrap) so we never do it.

use k8s_openapi::api::core::v1::ConfigMap;
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
    /// Parse a `host:port` string back into a typed endpoint. Inverse of
    /// [`Self::to_host_port`]; used by consumers reading
    /// `LatticeClusterStatus::endpoint`.
    pub fn parse(host_port: &str) -> Result<Self, Error> {
        Self::parse_host_port(host_port, "endpoint")
    }

    /// Parse `host:port` into a typed endpoint.
    fn parse_host_port(host_port: &str, source: &str) -> Result<Self, Error> {
        let (host, port_str) = host_port
            .rsplit_once(':')
            .ok_or_else(|| Error::internal(format!("{source} has no port: {host_port}")))?;
        let port: u16 = port_str
            .parse()
            .map_err(|e| Error::internal(format!("{source} port is not a u16: {port_str}: {e}")))?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Format as the colon-separated `host:port` string written into
    /// [`LatticeClusterStatus::endpoint`](lattice_crd::crd::LatticeClusterStatus).
    pub fn to_host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Read `spec.controlPlaneEndpoint` off the CAPI `Cluster` CR.
    ///
    /// Returns `Ok(None)` when the CR is absent (pre-provisioning) or its
    /// endpoint is still the CAPI default of `{host: "", port: 0}`. Errors
    /// only on real I/O or schema-shape failures.
    pub async fn from_capi_cluster(
        client: &Client,
        cluster_name: &str,
        capi_namespace: &str,
    ) -> Result<Option<Self>, Error> {
        let api_resource = build_api_resource_with_discovery(client, "cluster.x-k8s.io", "Cluster")
            .await
            .map_err(|e| Error::internal(format!("CAPI Cluster discovery failed: {e}")))?;

        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), capi_namespace, &api_resource);

        let cluster = match api.get(cluster_name).await {
            Ok(c) => c,
            Err(kube::Error::Api(resp)) if resp.code == 404 => return Ok(None),
            Err(e) => {
                return Err(Error::internal(format!(
                    "failed to get CAPI Cluster {capi_namespace}/{cluster_name}: {e}"
                )));
            }
        };

        let Some(endpoint) = cluster
            .data
            .get("spec")
            .and_then(|s| s.get("controlPlaneEndpoint"))
        else {
            return Ok(None);
        };
        let host = endpoint.get("host").and_then(|h| h.as_str()).unwrap_or("");
        let port_i64 = endpoint.get("port").and_then(|p| p.as_i64()).unwrap_or(0);
        if host.is_empty() || port_i64 == 0 {
            return Ok(None);
        }
        let port = u16::try_from(port_i64).map_err(|_| {
            Error::internal(format!("controlPlaneEndpoint port {port_i64} out of range"))
        })?;
        Ok(Some(Self {
            host: host.to_string(),
            port,
        }))
    }

    /// Resolve the apiserver endpoint to write into
    /// [`LatticeClusterStatus::endpoint`](lattice_crd::crd::LatticeClusterStatus).
    ///
    /// This is the **only** function the cluster controller's populator
    /// calls; every consumer (cilium controller, etc.) reads
    /// `LatticeCluster.status.endpoint` instead of resolving directly.
    ///
    /// Dispatch:
    /// - Tries the CAPI Cluster CR (the canonical source for any
    ///   CAPI-provisioned cluster). Works for the parent reconciling a
    ///   child (CR lives in the parent's `capi-{name}` namespace) and
    ///   for a workload reconciling its own CR post-pivot.
    /// - For `is_self == true` (the cluster controller reconciling its
    ///   *own* cluster), falls back to the local `kubeadm-config` —
    ///   the management kind cluster is the one outlier that's never
    ///   CAPI-provisioned. We deliberately don't read kubeadm-config
    ///   when reconciling a child: that would be the wrong cluster's
    ///   apiserver.
    pub async fn resolve_for_cluster(
        client: &Client,
        cluster_name: &str,
        is_self: bool,
    ) -> Result<Option<Self>, Error> {
        let capi_ns = crate::capi_namespace(cluster_name);
        if let Some(ep) = Self::from_capi_cluster(client, cluster_name, &capi_ns).await? {
            return Ok(Some(ep));
        }
        if is_self {
            if let Some(ep) = Self::from_kubeadm_config(client).await? {
                return Ok(Some(ep));
            }
        }
        Ok(None)
    }

    /// Read `controlPlaneEndpoint` from `kube-system/kubeadm-config`.
    ///
    /// Returns `Ok(None)` when the ConfigMap is absent (RKE2/k3s never
    /// run kubeadm) or `controlPlaneEndpoint` is unset (single-node kind
    /// setups that elide it). Errors only on real I/O or parse failures.
    pub async fn from_kubeadm_config(client: &Client) -> Result<Option<Self>, Error> {
        let cms: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");
        let cm = match cms.get("kubeadm-config").await {
            Ok(cm) => cm,
            Err(kube::Error::Api(resp)) if resp.code == 404 => return Ok(None),
            Err(e) => {
                return Err(Error::internal(format!(
                    "failed to get kube-system/kubeadm-config: {e}"
                )));
            }
        };

        let Some(cluster_config_yaml) =
            cm.data.as_ref().and_then(|d| d.get("ClusterConfiguration"))
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
            Some(endpoint) => Self::parse_host_port(&endpoint, "controlPlaneEndpoint").map(Some),
            None => Ok(None),
        }
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

    #[test]
    fn parse_round_trips_to_host_port() {
        let ep = ApiServerEndpoint {
            host: "10.0.0.5".to_string(),
            port: 6443,
        };
        let formatted = ep.to_host_port();
        assert_eq!(formatted, "10.0.0.5:6443");
        assert_eq!(ApiServerEndpoint::parse(&formatted).unwrap(), ep);
    }

    #[test]
    fn parse_accepts_dns_host() {
        let ep = ApiServerEndpoint::parse("api.example.com:6443").unwrap();
        assert_eq!(ep.host, "api.example.com");
        assert_eq!(ep.port, 6443);
    }
}
