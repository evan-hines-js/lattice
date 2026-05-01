//! Cilium helm chart manifests + `CiliumClusterwideNetworkPolicy` generators.
//!
//! Policies land as part of the Cilium install: they are enforcement rules
//! owned by the Cilium CNI, not by individual workloads.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use lattice_common::kube_utils::{extract_image_registries, split_yaml_documents};
use lattice_common::mesh::{CILIUM_GATEWAY_NAME_LABEL, HBONE_PORT, ISTIOD_XDS_PORT};
use lattice_common::policy::cilium::{
    CiliumClusterwideNetworkPolicy, CiliumClusterwideSpec, CiliumPort, CiliumPortRule,
    ClusterwideEgressRule, ClusterwideIngressRule, ClusterwideMetadata, DnsMatch, DnsRules,
    EnableDefaultDeny, EndpointSelector, MatchExpression,
};
use lattice_common::ApiServerEndpoint;
use lattice_core::system_namespaces;
use lattice_crd::crd::ProviderType;

/// L2-announce + SNAT variant of the Cilium install.
static CILIUM_L2_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/cilium-l2.yaml"));
/// BGP control-plane + DSR variant. Used by the basis provider; k8s
/// nodes peer with the cell's iBGP route reflector embedded in
/// basis-controller. The CRDs that name the reflector + select the
/// LB pool are rendered per-cluster by basis-capi-provider, not here.
static CILIUM_BGP_TEMPLATE: &str = include_str!(concat!(env!("OUT_DIR"), "/cilium-bgp.yaml"));

const PLACEHOLDER_HOST: &str = "__LATTICE_API_SERVER_HOST__";
const PLACEHOLDER_PORT: &str = "__LATTICE_API_SERVER_PORT__";
const PLACEHOLDER_POD_CIDR: &str = "__LATTICE_POD_CIDR__";

/// Which LB advertisement plane Cilium is configured for. Selected
/// per-cluster: providers with a BGP fabric (basis) get [`Self::Bgp`],
/// the rest get [`Self::L2`]. The two paths share everything except
/// `loadBalancer.mode`, `l2announcements.enabled`, and
/// `bgpControlPlane.enabled`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CiliumLbMode {
    /// L2-announce + SNAT. Default for non-BGP providers.
    L2,
    /// BGP-announce + DSR (geneve dispatch). Selected for basis.
    Bgp,
}

impl CiliumLbMode {
    fn template(self) -> &'static str {
        match self {
            Self::L2 => CILIUM_L2_TEMPLATE,
            Self::Bgp => CILIUM_BGP_TEMPLATE,
        }
    }
}

impl From<ProviderType> for CiliumLbMode {
    /// Pick the variant based on whether the provider has a BGP
    /// fabric available. basis runs an iBGP route reflector embedded
    /// in basis-controller; everything else (Docker/kind, Proxmox,
    /// cloud providers) gets the L2-announce path. Cloud providers
    /// don't actually use Cilium's L2-announce — their LB IPs come
    /// from the cloud LB — but L2 is the safe default that doesn't
    /// require any control-plane peer config.
    fn from(provider: ProviderType) -> Self {
        match provider {
            ProviderType::Basis => Self::Bgp,
            // Docker/kind, Proxmox, and cloud providers default to L2.
            // Cloud providers don't actually use Cilium's L2-announce
            // (their LB IPs come from the cloud LB) but L2 is the
            // safe default that doesn't require any control-plane
            // peer config. The wildcard catches future variants the
            // same way — non-basis = L2 until proven otherwise.
            _ => Self::L2,
        }
    }
}

/// Cilium chart version pinned at build time from `versions.toml`.
pub fn cilium_version() -> &'static str {
    env!("CILIUM_VERSION")
}

/// Render Cilium manifests with the given API server endpoint and pod
/// CIDR substituted for the build-time placeholders.
///
/// Single source of truth for installable Cilium manifests. The pod
/// CIDR is critical: Cilium native-routing only skips masquerade for
/// destinations inside `ipv4NativeRoutingCIDR`. Setting it wider than
/// the actual pod CIDR (e.g. the underlay supernet) makes pod-egress
/// to LAN destinations leak the pod IP and break return-path routing.
///
/// `endpoint` is only consulted when the chart was rendered with
/// `KUBE_PROXY_REPLACEMENT = true` (the host/port placeholders are
/// only emitted in that mode). With stock kube-proxy the param is
/// kept on the signature so callers don't churn when the toggle flips.
///
/// `lb_mode` selects the L2-announce or BGP variant of the chart;
/// see [`CiliumLbMode`].
pub fn render_cilium_manifests(
    endpoint: &ApiServerEndpoint,
    pod_cidr: &str,
    lb_mode: CiliumLbMode,
) -> Vec<String> {
    let yaml = lb_mode
        .template()
        .replace(PLACEHOLDER_HOST, &endpoint.host)
        .replace(PLACEHOLDER_PORT, &endpoint.port.to_string())
        .replace(PLACEHOLDER_POD_CIDR, pod_cidr);
    split_yaml_documents(&yaml)
}

/// Image registry hosts referenced by Cilium's chart manifests.
///
/// Computed once from the unrendered templates — the API server
/// endpoint placeholders never appear on `image:` lines, so
/// substitution is irrelevant for registry extraction. Both LB
/// variants share the same image set, but we feed both in to be
/// robust against a future divergence (e.g. a BGP-only sidecar).
pub fn image_registries() -> &'static BTreeSet<String> {
    static REGS: LazyLock<BTreeSet<String>> =
        LazyLock::new(|| extract_image_registries(&[CILIUM_L2_TEMPLATE, CILIUM_BGP_TEMPLATE]));
    &REGS
}

/// Generate a `CiliumClusterwideNetworkPolicy` to allow ztunnel/ambient traffic.
///
/// Required for Istio ambient mode when default-deny is active. ztunnel uses
/// link-local 169.254.7.127 for SNAT-ed kubelet health probes.
/// See: <https://istio.io/latest/docs/ambient/install/platform-prerequisites/>
pub fn generate_ztunnel_allowlist() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("allow-ambient-hostprobes"),
        CiliumClusterwideSpec {
            description: Some(
                "Allows SNAT-ed kubelet health check probes into ambient pods".to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::default(),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec!["169.254.7.127/32".to_string()],
                from_endpoints: vec![],
                from_entities: vec![],
                to_ports: vec![],
            }],
            egress: vec![],
        },
    )
}

/// Allow ingress from the local node (`host`), peer nodes (`remote-node`),
/// and the kube-apiserver to every pod, on any port.
///
/// Required for kubelet liveness/readiness probes, kube-apiserver
/// webhook callbacks, Service traffic SNATed to the node IP, and
/// Cilium health probes between nodes. Without it, any pod whose
/// namespace falls under `default-deny` and has a per-pod CNP silently
/// drops these flows the moment a second node joins, since they
/// arrive identified as `remote-node` (or `host` for the local
/// kubelet) rather than as a known pod identity.
///
/// `kube-apiserver` is listed alongside `host`/`remote-node` because Cilium
/// tags apiserver IPs with the dedicated `reserved:kube-apiserver` identity,
/// and policies that select only the node identities can miss webhook
/// callbacks before per-pod LMM CNPs are reconciled (they fail closed at
/// socketLB with `connect: operation not permitted`).
///
/// `enableDefaultDeny: { ingress: false }` is critical: this policy
/// is purely additive and must not flip pods into default-deny ingress.
pub fn generate_allow_node_ingress() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("allow-node-ingress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow ingress from host + remote-node + kube-apiserver to all pods. Required for kubelet probes, admission webhooks, SNATed Service traffic, and cilium-health.".to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::default(),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec![],
                from_endpoints: vec![],
                from_entities: vec![
                    "host".to_string(),
                    "remote-node".to_string(),
                    "kube-apiserver".to_string(),
                ],
                to_ports: vec![],
            }],
            egress: vec![],
        },
    )
}

/// Mesh-wide default-deny policy — L4 defense-in-depth alongside Istio's L7
/// AuthorizationPolicy.
///
/// - No ingress rules → deny all ingress.
/// - Only DNS egress to `kube-dns` + kube-apiserver egress allowed.
/// - System namespaces excluded via `matchExpressions`.
pub fn generate_default_deny() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("default-deny"),
        CiliumClusterwideSpec {
            description: Some(
                "Block all ingress traffic by default, allow DNS and K8s API egress".to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: "k8s:io.kubernetes.pod.namespace".to_string(),
                    operator: "NotIn".to_string(),
                    values: system_namespaces::all()
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }],
            },
            ingress: vec![],
            egress: vec![
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "UDP".to_string(),
                            },
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "TCP".to_string(),
                            },
                        ],
                        rules: Some(DnsRules {
                            dns: vec![DnsMatch {
                                match_pattern: Some("*".to_string()),
                            }],
                        }),
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec!["kube-apiserver".to_string()],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
            ],
        },
    )
}

/// Egress policy for every Istio Gateway API proxy pod (waypoints + ingress
/// gateways), keyed off `gateway.networking.k8s.io/gateway-name`.
///
/// One cluster-wide policy covers every service namespace without duplicating
/// namespace-scoped policies.
pub fn generate_mesh_proxy_egress_policy() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("mesh-proxy-egress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow Istio mesh proxy pods (waypoints + ingress gateways) to reach istiod and forward traffic"
                    .to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: CILIUM_GATEWAY_NAME_LABEL.to_string(),
                    operator: "Exists".to_string(),
                    values: vec![],
                }],
            },
            ingress: vec![],
            egress: vec![
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "UDP".to_string(),
                            },
                            CiliumPort {
                                port: "53".to_string(),
                                protocol: "TCP".to_string(),
                            },
                        ],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "istio-system".to_string(),
                        ),
                        ("k8s:app".to_string(), "istiod".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: ISTIOD_XDS_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: HBONE_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector {
                        match_labels: BTreeMap::new(),
                        match_expressions: vec![MatchExpression {
                            key: "k8s:io.kubernetes.pod.namespace".to_string(),
                            operator: "NotIn".to_string(),
                            values: system_namespaces::all()
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        }],
                    }],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec!["0.0.0.0/0".to_string()],
                    to_ports: vec![],
                },
            ],
        },
    )
}

/// Ingress policy for the east-west gateway accepting cross-cluster HBONE
/// on port 15008. Egress is covered by the mesh-proxy-egress policy since the
/// gateway pods carry the gateway-name label.
pub fn generate_eastwest_gateway_policy() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("eastwest-gateway-ingress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow east-west gateway to receive cross-cluster HBONE traffic from external networks"
                    .to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::from_labels(BTreeMap::from([
                (
                    "k8s:io.kubernetes.pod.namespace".to_string(),
                    "istio-system".to_string(),
                ),
                (
                    CILIUM_GATEWAY_NAME_LABEL.to_string(),
                    "istio-eastwestgateway".to_string(),
                ),
            ])),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec!["0.0.0.0/0".to_string()],
                from_endpoints: vec![],
                from_entities: vec![],
                to_ports: vec![CiliumPortRule {
                    ports: vec![CiliumPort {
                        port: HBONE_PORT.to_string(),
                        protocol: "TCP".to_string(),
                    }],
                    rules: None,
                }],
            }],
            egress: vec![],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!cilium_version().is_empty());
    }

    fn test_endpoint() -> ApiServerEndpoint {
        ApiServerEndpoint {
            host: "api.example.com".to_string(),
            port: 6443,
        }
    }

    #[test]
    fn manifests_contain_agent() {
        let m = render_cilium_manifests(&test_endpoint(), "192.168.0.0/16", CiliumLbMode::L2);
        assert!(!m.is_empty());
        let combined = m.join("\n");
        assert!(combined.contains("kind: DaemonSet"));
        assert!(combined.contains("cilium-agent"));
    }

    #[test]
    fn rendered_manifests_substitute_placeholders() {
        let m = render_cilium_manifests(&test_endpoint(), "192.168.0.0/16", CiliumLbMode::L2);
        let combined = m.join("\n");
        assert!(
            !combined.contains(PLACEHOLDER_HOST),
            "host placeholder must not appear in rendered output"
        );
        assert!(
            !combined.contains(PLACEHOLDER_PORT),
            "port placeholder must not appear in rendered output"
        );
        assert!(
            !combined.contains(PLACEHOLDER_POD_CIDR),
            "pod CIDR placeholder must be substituted"
        );
        assert!(combined.contains("192.168.0.0/16"));
        // Host/port placeholders only appear in the rendered chart when
        // kube-proxy replacement is enabled (chart sets `k8sServiceHost`
        // / `k8sServicePort` only in that mode). Verify substitution
        // happened in that case; skip otherwise.
        if super::super::KUBE_PROXY_REPLACEMENT {
            assert!(combined.contains("api.example.com"));
            assert!(combined.contains("6443"));
        }
    }

    /// L2 vs BGP variants must differ on the LB advertisement
    /// plane: only L2 sets `loadBalancer.mode=snat` /
    /// `l2announcements.enabled=true`, only BGP enables
    /// `bgpControlPlane`. Pin the wire output here so a future
    /// chart upgrade can't silently collapse the variants.
    #[test]
    fn lb_mode_picks_distinct_templates() {
        let l2 = render_cilium_manifests(&test_endpoint(), "192.168.0.0/16", CiliumLbMode::L2)
            .join("\n");
        let bgp = render_cilium_manifests(&test_endpoint(), "192.168.0.0/16", CiliumLbMode::Bgp)
            .join("\n");
        assert_ne!(l2, bgp, "L2 and BGP templates must render differently");
        assert!(l2.contains("enable-l2-announcements: \"true\""));
        assert!(bgp.contains("enable-bgp-control-plane: \"true\""));
    }

    #[test]
    fn ztunnel_allowlist_allows_link_local() {
        let p = generate_ztunnel_allowlist();
        assert_eq!(p.metadata.name, "allow-ambient-hostprobes");
        assert!(p
            .spec
            .ingress
            .iter()
            .any(|r| r.from_cidr.contains(&"169.254.7.127/32".to_string())));
    }

    #[test]
    fn allow_node_ingress_is_additive_and_unrestricted() {
        let p = generate_allow_node_ingress();
        assert_eq!(p.metadata.name, "allow-node-ingress");
        let dd = p
            .spec
            .enable_default_deny
            .as_ref()
            .expect("enableDefaultDeny must be set");
        assert!(!dd.ingress, "must not flip pods into default-deny ingress");
        assert!(p.spec.endpoint_selector.match_labels.is_empty());
        assert!(p.spec.endpoint_selector.match_expressions.is_empty());
        let rule = &p.spec.ingress[0];
        assert!(rule.from_entities.contains(&"host".to_string()));
        assert!(rule.from_entities.contains(&"remote-node".to_string()));
        assert!(rule.from_entities.contains(&"kube-apiserver".to_string()));
        assert!(rule.to_ports.is_empty(), "no port restriction");
        assert!(p.spec.egress.is_empty());
    }

    #[test]
    fn default_deny_excludes_system_namespaces() {
        let p = generate_default_deny();
        let expr = &p.spec.endpoint_selector.match_expressions[0];
        assert_eq!(expr.operator, "NotIn");
        assert!(expr.values.contains(&"kube-system".to_string()));
        assert!(p.spec.ingress.is_empty());
    }

    #[test]
    fn mesh_proxy_egress_has_all_five_rules() {
        let p = generate_mesh_proxy_egress_policy();
        assert_eq!(p.spec.egress.len(), 5);
    }

    #[test]
    fn eastwest_gateway_ingress_on_hbone_port() {
        let p = generate_eastwest_gateway_policy();
        let port = &p.spec.ingress[0].to_ports[0].ports[0];
        assert_eq!(port.port, HBONE_PORT.to_string());
    }
}
