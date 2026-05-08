//! Service port specifications shared across all Lattice workload CRDs.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::types::ServiceType;
use crate::crd::workload::tls::TlsSpec;

/// Service port specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortSpec {
    /// Service port
    pub port: u16,

    /// Target port (defaults to port)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,

    /// Protocol (TCP or UDP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Service exposure specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePortsSpec {
    /// Named network ports
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, PortSpec>,

    /// K8s `Service.spec.type`. Defaults to ClusterIP. NodePort and LoadBalancer
    /// expose the workload externally and are mutually exclusive with
    /// `LatticeService.spec.ingress` (Gateway API).
    #[serde(default)]
    pub service_type: ServiceType,

    /// Public hostnames this Service handles. Optional — declare here when
    /// the Service is the canonical public endpoint (no upstream proxy in
    /// front of it). When fronted by an edge proxy, leave empty and let the
    /// proxy own the hostname list. Drives `ClusterRoute.hostname` entries
    /// for downstream consumers and (when `publishDns: true`) the
    /// `external-dns.alpha.kubernetes.io/hostname` annotation on the Service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// When true, emit an `external-dns.alpha.kubernetes.io/hostname`
    /// annotation on the K8s Service so external-dns publishes DNS records
    /// pointing at this Service's external IP. Defaults to false: hostnames
    /// (if any) flow into the route table for routing without claiming
    /// public DNS — for setups where an upstream proxy owns the DNS record.
    /// Requires `serviceType` external (NodePort or LoadBalancer) and
    /// non-empty `hostnames`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub publish_dns: bool,

    /// TLS configuration for this Service. When `issuerRef` is set, the
    /// compiler emits a cert-manager Certificate covering `hostnames` and
    /// writes the TLS material into Secret `{service}-tls`. The workload's
    /// pod is responsible for mounting the Secret and terminating TLS
    /// (e.g., via an nginx sidecar in front of the app container).
    /// Requires `serviceType` external and non-empty `hostnames`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsSpec>,
}

impl ServicePortsSpec {
    /// Validate service port specification
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for (name, port_spec) in &self.ports {
            // Validate port name is a valid DNS label (max 15 chars for IANA compliance)
            lattice_core::validate_dns_label(name, "port name")
                .map_err(crate::ValidationError::new)?;
            if name.len() > 15 {
                return Err(crate::ValidationError::new(format!(
                    "port name '{}' exceeds 15 character IANA service name limit",
                    name
                )));
            }

            // Validate port is not zero
            if port_spec.port == 0 {
                return Err(crate::ValidationError::new(format!(
                    "service port '{}': port cannot be 0",
                    name
                )));
            }

            // Validate target_port is not zero
            if let Some(target_port) = port_spec.target_port {
                if target_port == 0 {
                    return Err(crate::ValidationError::new(format!(
                        "service port '{}': target_port cannot be 0",
                        name
                    )));
                }
            }

            // Check for duplicate port numbers
            if !seen_ports.insert(port_spec.port) {
                return Err(crate::ValidationError::new(format!(
                    "duplicate service port number: {}",
                    port_spec.port
                )));
            }
        }

        if self.publish_dns && self.hostnames.is_empty() {
            return Err(crate::ValidationError::new(
                "service.publishDns=true requires at least one entry in service.hostnames",
            ));
        }
        if self.publish_dns && !self.service_type.is_external() {
            return Err(crate::ValidationError::new(
                "service.publishDns=true requires serviceType=NodePort or LoadBalancer; \
                 ClusterIP services have no external endpoint for external-dns to publish",
            ));
        }
        if let Some(tls) = &self.tls {
            tls.validate("service.tls")
                .map_err(crate::ValidationError::new)?;
            if !self.service_type.is_external() {
                return Err(crate::ValidationError::new(
                    "service.tls requires serviceType=NodePort or LoadBalancer; \
                     ClusterIP services terminate TLS via the Gateway-API ingress \
                     path instead",
                ));
            }
            if tls.effective_issuer_ref().is_some() && self.hostnames.is_empty() {
                return Err(crate::ValidationError::new(
                    "service.tls in auto mode (issuerRef explicit or platform default) \
                     requires at least one entry in service.hostnames \
                     (cert-manager rejects empty dnsNames)",
                ));
            }
        }
        for hostname in &self.hostnames {
            lattice_core::validate_dns_subdomain(hostname, "hostname")
                .map_err(crate::ValidationError::new)?;
        }

        Ok(())
    }

    /// Name of the Secret cert-manager will populate when `tls.issuerRef` is
    /// set. Centralizing the format here means callers (workload compiler,
    /// pod-template builders that need to mount it) can't drift.
    pub fn tls_secret_name(service_name: &str) -> String {
        format!("{service_name}-tls")
    }

    /// Name of the Certificate resource emitted when `tls.issuerRef` is set.
    pub fn tls_certificate_name(service_name: &str) -> String {
        format!("{service_name}-tls-cert")
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_service_ports_fail() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        ports.insert(
            "http2".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec {
            ports,
            ..Default::default()
        };
        assert!(svc.validate().is_err());
    }

    #[test]
    fn test_port_zero_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 0,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec {
            ports,
            ..Default::default()
        };
        assert!(svc.validate().is_err());
    }

    #[test]
    fn test_port_name_with_underscores_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "my_port".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec {
            ports,
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("port name"));
    }

    #[test]
    fn test_port_name_exceeding_15_chars_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "ab".repeat(8), // 16 chars
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec {
            ports,
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("15 character"));
    }

    #[test]
    fn test_valid_port_name_accepted() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        let svc = ServicePortsSpec {
            ports,
            ..Default::default()
        };
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn service_type_defaults_to_cluster_ip() {
        let svc = ServicePortsSpec::default();
        assert_eq!(svc.service_type, ServiceType::ClusterIP);
        assert!(!svc.service_type.is_external());
    }

    #[test]
    fn service_type_round_trips() {
        let json = r#"{"serviceType":"LoadBalancer"}"#;
        let svc: ServicePortsSpec = serde_json::from_str(json).unwrap();
        assert_eq!(svc.service_type, ServiceType::LoadBalancer);
        assert!(svc.service_type.is_external());
    }

    #[test]
    fn hostnames_allowed_on_cluster_ip_for_routing_advertisement() {
        let svc = ServicePortsSpec {
            hostnames: vec!["app.example.com".to_string()],
            ..Default::default()
        };
        // ClusterIP + hostnames + publishDns=false: routing only, no DNS publish.
        // Caller (e.g. edge proxy) reaches the pod via FQDN over the mesh.
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn publish_dns_without_hostnames_rejected() {
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            publish_dns: true,
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("publishDns"), "got: {err}");
    }

    #[test]
    fn publish_dns_on_cluster_ip_rejected() {
        let svc = ServicePortsSpec {
            hostnames: vec!["app.example.com".to_string()],
            publish_dns: true,
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("publishDns"), "got: {err}");
    }

    #[test]
    fn hostnames_with_load_balancer_accepted() {
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            hostnames: vec![
                "app.example.com".to_string(),
                "app.alt.example.com".to_string(),
            ],
            ..Default::default()
        };
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn invalid_hostname_rejected() {
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            hostnames: vec!["BAD_HOSTNAME!".to_string()],
            ..Default::default()
        };
        assert!(svc.validate().is_err());
    }

    #[test]
    fn tls_on_cluster_ip_rejected() {
        use crate::crd::workload::tls::{CertIssuerRef, TlsSpec};
        let svc = ServicePortsSpec {
            hostnames: vec!["app.example.com".to_string()],
            tls: Some(TlsSpec {
                issuer_ref: Some(CertIssuerRef {
                    name: "ca".to_string(),
                    kind: None,
                }),
                secret_name: None,
            }),
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("service.tls"), "got: {err}");
    }

    #[test]
    fn tls_auto_without_hostnames_rejected() {
        use crate::crd::workload::tls::{CertIssuerRef, TlsSpec};
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            tls: Some(TlsSpec {
                issuer_ref: Some(CertIssuerRef {
                    name: "ca".to_string(),
                    kind: None,
                }),
                secret_name: None,
            }),
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("hostnames"), "got: {err}");
    }

    #[test]
    fn tls_with_loadbalancer_and_hostnames_accepted() {
        use crate::crd::workload::tls::{CertIssuerRef, TlsSpec};
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            hostnames: vec!["app.example.com".to_string()],
            tls: Some(TlsSpec {
                issuer_ref: Some(CertIssuerRef {
                    name: "ca".to_string(),
                    kind: None,
                }),
                secret_name: None,
            }),
            ..Default::default()
        };
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn tls_manual_secret_does_not_require_hostnames() {
        use crate::crd::workload::tls::TlsSpec;
        let svc = ServicePortsSpec {
            service_type: ServiceType::LoadBalancer,
            tls: Some(TlsSpec {
                secret_name: Some("byo-tls".to_string()),
                issuer_ref: None,
            }),
            ..Default::default()
        };
        assert!(svc.validate().is_ok());
    }
}
