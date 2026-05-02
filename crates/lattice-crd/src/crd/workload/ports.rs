//! Service port specifications shared across all Lattice workload CRDs.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::types::ServiceType;

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

    /// DNS hostnames published via external-dns when the Service is externally
    /// exposed (`serviceType != ClusterIP`). Emitted as an
    /// `external-dns.alpha.kubernetes.io/hostname` annotation on the Service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
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

        if !self.hostnames.is_empty() && !self.service_type.is_external() {
            return Err(crate::ValidationError::new(
                "service.hostnames requires serviceType=NodePort or LoadBalancer; \
                 ClusterIP services have no external IP for external-dns to publish",
            ));
        }
        for hostname in &self.hostnames {
            lattice_core::validate_dns_subdomain(hostname, "hostname")
                .map_err(crate::ValidationError::new)?;
        }

        Ok(())
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
    fn hostnames_with_cluster_ip_rejected() {
        let svc = ServicePortsSpec {
            hostnames: vec!["app.example.com".to_string()],
            ..Default::default()
        };
        let err = svc.validate().unwrap_err().to_string();
        assert!(err.contains("hostnames"), "got: {err}");
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
}
