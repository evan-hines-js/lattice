//! cert-manager.io/v1 Certificate resources and a single helper for emitting
//! them from a Lattice TLS spec. Used by every compiler that produces a
//! TLS-terminating endpoint (Gateway-API ingress routes, LoadBalancer /
//! NodePort Services, anything else that mounts a cert).

use lattice_crd::crd::CertIssuerRef;
use serde::{Deserialize, Serialize};

use crate::kube_utils::{HasApiResource, ObjectMeta};

/// cert-manager.io/v1 Certificate resource.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// API version (always `cert-manager.io/v1`).
    #[serde(default = "Certificate::default_api_version")]
    pub api_version: String,
    /// Resource kind (always `Certificate`).
    #[serde(default = "Certificate::default_kind")]
    pub kind: String,
    /// Resource metadata (name + namespace).
    pub metadata: ObjectMeta,
    /// Certificate request spec.
    pub spec: CertificateSpec,
}

impl HasApiResource for Certificate {
    const API_VERSION: &'static str = "cert-manager.io/v1";
    const KIND: &'static str = "Certificate";
}

impl Certificate {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }

    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Construct a Certificate with the API version and kind defaults filled in.
    pub fn new(metadata: ObjectMeta, spec: CertificateSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata,
            spec,
        }
    }
}

/// `Certificate.spec` — the certificate request body cert-manager reconciles.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    /// Name of the Secret cert-manager will write the issued certificate into.
    pub secret_name: String,
    /// DNS Subject Alternative Names for the certificate.
    pub dns_names: Vec<String>,
    /// Reference to the issuer that signs this certificate.
    pub issuer_ref: IssuerRef,
}

/// Reference to a cert-manager Issuer or ClusterIssuer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerRef {
    /// Issuer name.
    pub name: String,
    /// Issuer kind — `Issuer` (namespaced) or `ClusterIssuer`.
    pub kind: String,
    /// API group (always `cert-manager.io` in practice).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Build a `Certificate` from a Lattice `CertIssuerRef` plus the per-callsite
/// naming context. Single source of truth for emitting certificates — every
/// compiler (Gateway-API routes, LoadBalancer / NodePort Services, model
/// ingress) routes through here so the IssuerRef shape, group default
/// (`cert-manager.io`), and ClusterIssuer fallback are owned in one place.
///
/// Returns `None` when `dns_names` is empty (cert-manager rejects empty
/// `dnsNames`); the caller's invariant is "if you asked for a cert, you
/// have hosts to put in it."
///
/// Not named `CertificateRequest` deliberately: cert-manager already owns
/// that name as a separate CRD (`cert-manager.io/v1 Kind=CertificateRequest`),
/// the intermediate signing request the controller produces from a
/// `Certificate`. Confusing the two would be a footgun.
pub fn compile_certificate(
    cert_name: &str,
    namespace: &str,
    secret_name: &str,
    dns_names: &[String],
    issuer: &CertIssuerRef,
) -> Option<Certificate> {
    if dns_names.is_empty() {
        return None;
    }
    Some(Certificate::new(
        ObjectMeta::new(cert_name, namespace),
        CertificateSpec {
            secret_name: secret_name.to_string(),
            dns_names: dns_names.to_vec(),
            issuer_ref: IssuerRef {
                name: issuer.name.clone(),
                kind: issuer.kind_or_default().to_string(),
                group: Some("cert-manager.io".to_string()),
            },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(name: &str) -> CertIssuerRef {
        CertIssuerRef {
            name: name.to_string(),
            kind: None,
        }
    }

    #[test]
    fn compile_emits_expected_shape() {
        let hosts = vec!["api.example.com".to_string()];
        let cert = compile_certificate(
            "api-cert",
            "prod",
            "api-tls",
            &hosts,
            &issuer("letsencrypt"),
        )
        .expect("should compile");

        assert_eq!(cert.metadata.name, "api-cert");
        assert_eq!(cert.metadata.namespace, "prod");
        assert_eq!(cert.spec.secret_name, "api-tls");
        assert_eq!(cert.spec.dns_names, hosts);
        assert_eq!(cert.spec.issuer_ref.name, "letsencrypt");
        assert_eq!(cert.spec.issuer_ref.kind, "ClusterIssuer");
        assert_eq!(
            cert.spec.issuer_ref.group.as_deref(),
            Some("cert-manager.io")
        );
    }

    #[test]
    fn empty_dns_names_yields_none() {
        let hosts: Vec<String> = vec![];
        let cert = compile_certificate("noop", "prod", "noop-tls", &hosts, &issuer("letsencrypt"));
        assert!(cert.is_none());
    }

    #[test]
    fn explicit_issuer_kind_overrides_default() {
        let hosts = vec!["api.example.com".to_string()];
        let issuer = CertIssuerRef {
            name: "ns-ca".to_string(),
            kind: Some("Issuer".to_string()),
        };
        let cert = compile_certificate("api-cert", "prod", "api-tls", &hosts, &issuer)
            .expect("should compile");
        assert_eq!(cert.spec.issuer_ref.kind, "Issuer");
    }
}
