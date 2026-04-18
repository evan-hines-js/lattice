//! Trust-domain derivation from the shared `lattice-ca` Secret.
//!
//! Every cluster that shares the same root CA gets the same trust domain, so
//! cross-cluster mTLS works without `trustDomainAliases`. The domain is built
//! from the first 27 bytes (54 hex chars) of the SHA-256 of the root CA's
//! DER-encoded certificate, prefixed with `lattice.`. Total length is 62 —
//! under Istio's 63-char trust-domain limit.
//!
//! Verify with: `openssl x509 -in ca.crt -fingerprint -sha256 -noout`.

use k8s_openapi::api::core::v1::Secret;
use kube::Client;

use lattice_common::{CA_CERT_KEY, CA_KEY_KEY, CA_SECRET};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_infra::pki::CertificateAuthority;

/// Istio CA configuration resolved from cluster state.
///
/// - `lattice-ca` absent → `trust_domain` and `root_ca` both `None`;
///   the controller skips Istio entirely until the CA appears.
/// - `lattice-ca` present + `cacerts` already in `istio-system` →
///   `trust_domain` is `Some`, `root_ca` is `None` so we do NOT regenerate
///   the intermediate CA (regenerating on every reconcile would break
///   in-flight mTLS connections).
/// - `lattice-ca` present + no `cacerts` → both `Some`; the controller
///   generates and installs the cacerts Secret before istiod starts.
pub struct IstioCaConfig {
    pub trust_domain: Option<String>,
    pub root_ca: Option<CertificateAuthority>,
}

/// Resolve the Istio CA configuration from cluster state.
pub async fn resolve_istio_ca(client: &Client) -> IstioCaConfig {
    let api: kube::Api<Secret> = kube::Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let Ok(secret) = api.get(CA_SECRET).await else {
        return IstioCaConfig {
            trust_domain: None,
            root_ca: None,
        };
    };

    let Some(data) = secret.data else {
        return IstioCaConfig {
            trust_domain: None,
            root_ca: None,
        };
    };

    let Some(cert_pem) = data
        .get(CA_CERT_KEY)
        .and_then(|b| String::from_utf8(b.0.clone()).ok())
    else {
        return IstioCaConfig {
            trust_domain: None,
            root_ca: None,
        };
    };

    let Some(trust_domain) = trust_domain_from_ca(&cert_pem) else {
        return IstioCaConfig {
            trust_domain: None,
            root_ca: None,
        };
    };

    // If cacerts already exists in istio-system we must NOT regenerate it.
    let cacerts_api: kube::Api<Secret> = kube::Api::namespaced(client.clone(), "istio-system");
    if cacerts_api.get("cacerts").await.is_ok() {
        return IstioCaConfig {
            trust_domain: Some(trust_domain),
            root_ca: None,
        };
    }

    let root_ca = data
        .get(CA_KEY_KEY)
        .and_then(|b| String::from_utf8(b.0.clone()).ok())
        .and_then(|key_pem| CertificateAuthority::from_pem(&cert_pem, &key_pem).ok());

    IstioCaConfig {
        trust_domain: Some(trust_domain),
        root_ca,
    }
}

/// Trust domain as 27-byte SHA-256 prefix of the DER-encoded root CA,
/// formatted as `lattice.{hex}`.
pub fn trust_domain_from_ca(ca_cert_pem: &str) -> Option<String> {
    let der = lattice_infra::pki::parse_pem(ca_cert_pem)
        .ok()
        .filter(|d| !d.is_empty())?;
    let hash = lattice_common::kube_utils::sha256(&der);
    let hex: String = hash.iter().take(27).map(|b| format!("{:02x}", b)).collect();
    Some(format!("lattice.{}", hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_fits_dns_label_limit() {
        let fake_pem =
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh0TTDMA==\n-----END CERTIFICATE-----\n";
        let td = trust_domain_from_ca(fake_pem).expect("parse test PEM");
        assert!(td.len() <= 63, "trust domain '{td}' is {} chars", td.len());
        assert!(td.starts_with("lattice."));
    }
}
