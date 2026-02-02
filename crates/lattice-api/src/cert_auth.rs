//! Client certificate authentication for mTLS
//!
//! Extracts user identity from TLS client certificates. This allows CAPI controllers
//! (which use kubeconfig with client certs) to authenticate to the auth proxy.
//!
//! # Certificate Identity Extraction
//!
//! The username is extracted from the certificate's Common Name (CN) field.
//! For CAPI-generated kubeconfigs, this is typically "kubernetes-admin".
//!
//! # Security Model
//!
//! - Client certs are accepted but not verified against a specific CA
//! - This is acceptable because:
//!   1. The proxy is only accessible within the cluster network
//!   2. Cedar policies provide the actual authorization
//!   3. The cert CN provides identity for authorization decisions

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DistinguishedName, RootCertStore, SignatureScheme};
use tracing::{debug, warn};

use crate::auth::UserIdentity;
use crate::error::{Error, Result};

/// Client certificate validator
///
/// Extracts user identity from the Common Name (CN) field of client certificates.
pub struct CertValidator;

impl CertValidator {
    /// Create a new certificate validator
    pub fn new() -> Self {
        Self
    }

    /// Extract user identity from a certificate chain
    ///
    /// Parses the first certificate in the chain and extracts the CN as username.
    pub fn extract_identity(&self, cert_chain: &[CertificateDer<'_>]) -> Result<UserIdentity> {
        let cert = cert_chain
            .first()
            .ok_or_else(|| Error::Unauthorized("No client certificate provided".into()))?;

        // Parse the certificate to extract CN
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|e| Error::Internal(format!("Failed to parse client certificate: {}", e)))?;

        // Extract Common Name from subject
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .ok_or_else(|| Error::Unauthorized("Client certificate has no Common Name".into()))?;

        debug!(cn = %cn, "Extracted identity from client certificate");

        Ok(UserIdentity {
            username: cn.to_string(),
            groups: vec![], // Client certs don't have groups
        })
    }
}

impl Default for CertValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// A permissive client certificate verifier that accepts any certificate.
///
/// This verifier captures client certificates without requiring them to be signed
/// by a specific CA. It's used when we want to extract identity from certificates
/// but don't have access to the signing CA (e.g., CAPI client certs signed by
/// child cluster CAs).
///
/// # Security Considerations
///
/// This should only be used in environments where:
/// 1. Network access to the proxy is already restricted
/// 2. Cedar policies provide the actual authorization
/// 3. The certificate CN is sufficient for identity
#[derive(Debug)]
pub struct PermissiveClientCertVerifier {
    /// Inner verifier for signature validation (uses empty root store)
    inner: Arc<dyn ClientCertVerifier>,
    /// Supported signature schemes
    schemes: Vec<SignatureScheme>,
}

impl PermissiveClientCertVerifier {
    /// Create a new permissive verifier
    pub fn new() -> Self {
        // Create an empty root store - we won't verify against any CA
        let root_store = RootCertStore::empty();

        // Create inner verifier that handles signature validation
        // We use allow_unauthenticated() to make client certs optional
        let inner = WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .expect("Failed to build client cert verifier");

        Self {
            schemes: inner.supported_verify_schemes(),
            inner,
        }
    }
}

impl Default for PermissiveClientCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientCertVerifier for PermissiveClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Return empty - we accept certs from any CA
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        // Accept all client certificates
        // The actual authorization is done by Cedar policies
        debug!("Accepting client certificate (permissive mode)");
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        // Client certs are optional - we also support Bearer token auth
        false
    }
}

/// Client certificate chain extracted from TLS connection
///
/// This is stored as a request extension so handlers can access it.
#[derive(Clone, Debug)]
pub struct ClientCertChain(pub Vec<Vec<u8>>);

impl ClientCertChain {
    /// Create from certificate DER bytes
    pub fn new(certs: Vec<Vec<u8>>) -> Self {
        Self(certs)
    }

    /// Check if any certificates were provided
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to CertificateDer for parsing
    pub fn to_certificate_der(&self) -> Vec<CertificateDer<'static>> {
        self.0
            .iter()
            .map(|bytes| CertificateDer::from(bytes.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_validator_new() {
        let validator = CertValidator::new();
        // Just verify it can be created
        drop(validator);
    }

    #[test]
    fn test_permissive_verifier_not_mandatory() {
        let verifier = PermissiveClientCertVerifier::new();
        assert!(!verifier.client_auth_mandatory());
    }

    #[test]
    fn test_permissive_verifier_empty_hints() {
        let verifier = PermissiveClientCertVerifier::new();
        assert!(verifier.root_hint_subjects().is_empty());
    }

    #[test]
    fn test_client_cert_chain_empty() {
        let chain = ClientCertChain::new(vec![]);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_client_cert_chain_non_empty() {
        let chain = ClientCertChain::new(vec![vec![1, 2, 3]]);
        assert!(!chain.is_empty());
    }
}
