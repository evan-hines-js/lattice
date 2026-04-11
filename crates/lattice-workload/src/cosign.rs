//! Image signature verification using sigstore-rs.
//!
//! Verifies cosign signatures on container images using public keys.
//! Uses sigstore-rs with aws-lc-rs backend for FIPS compliance.

use sigstore::cosign::verification_constraint::PublicKeyVerifier;
use sigstore::cosign::CosignCapabilities;
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
use tracing::{debug, info, warn};

/// Result of verifying a single image.
#[derive(Debug)]
pub enum VerifyResult {
    /// Signature is valid.
    Verified,
    /// No valid signature found.
    NotSigned(String),
    /// Verification error.
    Error(String),
}

/// Verify an image signature using a cosign public key (PEM bytes).
pub async fn verify_image(image: &str, key_pem: &[u8]) -> VerifyResult {
    let oci_ref = match image.parse::<OciReference>() {
        Ok(r) => r,
        Err(e) => return VerifyResult::Error(format!("invalid image reference '{image}': {e}")),
    };

    // Use HTTP for registries that don't support TLS (IP:port, localhost, etc.)
    let mut oci_config = ClientConfig::default();
    let registry = oci_ref.registry();
    if is_insecure_registry(registry) {
        oci_config.protocol = ClientProtocol::Http;
    }

    let mut client = match sigstore::cosign::ClientBuilder::default()
        .with_oci_client_config(oci_config)
        .build()
    {
        Ok(c) => c,
        Err(e) => return VerifyResult::Error(format!("failed to build cosign client: {e}")),
    };

    let auth = Auth::Anonymous;

    let (cosign_image, source_digest) = match client.triangulate(&oci_ref, &auth).await {
        Ok(result) => result,
        Err(e) => {
            return VerifyResult::NotSigned(format!(
                "no cosign signature found for {image}: {e}"
            ))
        }
    };

    let layers = match client
        .trusted_signature_layers(&auth, &source_digest, &cosign_image)
        .await
    {
        Ok(l) => l,
        Err(e) => {
            return VerifyResult::NotSigned(format!(
                "failed to fetch signature layers for {image}: {e}"
            ))
        }
    };

    if layers.is_empty() {
        return VerifyResult::NotSigned(format!("no signature layers found for {image}"));
    }

    let verifier = match PublicKeyVerifier::try_from(key_pem) {
        Ok(v) => v,
        Err(e) => return VerifyResult::Error(format!("failed to create key verifier: {e}")),
    };

    let constraints: sigstore::cosign::verification_constraint::VerificationConstraintVec =
        vec![Box::new(verifier)];
    match sigstore::cosign::verify_constraints(&layers, constraints.iter()) {
        Ok(()) => {
            info!(image = image, "signature verification succeeded");
            VerifyResult::Verified
        }
        Err(e) => {
            debug!(image = image, error = %e, "signature verification failed");
            VerifyResult::NotSigned(format!(
                "image {image} has {} signatures but none match the provided key",
                layers.len()
            ))
        }
    }
}

/// Detect registries that use HTTP instead of HTTPS.
///
/// Registries accessed by IP address, with non-standard ports, or on localhost
/// are typically insecure (no TLS). Standard registries (ghcr.io, docker.io,
/// quay.io, etc.) use HTTPS.
fn is_insecure_registry(registry: &str) -> bool {
    // Localhost is always insecure
    if registry.starts_with("localhost") || registry.starts_with("127.0.0.1") {
        return true;
    }
    // IP address with port (e.g., 10.0.0.131:5557)
    if let Some((host, _port)) = registry.rsplit_once(':') {
        if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return true;
        }
    }
    // Bare IP without port
    if registry.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_image_ref_returns_error() {
        let result = verify_image("not a valid ref!!!", b"fake-key").await;
        assert!(matches!(result, VerifyResult::Error(_)));
    }
}
