//! Certificate blocklist for immediate revocation of compromised agent certificates.
//!
//! Stores SHA-256 fingerprints of blocked certificates and checks them during
//! mTLS authentication. Persisted to a ConfigMap for crash recovery.

use std::sync::Arc;

use dashmap::DashSet;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tracing::{debug, info, warn};

use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// ConfigMap name for persisting blocked certificate fingerprints
const BLOCKLIST_CONFIGMAP: &str = "lattice-cert-blocklist";
/// Key within the ConfigMap data
const BLOCKLIST_DATA_KEY: &str = "fingerprints";
/// Field manager for server-side apply
const FIELD_MANAGER: &str = "lattice-cert-blocklist";

/// Thread-safe certificate blocklist using SHA-256 fingerprints.
///
/// Checked during mTLS authentication to reject compromised certificates
/// without waiting for them to expire.
#[derive(Clone)]
pub struct CertificateBlocklist {
    fingerprints: Arc<DashSet<String>>,
}

impl CertificateBlocklist {
    /// Create an empty blocklist.
    pub fn new() -> Self {
        Self {
            fingerprints: Arc::new(DashSet::new()),
        }
    }

    /// Check if a certificate fingerprint is blocked.
    pub fn is_blocked(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Add a certificate fingerprint to the blocklist.
    pub fn add(&self, fingerprint: String) {
        info!(fingerprint = %fingerprint, "Blocking certificate");
        self.fingerprints.insert(fingerprint);
    }

    /// Remove a certificate fingerprint from the blocklist.
    pub fn remove(&self, fingerprint: &str) -> bool {
        self.fingerprints.remove(fingerprint).is_some()
    }

    /// Number of blocked certificates.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Compute the SHA-256 fingerprint of a DER-encoded certificate.
    ///
    /// Uses FIPS-validated `aws_lc_rs::digest::SHA256`.
    pub fn fingerprint(cert_der: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert_der);
        digest
            .as_ref()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Load blocklist from a ConfigMap in lattice-system namespace.
    ///
    /// If the ConfigMap doesn't exist, returns an empty blocklist.
    pub async fn load_from_configmap(client: &Client) -> Result<Self, kube::Error> {
        let api: Api<k8s_openapi::api::core::v1::ConfigMap> =
            Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let blocklist = Self::new();

        match api.get(BLOCKLIST_CONFIGMAP).await {
            Ok(cm) => {
                if let Some(data) = cm.data {
                    if let Some(raw) = data.get(BLOCKLIST_DATA_KEY) {
                        for line in raw.lines() {
                            let fp = line.trim();
                            if !fp.is_empty() {
                                blocklist.fingerprints.insert(fp.to_string());
                            }
                        }
                        info!(
                            count = blocklist.len(),
                            "Loaded certificate blocklist from ConfigMap"
                        );
                    }
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                debug!("No certificate blocklist ConfigMap found, starting empty");
            }
            Err(e) => return Err(e),
        }

        Ok(blocklist)
    }

    /// Persist the current blocklist to a ConfigMap.
    pub async fn persist_to_configmap(&self, client: &Client) -> Result<(), kube::Error> {
        let api: Api<k8s_openapi::api::core::v1::ConfigMap> =
            Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let fingerprints: Vec<String> = self
            .fingerprints
            .iter()
            .map(|fp| fp.key().clone())
            .collect();
        let data = fingerprints.join("\n");

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": BLOCKLIST_CONFIGMAP,
                "namespace": LATTICE_SYSTEM_NAMESPACE,
            },
            "data": {
                BLOCKLIST_DATA_KEY: data,
            }
        });

        let params = PatchParams::apply(FIELD_MANAGER).force();
        api.patch(BLOCKLIST_CONFIGMAP, &params, &Patch::Apply(&cm))
            .await?;

        info!(count = fingerprints.len(), "Persisted certificate blocklist to ConfigMap");
        Ok(())
    }

    /// Sync from a ConfigMap, adding any new entries not already present.
    pub async fn sync_from_configmap(&self, client: &Client) -> Result<(), kube::Error> {
        let api: Api<k8s_openapi::api::core::v1::ConfigMap> =
            Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        match api.get(BLOCKLIST_CONFIGMAP).await {
            Ok(cm) => {
                if let Some(data) = cm.data {
                    if let Some(raw) = data.get(BLOCKLIST_DATA_KEY) {
                        let mut added = 0u32;
                        for line in raw.lines() {
                            let fp = line.trim();
                            if !fp.is_empty() && self.fingerprints.insert(fp.to_string()) {
                                added += 1;
                            }
                        }
                        if added > 0 {
                            info!(added, total = self.len(), "Synced new entries from blocklist ConfigMap");
                        }
                    }
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => {
                warn!(error = %e, "Failed to sync blocklist from ConfigMap");
            }
        }

        Ok(())
    }
}

impl Default for CertificateBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blocklist_blocks_nothing() {
        let blocklist = CertificateBlocklist::new();
        assert!(!blocklist.is_blocked("abc123"));
        assert!(blocklist.is_empty());
        assert_eq!(blocklist.len(), 0);
    }

    #[test]
    fn add_and_check_fingerprint() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("deadbeef".to_string());

        assert!(blocklist.is_blocked("deadbeef"));
        assert!(!blocklist.is_blocked("other"));
        assert_eq!(blocklist.len(), 1);
    }

    #[test]
    fn remove_fingerprint() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("deadbeef".to_string());
        assert!(blocklist.is_blocked("deadbeef"));

        assert!(blocklist.remove("deadbeef"));
        assert!(!blocklist.is_blocked("deadbeef"));
        assert!(blocklist.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let blocklist = CertificateBlocklist::new();
        assert!(!blocklist.remove("nonexistent"));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let data = b"test certificate data";
        let fp1 = CertificateBlocklist::fingerprint(data);
        let fp2 = CertificateBlocklist::fingerprint(data);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn fingerprint_differs_for_different_certs() {
        let fp1 = CertificateBlocklist::fingerprint(b"cert one");
        let fp2 = CertificateBlocklist::fingerprint(b"cert two");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn clone_shares_state() {
        let blocklist = CertificateBlocklist::new();
        let clone = blocklist.clone();

        blocklist.add("shared".to_string());
        assert!(clone.is_blocked("shared"));
    }

    #[test]
    fn duplicate_add_is_idempotent() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("dup".to_string());
        blocklist.add("dup".to_string());
        assert_eq!(blocklist.len(), 1);
    }
}
