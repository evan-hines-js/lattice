//! Auto-detection of bootstrap method based on network reachability
//!
//! Determines whether to use CRS (push) or webhook (pull) based on whether
//! the parent cluster can reach the child cluster's API server.

use std::time::Duration;

use kube::{Client, Config};
use tracing::{debug, info};

/// Bootstrap method for provisioning child clusters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMethod {
    /// Parent pushes manifests via ClusterResourceSet
    /// Used when parent can reach child API server
    ClusterResourceSet,

    /// Child pulls manifests via webhook callback
    /// Used when parent cannot reach child (NAT, firewall, air-gapped)
    Webhook,
}

impl std::fmt::Display for BootstrapMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapMethod::ClusterResourceSet => write!(f, "ClusterResourceSet"),
            BootstrapMethod::Webhook => write!(f, "Webhook"),
        }
    }
}

/// Detect the best bootstrap method for a child cluster
///
/// Attempts to reach the child cluster's API server using the provided kubeconfig.
/// If reachable, returns CRS (more reliable). If not, returns Webhook (outbound-only).
pub async fn detect_bootstrap_method(kubeconfig_data: &[u8]) -> BootstrapMethod {
    match try_reach_api(kubeconfig_data, Duration::from_secs(10)).await {
        Ok(_) => {
            info!("child API reachable, using ClusterResourceSet bootstrap");
            BootstrapMethod::ClusterResourceSet
        }
        Err(e) => {
            info!(error = %e, "child API not reachable, using Webhook bootstrap");
            BootstrapMethod::Webhook
        }
    }
}

/// Attempt to reach a Kubernetes API server
///
/// Returns Ok if the API server responds to a version request within the timeout.
async fn try_reach_api(kubeconfig_data: &[u8], timeout: Duration) -> Result<(), String> {
    // Parse kubeconfig from bytes
    let kubeconfig_str =
        std::str::from_utf8(kubeconfig_data).map_err(|e| format!("invalid kubeconfig UTF-8: {e}"))?;

    let kubeconfig: kube::config::Kubeconfig =
        serde_yaml::from_str(kubeconfig_str).map_err(|e| format!("invalid kubeconfig YAML: {e}"))?;

    // Build client config from kubeconfig
    let config = Config::from_custom_kubeconfig(kubeconfig, &Default::default())
        .await
        .map_err(|e| format!("failed to build config: {e}"))?;

    // Create client with custom timeout
    let client = Client::try_from(config).map_err(|e| format!("failed to create client: {e}"))?;

    // Try to reach the API server with timeout
    let result = tokio::time::timeout(timeout, async {
        // Use version endpoint - lightweight and always available
        client
            .apiserver_version()
            .await
            .map_err(|e| format!("API request failed: {e}"))
    })
    .await;

    match result {
        Ok(Ok(version)) => {
            debug!(version = %version.git_version, "API server reachable");
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("timeout waiting for API server".to_string()),
    }
}

/// Create a kube Client from kubeconfig bytes
///
/// Used to interact with the child cluster after detecting CRS bootstrap method.
pub async fn client_from_kubeconfig(kubeconfig_data: &[u8]) -> Result<Client, String> {
    let kubeconfig_str =
        std::str::from_utf8(kubeconfig_data).map_err(|e| format!("invalid kubeconfig UTF-8: {e}"))?;

    let kubeconfig: kube::config::Kubeconfig =
        serde_yaml::from_str(kubeconfig_str).map_err(|e| format!("invalid kubeconfig YAML: {e}"))?;

    let config = Config::from_custom_kubeconfig(kubeconfig, &Default::default())
        .await
        .map_err(|e| format!("failed to build config: {e}"))?;

    Client::try_from(config).map_err(|e| format!("failed to create client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_crypto() {
        // Install crypto provider for rustls (required for TLS in tests)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn test_bootstrap_method_display() {
        assert_eq!(BootstrapMethod::ClusterResourceSet.to_string(), "ClusterResourceSet");
        assert_eq!(BootstrapMethod::Webhook.to_string(), "Webhook");
    }

    #[test]
    fn test_bootstrap_method_equality() {
        assert_eq!(BootstrapMethod::ClusterResourceSet, BootstrapMethod::ClusterResourceSet);
        assert_eq!(BootstrapMethod::Webhook, BootstrapMethod::Webhook);
        assert_ne!(BootstrapMethod::ClusterResourceSet, BootstrapMethod::Webhook);
    }

    #[test]
    fn test_bootstrap_method_debug() {
        let crs = BootstrapMethod::ClusterResourceSet;
        let webhook = BootstrapMethod::Webhook;
        assert!(format!("{:?}", crs).contains("ClusterResourceSet"));
        assert!(format!("{:?}", webhook).contains("Webhook"));
    }

    #[tokio::test]
    async fn test_invalid_kubeconfig_returns_webhook() {
        init_crypto();
        // Invalid kubeconfig should fall back to webhook
        let method = detect_bootstrap_method(b"not valid yaml {{{{").await;
        assert_eq!(method, BootstrapMethod::Webhook);
    }

    #[tokio::test]
    async fn test_unreachable_api_returns_webhook() {
        init_crypto();
        // Valid kubeconfig but unreachable server should fall back to webhook
        let kubeconfig = r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://192.0.2.1:6443
    insecure-skip-tls-verify: true
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: fake-token
"#;
        let method = detect_bootstrap_method(kubeconfig.as_bytes()).await;
        assert_eq!(method, BootstrapMethod::Webhook);
    }

    #[tokio::test]
    async fn test_client_from_kubeconfig_invalid_utf8() {
        init_crypto();
        // Invalid UTF-8 bytes
        let invalid_utf8 = &[0xff, 0xfe, 0x00, 0x01];
        let result = client_from_kubeconfig(invalid_utf8).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("invalid kubeconfig UTF-8"), "expected UTF-8 error, got: {}", err);
    }

    #[tokio::test]
    async fn test_client_from_kubeconfig_invalid_yaml() {
        init_crypto();
        let invalid_yaml = b"not: valid: yaml: {{{{";
        let result = client_from_kubeconfig(invalid_yaml).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("invalid kubeconfig YAML"), "expected YAML error, got: {}", err);
    }

    #[tokio::test]
    async fn test_client_from_kubeconfig_empty_config() {
        init_crypto();
        // Empty kubeconfig (valid YAML but no clusters)
        let empty_config = b"apiVersion: v1\nkind: Config\n";
        let result = client_from_kubeconfig(empty_config).await;
        // Should fail because there's no current-context
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_reach_api_invalid_utf8() {
        init_crypto();
        let invalid_utf8 = &[0xff, 0xfe];
        let result = try_reach_api(invalid_utf8, Duration::from_millis(100)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid kubeconfig UTF-8"));
    }

    #[tokio::test]
    async fn test_try_reach_api_invalid_yaml() {
        init_crypto();
        let invalid_yaml = b"{{{{not yaml";
        let result = try_reach_api(invalid_yaml, Duration::from_millis(100)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid kubeconfig YAML"));
    }

    #[tokio::test]
    async fn test_try_reach_api_timeout() {
        init_crypto();
        // Valid kubeconfig but server won't respond (TEST-NET-1 per RFC 5737)
        let kubeconfig = r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://192.0.2.1:6443
    insecure-skip-tls-verify: true
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: test
"#;
        // Very short timeout to ensure it times out or fails quickly
        let result = try_reach_api(kubeconfig.as_bytes(), Duration::from_millis(50)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_detect_with_empty_kubeconfig() {
        init_crypto();
        let method = detect_bootstrap_method(b"").await;
        assert_eq!(method, BootstrapMethod::Webhook);
    }

    #[tokio::test]
    async fn test_detect_with_valid_but_unreachable_config() {
        init_crypto();
        // Use localhost on unlikely port - should fail to connect
        let kubeconfig = r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:59999
    insecure-skip-tls-verify: true
  name: local
contexts:
- context:
    cluster: local
    user: local
  name: local
current-context: local
users:
- name: local
  user:
    token: test
"#;
        let method = detect_bootstrap_method(kubeconfig.as_bytes()).await;
        assert_eq!(method, BootstrapMethod::Webhook);
    }
}
