//! Environment configuration for the agent
//!
//! Provides trait-based access to environment configuration,
//! enabling dependency injection and mocking for tests.

/// Trait for reading Kubernetes environment configuration
///
/// This abstracts reading from environment variables, enabling
/// proper unit testing without manipulating global state.
#[cfg_attr(test, mockall::automock)]
pub trait K8sEnvConfig: Send + Sync {
    /// Get the Kubernetes service host from environment
    fn kubernetes_service_host(&self) -> Option<String>;

    /// Get the Kubernetes service port from environment (defaults to 443)
    fn kubernetes_service_port(&self) -> String;
}

/// Build the K8s API server endpoint URL from config
///
/// Returns empty string if host is not set.
pub fn api_server_endpoint(config: &dyn K8sEnvConfig) -> String {
    match config.kubernetes_service_host() {
        Some(host) => {
            let port = config.kubernetes_service_port();
            format!("https://{}:{}", host, port)
        }
        None => String::new(),
    }
}

/// Default implementation that reads from environment variables
#[derive(Clone, Default)]
pub struct OsEnvConfig;

impl K8sEnvConfig for OsEnvConfig {
    fn kubernetes_service_host(&self) -> Option<String> {
        std::env::var("KUBERNETES_SERVICE_HOST").ok()
    }

    fn kubernetes_service_port(&self) -> String {
        std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_server_endpoint_when_set() {
        let mut mock = MockK8sEnvConfig::new();
        mock.expect_kubernetes_service_host()
            .returning(|| Some("10.96.0.1".to_string()));
        mock.expect_kubernetes_service_port()
            .returning(|| "443".to_string());

        assert_eq!(api_server_endpoint(&mock), "https://10.96.0.1:443");
    }

    #[test]
    fn test_api_server_endpoint_when_not_set() {
        let mut mock = MockK8sEnvConfig::new();
        mock.expect_kubernetes_service_host().returning(|| None);

        assert_eq!(api_server_endpoint(&mock), "");
    }

    #[test]
    fn test_api_server_endpoint_custom_port() {
        let mut mock = MockK8sEnvConfig::new();
        mock.expect_kubernetes_service_host()
            .returning(|| Some("10.96.0.1".to_string()));
        mock.expect_kubernetes_service_port()
            .returning(|| "6443".to_string());

        assert_eq!(api_server_endpoint(&mock), "https://10.96.0.1:6443");
    }
}
