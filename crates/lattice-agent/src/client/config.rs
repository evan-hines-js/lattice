//! Configuration types and constants for the agent client.

use std::time::Duration;

/// TTL for forwarded exec session cache (30 minutes).
pub(crate) const EXEC_SESSION_CACHE_TTL: Duration = Duration::from_secs(1800);
/// HTTP connect timeout for CSR signing requests.
pub(crate) const CSR_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP request timeout for CSR signing requests.
pub(crate) const CSR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// gRPC keep-alive timeout (peer must respond within this window).
pub(crate) const GRPC_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// HTTP/2 keep-alive interval (how often to send keep-alive pings).
pub(crate) const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Timeout for a single CAPI installation attempt.
pub(crate) const CAPI_INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
/// Delay between CAPI installation retry attempts.
pub(crate) const CAPI_INSTALL_RETRY_DELAY: Duration = Duration::from_secs(30);
/// Polling interval for cluster deletion detection.
pub(crate) const DELETION_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Base retry interval for unpivot loop.
pub(crate) const UNPIVOT_BASE_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum retry interval for unpivot loop (backoff cap).
pub(crate) const UNPIVOT_MAX_INTERVAL: Duration = Duration::from_secs(60);
/// Base polling interval for CAPI CRD availability check.
pub(crate) const CAPI_CRD_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Configuration for the agent client
#[derive(Clone, Debug)]
pub struct AgentClientConfig {
    /// Cell gRPC endpoint (e.g., "https://cell.example.com:443")
    pub cell_grpc_endpoint: String,
    /// Cell HTTP endpoint for CSR signing (e.g., "https://cell.example.com:8080")
    pub cell_http_endpoint: String,
    /// Cluster name this agent manages
    pub cluster_name: String,
    /// Agent version string
    pub agent_version: String,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// CA certificate PEM (for verifying cell)
    pub ca_cert_pem: Option<String>,
}

impl Default for AgentClientConfig {
    fn default() -> Self {
        Self {
            cell_grpc_endpoint: "https://localhost:50051".to_string(),
            cell_http_endpoint: "http://localhost:8080".to_string(),
            cluster_name: "unknown".to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            heartbeat_interval: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            ca_cert_pem: None,
        }
    }
}

/// Credentials for mTLS connection
#[derive(Clone)]
pub struct AgentCredentials {
    /// Agent certificate PEM (signed by cell CA)
    pub cert_pem: String,
    /// Agent private key PEM (zeroized on drop)
    pub key_pem: zeroize::Zeroizing<String>,
    /// CA certificate PEM (for verifying cell)
    pub ca_cert_pem: String,
}

/// Error type for certificate operations
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    /// CSR generation failed
    #[error("CSR generation failed: {0}")]
    CsrError(String),
    /// Invalid response
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Agent client state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// Not connected to cell
    Disconnected,
    /// Connecting to cell
    Connecting,
    /// Connected and streaming
    Connected,
    /// Connection failed
    Failed,
}

/// Client errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// Invalid endpoint URL
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    /// Connection to cell failed
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// Stream creation failed
    #[error("stream failed: {0}")]
    StreamFailed(String),
    /// TLS configuration error
    #[error("TLS error: {0}")]
    TlsError(String),
    /// Not connected to cell
    #[error("not connected")]
    NotConnected,
    /// Channel closed
    #[error("channel closed")]
    ChannelClosed,
    /// CAPI installation failed
    #[error("CAPI installation failed: {0}")]
    CapiInstallFailed(String),
    /// Kubernetes API error
    #[error("Kubernetes API error: {0}")]
    K8sApiError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentClientConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.cluster_name, "unknown");
        assert_eq!(config.cell_grpc_endpoint, "https://localhost:50051");
        assert_eq!(config.cell_http_endpoint, "http://localhost:8080");
        assert!(config.ca_cert_pem.is_none());
    }

    // Test CertificateError display
    #[test]
    fn test_certificate_error_http_display() {
        let err = CertificateError::HttpError("connection refused".to_string());
        assert_eq!(err.to_string(), "HTTP request failed: connection refused");
    }

    #[test]
    fn test_certificate_error_csr_display() {
        let err = CertificateError::CsrError("invalid key".to_string());
        assert_eq!(err.to_string(), "CSR generation failed: invalid key");
    }

    #[test]
    fn test_certificate_error_invalid_response_display() {
        let err = CertificateError::InvalidResponse("malformed json".to_string());
        assert_eq!(err.to_string(), "invalid response: malformed json");
    }

    // Test ClientError display
    #[test]
    fn test_client_error_invalid_endpoint_display() {
        let err = ClientError::InvalidEndpoint("bad url".to_string());
        assert_eq!(err.to_string(), "invalid endpoint: bad url");
    }

    #[test]
    fn test_client_error_connection_failed_display() {
        let err = ClientError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "connection failed: timeout");
    }

    #[test]
    fn test_client_error_stream_failed_display() {
        let err = ClientError::StreamFailed("broken pipe".to_string());
        assert_eq!(err.to_string(), "stream failed: broken pipe");
    }

    #[test]
    fn test_client_error_tls_display() {
        let err = ClientError::TlsError("certificate expired".to_string());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn test_client_error_not_connected_display() {
        let err = ClientError::NotConnected;
        assert_eq!(err.to_string(), "not connected");
    }

    #[test]
    fn test_client_error_channel_closed_display() {
        let err = ClientError::ChannelClosed;
        assert_eq!(err.to_string(), "channel closed");
    }

    #[test]
    fn test_client_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ClientError::NotConnected);
        assert!(err.to_string().contains("not connected"));
    }

    // Test ClientState enum
    #[test]
    fn test_client_state_equality() {
        assert_eq!(ClientState::Disconnected, ClientState::Disconnected);
        assert_eq!(ClientState::Connecting, ClientState::Connecting);
        assert_eq!(ClientState::Connected, ClientState::Connected);
        assert_eq!(ClientState::Failed, ClientState::Failed);
        assert_ne!(ClientState::Disconnected, ClientState::Connected);
    }

    #[test]
    fn test_client_state_copy() {
        let state = ClientState::Connected;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_client_state_debug() {
        let state = ClientState::Connecting;
        let debug_str = format!("{:?}", state);
        assert_eq!(debug_str, "Connecting");
    }

    #[test]
    fn test_credentials_struct() {
        let creds = AgentCredentials {
            cert_pem: "cert".to_string(),
            key_pem: zeroize::Zeroizing::new("key".to_string()),
            ca_cert_pem: "ca".to_string(),
        };
        assert_eq!(creds.cert_pem, "cert");
        assert_eq!(&*creds.key_pem, "key");
        assert_eq!(creds.ca_cert_pem, "ca");
    }

    /// Story: Agent configuration can be customized for different environments
    #[test]
    fn agent_config_customization() {
        let config = AgentClientConfig {
            cell_grpc_endpoint: "https://cell.prod.example.com:443".to_string(),
            cell_http_endpoint: "http://cell.prod.example.com:8080".to_string(),
            cluster_name: "prod-us-west-2-cluster-42".to_string(),
            agent_version: "2.0.0".to_string(),
            heartbeat_interval: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(30),
            ca_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            ),
        };

        assert_eq!(
            config.cell_grpc_endpoint,
            "https://cell.prod.example.com:443"
        );
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.ca_cert_pem.is_some());
    }

    /// Story: Default configuration provides sensible defaults
    #[test]
    fn default_config_sensible_values() {
        let config = AgentClientConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert!(config.cell_grpc_endpoint.contains("localhost"));
        assert!(config.cell_http_endpoint.contains("localhost"));
    }

    /// Story: Certificate errors provide actionable information
    #[test]
    fn certificate_errors_are_descriptive() {
        let http_err = CertificateError::HttpError("connection refused".to_string());
        let msg = http_err.to_string();
        assert!(msg.contains("HTTP request failed"));
        assert!(msg.contains("connection refused"));

        let csr_err = CertificateError::CsrError("invalid key size".to_string());
        let msg = csr_err.to_string();
        assert!(msg.contains("CSR generation failed"));
        assert!(msg.contains("invalid key size"));

        let resp_err = CertificateError::InvalidResponse("JSON parse error".to_string());
        let msg = resp_err.to_string();
        assert!(msg.contains("invalid response"));
        assert!(msg.contains("JSON parse error"));
    }

    /// Story: Client errors cover all connection failure modes
    #[test]
    fn client_errors_cover_failure_modes() {
        let err = ClientError::InvalidEndpoint("not a valid URL".to_string());
        assert!(err.to_string().contains("invalid endpoint"));

        let err = ClientError::ConnectionFailed("tcp connect error".to_string());
        assert!(err.to_string().contains("connection failed"));

        let err = ClientError::StreamFailed("status: UNAVAILABLE".to_string());
        assert!(err.to_string().contains("stream failed"));

        let err = ClientError::TlsError("certificate expired".to_string());
        assert!(err.to_string().contains("TLS error"));

        let err = ClientError::NotConnected;
        assert!(err.to_string().contains("not connected"));

        let err = ClientError::ChannelClosed;
        assert!(err.to_string().contains("channel closed"));
    }

    /// Story: Client errors implement std::error::Error for error handling chains
    #[test]
    fn client_errors_implement_error_trait() {
        fn takes_error(_: &dyn std::error::Error) {}

        let err = ClientError::NotConnected;
        takes_error(&err);

        let err = ClientError::ConnectionFailed("test".to_string());
        takes_error(&err);
    }

    /// Story: Agent credentials are cloneable for use in multiple contexts
    #[test]
    fn credentials_can_be_cloned() {
        let creds = AgentCredentials {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string(),
            key_pem: zeroize::Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----".to_string(),
            ),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
                .to_string(),
        };

        let cloned = creds.clone();
        assert_eq!(cloned.cert_pem, creds.cert_pem);
        assert_eq!(cloned.key_pem, creds.key_pem);
        assert_eq!(cloned.ca_cert_pem, creds.ca_cert_pem);
    }

    /// Story: AgentClientConfig is cloneable for sharing across components
    #[test]
    fn config_is_cloneable() {
        let config = AgentClientConfig {
            cell_grpc_endpoint: "https://cell:443".to_string(),
            cell_http_endpoint: "http://cell:8080".to_string(),
            cluster_name: "clone-test".to_string(),
            agent_version: "2.0.0".to_string(),
            heartbeat_interval: Duration::from_secs(45),
            connect_timeout: Duration::from_secs(15),
            ca_cert_pem: Some("cert".to_string()),
        };

        let cloned = config.clone();

        assert_eq!(cloned.cell_grpc_endpoint, config.cell_grpc_endpoint);
        assert_eq!(cloned.cell_http_endpoint, config.cell_http_endpoint);
        assert_eq!(cloned.cluster_name, config.cluster_name);
        assert_eq!(cloned.agent_version, config.agent_version);
        assert_eq!(cloned.heartbeat_interval, config.heartbeat_interval);
        assert_eq!(cloned.connect_timeout, config.connect_timeout);
        assert_eq!(cloned.ca_cert_pem, config.ca_cert_pem);
    }

    /// Story: AgentClientConfig is debuggable for logging
    #[test]
    fn config_is_debuggable() {
        let config = AgentClientConfig {
            cluster_name: "debug-test".to_string(),
            ..Default::default()
        };

        let debug = format!("{:?}", config);
        assert!(debug.contains("debug-test"));
        assert!(debug.contains("AgentClientConfig"));
    }

    /// Story: Client state machine covers all states
    #[test]
    fn client_state_values() {
        let states = [
            ClientState::Disconnected,
            ClientState::Connecting,
            ClientState::Connected,
            ClientState::Failed,
        ];

        for (i, state_a) in states.iter().enumerate() {
            for (j, state_b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(state_a, state_b);
                } else {
                    assert_ne!(state_a, state_b);
                }
            }
        }
    }

    /// Story: Client state is clone and copy
    #[test]
    fn client_state_is_copy() {
        let state = ClientState::Connected;
        let copied = state;
        let also_copied = state;

        assert_eq!(state, copied);
        assert_eq!(state, also_copied);
        assert_eq!(copied, also_copied);
    }

    /// Story: ClientError types are comparable for testing
    #[test]
    fn client_errors_are_comparable() {
        assert_eq!(
            ClientError::InvalidEndpoint("test".to_string()),
            ClientError::InvalidEndpoint("test".to_string())
        );

        assert_ne!(
            ClientError::InvalidEndpoint("a".to_string()),
            ClientError::InvalidEndpoint("b".to_string())
        );

        assert_ne!(
            ClientError::InvalidEndpoint("test".to_string()),
            ClientError::ConnectionFailed("test".to_string())
        );

        assert_eq!(ClientError::NotConnected, ClientError::NotConnected);
        assert_eq!(ClientError::ChannelClosed, ClientError::ChannelClosed);
        assert_ne!(ClientError::NotConnected, ClientError::ChannelClosed);
    }
}
