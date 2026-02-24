//! Error types for the webhook server

/// Webhook server errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// TLS certificate error
    #[error("TLS certificate error: {0}")]
    Tls(String),

    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    /// PKI error from lattice-infra
    #[error("PKI error: {0}")]
    Pki(#[from] lattice_infra::pki::PkiError),

    /// Server bind/listen error
    #[error("server error: {0}")]
    Server(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
