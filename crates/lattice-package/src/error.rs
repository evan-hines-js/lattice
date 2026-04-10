//! Package controller error types

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("secret authorization denied: {0}")]
    SecretAccessDenied(String),

    #[error("template expansion failed: {0}")]
    TemplateExpansion(String),

    #[error(
        "secret resource '{resource}' referenced in values but not declared in resources block"
    )]
    UndeclaredResource { resource: String },

    #[error("secret '{resource}.{key}' not found in synced Secret data")]
    SecretKeyMissing { resource: String, key: String },

    #[error("helm failed: {0}")]
    Helm(String),

    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    #[error("{0}")]
    Common(#[from] lattice_common::Error),

    #[error("compilation error: {0}")]
    Compilation(String),
}

impl PackageError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Kube(_) | Self::Helm(_))
    }
}
