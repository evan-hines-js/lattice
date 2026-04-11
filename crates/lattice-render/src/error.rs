//! Template error types

use std::fmt;

/// Errors that can occur during template operations
#[derive(Debug)]
pub enum TemplateError {
    /// Template rendering failed
    Render(String),
    /// Template syntax is invalid
    Syntax(String),
    /// Required variable is undefined
    Undefined(String),
    /// Container image "." placeholder has no config value
    MissingImage(String),
    /// Inline access denied because an external service CRD governs this host
    PermissionDenied(String),
}

impl TemplateError {
    /// Create a missing image error for a container
    pub fn missing_image(container_name: &str) -> Self {
        Self::MissingImage(container_name.to_string())
    }
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Render(e) => write!(f, "template render error: {}", e),
            Self::Syntax(msg) => write!(f, "template syntax error: {}", msg),
            Self::Undefined(var) => write!(f, "undefined variable: {}", var),
            Self::MissingImage(container) => write!(
                f,
                "container '{}' has image: \".\" but no image found in config (expected config.image.{} or config.image)",
                container, container
            ),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {}", msg),
        }
    }
}

impl std::error::Error for TemplateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_image_constructor() {
        let err = TemplateError::missing_image("my-container");
        let msg = err.to_string();
        assert!(msg.contains("my-container"));
        assert!(msg.contains("config.image.my-container"));
    }
}
