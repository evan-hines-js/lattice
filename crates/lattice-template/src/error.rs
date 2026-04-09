//! Template error types

/// Errors from template expansion
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// Unclosed `${` in a string value
    #[error("unclosed ${{}} at '{path}'")]
    UnclosedPlaceholder {
        /// Path in the value tree
        path: String,
    },

    /// A `${dotted.path}` could not be resolved from the context
    #[error("unresolved variable '${{{{{}}}}}' at '{path}'", expr)]
    Unresolved {
        /// The expression that could not be resolved
        expr: String,
        /// Path in the value tree
        path: String,
    },

    /// A `${secret.X.Y}` reference could not be resolved in Resolve mode
    #[error("unresolved secret '${{{{{}.{}}}}}'  at '{path}'", resource, key)]
    UnresolvedSecret {
        /// Secret resource name
        resource: String,
        /// Key within the secret
        key: String,
        /// Path in the value tree
        path: String,
    },

    /// Invalid `${secret.X.Y}` syntax (missing dot, empty parts)
    #[error("invalid secret reference '${{{{{inner}}}}}' at '{path}': expected ${{secret.RESOURCE.KEY}}")]
    InvalidSecretRef {
        /// The inner content that failed to parse
        inner: String,
        /// Path in the value tree
        path: String,
    },

    /// A `$secret` directive is missing required fields
    #[error("invalid $secret directive at '{path}': {reason}")]
    InvalidDirective {
        /// Path in the value tree
        path: String,
        /// What's wrong
        reason: String,
    },
}
