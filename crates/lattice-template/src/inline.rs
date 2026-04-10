//! Inline secret reference parsing: `${secret.RESOURCE.KEY}`

/// A `${secret.X.Y}` reference found in a string value.
#[derive(Clone, Debug, PartialEq)]
pub struct InlineSecretRef {
    /// Dotted path in the value tree where this was found
    pub path: String,
    /// Resource name (X in `${secret.X.Y}`)
    pub resource_name: String,
    /// Key within the secret (Y in `${secret.X.Y}`)
    pub key: String,
    /// ESO-safe data key for Go template references.
    /// Hyphens replaced with underscores: `"db_creds_password"`.
    /// Used as `spec.data[].secretKey` and `{{ .eso_data_key }}` in ESO templates.
    pub eso_data_key: String,
}

/// Parse the inner part of `secret.RESOURCE.KEY` (after stripping the `secret.` prefix).
///
/// Returns `(resource_name, key, eso_data_key)` or `None` if invalid.
pub(crate) fn parse_secret_inner(inner: &str) -> Option<(String, String, String)> {
    let dot = inner.find('.')?;
    let resource = &inner[..dot];
    let key = &inner[dot + 1..];

    if resource.is_empty() || key.is_empty() || key.contains('.') {
        return None;
    }

    let eso_data_key = format!("{}_{}", resource.replace('-', "_"), key.replace('-', "_"));

    Some((resource.to_string(), key.to_string(), eso_data_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ref() {
        let (r, k, eso) = parse_secret_inner("db-creds.password").unwrap();
        assert_eq!(r, "db-creds");
        assert_eq!(k, "password");
        assert_eq!(eso, "db_creds_password");
    }

    #[test]
    fn nested_key_rejected() {
        assert!(parse_secret_inner("db.nested.key").is_none());
    }

    #[test]
    fn empty_resource_rejected() {
        assert!(parse_secret_inner(".password").is_none());
    }

    #[test]
    fn empty_key_rejected() {
        assert!(parse_secret_inner("db.").is_none());
    }

    #[test]
    fn no_dot_rejected() {
        assert!(parse_secret_inner("nodot").is_none());
    }
}
