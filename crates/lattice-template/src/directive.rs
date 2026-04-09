//! `$secret` directive parsing
//!
//! A `$secret` directive is a JSON object in the value tree that declares
//! a K8s Secret should be created from resource references and the object
//! replaced with the Secret name.
//!
//! The directive maps target keys (what the chart reads) to resource
//! references using `${resource.key}` syntax:
//!
//! ```yaml
//! $secret:
//!   redis-password: "${redis-creds.password}"
//!   redis-username: "${redis-creds.username}"
//! ```

use crate::error::TemplateError;

/// A `$secret` directive extracted from the value tree.
///
/// The controller creates an ESO ExternalSecret from the key mappings
/// and replaces the directive node with `Value::String(secret_name)`.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretDirective {
    /// Deterministic name for the generated K8s Secret.
    pub secret_name: String,
    /// Dotted path in the tree where this directive was found
    pub path: String,
    /// Key mappings: target key (K8s Secret) → resource reference.
    /// Each value is a parsed `${resource.key}` reference.
    pub keys: Vec<DirectiveKeyMapping>,
}

/// A single key mapping in a `$secret` directive.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectiveKeyMapping {
    /// Key in the generated K8s Secret (what the chart reads)
    pub target_key: String,
    /// Resource name from the `resources` block
    pub resource_name: String,
    /// Key within the resource
    pub resource_key: String,
}

/// Parse a `$secret` directive from a JSON object.
///
/// Expected shape:
/// ```json
/// {
///   "redis-password": "${redis-creds.password}",
///   "redis-username": "${redis-creds.username}"
/// }
/// ```
///
/// Each value must be a `${resource.key}` reference.
pub(crate) fn parse_directive(
    value: &serde_json::Value,
    path: &str,
    name_prefix: &str,
) -> Result<SecretDirective, TemplateError> {
    let obj = value.as_object().ok_or_else(|| TemplateError::InvalidDirective {
        path: path.to_string(),
        reason: "$secret value must be an object".to_string(),
    })?;

    if obj.is_empty() {
        return Err(TemplateError::InvalidDirective {
            path: path.to_string(),
            reason: "$secret must have at least one key mapping".to_string(),
        });
    }

    let mut keys = Vec::with_capacity(obj.len());

    for (target_key, ref_value) in obj {
        let ref_str = ref_value.as_str().ok_or_else(|| TemplateError::InvalidDirective {
            path: path.to_string(),
            reason: format!(
                "{}: value must be a string resource reference like \"${{resource.key}}\"",
                target_key
            ),
        })?;

        let (resource_name, resource_key) =
            parse_resource_ref(ref_str).ok_or_else(|| TemplateError::InvalidDirective {
                path: path.to_string(),
                reason: format!(
                    "{}: expected \"${{resource.key}}\" but got \"{}\"",
                    target_key, ref_str
                ),
            })?;

        keys.push(DirectiveKeyMapping {
            target_key: target_key.clone(),
            resource_name,
            resource_key,
        });
    }

    let path_slug = slugify_path(path);
    let secret_name = if path_slug.is_empty() {
        name_prefix.to_string()
    } else {
        format!("{}-{}", name_prefix, path_slug)
    };

    Ok(SecretDirective {
        secret_name,
        path: path.to_string(),
        keys,
    })
}

/// Parse a `${resource.key}` reference string.
///
/// Returns `(resource_name, key)` or `None` if the format is invalid.
fn parse_resource_ref(s: &str) -> Option<(String, String)> {
    let trimmed = s.trim();
    let inner = trimmed.strip_prefix("${")?.strip_suffix('}')?;
    let dot = inner.find('.')?;
    let resource = &inner[..dot];
    let key = &inner[dot + 1..];

    if resource.is_empty() || key.is_empty() || key.contains('.') {
        return None;
    }

    Some((resource.to_string(), key.to_string()))
}

/// Convert a dotted path into a DNS-safe slug for use in K8s Secret names.
///
/// `"auth.existingSecret"` → `"auth-existingsecret"`
/// `"tls[0].secretName"` → `"tls-0-secretname"`
fn slugify_path(path: &str) -> String {
    let mut slug = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            'a'..='z' | '0'..='9' | '-' => slug.push(c),
            'A'..='Z' => slug.push(c.to_ascii_lowercase()),
            '.' | '[' | ']' => {
                if !slug.ends_with('-') && !slug.is_empty() {
                    slug.push('-');
                }
            }
            _ => {
                if !slug.ends_with('-') && !slug.is_empty() {
                    slug.push('-');
                }
            }
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_full_directive() {
        let val = json!({
            "redis-password": "${redis-creds.password}",
            "redis-username": "${redis-creds.username}"
        });
        let d = parse_directive(&val, "auth.existingSecret", "redis-prod").unwrap();
        assert_eq!(d.secret_name, "redis-prod-auth-existingsecret");
        assert_eq!(d.keys.len(), 2);

        let pw = d.keys.iter().find(|k| k.target_key == "redis-password").unwrap();
        assert_eq!(pw.resource_name, "redis-creds");
        assert_eq!(pw.resource_key, "password");
    }

    #[test]
    fn parse_mixed_resources() {
        let val = json!({
            "db-password": "${db-creds.password}",
            "tls.crt": "${tls-cert.cert}"
        });
        let d = parse_directive(&val, "secrets.ref", "my-app").unwrap();
        assert_eq!(d.keys.len(), 2);

        let db = d.keys.iter().find(|k| k.target_key == "db-password").unwrap();
        assert_eq!(db.resource_name, "db-creds");

        let tls = d.keys.iter().find(|k| k.target_key == "tls.crt").unwrap();
        assert_eq!(tls.resource_name, "tls-cert");
    }

    #[test]
    fn empty_directive_errors() {
        let val = json!({});
        let err = parse_directive(&val, "x", "p").unwrap_err();
        assert!(err.to_string().contains("at least one key"));
    }

    #[test]
    fn non_ref_value_errors() {
        let val = json!({ "key": "plain-string" });
        let err = parse_directive(&val, "x", "p").unwrap_err();
        assert!(err.to_string().contains("expected \"${resource.key}\""));
    }

    #[test]
    fn non_string_value_errors() {
        let val = json!({ "key": 42 });
        let err = parse_directive(&val, "x", "p").unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn parse_resource_ref_valid() {
        let (r, k) = parse_resource_ref("${db.password}").unwrap();
        assert_eq!(r, "db");
        assert_eq!(k, "password");
    }

    #[test]
    fn parse_resource_ref_invalid() {
        assert!(parse_resource_ref("plain").is_none());
        assert!(parse_resource_ref("${nodot}").is_none());
        assert!(parse_resource_ref("${a.b.c}").is_none());
        assert!(parse_resource_ref("${}").is_none());
    }

    #[test]
    fn slugify() {
        assert_eq!(slugify_path("auth.existingSecret"), "auth-existingsecret");
        assert_eq!(slugify_path("tls[0].secretName"), "tls-0-secretname");
        assert_eq!(slugify_path(""), "");
    }
}
