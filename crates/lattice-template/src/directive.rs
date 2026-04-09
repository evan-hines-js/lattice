//! `$secret` directive parsing
//!
//! A `$secret` directive is a JSON object in the value tree that declares
//! a K8s Secret should be created and the object replaced with the Secret name.

use std::collections::BTreeMap;

use crate::error::TemplateError;

/// A `$secret` directive extracted from the value tree.
///
/// The controller creates an ESO ExternalSecret from this and replaces
/// the directive node with `Value::String(secret_name)`.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretDirective {
    /// Deterministic name for the generated K8s Secret.
    /// Format: `{name_prefix}-{path_slug}` where path_slug is derived
    /// from the values path (e.g., `redis-prod-auth`).
    pub secret_name: String,
    /// Dotted path in the tree where this directive was found
    pub path: String,
    /// Remote key in the secret store (the `id` field)
    pub id: String,
    /// ClusterSecretStore name
    pub provider: String,
    /// Key mapping: target key (K8s Secret) → source key (store).
    /// Empty means passthrough all keys (`dataFrom.extract`).
    pub keys: BTreeMap<String, String>,
}

/// Parse a `$secret` directive from a JSON object.
///
/// Expected shape:
/// ```json
/// {
///   "id": "payments/redis/prod",
///   "provider": "vault-prod",
///   "keys": {
///     "redis-password": "password",
///     "tls.crt": "cert"
///   }
/// }
/// ```
pub(crate) fn parse_directive(
    value: &serde_json::Value,
    path: &str,
    name_prefix: &str,
) -> Result<SecretDirective, TemplateError> {
    let obj = value.as_object().ok_or_else(|| TemplateError::InvalidDirective {
        path: path.to_string(),
        reason: "$secret value must be an object".to_string(),
    })?;

    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TemplateError::InvalidDirective {
            path: path.to_string(),
            reason: "missing required field 'id'".to_string(),
        })?
        .to_string();

    let provider = obj
        .get("provider")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TemplateError::InvalidDirective {
            path: path.to_string(),
            reason: "missing required field 'provider'".to_string(),
        })?
        .to_string();

    let keys = match obj.get("keys") {
        Some(serde_json::Value::Object(map)) => {
            let mut keys = BTreeMap::new();
            for (k, v) in map {
                let source = v.as_str().ok_or_else(|| TemplateError::InvalidDirective {
                    path: path.to_string(),
                    reason: format!("keys.{}: value must be a string (source store key)", k),
                })?;
                keys.insert(k.clone(), source.to_string());
            }
            keys
        }
        Some(serde_json::Value::Null) | None => BTreeMap::new(),
        Some(_) => {
            return Err(TemplateError::InvalidDirective {
                path: path.to_string(),
                reason: "'keys' must be an object mapping target keys to source keys".to_string(),
            });
        }
    };

    let path_slug = slugify_path(path);
    let secret_name = if path_slug.is_empty() {
        name_prefix.to_string()
    } else {
        format!("{}-{}", name_prefix, path_slug)
    };

    Ok(SecretDirective {
        secret_name,
        path: path.to_string(),
        id,
        provider,
        keys,
    })
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
    // Trim trailing hyphens
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
            "id": "payments/redis/prod",
            "provider": "vault-prod",
            "keys": {
                "redis-password": "password",
                "tls.crt": "cert"
            }
        });
        let d = parse_directive(&val, "auth.existingSecret", "redis-prod").unwrap();
        assert_eq!(d.secret_name, "redis-prod-auth-existingsecret");
        assert_eq!(d.id, "payments/redis/prod");
        assert_eq!(d.provider, "vault-prod");
        assert_eq!(d.keys.get("redis-password"), Some(&"password".to_string()));
        assert_eq!(d.keys.get("tls.crt"), Some(&"cert".to_string()));
    }

    #[test]
    fn parse_directive_no_keys() {
        let val = json!({
            "id": "infra/tls/wildcard",
            "provider": "vault-prod"
        });
        let d = parse_directive(&val, "tls.secretName", "my-app").unwrap();
        assert_eq!(d.secret_name, "my-app-tls-secretname");
        assert!(d.keys.is_empty());
    }

    #[test]
    fn missing_id_errors() {
        let val = json!({ "provider": "vault" });
        let err = parse_directive(&val, "x", "p").unwrap_err();
        assert!(err.to_string().contains("missing required field 'id'"));
    }

    #[test]
    fn missing_provider_errors() {
        let val = json!({ "id": "foo" });
        let err = parse_directive(&val, "x", "p").unwrap_err();
        assert!(err.to_string().contains("missing required field 'provider'"));
    }

    #[test]
    fn slugify() {
        assert_eq!(slugify_path("auth.existingSecret"), "auth-existingsecret");
        assert_eq!(slugify_path("tls[0].secretName"), "tls-0-secretname");
        assert_eq!(slugify_path("global.postgresql.auth.existingSecret"), "global-postgresql-auth-existingsecret");
        assert_eq!(slugify_path(""), "");
    }
}
