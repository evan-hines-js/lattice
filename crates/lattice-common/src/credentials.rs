//! Cloud provider credentials
//!
//! Data structures for cloud provider credentials used by CAPI.

use std::collections::HashMap;

/// AWS credentials for CAPA provider
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    /// AWS access key ID
    pub access_key_id: String,
    /// AWS secret access key
    pub secret_access_key: String,
    /// AWS region
    pub region: String,
    /// Optional session token for temporary credentials
    pub session_token: Option<String>,
}

impl AwsCredentials {
    /// Load credentials from environment variables
    pub fn from_env() -> Option<Self> {
        Some(Self {
            access_key_id: std::env::var("AWS_ACCESS_KEY_ID").ok()?,
            secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").ok()?,
            region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .ok()?,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
        })
    }

    /// Load credentials from a K8s secret's string data
    pub fn from_secret(secret: &HashMap<String, String>) -> Option<Self> {
        Some(Self {
            access_key_id: secret.get("AWS_ACCESS_KEY_ID")?.clone(),
            secret_access_key: secret.get("AWS_SECRET_ACCESS_KEY")?.clone(),
            region: secret.get("AWS_REGION")?.clone(),
            session_token: secret.get("AWS_SESSION_TOKEN").cloned(),
        })
    }

    /// Generate AWS_B64ENCODED_CREDENTIALS for clusterctl
    ///
    /// clusterctl requires credentials in a base64-encoded INI profile format.
    pub fn to_b64_encoded(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let mut profile = format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\nregion = {}",
            self.access_key_id, self.secret_access_key, self.region
        );

        if let Some(ref token) = self.session_token {
            profile.push_str(&format!("\naws_session_token = {}", token));
        }

        STANDARD.encode(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_credentials_from_secret() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());
        secret.insert("AWS_REGION".to_string(), "us-west-2".to_string());

        let creds = AwsCredentials::from_secret(&secret).unwrap();
        assert_eq!(creds.access_key_id, "AKID");
        assert_eq!(creds.region, "us-west-2");
        assert!(creds.session_token.is_none());
    }

    #[test]
    fn test_aws_credentials_b64_encoded() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: "SECRET".to_string(),
            region: "us-west-2".to_string(),
            session_token: None,
        };

        let encoded = creds.to_b64_encoded();
        // Should be base64 encoded
        assert!(!encoded.is_empty());
    }
}
