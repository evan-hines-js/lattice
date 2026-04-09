//! Template string types
//!
//! - `TemplateString`: allows `${...}` placeholders
//! - `StaticString`: rejects any template syntax at parse time

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A string that may contain `${...}` placeholders for template expansion.
///
/// Use for values that support templating: env var values, image tags, etc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TemplateString(String);

impl TemplateString {
    /// Create a new template string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this string contains any template placeholders.
    pub fn has_placeholders(&self) -> bool {
        self.0.contains("${")
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TemplateString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TemplateString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TemplateString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A string that must NOT contain template syntax.
///
/// Use for identifiers, keys, and names that should never be templated:
/// container names, resource keys, etc. Validated at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct StaticString(String);

impl StaticString {
    /// Get the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for StaticString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error when a string contains template syntax but shouldn't.
#[derive(Debug, Clone)]
pub struct StaticStringError {
    /// The invalid value
    pub value: String,
    /// Why it's invalid
    pub reason: &'static str,
}

impl fmt::Display for StaticStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "static string cannot contain template syntax: {} (found in '{}')",
            self.reason, self.value
        )
    }
}

impl std::error::Error for StaticStringError {}

impl TryFrom<String> for StaticString {
    type Error = StaticStringError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.contains("${") {
            return Err(StaticStringError {
                value: s,
                reason: "contains ${...} placeholder",
            });
        }
        Ok(Self(s))
    }
}

impl<'de> Deserialize<'de> for StaticString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        StaticString::try_from(s).map_err(serde::de::Error::custom)
    }
}

/// Check if a string contains template syntax (`${`).
pub fn has_template_syntax(s: &str) -> bool {
    s.contains("${")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_string_has_placeholders() {
        assert!(TemplateString::new("${foo}").has_placeholders());
        assert!(!TemplateString::new("plain").has_placeholders());
    }

    #[test]
    fn static_string_valid() {
        let s: Result<StaticString, _> = "valid-name".to_string().try_into();
        assert!(s.is_ok());
    }

    #[test]
    fn static_string_rejects_placeholder() {
        let s: Result<StaticString, _> = "bad-${var}".to_string().try_into();
        assert!(s.is_err());
    }

    #[test]
    fn static_string_serde_roundtrip() {
        let json = r#""valid-name""#;
        let s: StaticString = serde_json::from_str(json).unwrap();
        assert_eq!(s.as_str(), "valid-name");

        let json = r#""bad-${x}""#;
        let result: Result<StaticString, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn has_syntax_check() {
        assert!(has_template_syntax("hello ${world}"));
        assert!(!has_template_syntax("hello world"));
    }
}
