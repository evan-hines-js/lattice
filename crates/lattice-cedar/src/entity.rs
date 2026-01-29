//! Cedar entity builders
//!
//! Builds Cedar entities (Principal, Action, Resource) from HTTP request context.
//!
//! ## Passthrough Architecture
//!
//! This module implements a **generic passthrough** architecture for Cedar authorization:
//! - Pass through ALL headers to context (normalized to camelCase)
//! - Pass through ALL JWT claims as principal attributes
//! - Pass through request metadata (source/destination addresses)
//! - Customers define their own entity types and schemas
//!
//! Our job is to faithfully transform ExtAuthz requests into Cedar primitives
//! and evaluate against customer-defined policies.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use envoy_types::ext_authz::v3::pb::CheckRequest;
use serde_json::Value;

use crate::error::{CedarError, Result};
use crate::jwt::{Audience, ValidatedToken};

// ============================================================================
// Context Building - Passthrough All Request Data
// ============================================================================

/// Build Cedar context from ALL ExtAuthz request data (passthrough architecture)
///
/// This function passes through:
/// - ALL headers (normalized: `x-custom-header` → `customHeader`)
/// - Source/destination addresses from Envoy attributes
/// - Request metadata (method, path, protocol)
/// - Current timestamp
///
/// Customers can access any of this data in their Cedar policies via `context.<key>`.
pub fn build_context_from_request(check_request: &CheckRequest) -> Result<Context> {
    let mut pairs: Vec<(String, RestrictedExpression)> = Vec::new();

    // Pass through ALL headers from HTTP request
    if let Some(http) = get_http_request(check_request) {
        for (key, value) in &http.headers {
            // Normalize header names: x-custom-header → customHeader
            let normalized_key = normalize_header_name(key);
            pairs.push((
                normalized_key,
                RestrictedExpression::new_string(value.to_string()),
            ));
        }

        // Add HTTP method and path
        pairs.push((
            "method".to_string(),
            RestrictedExpression::new_string(http.method.clone()),
        ));
        pairs.push((
            "path".to_string(),
            RestrictedExpression::new_string(http.path.clone()),
        ));
        if !http.protocol.is_empty() {
            pairs.push((
                "protocol".to_string(),
                RestrictedExpression::new_string(http.protocol.clone()),
            ));
        }
        if !http.scheme.is_empty() {
            pairs.push((
                "scheme".to_string(),
                RestrictedExpression::new_string(http.scheme.clone()),
            ));
        }
    }

    // Pass through request metadata (source/destination)
    if let Some(attrs) = &check_request.attributes {
        if let Some(src) = &attrs.source {
            if let Some(addr) = &src.address {
                if let Some(socket_addr) = extract_socket_address(addr) {
                    pairs.push((
                        "sourceAddress".to_string(),
                        RestrictedExpression::new_string(socket_addr),
                    ));
                }
            }
            if !src.principal.is_empty() {
                pairs.push((
                    "sourcePrincipal".to_string(),
                    RestrictedExpression::new_string(src.principal.clone()),
                ));
            }
            if !src.service.is_empty() {
                pairs.push((
                    "sourceService".to_string(),
                    RestrictedExpression::new_string(src.service.clone()),
                ));
            }
        }
        if let Some(dst) = &attrs.destination {
            if let Some(addr) = &dst.address {
                if let Some(socket_addr) = extract_socket_address(addr) {
                    pairs.push((
                        "destinationAddress".to_string(),
                        RestrictedExpression::new_string(socket_addr),
                    ));
                }
            }
            if !dst.service.is_empty() {
                pairs.push((
                    "destinationService".to_string(),
                    RestrictedExpression::new_string(dst.service.clone()),
                ));
            }
        }
    }

    // Add timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    pairs.push(("timestamp".to_string(), RestrictedExpression::new_long(now)));

    Context::from_pairs(pairs)
        .map_err(|e| CedarError::policy_evaluation(format!("failed to create context: {}", e)))
}

/// Extract HTTP request from CheckRequest
fn get_http_request(
    check_request: &CheckRequest,
) -> Option<&envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest> {
    check_request
        .attributes
        .as_ref()?
        .request
        .as_ref()?
        .http
        .as_ref()
}

/// Extract socket address as string from Envoy Address
fn extract_socket_address(
    addr: &envoy_types::pb::envoy::config::core::v3::Address,
) -> Option<String> {
    use envoy_types::pb::envoy::config::core::v3::address::Address::SocketAddress;
    use envoy_types::pb::envoy::config::core::v3::socket_address::PortSpecifier::PortValue;

    if let Some(SocketAddress(sa)) = &addr.address {
        let port = match &sa.port_specifier {
            Some(PortValue(p)) => *p,
            _ => 0,
        };
        return Some(format!("{}:{}", sa.address, port));
    }
    None
}

/// Normalize header names to camelCase for Cedar context
///
/// Examples:
/// - `x-request-id` → `xRequestId`
/// - `content-type` → `contentType`
/// - `X-Custom-Header` → `xCustomHeader`
/// - `:authority` → `authority`
pub fn normalize_header_name(header: &str) -> String {
    // Handle pseudo-headers (start with :)
    let header = header.strip_prefix(':').unwrap_or(header);

    let mut result = String::with_capacity(header.len());
    let mut capitalize_next = false;

    for ch in header.chars() {
        if ch == '-' || ch == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else if result.is_empty() {
            // First character is lowercase
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch.to_ascii_lowercase());
        }
    }

    result
}

// ============================================================================
// JWT Claims - Passthrough All Claims
// ============================================================================

/// Convert a JSON value to a Cedar RestrictedExpression
///
/// Passthrough conversion:
/// - String → Cedar string
/// - Number → Cedar long
/// - Bool → Cedar bool
/// - Array of strings → Cedar set
/// - Other arrays/objects → JSON string representation
pub fn json_to_cedar_value(value: &Value) -> RestrictedExpression {
    match value {
        Value::String(s) => RestrictedExpression::new_string(s.clone()),
        Value::Number(n) => RestrictedExpression::new_long(n.as_i64().unwrap_or(0)),
        Value::Bool(b) => RestrictedExpression::new_bool(*b),
        Value::Array(arr) => {
            // Try to convert to a set of strings
            let string_values: Vec<RestrictedExpression> = arr
                .iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(|s| RestrictedExpression::new_string(s.to_string()))
                })
                .collect();

            if string_values.len() == arr.len() && !arr.is_empty() {
                // All items are strings, return as set
                RestrictedExpression::new_set(string_values)
            } else {
                // Mixed types or empty, serialize as JSON string
                RestrictedExpression::new_string(value.to_string())
            }
        }
        Value::Object(_) => {
            // Objects become JSON strings for now
            // Future: could try to build a Cedar record
            RestrictedExpression::new_string(value.to_string())
        }
        Value::Null => RestrictedExpression::new_string("null".to_string()),
    }
}

/// Build a Cedar principal entity from a validated JWT token (passthrough all claims)
///
/// This function passes through ALL claims from the JWT as principal attributes.
/// The principal type can be customized via the `type` claim, defaulting to "Principal".
///
/// Standard claims are mapped:
/// - `sub` → entity ID
/// - All other claims → attributes
///
/// Customers can access any claim in their Cedar policies via `principal.<claim>`.
pub fn build_principal_from_token(token: &ValidatedToken) -> Result<Entity> {
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();

    // Pass through ALL standard claims
    if let Some(sub) = &token.claims.sub {
        attrs.insert(
            "sub".to_string(),
            RestrictedExpression::new_string(sub.clone()),
        );
    }
    if let Some(iss) = &token.claims.iss {
        attrs.insert(
            "iss".to_string(),
            RestrictedExpression::new_string(iss.clone()),
        );
    }
    if let Some(aud) = &token.claims.aud {
        match aud {
            Audience::Single(s) => {
                attrs.insert(
                    "aud".to_string(),
                    RestrictedExpression::new_string(s.clone()),
                );
            }
            Audience::Multiple(arr) => {
                let set: Vec<RestrictedExpression> = arr
                    .iter()
                    .map(|s: &String| RestrictedExpression::new_string(s.clone()))
                    .collect();
                attrs.insert("aud".to_string(), RestrictedExpression::new_set(set));
            }
        }
    }
    if let Some(exp) = token.claims.exp {
        attrs.insert(
            "exp".to_string(),
            RestrictedExpression::new_long(exp as i64),
        );
    }
    if let Some(iat) = token.claims.iat {
        attrs.insert(
            "iat".to_string(),
            RestrictedExpression::new_long(iat as i64),
        );
    }
    if let Some(nbf) = token.claims.nbf {
        attrs.insert(
            "nbf".to_string(),
            RestrictedExpression::new_long(nbf as i64),
        );
    }
    if let Some(jti) = &token.claims.jti {
        attrs.insert(
            "jti".to_string(),
            RestrictedExpression::new_string(jti.clone()),
        );
    }

    // Pass through ALL extra claims (custom claims from JWT)
    for (key, value) in &token.claims.extra {
        attrs.insert(key.clone(), json_to_cedar_value(value));
    }

    // Determine principal type and ID
    // Allow customers to specify type via a claim, default to "Principal"
    let principal_type = token
        .claims
        .extra
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("Principal");

    let principal_id = token.subject().unwrap_or("anonymous");

    let type_name = EntityTypeName::from_str(principal_type)
        .map_err(|e| CedarError::policy_evaluation(format!("invalid principal type: {}", e)))?;
    let id = EntityId::from_str(principal_id)
        .map_err(|e| CedarError::policy_evaluation(format!("invalid principal id: {}", e)))?;
    let uid = EntityUid::from_type_name_and_id(type_name, id);

    Entity::new(uid, attrs, HashSet::new()).map_err(|e| {
        CedarError::policy_evaluation(format!("failed to create principal entity: {}", e))
    })
}

// ============================================================================
// Original Entity Types (maintained for backwards compatibility)
// ============================================================================

/// HTTP action mapped to Cedar action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// GET, HEAD, OPTIONS requests
    Read,
    /// POST, PUT, PATCH requests
    Write,
    /// DELETE requests
    Delete,
}

impl Action {
    /// Create action from HTTP method
    pub fn from_method(method: &str) -> Self {
        match method.to_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Action::Read,
            "POST" | "PUT" | "PATCH" => Action::Write,
            "DELETE" => Action::Delete,
            _ => Action::Read, // Default to read for unknown methods
        }
    }

    /// Get the Cedar action name
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
        }
    }

    /// Convert to Cedar EntityUid
    pub fn to_entity_uid(&self) -> EntityUid {
        let type_name = EntityTypeName::from_str("Action").expect("valid type name");
        let id = EntityId::from_str(self.as_str()).expect("valid entity id");
        EntityUid::from_type_name_and_id(type_name, id)
    }
}

/// Resource information from HTTP request
#[derive(Debug, Clone)]
pub struct Resource {
    /// Request path
    pub path: String,
    /// Target service name
    pub service: String,
    /// Target namespace
    pub namespace: String,
    /// HTTP method
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
}

impl Resource {
    /// Create a new resource
    pub fn new(
        path: impl Into<String>,
        service: impl Into<String>,
        namespace: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            service: service.into(),
            namespace: namespace.into(),
            method: method.into(),
            headers: HashMap::new(),
        }
    }

    /// Add headers to the resource
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Convert to Cedar EntityUid
    pub fn to_entity_uid(&self) -> EntityUid {
        let type_name = EntityTypeName::from_str("Resource").expect("valid type name");
        // Use a composite ID: namespace/service/path
        let id_str = format!("{}/{}{}", self.namespace, self.service, self.path);
        let id = EntityId::from_str(&id_str).expect("valid entity id");
        EntityUid::from_type_name_and_id(type_name, id)
    }

    /// Convert to Cedar Entity with attributes
    pub fn to_entity(&self) -> Result<Entity> {
        let uid = self.to_entity_uid();

        let mut attrs = HashMap::new();

        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(self.path.clone()),
        );
        attrs.insert(
            "service".to_string(),
            RestrictedExpression::new_string(self.service.clone()),
        );
        attrs.insert(
            "namespace".to_string(),
            RestrictedExpression::new_string(self.namespace.clone()),
        );
        attrs.insert(
            "method".to_string(),
            RestrictedExpression::new_string(self.method.clone()),
        );

        // Add headers as a record
        let header_pairs: Vec<(String, RestrictedExpression)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), RestrictedExpression::new_string(v.clone())))
            .collect();
        attrs.insert(
            "headers".to_string(),
            RestrictedExpression::new_record(header_pairs).map_err(|e| {
                CedarError::policy_evaluation(format!("failed to create headers record: {}", e))
            })?,
        );

        Entity::new(uid, attrs, HashSet::new()).map_err(|e| {
            CedarError::policy_evaluation(format!("failed to create resource entity: {}", e))
        })
    }
}

/// Builder for Cedar authorization requests
///
/// Uses passthrough mode: all JWT claims become principal attributes.
#[derive(Debug, Default)]
pub struct EntityBuilder;

impl EntityBuilder {
    /// Create a new entity builder
    pub fn new() -> Self {
        Self
    }

    /// Build a Cedar request from components (with empty context)
    pub fn build_request(
        &self,
        token: Option<&ValidatedToken>,
        action: Action,
        resource: &Resource,
    ) -> Result<(Request, Entities)> {
        self.build_request_with_context(token, action, resource, Context::empty())
    }

    /// Build a Cedar request with custom context
    ///
    /// Use `build_context_from_request()` to create the context from a CheckRequest.
    pub fn build_request_with_context(
        &self,
        token: Option<&ValidatedToken>,
        action: Action,
        resource: &Resource,
        context: Context,
    ) -> Result<(Request, Entities)> {
        // Build principal entity using passthrough
        let (principal_uid, principal_entity) = match token {
            Some(t) => {
                let entity = build_principal_from_token(t)?;
                (entity.uid().clone(), entity)
            }
            None => {
                // Anonymous principal
                let uid = EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("Principal").expect("valid type name"),
                    EntityId::from_str("anonymous").expect("valid entity id"),
                );
                let entity =
                    Entity::new(uid.clone(), HashMap::new(), HashSet::new()).map_err(|e| {
                        CedarError::policy_evaluation(format!(
                            "failed to create anonymous entity: {}",
                            e
                        ))
                    })?;
                (uid, entity)
            }
        };

        let action_uid = action.to_entity_uid();
        let resource_uid = resource.to_entity_uid();

        // Build resource entity
        let resource_entity = resource.to_entity()?;

        let entities =
            Entities::from_entities([principal_entity, resource_entity], None).map_err(|e| {
                CedarError::policy_evaluation(format!("failed to create entities: {}", e))
            })?;

        // Build request with provided context
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            None, // No schema validation at request time
        )
        .map_err(|e| CedarError::policy_evaluation(format!("failed to create request: {}", e)))?;

        Ok((request, entities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_from_method() {
        assert_eq!(Action::from_method("GET"), Action::Read);
        assert_eq!(Action::from_method("get"), Action::Read);
        assert_eq!(Action::from_method("HEAD"), Action::Read);
        assert_eq!(Action::from_method("OPTIONS"), Action::Read);
        assert_eq!(Action::from_method("POST"), Action::Write);
        assert_eq!(Action::from_method("PUT"), Action::Write);
        assert_eq!(Action::from_method("PATCH"), Action::Write);
        assert_eq!(Action::from_method("DELETE"), Action::Delete);
        assert_eq!(Action::from_method("UNKNOWN"), Action::Read);
    }

    #[test]
    fn test_action_to_entity_uid() {
        let read = Action::Read.to_entity_uid();
        assert!(read.to_string().contains("read"));

        let write = Action::Write.to_entity_uid();
        assert!(write.to_string().contains("write"));

        let delete = Action::Delete.to_entity_uid();
        assert!(delete.to_string().contains("delete"));
    }

    #[test]
    fn test_resource_new() {
        let resource = Resource::new("/api/users", "api-server", "default", "GET");

        assert_eq!(resource.path, "/api/users");
        assert_eq!(resource.service, "api-server");
        assert_eq!(resource.namespace, "default");
        assert_eq!(resource.method, "GET");
    }

    #[test]
    fn test_resource_to_entity() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let resource =
            Resource::new("/api/users", "api-server", "default", "GET").with_headers(headers);

        let entity = resource.to_entity();
        assert!(entity.is_ok());
    }

    #[test]
    fn test_entity_builder() {
        let builder = EntityBuilder::new();

        let resource = Resource::new("/test", "svc", "ns", "GET");
        let result = builder.build_request(None, Action::Read, &resource);

        assert!(result.is_ok());
    }

    // ========================================================================
    // Passthrough Architecture Tests
    // ========================================================================

    #[test]
    fn test_normalize_header_name() {
        // Standard headers
        assert_eq!(normalize_header_name("content-type"), "contentType");
        assert_eq!(normalize_header_name("x-request-id"), "xRequestId");
        assert_eq!(normalize_header_name("X-Custom-Header"), "xCustomHeader");

        // Pseudo-headers (with colon prefix)
        assert_eq!(normalize_header_name(":authority"), "authority");
        assert_eq!(normalize_header_name(":method"), "method");

        // Edge cases
        assert_eq!(normalize_header_name("simple"), "simple");
        assert_eq!(normalize_header_name("UPPER"), "upper");
        assert_eq!(normalize_header_name("x-a-b-c"), "xABC");
    }

    #[test]
    fn test_json_to_cedar_value_string() {
        let value = Value::String("hello".to_string());
        let expr = json_to_cedar_value(&value);
        // We can't easily inspect the expression, but we can verify it doesn't panic
        assert!(format!("{:?}", expr).contains("hello"));
    }

    #[test]
    fn test_json_to_cedar_value_number() {
        let value = Value::Number(serde_json::Number::from(42));
        let expr = json_to_cedar_value(&value);
        assert!(format!("{:?}", expr).contains("42"));
    }

    #[test]
    fn test_json_to_cedar_value_bool() {
        let value = Value::Bool(true);
        let expr = json_to_cedar_value(&value);
        assert!(format!("{:?}", expr).contains("true"));
    }

    #[test]
    fn test_json_to_cedar_value_string_array() {
        let value = serde_json::json!(["admin", "user"]);
        let expr = json_to_cedar_value(&value);
        // String arrays become Cedar sets
        let debug_str = format!("{:?}", expr);
        assert!(debug_str.contains("admin") || debug_str.contains("Set"));
    }

    #[test]
    fn test_json_to_cedar_value_mixed_array() {
        let value = serde_json::json!([1, "two", 3]);
        let expr = json_to_cedar_value(&value);
        // Mixed arrays become JSON strings
        let debug_str = format!("{:?}", expr);
        assert!(debug_str.contains("1") || debug_str.contains("two"));
    }

    #[test]
    fn test_json_to_cedar_value_object() {
        let value = serde_json::json!({"key": "value"});
        let expr = json_to_cedar_value(&value);
        // Objects become JSON strings
        let debug_str = format!("{:?}", expr);
        assert!(debug_str.contains("key") || debug_str.contains("value"));
    }

    #[test]
    fn test_entity_builder_passthrough() {
        let builder = EntityBuilder::new();

        let resource = Resource::new("/test", "svc", "ns", "GET");
        let result = builder.build_request(None, Action::Read, &resource);

        assert!(result.is_ok());
        let (request, entities) = result.unwrap();

        // Verify we got entities (principal + resource)
        assert!(!entities.iter().collect::<Vec<_>>().is_empty());

        // Verify request was created with anonymous principal
        assert!(request.principal().is_some());
    }

    #[test]
    fn test_entity_builder_with_context() {
        let builder = EntityBuilder::new();

        // Create a simple context
        let pairs = vec![
            (
                "customHeader".to_string(),
                RestrictedExpression::new_string("value".to_string()),
            ),
            (
                "timestamp".to_string(),
                RestrictedExpression::new_long(12345),
            ),
        ];
        let context = Context::from_pairs(pairs).unwrap();

        let resource = Resource::new("/test", "svc", "ns", "GET");
        let result = builder.build_request_with_context(None, Action::Read, &resource, context);

        assert!(result.is_ok());
    }
}
