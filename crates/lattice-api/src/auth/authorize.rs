//! Combined authentication and authorization
//!
//! Provides a unified interface for authenticating and authorizing requests
//! in a single call, reducing code duplication in handlers.

use std::sync::Arc;

use axum::http::HeaderMap;
use tracing::debug;

use crate::auth::UserIdentity;
use crate::auth_chain::AuthChain;
use crate::error::{Error, Result};
use lattice_auth::extract_bearer_token;
use lattice_cedar::{ClusterAttributes, PolicyEngine};

/// Authenticate and authorize a request in one call
///
/// Combines token validation and Cedar policy evaluation.
pub async fn authenticate_and_authorize(
    auth: &Arc<AuthChain>,
    cedar: &Arc<PolicyEngine>,
    headers: &HeaderMap,
    cluster: &str,
    attrs: &ClusterAttributes,
) -> Result<UserIdentity> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    let identity = auth.validate(token).await?;

    debug!(
        user = %identity.username,
        cluster = %cluster,
        "Checking authorization"
    );

    cedar
        .authorize_cluster(&identity.username, &identity.groups, cluster, attrs, None)
        .await
        .map_err(|e| match e {
            lattice_cedar::Error::Forbidden(msg) => Error::Forbidden(msg),
            lattice_cedar::Error::Config(msg) => Error::Config(msg),
            other => Error::Internal(other.to_string()),
        })?;

    Ok(identity)
}

/// Authenticate a request (without authorization)
///
/// Use this when you only need to validate the token without checking
/// Cedar policies (e.g., for the kubeconfig endpoint).
pub async fn authenticate(auth: &Arc<AuthChain>, headers: &HeaderMap) -> Result<UserIdentity> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    auth.validate(token).await
}
