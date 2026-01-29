//! Cedar authorization engine for Lattice service mesh
//!
//! This crate provides Cedar policy evaluation as an Envoy ext_authz gRPC service.
//! It adds user-to-resource authorization (via OIDC/JWT + Cedar policies) on top of
//! the existing service-to-service authorization (Cilium L4 + Istio L7).
//!
//! ## Passthrough Architecture
//!
//! This is a **generic passthrough** authorization engine:
//! - Pass through ALL headers to Cedar context
//! - Pass through ALL JWT claims as principal attributes
//! - Customers define their own entity types, schemas, and policies
//!
//! Our job is to faithfully transform ExtAuthz requests into Cedar primitives
//! and evaluate against customer-defined policies.
//!
//! ## Architecture
//!
//! ```text
//! Request -> Cilium L4 -> Istio L7 (mTLS) -> Cedar ExtAuth (this) -> Service
//!                                                   |
//!                                                   +-- JWT validation (OIDC)
//!                                                   +-- Cedar policy evaluation
//! ```
//!
//! ## Integration
//!
//! This crate is used by `lattice-operator` when `--enable-cedar-authz` is set.
//! The operator starts the ExtAuth gRPC server alongside the other controllers.
//!
//! ## Example Policy (Passthrough)
//!
//! ```cedar
//! // Allow users from engineering department with valid request ID
//! permit(
//!     principal,
//!     action,
//!     resource
//! ) when {
//!     principal.department == "engineering" &&
//!     context.xRequestId exists
//! };
//!
//! // Deny access to /admin paths for non-admins
//! forbid(
//!     principal,
//!     action,
//!     resource
//! ) when {
//!     resource.path.startsWith("/admin") &&
//!     !principal.roles.contains("admin")
//! };
//! ```

#![deny(missing_docs)]

pub mod controller;
pub mod entity;
pub mod jwt;
pub mod metrics;
pub mod policy;
pub mod server;

mod error;

pub use controller::{
    error_policy, policy_error_policy, reconcile, reconcile_policy, run_all_controllers,
    run_controller, run_policy_controller, Context,
};
pub use entity::{
    build_context_from_request, build_principal_from_token, json_to_cedar_value,
    normalize_header_name, Action, EntityBuilder, Resource,
};
pub use error::{CedarError, Result};
pub use jwt::{JwksCache, JwtValidator};
pub use policy::{
    EvaluationResult, InheritedPolicyEntry, PolicyCompiler, PolicyDecision, PolicyEntry,
    PolicyStore,
};
pub use server::CedarAuthzServer;

/// Default port for the Cedar ExtAuth gRPC server
pub const DEFAULT_CEDAR_GRPC_PORT: u16 = 50052;
