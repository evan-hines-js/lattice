//! Network type definitions for Gateway API and certificates
//!
//! Types for generating:
//! - Gateway API resources (Gateway, HTTPRoute, GRPCRoute, TCPRoute)
//! - cert-manager Certificate resources
//!
//! All types implement the `HasApiResource` trait for consistent
//! API version and kind handling.

pub mod gateway_api;
