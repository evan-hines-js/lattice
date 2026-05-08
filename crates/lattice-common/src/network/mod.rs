//! Network type definitions for Gateway API and certificates.
//!
//! - [`gateway_api`] — Gateway API resources (Gateway, HTTPRoute, GRPCRoute, TCPRoute)
//! - [`cert_manager`] — cert-manager.io Certificate / IssuerRef + the
//!   `CertificateRequest` builder used by every TLS-emitting compiler

pub mod cert_manager;
pub mod gateway_api;
