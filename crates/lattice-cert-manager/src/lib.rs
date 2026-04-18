//! cert-manager dependency install — helm manifests + controller.
//!
//! Distinct from `lattice-cert-issuer`, which manages the user-facing
//! `CertIssuer` CRD that represents issuers (ACME, CA, Vault, self-signed)
//! cert-manager should honor. This crate installs cert-manager itself.

pub mod install;
