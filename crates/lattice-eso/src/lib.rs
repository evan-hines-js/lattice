//! External Secrets Operator dependency install.
//!
//! Owns the ESO helm manifests, ESO's mesh enrollment (LatticeMeshMembers
//! for `external-secrets-webhook`, `external-secrets`, and
//! `external-secrets-cert-controller`), and the ESOInstall controller.

pub mod install;
