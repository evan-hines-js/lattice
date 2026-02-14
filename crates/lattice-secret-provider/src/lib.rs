//! SecretProvider controller for Lattice
//!
//! This controller watches SecretProvider CRDs and ensures the corresponding
//! ESO ClusterSecretStore exists. It continuously reconciles to handle cases
//! where ESO is installed after the SecretProvider is created.

#![deny(missing_docs)]

pub mod controller;
pub mod eso;
pub mod webhook;
