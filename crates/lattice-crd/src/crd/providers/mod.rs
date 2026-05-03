//! Provider-specific configuration types for infrastructure provisioning.
//!
//! Each provider module contains the configuration struct for its respective
//! Cluster API provider:
//! - CAPA (AWS) - public cloud
//! - CAPD (Docker/Kind) - local development only
//! - CAPMOX (Proxmox) - on-premises virtualization
//! - Basis (lattos/basis) - minimal bare-metal VM scheduler

mod aws;
mod basis;
mod docker;
mod proxmox;

pub use aws::AwsConfig;
pub use basis::BasisConfig;
pub use docker::DockerConfig;
pub use proxmox::{AdditionalNetwork, Ipv4PoolConfig, Ipv6PoolConfig, ProxmoxConfig};
