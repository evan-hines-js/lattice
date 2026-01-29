//! Startup utilities for the Lattice operator
//!
//! This module contains all startup and initialization logic extracted from main.rs.

mod ca_rotation;
mod cell;
mod crds;
mod infrastructure;
mod manifests;
mod recovery;

pub use ca_rotation::start_ca_rotation;
pub use cell::{discover_cell_host, ensure_cell_service_exists, get_cell_server_sans};
pub use crds::ensure_crds_installed;
pub use infrastructure::ensure_infrastructure;
pub use manifests::apply_manifests;
pub use recovery::{re_register_existing_clusters, wait_for_api_ready};
