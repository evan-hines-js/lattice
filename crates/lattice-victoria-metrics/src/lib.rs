//! VictoriaMetrics K8s Stack install — helm manifests + controller.
//!
//! Re-exports the query-URL helpers consumed by `lattice-operator` /
//! `lattice-service` so they don't have to import the install module path.

pub mod install;

pub use install::manifests::{query_path, query_port, query_url, victoria_metrics_version};
