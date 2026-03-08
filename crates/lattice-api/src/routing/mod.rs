//! Path utilities for K8s API proxy
//!
//! Provides single-source-of-truth path manipulation functions used across
//! the proxy handlers and forwarders.

mod path;

pub use path::{parse_cluster_path, strip_cluster_prefix};
