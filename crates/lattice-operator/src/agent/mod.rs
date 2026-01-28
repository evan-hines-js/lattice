//! Agent connection management
//!
//! This module handles connecting to a parent cell when this cluster has a cellRef.

mod startup;

pub use startup::start_agent_with_retry;
