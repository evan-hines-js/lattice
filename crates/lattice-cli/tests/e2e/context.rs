//! Infrastructure context for E2E and integration tests
//!
//! This module provides the `InfraContext` struct which holds cluster connection
//! information. Tests can either:
//! 1. Load configuration from environment variables (for standalone integration tests)
//! 2. Create context programmatically (for E2E tests that provision clusters)
//!
//! # Environment Variables for Standalone Tests
//!
//! ```bash
//! # Point to existing clusters (skip setup)
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig
//! LATTICE_WORKLOAD2_KUBECONFIG=/path/to/workload2-kubeconfig
//! ```
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! // Standalone integration test
//! let ctx = InfraContext::from_env()
//!     .expect("Set LATTICE_MGMT_KUBECONFIG to run standalone");
//!
//! // E2E test that creates clusters
//! let ctx = InfraContext::new(
//!     mgmt_kubeconfig,
//!     Some(workload_kubeconfig),
//!     None,
//!     InfraProvider::Docker,
//! );
//! ```

use super::providers::InfraProvider;

/// Cluster infrastructure context - connection info for tests
///
/// This struct provides a unified way for integration tests to receive
/// cluster connection information, regardless of whether the clusters
/// were created by the test itself or pre-exist.
#[derive(Debug, Clone)]
pub struct InfraContext {
    /// Path to management cluster kubeconfig
    pub mgmt_kubeconfig: String,

    /// Path to first workload cluster kubeconfig (optional)
    pub workload_kubeconfig: Option<String>,

    /// Path to second workload cluster kubeconfig (optional)
    pub workload2_kubeconfig: Option<String>,

    /// Infrastructure provider type
    pub provider: InfraProvider,
}

impl InfraContext {
    /// Load configuration from environment variables (for standalone integration tests)
    ///
    /// Returns `Some(InfraContext)` if at least `LATTICE_MGMT_KUBECONFIG` is set.
    /// Other kubeconfig paths are optional.
    ///
    /// # Environment Variables
    ///
    /// - `LATTICE_MGMT_KUBECONFIG` (required): Path to management cluster kubeconfig
    /// - `LATTICE_WORKLOAD_KUBECONFIG` (optional): Path to workload cluster kubeconfig
    /// - `LATTICE_WORKLOAD2_KUBECONFIG` (optional): Path to second workload cluster kubeconfig
    /// - `LATTICE_PROVIDER` (optional): Provider type (docker, aws, proxmox, openstack). Defaults to docker.
    pub fn from_env() -> Option<Self> {
        let mgmt = std::env::var("LATTICE_MGMT_KUBECONFIG").ok()?;

        Some(Self {
            mgmt_kubeconfig: mgmt,
            workload_kubeconfig: std::env::var("LATTICE_WORKLOAD_KUBECONFIG").ok(),
            workload2_kubeconfig: std::env::var("LATTICE_WORKLOAD2_KUBECONFIG").ok(),
            provider: Self::provider_from_env(),
        })
    }

    /// Create a context with explicit paths (for E2E tests that create clusters)
    ///
    /// # Arguments
    ///
    /// * `mgmt_kubeconfig` - Path to management cluster kubeconfig
    /// * `workload_kubeconfig` - Optional path to workload cluster kubeconfig
    /// * `workload2_kubeconfig` - Optional path to second workload cluster kubeconfig
    /// * `provider` - Infrastructure provider type
    pub fn new(
        mgmt_kubeconfig: String,
        workload_kubeconfig: Option<String>,
        workload2_kubeconfig: Option<String>,
        provider: InfraProvider,
    ) -> Self {
        Self {
            mgmt_kubeconfig,
            workload_kubeconfig,
            workload2_kubeconfig,
            provider,
        }
    }

    /// Create a context with only management cluster
    pub fn mgmt_only(mgmt_kubeconfig: String, provider: InfraProvider) -> Self {
        Self::new(mgmt_kubeconfig, None, None, provider)
    }

    /// Add workload cluster kubeconfig to the context
    pub fn with_workload(mut self, workload_kubeconfig: String) -> Self {
        self.workload_kubeconfig = Some(workload_kubeconfig);
        self
    }

    /// Add second workload cluster kubeconfig to the context
    pub fn with_workload2(mut self, workload2_kubeconfig: String) -> Self {
        self.workload2_kubeconfig = Some(workload2_kubeconfig);
        self
    }

    /// Check if workload cluster is available
    pub fn has_workload(&self) -> bool {
        self.workload_kubeconfig.is_some()
    }

    /// Check if second workload cluster is available
    pub fn has_workload2(&self) -> bool {
        self.workload2_kubeconfig.is_some()
    }

    /// Get workload kubeconfig or return an error
    pub fn require_workload(&self) -> Result<&str, String> {
        self.workload_kubeconfig
            .as_deref()
            .ok_or_else(|| "Workload cluster kubeconfig required but not set".to_string())
    }

    /// Get workload2 kubeconfig or return an error
    pub fn require_workload2(&self) -> Result<&str, String> {
        self.workload2_kubeconfig
            .as_deref()
            .ok_or_else(|| "Workload2 cluster kubeconfig required but not set".to_string())
    }

    /// Parse provider from environment variable
    fn provider_from_env() -> InfraProvider {
        match std::env::var("LATTICE_PROVIDER")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "aws" => InfraProvider::Aws,
            "proxmox" => InfraProvider::Proxmox,
            "openstack" => InfraProvider::OpenStack,
            _ => InfraProvider::Docker,
        }
    }
}

/// Initialize E2E test environment (crypto provider, tracing only)
///
/// Call this at the start of E2E tests that create their own infrastructure.
/// Does not require environment variables since E2E tests provision clusters.
pub fn init_e2e_test() {
    lattice_common::install_crypto_provider();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

/// Initialize integration test environment (crypto provider, tracing, load config)
///
/// Call this at the start of standalone integration tests to set up:
/// - FIPS-compliant crypto provider
/// - Tracing subscriber with env filter
/// - InfraContext loaded from environment variables
///
/// # Panics
///
/// Panics if required environment variables are not set.
pub fn init_test_env(require_msg: &str) -> InfraContext {
    init_e2e_test();
    InfraContext::from_env().expect(require_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder_pattern() {
        let ctx = InfraContext::mgmt_only("/tmp/mgmt".to_string(), InfraProvider::Docker)
            .with_workload("/tmp/workload".to_string())
            .with_workload2("/tmp/workload2".to_string());

        assert_eq!(ctx.mgmt_kubeconfig, "/tmp/mgmt");
        assert_eq!(ctx.workload_kubeconfig, Some("/tmp/workload".to_string()));
        assert_eq!(ctx.workload2_kubeconfig, Some("/tmp/workload2".to_string()));
        assert!(ctx.has_workload());
        assert!(ctx.has_workload2());
    }

    #[test]
    fn test_require_methods() {
        let ctx = InfraContext::mgmt_only("/tmp/mgmt".to_string(), InfraProvider::Docker);

        assert!(ctx.require_workload().is_err());
        assert!(ctx.require_workload2().is_err());

        let ctx = ctx.with_workload("/tmp/workload".to_string());
        assert!(ctx.require_workload().is_ok());
        assert_eq!(ctx.require_workload().unwrap(), "/tmp/workload");
    }
}
