//! Error types for the Lattice operator

use thiserror::Error;

/// Main error type for Lattice operations
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    /// Validation error for CRD specs
    #[error("validation error: {0}")]
    Validation(String),

    /// Infrastructure provider error
    #[error("provider error: {0}")]
    Provider(String),

    /// Pivot operation error
    #[error("pivot error: {0}")]
    Pivot(String),

    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// CAPI installation error
    #[error("CAPI installation error: {0}")]
    CapiInstallation(String),
}

impl Error {
    /// Create a validation error with the given message
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a provider error with the given message
    pub fn provider(msg: impl Into<String>) -> Self {
        Self::Provider(msg.into())
    }

    /// Create a pivot error with the given message
    pub fn pivot(msg: impl Into<String>) -> Self {
        Self::Pivot(msg.into())
    }

    /// Create a serialization error with the given message
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    /// Create a CAPI installation error with the given message
    pub fn capi_installation(msg: impl Into<String>) -> Self {
        Self::CapiInstallation(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Story Tests: Error Propagation in Cluster Operations
    // ==========================================================================
    //
    // These tests demonstrate how errors flow through the system during
    // various cluster lifecycle operations. Each error type represents
    // a different failure category with specific handling requirements.

    /// Story: CRD validation catches misconfigurations before provisioning
    ///
    /// When a user creates a LatticeCluster with invalid configuration,
    /// the validation layer catches it immediately with a clear error message.
    #[test]
    fn story_validation_prevents_invalid_cluster_creation() {
        // Scenario: User tries to create a cluster with invalid name
        let err = Error::validation("cluster name 'My Cluster!' contains invalid characters");
        assert!(err.to_string().contains("validation error"));
        assert!(err.to_string().contains("invalid characters"));

        // Scenario: User specifies even number of control plane nodes
        let err = Error::validation("control plane count must be odd for HA (1, 3, 5, ...)");
        assert!(err.to_string().contains("odd for HA"));

        // Scenario: User specifies zero control plane nodes
        let err = Error::validation("control plane count must be at least 1");
        assert!(err.to_string().contains("at least 1"));

        // Validation errors are categorized correctly for handling
        match Error::validation("any message") {
            Error::Validation(msg) => assert_eq!(msg, "any message"),
            _ => panic!("Expected Validation variant"),
        }
    }

    /// Story: Provider errors surface infrastructure failures
    ///
    /// When infrastructure provisioning fails (Docker, AWS, GCP, Azure),
    /// the error clearly indicates which provider failed and why.
    #[test]
    fn story_provider_errors_during_cluster_provisioning() {
        // Scenario: Docker daemon not running for local development
        let err = Error::provider("docker daemon not available: connection refused");
        assert!(err.to_string().contains("provider error"));
        assert!(err.to_string().contains("docker"));

        // Scenario: AWS credentials expired
        let err = Error::provider("AWS authentication failed: token expired");
        assert!(err.to_string().contains("AWS"));

        // Scenario: GCP quota exceeded
        let err = Error::provider("GCP quota exceeded for n2-standard-4 instances in us-west1");
        assert!(err.to_string().contains("quota exceeded"));

        // Provider errors are categorized correctly
        match Error::provider("any provider issue") {
            Error::Provider(msg) => assert_eq!(msg, "any provider issue"),
            _ => panic!("Expected Provider variant"),
        }
    }

    /// Story: Pivot errors indicate CAPI migration failures
    ///
    /// The pivot operation moves CAPI resources from parent to child cluster.
    /// Failures here require careful handling as the cluster may be in an
    /// intermediate state.
    #[test]
    fn story_pivot_errors_during_self_management_transition() {
        // Scenario: clusterctl move command fails
        let err = Error::pivot("clusterctl move failed: unable to connect to target cluster");
        assert!(err.to_string().contains("pivot error"));
        assert!(err.to_string().contains("clusterctl"));

        // Scenario: CAPI resources export fails
        let err = Error::pivot("failed to export CAPI resources: MachineDeployment not found");
        assert!(err.to_string().contains("export"));

        // Scenario: Target cluster not ready for pivot
        let err = Error::pivot("target cluster not ready: agent not connected");
        assert!(err.to_string().contains("agent not connected"));

        // Pivot errors are categorized correctly
        match Error::pivot("pivot issue") {
            Error::Pivot(msg) => assert_eq!(msg, "pivot issue"),
            _ => panic!("Expected Pivot variant"),
        }
    }

    /// Story: Serialization errors surface manifest/config issues
    ///
    /// When YAML/JSON processing fails, the error indicates what
    /// was being processed and what went wrong.
    #[test]
    fn story_serialization_errors_in_manifest_processing() {
        // Scenario: Invalid YAML in cluster spec
        let err = Error::serialization("invalid YAML: unexpected key 'typo_field' at line 15");
        assert!(err.to_string().contains("serialization error"));
        assert!(err.to_string().contains("YAML"));

        // Scenario: JSON parsing failure in API response
        let err =
            Error::serialization("failed to parse CAPI Machine status: missing field 'phase'");
        assert!(err.to_string().contains("missing field"));

        // Serialization errors are categorized correctly
        match Error::serialization("parse error") {
            Error::Serialization(msg) => assert_eq!(msg, "parse error"),
            _ => panic!("Expected Serialization variant"),
        }
    }

    /// Story: Error helper functions accept both String and &str
    ///
    /// For ergonomic API usage, error constructors accept anything
    /// that implements Into<String>.
    #[test]
    fn story_error_construction_ergonomics() {
        // From String
        let dynamic_msg = format!("cluster {} not found", "test-cluster");
        let err = Error::validation(dynamic_msg);
        assert!(err.to_string().contains("test-cluster"));

        // From &str literal
        let err = Error::provider("static message");
        assert!(err.to_string().contains("static message"));

        // From formatted string
        let cluster_name = "prod-us-west";
        let err = Error::pivot(format!("pivot failed for {}", cluster_name));
        assert!(err.to_string().contains("prod-us-west"));
    }

    /// Story: Errors are categorized for proper handling in controllers
    ///
    /// Different error types require different handling strategies in the
    /// reconciliation loop (retry, alert, fail permanently, etc.).
    #[test]
    fn story_error_categorization_for_controller_handling() {
        fn categorize_error(err: &Error) -> &'static str {
            match err {
                Error::Validation(_) => "reject_and_fail", // User error, don't retry
                Error::Provider(_) => "retry_with_backoff", // Infra might recover
                Error::Pivot(_) => "manual_intervention",  // State needs review
                Error::Serialization(_) => "reject_and_fail", // Code/config bug
                Error::Kube(_) => "retry_with_backoff",    // K8s API might recover
                Error::CapiInstallation(_) => "retry_with_backoff", // CAPI install might recover
            }
        }

        // Validation errors should fail permanently (user must fix config)
        assert_eq!(
            categorize_error(&Error::validation("bad config")),
            "reject_and_fail"
        );

        // Provider errors might recover (retry)
        assert_eq!(
            categorize_error(&Error::provider("timeout")),
            "retry_with_backoff"
        );

        // Pivot errors need human review
        assert_eq!(
            categorize_error(&Error::pivot("partial state")),
            "manual_intervention"
        );
    }
}
