//! Model artifact CRD types
//!
//! Defines `ModelArtifact` CRD — managed by the ModelCache controller to track
//! the cache state of pre-fetched model artifacts.
//!
//! Model loading is triggered by `type: model` resources on LatticeServiceSpec.
//! The VolumeCompiler generates scheduling gates and pod volume references;
//! the ModelCache controller creates PVCs (owned by ModelArtifact) and
//! pre-fetch Jobs to populate them.

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// ModelParams — parsed from ResourceSpec.params when type == model
// =============================================================================

/// Parameters for a model resource
///
/// Parsed from the generic `params` field on `ResourceSpec` when `type: model`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelParams {
    /// Model artifact URI
    ///
    /// Supported schemes:
    /// - `huggingface://org/model` — HuggingFace Hub
    /// - `s3://bucket/path` — AWS S3 (or S3-compatible)
    /// - `gs://bucket/path` — Google Cloud Storage
    /// - `az://container/path` — Azure Blob Storage
    /// - `file:///path` — Local path (for testing)
    pub uri: String,

    /// HuggingFace revision (branch, tag, or commit hash)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// PVC size for cached model artifacts
    ///
    /// Format: Kubernetes quantity (e.g., "5Gi", "140Gi").
    /// If omitted, defaults to "50Gi".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,

    /// Secret reference for model artifact credentials
    ///
    /// References a Kubernetes Secret in the same namespace containing
    /// provider-specific credentials (HF_TOKEN, AWS keys, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,

    /// Kubernetes storage class for the cache PVC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

/// Default PVC size for model cache when not specified
pub const DEFAULT_MODEL_CACHE_SIZE: &str = "50Gi";

impl ModelParams {
    /// Validate model parameters
    pub fn validate(&self) -> Result<(), String> {
        let valid_schemes = ["huggingface://", "s3://", "gs://", "az://", "file:///"];
        if !valid_schemes.iter().any(|s| self.uri.starts_with(s)) {
            return Err(format!(
                "model uri must start with one of: {}",
                valid_schemes.join(", ")
            ));
        }
        Ok(())
    }

    /// Extract the model name from the URI
    ///
    /// Examples:
    /// - `huggingface://meta-llama/Llama-3.3-70B-Instruct` → `meta-llama/Llama-3.3-70B-Instruct`
    /// - `s3://my-models/fraud-detector/v3` → `fraud-detector/v3`
    pub fn model_name(&self) -> &str {
        if let Some(rest) = self.uri.strip_prefix("huggingface://") {
            rest
        } else if let Some(rest) = self.uri.strip_prefix("s3://") {
            rest.find('/').map(|i| &rest[i + 1..]).unwrap_or(rest)
        } else if let Some(rest) = self.uri.strip_prefix("gs://") {
            rest.find('/').map(|i| &rest[i + 1..]).unwrap_or(rest)
        } else if let Some(rest) = self.uri.strip_prefix("az://") {
            rest.find('/').map(|i| &rest[i + 1..]).unwrap_or(rest)
        } else if let Some(rest) = self.uri.strip_prefix("file:///") {
            rest.rsplit('/').next().unwrap_or(rest)
        } else {
            &self.uri
        }
    }

    /// Generate a deterministic PVC name for this model's cache
    ///
    /// Content-addressable: same URI + revision = same PVC name.
    /// Multiple LatticeServices using the same model share the same PVC.
    pub fn cache_pvc_name(&self) -> String {
        use aws_lc_rs::digest::{digest, SHA256};

        let revision = self.revision.as_deref().unwrap_or("main");
        let key = format!("{}@{}", self.uri, revision);
        let hash = digest(&SHA256, key.as_bytes());
        let short_hash: String = hash
            .as_ref()
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect();

        // Sanitize model name for K8s naming (lowercase, alphanumeric + hyphens)
        let sanitized: String = self
            .model_name()
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let sanitized = sanitized.trim_matches('-');

        // K8s names must be <= 253 chars; keep it well under
        let truncated = if sanitized.len() > 40 {
            &sanitized[..40]
        } else {
            sanitized
        };

        format!("model-cache-{}-{}", truncated, short_hash)
    }

    /// PVC size, with default fallback
    pub fn pvc_size(&self) -> &str {
        self.size.as_deref().unwrap_or(DEFAULT_MODEL_CACHE_SIZE)
    }
}

// =============================================================================
// ModelArtifact CRD — managed by ModelCache controller
// =============================================================================

/// ModelArtifact tracks the cache state of a specific model.
///
/// Created and managed exclusively by the ModelCache controller.
/// One ModelArtifact per unique model (URI + revision) in the namespace.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "ModelArtifact",
    plural = "modelartifacts",
    shortname = "ma",
    namespaced,
    status = "ModelArtifactStatus",
    printcolumn = r#"{"name":"Model","type":"string","jsonPath":".spec.uri"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"PVC","type":"string","jsonPath":".spec.pvcName"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ModelArtifactSpec {
    /// Model artifact URI
    pub uri: String,

    /// Revision (HuggingFace branch/tag/commit)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Name of the PVC backing this model cache
    pub pvc_name: String,

    /// PVC size for the model cache (Kubernetes quantity, e.g. "50Gi")
    pub cache_size: String,

    /// Kubernetes storage class for the cache PVC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

/// Status of a ModelArtifact
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelArtifactStatus {
    /// Current phase
    pub phase: ModelArtifactPhase,

    /// When the download completed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message if phase is Failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Number of times the download has been retried after failure
    #[serde(default)]
    pub retry_count: u32,
}

/// Base delay in seconds for retry backoff (30s * 2^retry_count, capped at 5 min)
pub const RETRY_BASE_DELAY_SECS: u64 = 30;

/// Maximum retry delay in seconds (5 minutes)
pub const RETRY_MAX_DELAY_SECS: u64 = 300;

/// Phase of a ModelArtifact
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ModelArtifactPhase {
    /// Waiting for download to begin
    #[default]
    Pending,
    /// Pre-fetch Job is downloading model data to PVC
    Downloading,
    /// Model data is cached and ready for use
    Ready,
    /// Download or validation failed
    Failed,
}

// =============================================================================
// Scheduling gate constant
// =============================================================================

/// Scheduling gate name used to block pods until model cache is ready
pub const MODEL_READY_GATE: &str = "lattice.dev/model-ready";

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_model_params(uri: &str) -> ModelParams {
        ModelParams {
            uri: uri.to_string(),
            revision: None,
            size: None,
            secret_ref: None,
            storage_class: None,
        }
    }

    #[test]
    fn validate_valid_huggingface_uri() {
        let params = make_model_params("huggingface://meta-llama/Llama-3.3-70B-Instruct");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn validate_valid_s3_uri() {
        let params = make_model_params("s3://my-models/fraud-detector/v3");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn validate_invalid_uri_scheme() {
        let params = make_model_params("http://example.com/model");
        let err = params.validate().unwrap_err();
        assert!(err.contains("model uri must start with one of"));
    }

    #[test]
    fn model_name_huggingface() {
        let params = make_model_params("huggingface://meta-llama/Llama-3.3-70B-Instruct");
        assert_eq!(params.model_name(), "meta-llama/Llama-3.3-70B-Instruct");
    }

    #[test]
    fn model_name_s3() {
        let params = make_model_params("s3://my-models/fraud-detector/v3");
        assert_eq!(params.model_name(), "fraud-detector/v3");
    }

    #[test]
    fn cache_pvc_name_deterministic() {
        let params = make_model_params("huggingface://meta-llama/Llama-3.3-70B-Instruct");
        let name1 = params.cache_pvc_name();
        let name2 = params.cache_pvc_name();
        assert_eq!(name1, name2);
        assert!(name1.starts_with("model-cache-"));
    }

    #[test]
    fn cache_pvc_name_different_revision() {
        let p1 = make_model_params("huggingface://meta-llama/Llama-3.3-70B-Instruct");
        let mut p2 = make_model_params("huggingface://meta-llama/Llama-3.3-70B-Instruct");
        p2.revision = Some("a1b2c3d".into());
        assert_ne!(p1.cache_pvc_name(), p2.cache_pvc_name());
    }

    #[test]
    fn pvc_size_default() {
        let params = make_model_params("huggingface://test/model");
        assert_eq!(params.pvc_size(), "50Gi");
    }

    #[test]
    fn pvc_size_custom() {
        let mut params = make_model_params("huggingface://test/model");
        params.size = Some("140Gi".into());
        assert_eq!(params.pvc_size(), "140Gi");
    }

    #[test]
    fn model_artifact_phase_default_is_pending() {
        assert_eq!(ModelArtifactPhase::default(), ModelArtifactPhase::Pending);
    }
}
