//! Bootstrap endpoint for kubeadm callback and CSR signing
//!
//! This module implements HTTP endpoints that run WITHOUT mTLS:
//! - Bootstrap endpoint: kubeadm postKubeadmCommands calls to get manifests
//! - CSR signing endpoint: agents submit CSRs to get signed certificates
//!
//! # Security Model
//!
//! - Endpoints are NON-mTLS (agent doesn't have cert yet)
//! - Bootstrap uses one-time token authentication
//! - CSR signing validates cluster is registered
//!
//! # Bootstrap Flow
//!
//! 1. Cluster created → bootstrap token generated
//! 2. kubeadm runs postKubeadmCommands
//! 3. Script calls `GET /api/clusters/{id}/bootstrap` with Bearer token
//! 4. Endpoint validates token, marks as used
//! 5. Returns: agent manifest, CNI manifest, CA certificate
//!
//! # CSR Flow
//!
//! 1. Agent generates keypair locally (private key never leaves agent)
//! 2. Agent creates CSR and sends to `POST /api/clusters/{id}/csr`
//! 3. Cell signs CSR with CA and returns certificate
//! 4. Agent uses cert for mTLS connection to gRPC server

mod token;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::pki::{CertificateAuthority, PkiError};

pub use token::{BootstrapToken, TokenStore};

/// Bootstrap endpoint errors
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Invalid or expired token
    #[error("invalid or expired token")]
    InvalidToken,

    /// Token already used
    #[error("token already used")]
    TokenAlreadyUsed,

    /// Cluster not found
    #[error("cluster not found: {0}")]
    ClusterNotFound(String),

    /// Missing authorization header
    #[error("missing authorization header")]
    MissingAuth,

    /// CSR signing error
    #[error("CSR signing failed: {0}")]
    CsrSigningFailed(String),

    /// Cluster not bootstrapped yet
    #[error("cluster not bootstrapped: {0}")]
    ClusterNotBootstrapped(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BootstrapError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            BootstrapError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::TokenAlreadyUsed => (StatusCode::GONE, self.to_string()),
            BootstrapError::ClusterNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            BootstrapError::MissingAuth => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::CsrSigningFailed(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            BootstrapError::ClusterNotBootstrapped(_) => {
                (StatusCode::PRECONDITION_FAILED, self.to_string())
            }
            BootstrapError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

impl From<PkiError> for BootstrapError {
    fn from(e: PkiError) -> Self {
        BootstrapError::CsrSigningFailed(e.to_string())
    }
}

/// Bootstrap response containing manifests for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Cluster ID
    pub cluster_id: String,
    /// Cell endpoint for gRPC connection (after CSR is signed)
    pub cell_endpoint: String,
    /// CA certificate in PEM format (for verifying cell)
    pub ca_certificate: String,
    /// Kubernetes manifests to apply (YAML)
    pub manifests: Vec<String>,
}

/// CSR signing request from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrRequest {
    /// CSR in PEM format
    pub csr_pem: String,
}

/// CSR signing response with signed certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrResponse {
    /// Signed certificate in PEM format
    pub certificate_pem: String,
    /// CA certificate in PEM format (for verifying peer)
    pub ca_certificate_pem: String,
}

/// Bootstrap manifest generator
pub trait ManifestGenerator: Send + Sync {
    /// Generate bootstrap manifests for a cluster
    fn generate(&self, cluster_id: &str, cell_endpoint: &str, ca_cert: &str) -> Vec<String>;
}

/// Cilium chart configuration
pub struct CiliumConfig {
    /// Helm chart repository URL
    pub repo_url: &'static str,
    /// Chart version
    pub version: &'static str,
}

impl Default for CiliumConfig {
    fn default() -> Self {
        Self {
            repo_url: "https://helm.cilium.io/",
            version: "1.16.5",
        }
    }
}

/// Default manifest generator that creates agent and CNI manifests
pub struct DefaultManifestGenerator {
    /// Pre-rendered Cilium manifests (from helm template)
    cilium_manifests: Vec<String>,
}

impl DefaultManifestGenerator {
    /// Create a new generator, pre-rendering Cilium manifests via helm template
    pub fn new() -> Result<Self, BootstrapError> {
        Self::with_config(CiliumConfig::default())
    }

    /// Create with custom Cilium configuration
    pub fn with_config(config: CiliumConfig) -> Result<Self, BootstrapError> {
        let cilium_manifests = Self::render_cilium(&config)?;
        Ok(Self { cilium_manifests })
    }

    /// Create without Cilium (for testing only)
    ///
    /// This should only be used in tests where Cilium is not needed.
    /// In production, use `new()` to include Cilium CNI manifests.
    pub fn without_cilium() -> Self {
        Self {
            cilium_manifests: vec![],
        }
    }

    /// Render Cilium manifests using helm template
    fn render_cilium(config: &CiliumConfig) -> Result<Vec<String>, BootstrapError> {
        use std::process::Command;

        // Cilium helm values for Istio compatibility (matching Elixir POC)
        let values = [
            "--set", "hubble.enabled=false",
            "--set", "hubble.relay.enabled=false",
            "--set", "hubble.ui.enabled=false",
            "--set", "prometheus.enabled=false",
            "--set", "operator.prometheus.enabled=false",
            "--set", "cni.exclusive=false",  // Istio compatibility
            "--set", "kubeProxyReplacement=false",
            "--set", "l2announcements.enabled=true",
            "--set", "externalIPs.enabled=true",
        ];

        let output = Command::new("helm")
            .args([
                "template",
                "cilium",
                "cilium",
                "--repo", config.repo_url,
                "--version", config.version,
                "--namespace", "kube-system",
            ])
            .args(&values)
            .output()
            .map_err(|e| BootstrapError::Internal(format!("failed to run helm: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BootstrapError::Internal(format!(
                "helm template failed: {}",
                stderr
            )));
        }

        let yaml_str = String::from_utf8_lossy(&output.stdout);

        // Parse multi-document YAML properly using serde_yaml
        let manifests: Vec<String> = serde_yaml::Deserializer::from_str(&yaml_str)
            .filter_map(|doc| {
                // Deserialize each document as a generic Value
                let value: serde_yaml::Value = serde_yaml::Value::deserialize(doc).ok()?;
                // Skip null/empty documents
                if value.is_null() {
                    return None;
                }
                // Only include documents that have a "kind" field (valid K8s resources)
                if value.get("kind").is_none() {
                    return None;
                }
                // Serialize back to YAML string
                serde_yaml::to_string(&value).ok()
            })
            .collect();

        info!(count = manifests.len(), "Rendered Cilium manifests");
        Ok(manifests)
    }

    /// Generate the agent manifests (non-Cilium)
    fn generate_agent_manifests(
        &self,
        cluster_id: &str,
        cell_endpoint: &str,
        ca_cert: &str,
    ) -> Vec<String> {
        let namespace = r#"apiVersion: v1
kind: Namespace
metadata:
  name: lattice-system"#
            .to_string();

        let ca_secret = format!(
            r#"apiVersion: v1
kind: Secret
metadata:
  name: lattice-ca
  namespace: lattice-system
type: Opaque
data:
  ca.crt: {}"#,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ca_cert)
        );

        // Parse cell_endpoint into HTTP and gRPC endpoints
        // cell_endpoint format: "host:grpc_port" (e.g., "172.18.255.1:443")
        // HTTP is on :8080, gRPC (TLS) is on :443 by default
        let (http_endpoint, grpc_endpoint) = {
            let parts: Vec<&str> = cell_endpoint.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                let host = parts[1];
                let grpc_port = parts[0];
                (
                    format!("http://{}:8080", host),
                    format!("https://{}:{}", host, grpc_port),
                )
            } else {
                // Fallback - assume host only, use default ports
                (
                    format!("http://{}:8080", cell_endpoint),
                    format!("https://{}:443", cell_endpoint),
                )
            }
        };

        let agent_config = format!(
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: lattice-agent-config
  namespace: lattice-system
data:
  cluster_id: "{cluster_id}"
  cell_http_endpoint: "{http_endpoint}"
  cell_grpc_endpoint: "{grpc_endpoint}""#
        );

        // Agent deployment - runs `lattice agent` subcommand
        let agent_deployment = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: lattice-agent
  namespace: lattice-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: lattice-agent
  template:
    metadata:
      labels:
        app: lattice-agent
    spec:
      serviceAccountName: lattice-agent
      containers:
      - name: agent
        image: lattice/agent:latest
        args:
        - agent
        env:
        - name: CLUSTER_ID
          valueFrom:
            configMapKeyRef:
              name: lattice-agent-config
              key: cluster_id
        - name: CELL_HTTP_ENDPOINT
          valueFrom:
            configMapKeyRef:
              name: lattice-agent-config
              key: cell_http_endpoint
        - name: CELL_GRPC_ENDPOINT
          valueFrom:
            configMapKeyRef:
              name: lattice-agent-config
              key: cell_grpc_endpoint
        - name: CA_CERT_PATH
          value: /var/run/secrets/lattice/ca/ca.crt
        volumeMounts:
        - name: ca-cert
          mountPath: /var/run/secrets/lattice/ca
          readOnly: true
        - name: tls
          mountPath: /var/run/secrets/lattice/tls
      volumes:
      - name: ca-cert
        secret:
          secretName: lattice-ca
      - name: tls
        emptyDir: {}"#
            .to_string();

        vec![namespace, ca_secret, agent_config, agent_deployment]
    }
}

impl ManifestGenerator for DefaultManifestGenerator {
    fn generate(&self, cluster_id: &str, cell_endpoint: &str, ca_cert: &str) -> Vec<String> {
        let mut manifests = Vec::new();

        // CNI manifests first (Cilium) - must be applied before other pods can run
        manifests.extend(self.cilium_manifests.clone());

        // Then agent manifests
        manifests.extend(self.generate_agent_manifests(cluster_id, cell_endpoint, ca_cert));

        manifests
    }
}

/// Cluster info stored in bootstrap state
#[derive(Clone, Debug)]
pub struct ClusterBootstrapInfo {
    /// Cluster ID
    pub cluster_id: String,
    /// Cell endpoint for agent to connect to
    pub cell_endpoint: String,
    /// CA certificate PEM
    pub ca_certificate: String,
    /// Bootstrap token (hashed)
    pub token_hash: String,
    /// When the token was created
    pub token_created: Instant,
    /// Whether the token has been used
    pub token_used: bool,
}

/// Bootstrap endpoint state
pub struct BootstrapState<G: ManifestGenerator = DefaultManifestGenerator> {
    /// Cluster info indexed by cluster_id
    clusters: DashMap<String, ClusterBootstrapInfo>,
    /// Manifest generator
    manifest_generator: G,
    /// Token TTL
    token_ttl: Duration,
    /// Certificate authority for signing CSRs
    ca: Arc<CertificateAuthority>,
}

impl<G: ManifestGenerator> BootstrapState<G> {
    /// Create a new bootstrap state with a CA
    pub fn new(generator: G, token_ttl: Duration, ca: Arc<CertificateAuthority>) -> Self {
        Self {
            clusters: DashMap::new(),
            manifest_generator: generator,
            token_ttl,
            ca,
        }
    }

    /// Get the CA certificate PEM for distribution
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    /// Register a cluster for bootstrap
    pub fn register_cluster(
        &self,
        cluster_id: String,
        cell_endpoint: String,
        ca_certificate: String,
    ) -> BootstrapToken {
        let token = BootstrapToken::generate();
        let token_hash = token.hash();

        let info = ClusterBootstrapInfo {
            cluster_id: cluster_id.clone(),
            cell_endpoint,
            ca_certificate,
            token_hash,
            token_created: Instant::now(),
            token_used: false,
        };

        self.clusters.insert(cluster_id, info);
        token
    }

    /// Validate and consume a bootstrap token
    pub fn validate_and_consume(
        &self,
        cluster_id: &str,
        token: &str,
    ) -> Result<ClusterBootstrapInfo, BootstrapError> {
        let mut entry = self
            .clusters
            .get_mut(cluster_id)
            .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

        let info = entry.value_mut();

        // Check if already used
        if info.token_used {
            return Err(BootstrapError::TokenAlreadyUsed);
        }

        // Check TTL
        if info.token_created.elapsed() > self.token_ttl {
            return Err(BootstrapError::InvalidToken);
        }

        // Verify token hash
        let token_obj = BootstrapToken::from_string(token);
        if token_obj.hash() != info.token_hash {
            return Err(BootstrapError::InvalidToken);
        }

        // Mark as used
        info.token_used = true;

        Ok(info.clone())
    }

    /// Generate bootstrap response for a cluster
    pub fn generate_response(&self, info: &ClusterBootstrapInfo) -> BootstrapResponse {
        let manifests = self.manifest_generator.generate(
            &info.cluster_id,
            &info.cell_endpoint,
            &info.ca_certificate,
        );

        BootstrapResponse {
            cluster_id: info.cluster_id.clone(),
            cell_endpoint: info.cell_endpoint.clone(),
            ca_certificate: info.ca_certificate.clone(),
            manifests,
        }
    }

    /// Sign a CSR for a cluster
    ///
    /// The cluster must be registered and have completed bootstrap (token used).
    /// This ensures only legitimate agents can get certificates.
    pub fn sign_csr(&self, cluster_id: &str, csr_pem: &str) -> Result<CsrResponse, BootstrapError> {
        // Check cluster exists
        let entry = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

        // Check cluster has been bootstrapped (token consumed)
        if !entry.token_used {
            return Err(BootstrapError::ClusterNotBootstrapped(
                cluster_id.to_string(),
            ));
        }

        // Sign the CSR
        let certificate_pem = self.ca.sign_csr(csr_pem, cluster_id)?;

        Ok(CsrResponse {
            certificate_pem,
            ca_certificate_pem: self.ca.ca_cert_pem().to_string(),
        })
    }

    /// Check if a cluster is registered
    pub fn is_cluster_registered(&self, cluster_id: &str) -> bool {
        self.clusters.contains_key(cluster_id)
    }
}

/// Extract bearer token from headers
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, BootstrapError> {
    let auth_header = headers
        .get("authorization")
        .ok_or(BootstrapError::MissingAuth)?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| BootstrapError::InvalidToken)?;

    auth_str
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or(BootstrapError::InvalidToken)
}

/// Bootstrap endpoint handler
pub async fn bootstrap_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<BootstrapResponse>, BootstrapError> {
    debug!(cluster_id = %cluster_id, "Bootstrap request received");

    // Extract token
    let token = extract_bearer_token(&headers)?;

    // Validate and consume
    let info = state.validate_and_consume(&cluster_id, &token)?;

    info!(cluster_id = %cluster_id, "Bootstrap token validated");

    // Generate response
    let response = state.generate_response(&info);

    Ok(Json(response))
}

/// CSR signing endpoint handler
///
/// Agents call this endpoint to get their CSR signed after bootstrap.
/// The cluster must have completed bootstrap (token consumed).
pub async fn csr_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    Json(request): Json<CsrRequest>,
) -> Result<Json<CsrResponse>, BootstrapError> {
    debug!(cluster_id = %cluster_id, "CSR signing request received");

    // Sign the CSR
    let response = state.sign_csr(&cluster_id, &request.csr_pem)?;

    info!(cluster_id = %cluster_id, "CSR signed successfully");

    Ok(Json(response))
}

/// Create the bootstrap router
///
/// Routes:
/// - `GET /api/clusters/{cluster_id}/bootstrap` - Get bootstrap manifests (one-time with token)
/// - `POST /api/clusters/{cluster_id}/csr` - Sign a CSR (after bootstrap)
pub fn bootstrap_router<G: ManifestGenerator + 'static>(
    state: Arc<BootstrapState<G>>,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/clusters/{cluster_id}/bootstrap",
            get(bootstrap_handler::<G>),
        )
        .route("/api/clusters/{cluster_id}/csr", post(csr_handler::<G>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::AgentCertRequest;
    use x509_parser::prelude::FromDer;

    struct TestManifestGenerator;

    impl ManifestGenerator for TestManifestGenerator {
        fn generate(&self, cluster_id: &str, _cell_endpoint: &str, _ca_cert: &str) -> Vec<String> {
            vec![format!("# Test manifest for {}", cluster_id)]
        }
    }

    fn test_ca() -> Arc<CertificateAuthority> {
        Arc::new(CertificateAuthority::new("Test CA").unwrap())
    }

    fn test_state() -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(TestManifestGenerator, Duration::from_secs(3600), test_ca())
    }

    fn test_state_with_ttl(ttl: Duration) -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(TestManifestGenerator, ttl, test_ca())
    }

    #[test]
    fn cluster_can_be_registered() {
        let state = test_state();

        let token = state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        );

        assert!(!token.as_str().is_empty());
    }

    #[test]
    fn valid_token_is_accepted() {
        let state = test_state();

        let token = state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        );

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();

        assert_eq!(info.cluster_id, "test-cluster");
    }

    #[test]
    fn invalid_token_is_rejected() {
        let state = test_state();

        state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "cert".to_string(),
        );

        let result = state.validate_and_consume("test-cluster", "wrong-token");

        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[test]
    fn token_can_only_be_used_once() {
        let state = test_state();

        let token = state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "cert".to_string(),
        );

        // First use succeeds
        let _ = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();

        // Second use fails
        let result = state.validate_and_consume("test-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::TokenAlreadyUsed)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "cert".to_string(),
        );

        // Wait for token to expire
        std::thread::sleep(Duration::from_millis(10));

        let result = state.validate_and_consume("test-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[test]
    fn unknown_cluster_is_rejected() {
        let state = test_state();

        let result = state.validate_and_consume("unknown-cluster", "any-token");
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[test]
    fn response_contains_manifests() {
        let state = test_state();

        let token = state.register_cluster(
            "test-cluster".to_string(),
            "https://cell.example.com:443".to_string(),
            "ca-cert".to_string(),
        );

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();
        let response = state.generate_response(&info);

        assert_eq!(response.cluster_id, "test-cluster");
        assert_eq!(response.cell_endpoint, "https://cell.example.com:443");
        assert_eq!(response.ca_certificate, "ca-cert");
        assert!(!response.manifests.is_empty());
        assert!(response.manifests[0].contains("test-cluster"));
    }

    // CSR signing tests

    #[test]
    fn csr_requires_bootstrapped_cluster() {
        let state = test_state();

        // Register but don't bootstrap
        state.register_cluster(
            "not-bootstrapped".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        let agent_req = AgentCertRequest::new("not-bootstrapped").unwrap();
        let result = state.sign_csr("not-bootstrapped", agent_req.csr_pem());

        assert!(matches!(
            result,
            Err(BootstrapError::ClusterNotBootstrapped(_))
        ));
    }

    #[test]
    fn csr_rejected_for_unknown_cluster() {
        let state = test_state();

        let agent_req = AgentCertRequest::new("unknown").unwrap();
        let result = state.sign_csr("unknown", agent_req.csr_pem());

        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[test]
    fn csr_signed_after_bootstrap() {
        let state = test_state();

        // Register and bootstrap
        let token = state.register_cluster(
            "csr-test".to_string(),
            "https://cell:443".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state.validate_and_consume("csr-test", token.as_str()).unwrap();

        // Now CSR signing should work
        let agent_req = AgentCertRequest::new("csr-test").unwrap();
        let result = state.sign_csr("csr-test", agent_req.csr_pem());

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(response.ca_certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn signed_cert_contains_cluster_id() {
        let state = test_state();

        // Register and bootstrap
        let token = state.register_cluster(
            "cluster-xyz".to_string(),
            "https://cell:443".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state.validate_and_consume("cluster-xyz", token.as_str()).unwrap();

        // Sign CSR
        let agent_req = AgentCertRequest::new("cluster-xyz").unwrap();
        let response = state.sign_csr("cluster-xyz", agent_req.csr_pem()).unwrap();

        // Verify the cert contains cluster ID in CN
        // Parse and check (using x509-parser)
        let cert_pem = &response.certificate_pem;
        let pem_obj = ::pem::parse(cert_pem.as_bytes()).unwrap();
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(pem_obj.contents()).unwrap();

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap();

        assert!(cn.contains("cluster-xyz"));
    }

    #[test]
    fn default_generator_creates_namespace() {
        let generator = DefaultManifestGenerator::without_cilium();
        let manifests = generator.generate("my-cluster", "https://cell:443", "ca-pem");

        let has_namespace = manifests
            .iter()
            .any(|m| m.contains("kind: Namespace") && m.contains("lattice-system"));
        assert!(has_namespace);
    }

    #[test]
    fn default_generator_creates_ca_secret() {
        let generator = DefaultManifestGenerator::without_cilium();
        let manifests = generator.generate("my-cluster", "https://cell:443", "my-ca-cert");

        let has_secret = manifests
            .iter()
            .any(|m| m.contains("kind: Secret") && m.contains("lattice-ca"));
        assert!(has_secret);
    }

    #[test]
    fn default_generator_creates_agent_deployment() {
        let generator = DefaultManifestGenerator::without_cilium();
        let manifests = generator.generate("my-cluster", "https://cell:443", "ca-pem");

        let has_deployment = manifests
            .iter()
            .any(|m| m.contains("kind: Deployment") && m.contains("lattice-agent"));
        assert!(has_deployment);
    }

    #[test]
    fn default_generator_creates_cilium_cni() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("my-cluster", "https://cell:443", "ca-pem");

        // Should include Cilium DaemonSet (rendered from helm template)
        let has_cilium_daemonset = manifests
            .iter()
            .any(|m| m.contains("kind: DaemonSet") && m.contains("cilium"));
        assert!(has_cilium_daemonset, "Should include Cilium DaemonSet");

        // Should include Cilium ConfigMap
        let has_cilium_config = manifests
            .iter()
            .any(|m| m.contains("kind: ConfigMap") && m.contains("cilium"));
        assert!(has_cilium_config, "Should include Cilium ConfigMap");
    }

    #[test]
    fn bearer_token_extracted_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token-123".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "test-token-123");
    }

    #[test]
    fn missing_auth_header_rejected() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::MissingAuth)));
    }

    #[test]
    fn non_bearer_auth_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());

        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    // ==========================================================================
    // Story Tests: Complete Bootstrap Flow
    // ==========================================================================
    //
    // These tests document the full bootstrap workflow as described in CLAUDE.md:
    // 1. Cluster is registered with a one-time token
    // 2. kubeadm postKubeadmCommands calls bootstrap endpoint with token
    // 3. Token is validated and consumed (one-time use)
    // 4. Agent receives manifests and CA certificate
    // 5. Agent generates keypair and submits CSR
    // 6. Cell signs CSR and returns certificate
    // 7. Agent uses certificate for mTLS connection

    /// Story: Complete bootstrap flow from registration to certificate
    ///
    /// This test demonstrates the entire bootstrap sequence as experienced
    /// by a newly provisioned workload cluster connecting to its parent cell.
    #[test]
    fn story_complete_bootstrap_flow() {
        let state = test_state();

        // Chapter 1: Cell registers a new cluster for provisioning
        // ---------------------------------------------------------
        // When CAPI creates a cluster, the cell registers it with a bootstrap token.
        // This token will be embedded in kubeadm postKubeadmCommands.
        let token = state.register_cluster(
            "prod-us-west-001".to_string(),
            "https://cell.lattice.example.com:443".to_string(),
            state.ca_cert_pem().to_string(),
        );
        assert!(state.is_cluster_registered("prod-us-west-001"));

        // Chapter 2: kubeadm runs postKubeadmCommands on the new cluster
        // ---------------------------------------------------------------
        // The bootstrap script calls: GET /api/clusters/prod-us-west-001/bootstrap
        // with Authorization: Bearer <token>
        let info = state.validate_and_consume("prod-us-west-001", token.as_str()).unwrap();
        assert_eq!(info.cluster_id, "prod-us-west-001");
        assert_eq!(info.cell_endpoint, "https://cell.lattice.example.com:443");

        // Chapter 3: Cell returns bootstrap response with manifests
        // ----------------------------------------------------------
        let response = state.generate_response(&info);
        assert!(!response.manifests.is_empty());
        assert!(!response.ca_certificate.is_empty());
        assert_eq!(response.cell_endpoint, "https://cell.lattice.example.com:443");

        // Chapter 4: Agent generates keypair and submits CSR
        // ---------------------------------------------------
        // Agent's private key NEVER leaves the workload cluster
        let agent_request = AgentCertRequest::new("prod-us-west-001").unwrap();
        assert!(!agent_request.csr_pem().contains("PRIVATE KEY")); // CSR doesn't contain key

        // Chapter 5: Cell signs the CSR
        // ------------------------------
        let csr_response = state.sign_csr("prod-us-west-001", agent_request.csr_pem()).unwrap();
        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(csr_response.ca_certificate_pem.contains("BEGIN CERTIFICATE"));

        // Epilogue: Agent now has everything needed for mTLS
        // - Private key (locally generated, never transmitted)
        // - Signed certificate (from CSR response)
        // - CA certificate (for verifying the cell)
    }

    /// Story: Security - Token replay attacks are prevented
    ///
    /// Bootstrap tokens are one-time use. An attacker who captures
    /// a token cannot use it to bootstrap a malicious agent.
    #[test]
    fn story_token_replay_attack_prevention() {
        let state = test_state();

        // Legitimate cluster gets registered
        let token = state.register_cluster(
            "secure-cluster".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        // Legitimate bootstrap succeeds
        let _ = state.validate_and_consume("secure-cluster", token.as_str()).unwrap();

        // Attacker captures the token and tries to replay it
        let replay_result = state.validate_and_consume("secure-cluster", token.as_str());

        // Attack is blocked!
        assert!(matches!(replay_result, Err(BootstrapError::TokenAlreadyUsed)));
    }

    /// Story: Security - Wrong tokens are rejected
    ///
    /// Tokens are cryptographically random and cluster-specific.
    /// Guessing or using the wrong token fails.
    #[test]
    fn story_invalid_token_rejection() {
        let state = test_state();

        state.register_cluster(
            "guarded-cluster".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        // Wrong token
        let result = state.validate_and_consume("guarded-cluster", "totally-wrong-token");
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));

        // Token for wrong cluster
        let other_token = state.register_cluster(
            "other-cluster".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );
        let cross_cluster_result = state.validate_and_consume("guarded-cluster", other_token.as_str());
        assert!(matches!(cross_cluster_result, Err(BootstrapError::InvalidToken)));
    }

    /// Story: Security - CSR signing requires completed bootstrap
    ///
    /// An agent can only get its CSR signed after completing the bootstrap
    /// flow. This prevents rogue agents from getting valid certificates.
    #[test]
    fn story_csr_requires_bootstrap_completion() {
        let state = test_state();

        // Register cluster but DON'T complete bootstrap
        let _token = state.register_cluster(
            "premature-cluster".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        // Try to get CSR signed without completing bootstrap
        let agent_request = AgentCertRequest::new("premature-cluster").unwrap();
        let result = state.sign_csr("premature-cluster", agent_request.csr_pem());

        // Blocked! Must complete bootstrap first
        assert!(matches!(result, Err(BootstrapError::ClusterNotBootstrapped(_))));
    }

    /// Story: Security - Unknown clusters cannot bootstrap
    ///
    /// Only pre-registered clusters can use the bootstrap endpoint.
    /// Random cluster IDs are rejected.
    #[test]
    fn story_unknown_cluster_rejection() {
        let state = test_state();

        // No clusters registered - attacker tries to bootstrap
        let result = state.validate_and_consume("hacker-cluster", "fake-token");
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));

        // Unknown cluster can't get CSR signed either
        let agent_request = AgentCertRequest::new("hacker-cluster").unwrap();
        let csr_result = state.sign_csr("hacker-cluster", agent_request.csr_pem());
        assert!(matches!(csr_result, Err(BootstrapError::ClusterNotFound(_))));
    }

    /// Story: Token expiration for time-limited bootstrap windows
    ///
    /// Tokens have a TTL. If a cluster takes too long to bootstrap,
    /// the token expires and a new one must be generated.
    #[test]
    fn story_expired_token_rejection() {
        // Very short TTL for testing
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = state.register_cluster(
            "slow-cluster".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        // Simulate slow bootstrap by waiting
        std::thread::sleep(Duration::from_millis(10));

        // Token has expired
        let result = state.validate_and_consume("slow-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    /// Story: Manifest generation for agent deployment
    ///
    /// The bootstrap response includes Kubernetes manifests that set up
    /// the Lattice agent on the new cluster.
    #[test]
    fn story_manifest_generation() {
        let generator = DefaultManifestGenerator::without_cilium();
        let manifests = generator.generate(
            "my-workload-cluster",
            "https://cell.example.com:443",
            "---CA CERT PEM---",
        );

        // Manifests create the lattice-system namespace
        let has_namespace = manifests.iter().any(|m|
            m.contains("kind: Namespace") && m.contains("lattice-system")
        );
        assert!(has_namespace, "Should create lattice-system namespace");

        // Manifests include CA certificate for verifying cell
        let has_ca_secret = manifests.iter().any(|m|
            m.contains("kind: Secret") && m.contains("lattice-ca")
        );
        assert!(has_ca_secret, "Should include CA certificate secret");

        // Manifests deploy the agent
        let has_agent = manifests.iter().any(|m|
            m.contains("kind: Deployment") && m.contains("lattice-agent")
        );
        assert!(has_agent, "Should deploy lattice-agent");

        // Agent config includes cluster ID and cell endpoint
        let has_config = manifests.iter().any(|m|
            m.contains("kind: ConfigMap") &&
            m.contains("my-workload-cluster") &&
            m.contains("cell.example.com")
        );
        assert!(has_config, "Should include agent configuration");
    }

    /// Story: HTTP API - Bearer token extraction
    ///
    /// The bootstrap endpoint uses standard Bearer token authentication.
    #[test]
    fn story_bearer_token_authentication() {
        // Valid Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-secret-token".parse().unwrap());
        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "my-secret-token");

        // Missing header
        let empty_headers = HeaderMap::new();
        let missing_result = extract_bearer_token(&empty_headers);
        assert!(matches!(missing_result, Err(BootstrapError::MissingAuth)));

        // Wrong auth scheme (Basic instead of Bearer)
        let mut basic_headers = HeaderMap::new();
        basic_headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let wrong_scheme = extract_bearer_token(&basic_headers);
        assert!(matches!(wrong_scheme, Err(BootstrapError::InvalidToken)));
    }

    /// Story: HTTP error responses map to correct status codes
    ///
    /// Different error types return appropriate HTTP status codes
    /// for proper client error handling.
    #[tokio::test]
    async fn story_error_http_responses() {
        use axum::http::StatusCode;

        // Authentication errors -> 401 Unauthorized
        let auth_err = BootstrapError::InvalidToken.into_response();
        assert_eq!(auth_err.status(), StatusCode::UNAUTHORIZED);

        let missing_auth = BootstrapError::MissingAuth.into_response();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        // Token already used -> 410 Gone (resource no longer available)
        let used_err = BootstrapError::TokenAlreadyUsed.into_response();
        assert_eq!(used_err.status(), StatusCode::GONE);

        // Unknown cluster -> 404 Not Found
        let not_found = BootstrapError::ClusterNotFound("x".to_string()).into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        // CSR before bootstrap -> 412 Precondition Failed
        let precondition = BootstrapError::ClusterNotBootstrapped("x".to_string()).into_response();
        assert_eq!(precondition.status(), StatusCode::PRECONDITION_FAILED);

        // Bad CSR -> 400 Bad Request
        let bad_csr = BootstrapError::CsrSigningFailed("error".to_string()).into_response();
        assert_eq!(bad_csr.status(), StatusCode::BAD_REQUEST);

        // Internal errors -> 500 (and message hidden for security)
        let internal = BootstrapError::Internal("secret details".to_string()).into_response();
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Story: CA certificate availability for distribution
    #[test]
    fn story_ca_certificate_distribution() {
        let state = test_state();

        // Cell provides CA cert for agents to verify mTLS
        let ca_cert = state.ca_cert_pem();
        assert!(ca_cert.contains("BEGIN CERTIFICATE"));

        // This CA cert is included in bootstrap response
        let token = state.register_cluster(
            "ca-test".to_string(),
            "https://cell:443".to_string(),
            ca_cert.to_string(),
        );
        let info = state.validate_and_consume("ca-test", token.as_str()).unwrap();
        let response = state.generate_response(&info);

        assert_eq!(response.ca_certificate, ca_cert);
    }

    // ==========================================================================
    // Integration Tests: HTTP Handlers
    // ==========================================================================

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Integration test: bootstrap_router creates valid routes
    #[tokio::test]
    async fn integration_bootstrap_router_creation() {
        let state = Arc::new(test_state());
        let _router = bootstrap_router(state);

        // Router should be created without panic
    }

    /// Integration test: bootstrap endpoint with valid token
    #[tokio::test]
    async fn integration_bootstrap_handler_success() {
        let state = Arc::new(test_state());
        let token = state.register_cluster(
            "http-test".to_string(),
            "https://cell:443".to_string(),
            "ca-cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/http-test/bootstrap")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let bootstrap_response: BootstrapResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(bootstrap_response.cluster_id, "http-test");
        assert_eq!(bootstrap_response.cell_endpoint, "https://cell:443");
        assert!(!bootstrap_response.manifests.is_empty());
    }

    /// Integration test: bootstrap endpoint with missing auth
    #[tokio::test]
    async fn integration_bootstrap_handler_missing_auth() {
        let state = Arc::new(test_state());
        state.register_cluster(
            "auth-test".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/auth-test/bootstrap")
            // No authorization header
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: bootstrap endpoint with invalid token
    #[tokio::test]
    async fn integration_bootstrap_handler_invalid_token() {
        let state = Arc::new(test_state());
        state.register_cluster(
            "token-test".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/token-test/bootstrap")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: bootstrap endpoint for unknown cluster
    #[tokio::test]
    async fn integration_bootstrap_handler_unknown_cluster() {
        let state = Arc::new(test_state());
        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/nonexistent/bootstrap")
            .header("authorization", "Bearer any-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test: CSR endpoint with valid request
    #[tokio::test]
    async fn integration_csr_handler_success() {
        let state = Arc::new(test_state());

        // Register and bootstrap first
        let token = state.register_cluster(
            "csr-http-test".to_string(),
            "https://cell:443".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state.validate_and_consume("csr-http-test", token.as_str()).unwrap();

        // Generate CSR
        let agent_req = AgentCertRequest::new("csr-http-test").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/csr-http-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let csr_response: CsrResponse = serde_json::from_slice(&body).unwrap();

        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(csr_response.ca_certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    /// Integration test: CSR endpoint before bootstrap
    #[tokio::test]
    async fn integration_csr_handler_before_bootstrap() {
        let state = Arc::new(test_state());

        // Register but DON'T bootstrap
        state.register_cluster(
            "not-bootstrapped".to_string(),
            "https://cell:443".to_string(),
            "cert".to_string(),
        );

        let agent_req = AgentCertRequest::new("not-bootstrapped").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/not-bootstrapped/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    /// Integration test: CSR endpoint for unknown cluster
    #[tokio::test]
    async fn integration_csr_handler_unknown_cluster() {
        let state = Arc::new(test_state());

        let agent_req = AgentCertRequest::new("unknown").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/unknown/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test: Full HTTP bootstrap flow
    #[tokio::test]
    async fn integration_full_http_bootstrap_flow() {
        let state = Arc::new(test_state());
        let ca_cert = state.ca_cert_pem().to_string();

        // Step 1: Register cluster
        let token = state.register_cluster(
            "full-flow-test".to_string(),
            "https://cell.example.com:443".to_string(),
            ca_cert.clone(),
        );

        let router = bootstrap_router(state);

        // Step 2: Bootstrap request
        let bootstrap_request = Request::builder()
            .method("GET")
            .uri("/api/clusters/full-flow-test/bootstrap")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .unwrap();

        let response = router.clone().oneshot(bootstrap_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let bootstrap_response: BootstrapResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(bootstrap_response.cluster_id, "full-flow-test");

        // Step 3: CSR signing
        let agent_req = AgentCertRequest::new("full-flow-test").unwrap();
        let csr_body = serde_json::to_string(&CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        })
        .unwrap();

        let csr_request = Request::builder()
            .method("POST")
            .uri("/api/clusters/full-flow-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(csr_body))
            .unwrap();

        let response = router.oneshot(csr_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let csr_response: CsrResponse = serde_json::from_slice(&body).unwrap();
        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
    }
}
