//! Shared test helpers for bootstrap module tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use lattice_common::ApiServerEndpoint;
use lattice_crd::crd::ProviderType;
use lattice_infra::pki::{
    CertificateAuthority, CertificateAuthorityBundle, DEFAULT_CERT_VALIDITY_HOURS,
};
use tokio::sync::RwLock;

use super::errors::BootstrapError;
use super::state::{
    ApiServerEndpointResolver, BootstrapConfig, BootstrapState, ClusterBootstrapInfo,
};
use super::token::BootstrapToken;
use super::types::{ClusterFacts, ClusterRegistration, ManifestGenerator};

/// Endpoint resolver for tests: returns a fixed endpoint for any cluster id.
pub fn test_endpoint_resolver() -> ApiServerEndpointResolver {
    Arc::new(|_| Box::pin(async move { Ok(test_api_server_endpoint()) }))
}

pub struct TestManifestGenerator;

#[async_trait::async_trait]
impl ManifestGenerator for TestManifestGenerator {
    async fn generate(
        &self,
        image: &str,
        _registry_credentials: Option<&str>,
        _cluster_name: Option<&str>,
        _provider: Option<ProviderType>,
    ) -> Result<Vec<String>, BootstrapError> {
        Ok(vec![format!("# Test manifest with image {}", image)])
    }
}

pub fn test_api_server_endpoint() -> ApiServerEndpoint {
    ApiServerEndpoint {
        host: "api.test.local".to_string(),
        port: 6443,
    }
}

pub fn test_ca_bundle() -> Arc<RwLock<CertificateAuthorityBundle>> {
    let ca = CertificateAuthority::new("Test CA").expect("test CA creation should succeed");
    Arc::new(RwLock::new(CertificateAuthorityBundle::new(ca)))
}

pub fn test_state() -> BootstrapState<TestManifestGenerator> {
    BootstrapState::new(BootstrapConfig {
        generator: TestManifestGenerator,
        token_ttl: Duration::from_secs(3600),
        ca_bundle: test_ca_bundle(),
        image: "test:latest".to_string(),
        cert_validity_hours: DEFAULT_CERT_VALIDITY_HOURS,
        kube_client: None,
        cluster_name: None,
        api_server_endpoint_resolver: test_endpoint_resolver(),
    })
}

pub fn test_state_with_ttl(ttl: Duration) -> BootstrapState<TestManifestGenerator> {
    BootstrapState::new(BootstrapConfig {
        generator: TestManifestGenerator,
        token_ttl: ttl,
        ca_bundle: test_ca_bundle(),
        image: "test:latest".to_string(),
        cert_validity_hours: DEFAULT_CERT_VALIDITY_HOURS,
        kube_client: None,
        cluster_name: None,
        api_server_endpoint_resolver: test_endpoint_resolver(),
    })
}

/// Build a `ClusterFacts` for a unit-test cluster of the given name +
/// provider. Synthesizes a minimal LatticeCluster manifest JSON.
pub fn test_facts(cluster_id: &str, provider: ProviderType) -> ClusterFacts {
    let manifest = format!(
        r#"{{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{{"name":"{cluster_id}"}}}}"#
    );
    ClusterFacts {
        cluster_name: cluster_id.to_string(),
        provider,
        bootstrap: lattice_crd::crd::BootstrapProvider::default(),
        k8s_version: "1.32.0".to_string(),
        autoscaling_enabled: false,
        lb_advertisement: None,
        cluster_manifest: manifest,
    }
}

/// Build a fully-formed `ClusterBootstrapInfo` for tests that need to
/// poke at state directly rather than going through register_cluster.
pub fn test_bootstrap_info(cluster_id: &str, provider: ProviderType) -> ClusterBootstrapInfo {
    ClusterBootstrapInfo {
        facts: test_facts(cluster_id, provider),
        cell_endpoint: "cell:8443:50051".to_string(),
        ca_certificate: "ca-cert".to_string(),
        token_hash: "test-token-hash".to_string(),
        token_created: Instant::now(),
        token_used: true,
        csr_token_hash: None,
        csr_token_created: None,
        csr_token_used: false,
        csr_token_raw: None,
    }
}

pub async fn register_test_cluster<G: ManifestGenerator>(
    state: &BootstrapState<G>,
    cluster_id: impl Into<String>,
    cell_endpoint: impl Into<String>,
    ca_certificate: impl Into<String>,
) -> BootstrapToken {
    let facts = test_facts(&cluster_id.into(), ProviderType::Docker);
    state
        .register_cluster(
            ClusterRegistration {
                facts,
                cell_endpoint: cell_endpoint.into(),
                ca_certificate: ca_certificate.into(),
            },
            None,
            None,
        )
        .await
}
