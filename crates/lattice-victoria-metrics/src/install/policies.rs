//! vmagent wildcard Cedar policy.
//!
//! vmagent uses `depends_all: true` to scrape metrics from any service that
//! exposes a `metrics` port; this policy authorizes that wildcard outbound.

use lattice_common::{MONITORING_NAMESPACE, VMAGENT_SA_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{CedarPolicy, CedarPolicySpec};

/// vmagent wildcard outbound grant for metrics scraping.
pub fn generate_vmagent_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "vmagent-wildcard-outbound",
        CedarPolicySpec {
            description: Some(
                "Allow vmagent wildcard outbound for metrics scraping".to_string(),
            ),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{MONITORING_NAMESPACE}/{VMAGENT_SA_NAME}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);"#,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}
