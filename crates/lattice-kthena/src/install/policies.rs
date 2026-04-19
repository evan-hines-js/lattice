//! Cedar wildcard policies for Kthena router + autoscaler.
//!
//! kthena-router uses `depends_all: true` (can reach any model service that
//! declares it as an allowed caller) and `allowed_callers: [*]` (any service
//! can send inference requests through it). kthena-autoscaler uses
//! `depends_all: true` to scrape metrics for scaling decisions.
//!
//! Both require explicit Cedar `AllowWildcard` grants because the wildcard
//! resource (`Lattice::Mesh::"outbound"` / `Lattice::Mesh::"inbound"`) is
//! default-deny.

use lattice_common::{KTHENA_AUTOSCALER_SA, KTHENA_NAMESPACE, KTHENA_ROUTER_SA};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{CedarPolicy, CedarPolicySpec};

/// kthena-router wildcard inbound + outbound.
pub fn generate_kthena_router_cedar_policy() -> CedarPolicy {
    let principal = format!("{KTHENA_NAMESPACE}/{KTHENA_ROUTER_SA}");
    let mut policy = CedarPolicy::new(
        "kthena-router-wildcard",
        CedarPolicySpec {
            description: Some(
                "Allow kthena-router wildcard outbound (model routing) and inbound (inference requests)".to_string(),
            ),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{principal}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);

permit(
    principal == Lattice::Service::"{principal}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"inbound"
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

/// kthena-autoscaler wildcard outbound for scraping model metrics.
pub fn generate_kthena_autoscaler_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "kthena-autoscaler-wildcard-outbound",
        CedarPolicySpec {
            description: Some(
                "Allow kthena-autoscaler wildcard outbound for model metrics scraping".to_string(),
            ),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{KTHENA_NAMESPACE}/{KTHENA_AUTOSCALER_SA}",
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
