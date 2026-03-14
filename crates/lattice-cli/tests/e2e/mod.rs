//! End-to-end tests for Lattice CLI installation
//!
//! This module contains three tiers of tests:
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Test Infrastructure                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  INTEGRATION TESTS (assume cluster exists, can run standalone)  │
//! │  ├─ integration/mesh.rs          - Mesh bilateral agreements    │
//! │  ├─ integration/capi.rs          - CAPI resource verification   │
//! │  ├─ integration/scaling.rs       - Worker scaling tests         │
//! │  ├─ integration/proxy.rs         - K8s API proxy through hier.  │
//! │  ├─ integration/kubeconfig.rs    - Kubeconfig patching verify   │
//! │  ├─ integration/cedar.rs         - Cedar policy enforcement     │
//! │  ├─ integration/cedar_secrets.rs - Cedar secret authorization   │
//! │  ├─ integration/cedar_security.rs- Cedar security overrides     │
//! │  ├─ integration/secrets.rs       - Local secrets integration    │

//! │  ├─ integration/gpu_health.rs     - GPU health cordon/drain      │
//! │  ├─ integration/oidc.rs          - OIDC authentication          │
//! │  ├─ integration/multi_hop.rs     - Multi-hop proxy operations   │
//! │  └─ integration/pivot.rs         - Unpivot verification         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  PER-INTEGRATION E2E (isolated: setup, one test, teardown)      │
//! │  ├─ mesh_e2e.rs              - Mesh only                        │
//! │  ├─ capi_e2e.rs              - CAPI only                        │
//! │  ├─ scaling_e2e.rs           - Scaling only                     │
//! │  ├─ proxy_e2e.rs             - Proxy only                       │
//! │  ├─ kubeconfig_e2e.rs        - Kubeconfig only                  │
//! │  ├─ cedar_e2e.rs             - Cedar only                       │
//! │  ├─ cedar_secrets_e2e.rs     - Cedar secrets only               │
//! │  ├─ cedar_security_e2e.rs   - Cedar security overrides only    │
//! │  ├─ secrets_e2e.rs           - Local secrets only               │

//! │  ├─ oidc_e2e.rs              - OIDC only                        │
//! │  ├─ workload2_e2e.rs         - Workload2 (3-cluster hierarchy)  │
//! │  └─ pivot_standalone_e2e.rs  - Pivot/unpivot only               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  UNIFIED E2E (full lifecycle, all tests in sequence)            │
//! │  ├─ unified_e2e.rs           - Full lifecycle                   │
//! │  ├─ upgrade_e2e.rs           - Upgrade with mesh traffic        │
//! │  └─ docker_independence_e2e.rs - Parent deletion survival       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Running Tests
//!
//! ## Per-integration E2E (isolated — setup, one test, teardown)
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_mesh_e2e -- --nocapture
//! cargo test --features provider-e2e --test e2e test_proxy_e2e -- --nocapture
//! ```
//!
//! ## Unified E2E (full lifecycle, all tests)
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_configurable_provider_pivot -- --nocapture
//! ```
//!
//! ## Integration tests on existing clusters (fast iteration)
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/tmp/e2e-mgmt-kubeconfig-xxx \
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig-xxx \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

#[cfg(feature = "provider-e2e")]
mod chaos;
#[cfg(feature = "provider-e2e")]
mod context;
mod gateway_fixtures;
mod gateway_helpers;
mod helpers;
#[cfg(feature = "provider-e2e")]
pub mod integration;
mod media_server_e2e;
mod mesh_fixtures;
mod mesh_helpers;
mod mesh_random;
mod mesh_removal;
mod mesh_tests;
mod providers;

// Unified E2E (full lifecycle)
mod unified_e2e;

// Specialized E2E
mod docker_independence_e2e;
mod upgrade_e2e;

// Per-integration E2E (isolated: setup, one test, teardown)
mod autoscaling_e2e;
mod capi_e2e;
mod cedar_e2e;
mod cedar_secrets_e2e;
mod cedar_security_e2e;
mod celery_queue_e2e;
mod ecommerce_e2e;
mod gateway_e2e;
mod gpu_health_e2e;
mod kubeconfig_e2e;
mod mesh_e2e;
mod mesh_onboarding_e2e;
mod oidc_e2e;
mod pivot_standalone_e2e;
mod proxy_e2e;
mod route_discovery_e2e;
mod scaling_e2e;
mod secrets_e2e;
mod topology_e2e;
mod vault_secrets_e2e;
mod webapp_postgres_e2e;
mod webhook_e2e;
mod workload2_e2e;
