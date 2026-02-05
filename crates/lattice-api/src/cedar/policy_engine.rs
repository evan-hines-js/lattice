//! Cedar policy authorization
//!
//! Uses Cedar for fine-grained access control to clusters.
//!
//! # Policy Inheritance
//!
//! Policies are loaded in two phases:
//! 1. **Inherited policies** (labeled `lattice.dev/inherited: true`) - from parent clusters
//! 2. **Local policies** - defined directly on this cluster
//!
//! Within each phase, policies are sorted by priority (higher first). Inherited
//! policies are loaded first to ensure parent policies take precedence (parent's
//! word is law). Cedar's default-deny semantics mean any `forbid` policy will
//! override `permit` policies.
//!
//! # Cluster Attributes
//!
//! Clusters have attributes populated from labels:
//! - `environment` from `lattice.dev/environment` (required by policy, fail-closed)
//! - `region` from `lattice.dev/region` (default: "unknown")
//! - `tier` from `lattice.dev/tier` (default: "standard")

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};
use kube::api::ListParams;
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::auth::UserIdentity;
use crate::error::{Error, Result};
use crate::is_local_resource;
use lattice_common::crd::CedarPolicy;
use lattice_common::INHERITED_LABEL;

// ============================================================================
// Constants
// ============================================================================

/// Lattice Cedar schema namespace
const NAMESPACE: &str = "Lattice";

/// Label keys for cluster attributes
const ENVIRONMENT_LABEL: &str = "lattice.dev/environment";
const REGION_LABEL: &str = "lattice.dev/region";
const TIER_LABEL: &str = "lattice.dev/tier";

/// Default values for optional cluster attributes
const DEFAULT_REGION: &str = "unknown";
const DEFAULT_TIER: &str = "standard";

// ============================================================================
// ClusterAttributes
// ============================================================================

/// Cluster attributes for Cedar entity building
///
/// These are extracted from cluster labels and used to build Cedar entities
/// with attributes for policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct ClusterAttributes {
    /// Environment (e.g., "prod", "staging", "dev")
    /// Only present if lattice.dev/environment label exists
    pub environment: Option<String>,
    /// Region (e.g., "us-west-2", "eu-central-1")
    /// Defaults to "unknown" if lattice.dev/region label is missing
    pub region: String,
    /// Tier (e.g., "standard", "premium", "critical")
    /// Defaults to "standard" if lattice.dev/tier label is missing
    pub tier: String,
}

impl ClusterAttributes {
    /// Create ClusterAttributes from a label map
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        Self {
            environment: labels.get(ENVIRONMENT_LABEL).cloned(),
            region: labels
                .get(REGION_LABEL)
                .cloned()
                .unwrap_or_else(|| DEFAULT_REGION.to_string()),
            tier: labels
                .get(TIER_LABEL)
                .cloned()
                .unwrap_or_else(|| DEFAULT_TIER.to_string()),
        }
    }
}

// ============================================================================
// PolicyEngine
// ============================================================================

/// Cedar policy engine
///
/// Evaluates authorization requests using Cedar policies loaded from CRDs.
pub struct PolicyEngine {
    /// Cedar authorizer
    authorizer: Authorizer,
    /// Parsed policy set (updated when CRDs change)
    policy_set: Arc<RwLock<PolicySet>>,
    /// Known clusters with their attributes for authorization checks
    cluster_attrs: Arc<RwLock<HashMap<String, ClusterAttributes>>>,
}

impl PolicyEngine {
    /// Create a new policy engine with no policies
    pub fn new() -> Self {
        Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(PolicySet::new())),
            cluster_attrs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create policy engine from CedarPolicy CRDs
    ///
    /// Loads all enabled CedarPolicy resources from lattice-system namespace.
    /// Inherited policies (from parent clusters) are loaded first, then local policies.
    pub async fn from_crds(client: &Client) -> Result<Self> {
        let policy_set = Self::load_policies_from_crds(client).await?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            cluster_attrs: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create policy engine with explicit policies (for testing)
    pub fn with_policies(policy_text: &str) -> Result<Self> {
        let policy_set: PolicySet =
            policy_text
                .parse()
                .map_err(|e: cedar_policy::ParseErrors| {
                    Error::Config(format!("Invalid Cedar policy: {}", e))
                })?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            cluster_attrs: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Update the list of known clusters and their attributes
    ///
    /// Called when the subtree registry changes.
    pub async fn set_clusters(&self, clusters: HashMap<String, ClusterAttributes>) {
        let mut attrs = self.cluster_attrs.write().await;
        *attrs = clusters;
    }

    /// Update the list of known clusters (simple version)
    ///
    /// Uses default attributes for all clusters.
    pub async fn set_known_clusters(&self, cluster_names: Vec<String>) {
        let clusters: HashMap<String, ClusterAttributes> = cluster_names
            .into_iter()
            .map(|name| (name, ClusterAttributes::default()))
            .collect();
        self.set_clusters(clusters).await;
    }

    /// Check if a user is authorized to access a cluster
    ///
    /// Uses AccessCluster action and an empty context.
    #[instrument(
        skip(self, identity),
        fields(
            user = %identity.username,
            otel.kind = "internal"
        )
    )]
    pub async fn authorize(&self, identity: &UserIdentity, cluster: &str) -> Result<()> {
        self.authorize_with_context(identity, cluster, Context::empty())
            .await
    }

    /// Check if a user is authorized to access a cluster with context
    ///
    /// # Arguments
    /// * `identity` - The authenticated user
    /// * `cluster` - The target cluster name
    /// * `context` - Cedar context with temporal and request metadata
    ///
    /// # Returns
    /// Ok(()) if authorized, Err(Forbidden) otherwise
    pub async fn authorize_with_context(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        context: Context,
    ) -> Result<()> {
        let policy_set = self.policy_set.read().await;
        let cluster_attrs = self.cluster_attrs.read().await;

        let attrs = cluster_attrs.get(cluster).cloned().unwrap_or_default();

        self.evaluate_authorization(identity, cluster, &attrs, context, &policy_set)
    }

    /// Evaluate authorization with a specific policy set and cluster attributes
    fn evaluate_authorization(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        attrs: &ClusterAttributes,
        context: Context,
        policy_set: &PolicySet,
    ) -> Result<()> {
        // Build Cedar entities
        let principal = build_user_uid(&identity.username)?;
        let action_uid = build_action_uid("AccessCluster")?;
        let resource = build_cluster_uid(cluster)?;
        let entities = build_entities(identity, cluster, attrs)?;

        // Create Cedar request
        let request = Request::new(
            principal.clone(),
            action_uid.clone(),
            resource.clone(),
            context,
            None, // No schema validation
        )
        .map_err(|e| Error::Internal(format!("Failed to build Cedar request: {}", e)))?;

        // Evaluate
        let response = self
            .authorizer
            .is_authorized(&request, policy_set, &entities);

        debug!(
            principal = %principal,
            action = %action_uid,
            resource = %resource,
            decision = ?response.decision(),
            "Cedar authorization result"
        );

        match response.decision() {
            Decision::Allow => {
                lattice_common::metrics::record_cedar_decision(
                    lattice_common::metrics::AuthDecision::Allow,
                    "AccessCluster",
                );
                Ok(())
            }
            Decision::Deny => {
                lattice_common::metrics::record_cedar_decision(
                    lattice_common::metrics::AuthDecision::Deny,
                    "AccessCluster",
                );
                Err(Error::Forbidden(format!(
                    "Access denied: user '{}' cannot access cluster '{}'",
                    identity.username, cluster
                )))
            }
        }
    }

    /// Get list of clusters the user can access
    ///
    /// Uses empty context for checking accessible clusters.
    pub async fn accessible_clusters(&self, identity: &UserIdentity) -> Vec<String> {
        self.accessible_clusters_with_context(identity, Context::empty())
            .await
    }

    /// Get list of clusters the user can access with context
    pub async fn accessible_clusters_with_context(
        &self,
        identity: &UserIdentity,
        context: Context,
    ) -> Vec<String> {
        let cluster_attrs = self.cluster_attrs.read().await;
        let policy_set = self.policy_set.read().await;

        cluster_attrs
            .iter()
            .filter(|(cluster, attrs)| {
                // Must clone context for each evaluation since Cedar consumes it
                let ctx = context.clone();
                self.evaluate_authorization(identity, cluster, attrs, ctx, &policy_set)
                    .is_ok()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Check if any policies are loaded
    pub async fn has_policies(&self) -> bool {
        let policy_set = self.policy_set.read().await;
        let has_any = policy_set.policies().next().is_some();
        has_any
    }

    /// Reload policies from CRDs
    pub async fn reload(&self, client: &Client) -> Result<()> {
        let new_policy_set = Self::load_policies_from_crds(client).await?;

        let mut policy_set = self.policy_set.write().await;
        *policy_set = new_policy_set;

        info!("Reloaded Cedar policies");
        Ok(())
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Load policies from CRDs, respecting inheritance order
    async fn load_policies_from_crds(client: &Client) -> Result<PolicySet> {
        let api: Api<CedarPolicy> = Api::namespaced(client.clone(), "lattice-system");

        // Fetch inherited policies (from parent clusters)
        let inherited_lp = ListParams::default().labels(&format!("{}=true", INHERITED_LABEL));
        let inherited_policies: Vec<CedarPolicy> = api
            .list(&inherited_lp)
            .await
            .map(|list| list.items)
            .unwrap_or_default();

        // Fetch local policies (not inherited)
        let all_policies = api.list(&Default::default()).await?;
        let local_policies: Vec<_> = all_policies
            .items
            .into_iter()
            .filter(|p| is_local_resource(&p.metadata))
            .collect();

        let mut policy_set = PolicySet::new();
        let mut inherited_count = 0;
        let mut local_count = 0;
        let mut error_count = 0;

        // Load inherited policies first (parent's word is law)
        let mut sorted_inherited = inherited_policies;
        sorted_inherited.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_inherited {
            let (loaded, errors) = Self::add_policy_to_set(&mut policy_set, &crd);
            inherited_count += loaded;
            error_count += errors;
        }

        // Load local policies second
        let mut sorted_local = local_policies;
        sorted_local.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_local {
            let (loaded, errors) = Self::add_policy_to_set(&mut policy_set, &crd);
            local_count += loaded;
            error_count += errors;
        }

        info!(
            inherited = inherited_count,
            local = local_count,
            errors = error_count,
            "Loaded Cedar policies from CRDs"
        );

        Ok(policy_set)
    }

    /// Add policies from a CedarPolicy CRD to the policy set
    ///
    /// Returns (loaded_count, error_count)
    fn add_policy_to_set(policy_set: &mut PolicySet, crd: &CedarPolicy) -> (usize, usize) {
        if !crd.spec.enabled {
            debug!(
                name = ?crd.metadata.name,
                "Skipping disabled CedarPolicy"
            );
            return (0, 0);
        }

        let mut loaded = 0;
        let mut errors = 0;

        match crd.spec.policies.parse::<PolicySet>() {
            Ok(parsed) => {
                for policy in parsed.policies() {
                    if let Err(e) = policy_set.add(policy.clone()) {
                        warn!(
                            name = ?crd.metadata.name,
                            error = %e,
                            "Failed to add policy (duplicate ID?)"
                        );
                        errors += 1;
                    } else {
                        loaded += 1;
                    }
                }
            }
            Err(e) => {
                warn!(
                    name = ?crd.metadata.name,
                    error = %e,
                    "Failed to parse CedarPolicy"
                );
                errors += 1;
            }
        }

        (loaded, errors)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Entity Building
// ============================================================================

/// Build an entity UID for a given type and ID
fn build_entity_uid(type_name: &str, id: &str) -> Result<EntityUid> {
    let full_type_name = format!("{}::{}", NAMESPACE, type_name);
    let entity_type: EntityTypeName =
        full_type_name
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| {
                Error::Internal(format!(
                    "Invalid Cedar entity type name '{}': {}",
                    full_type_name, e
                ))
            })?;
    let entity_id = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(entity_type, entity_id))
}

fn build_user_uid(username: &str) -> Result<EntityUid> {
    build_entity_uid("User", username)
}

fn build_group_uid(group: &str) -> Result<EntityUid> {
    build_entity_uid("Group", group)
}

fn build_action_uid(action: &str) -> Result<EntityUid> {
    build_entity_uid("Action", action)
}

fn build_cluster_uid(cluster: &str) -> Result<EntityUid> {
    build_entity_uid("Cluster", cluster)
}

/// Build the entities set for authorization
///
/// Creates entities for the user, their groups, and the cluster with attributes.
fn build_entities(
    identity: &UserIdentity,
    cluster: &str,
    attrs: &ClusterAttributes,
) -> Result<Entities> {
    let mut entities = Vec::new();

    // Create group entities
    let mut group_uids = Vec::new();
    for group in &identity.groups {
        group_uids.push(build_group_uid(group)?);
    }

    for group_uid in &group_uids {
        let group_entity = Entity::new(group_uid.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| Error::Internal(format!("Failed to create group entity: {}", e)))?;
        entities.push(group_entity);
    }

    // Create user entity with group membership
    let user_uid = build_user_uid(&identity.username)?;
    let user_entity = Entity::new(
        user_uid,
        HashMap::new(),
        group_uids.into_iter().collect::<HashSet<_>>(),
    )
    .map_err(|e| Error::Internal(format!("Failed to create user entity: {}", e)))?;
    entities.push(user_entity);

    // Create cluster entity with attributes
    let cluster_uid = build_cluster_uid(cluster)?;
    let cluster_entity = build_cluster_entity(cluster_uid, attrs)?;
    entities.push(cluster_entity);

    Entities::from_entities(entities, None)
        .map_err(|e| Error::Internal(format!("Failed to create entities set: {}", e)))
}

/// Build a cluster entity with attributes
fn build_cluster_entity(uid: EntityUid, attrs: &ClusterAttributes) -> Result<Entity> {
    let mut attr_map = HashMap::new();

    // Environment is only added if present (fail-closed via policy pattern)
    if let Some(ref env) = attrs.environment {
        attr_map.insert(
            "environment".to_string(),
            RestrictedExpression::new_string(env.clone()),
        );
    }

    // Region and tier always have values (with defaults)
    attr_map.insert(
        "region".to_string(),
        RestrictedExpression::new_string(attrs.region.clone()),
    );
    attr_map.insert(
        "tier".to_string(),
        RestrictedExpression::new_string(attrs.tier.clone()),
    );

    Entity::new(uid, attr_map, HashSet::new())
        .map_err(|e| Error::Internal(format!("Failed to create cluster entity: {}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Entity Building Tests
    // ========================================================================

    #[test]
    fn test_build_user_uid() {
        let uid = build_user_uid("alice@example.com").unwrap();
        assert!(uid.to_string().contains("User"));
        assert!(uid.to_string().contains("alice@example.com"));
    }

    #[test]
    fn test_build_group_uid() {
        let uid = build_group_uid("admins").unwrap();
        assert!(uid.to_string().contains("Group"));
        assert!(uid.to_string().contains("admins"));
    }

    #[test]
    fn test_build_action_uid() {
        let uid = build_action_uid("AccessCluster").unwrap();
        assert!(uid.to_string().contains("Action"));
        assert!(uid.to_string().contains("AccessCluster"));
    }

    #[test]
    fn test_build_cluster_uid() {
        let uid = build_cluster_uid("prod-frontend").unwrap();
        assert!(uid.to_string().contains("Cluster"));
        assert!(uid.to_string().contains("prod-frontend"));
    }

    // ========================================================================
    // ClusterAttributes Tests
    // ========================================================================

    #[test]
    fn test_cluster_attributes_from_labels_all_present() {
        let mut labels = HashMap::new();
        labels.insert(ENVIRONMENT_LABEL.to_string(), "prod".to_string());
        labels.insert(REGION_LABEL.to_string(), "us-west-2".to_string());
        labels.insert(TIER_LABEL.to_string(), "premium".to_string());

        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, Some("prod".to_string()));
        assert_eq!(attrs.region, "us-west-2");
        assert_eq!(attrs.tier, "premium");
    }

    #[test]
    fn test_cluster_attributes_from_labels_defaults() {
        let labels = HashMap::new();
        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, None);
        assert_eq!(attrs.region, DEFAULT_REGION);
        assert_eq!(attrs.tier, DEFAULT_TIER);
    }

    #[test]
    fn test_cluster_attributes_from_labels_partial() {
        let mut labels = HashMap::new();
        labels.insert(ENVIRONMENT_LABEL.to_string(), "staging".to_string());

        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, Some("staging".to_string()));
        assert_eq!(attrs.region, DEFAULT_REGION);
        assert_eq!(attrs.tier, DEFAULT_TIER);
    }

    // ========================================================================
    // Entities Building Tests
    // ========================================================================

    #[test]
    fn test_build_entities_with_groups() {
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec!["admins".to_string(), "developers".to_string()],
        };

        let attrs = ClusterAttributes {
            environment: Some("prod".to_string()),
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        let entities = build_entities(&identity, "prod-cluster", &attrs).unwrap();
        // Should have: 1 user + 2 groups + 1 cluster = 4 entities
        assert_eq!(entities.iter().count(), 4);
    }

    #[test]
    fn test_build_entities_no_groups() {
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let attrs = ClusterAttributes::default();
        let entities = build_entities(&identity, "test-cluster", &attrs).unwrap();
        // Should have: 1 user + 0 groups + 1 cluster = 2 entities
        assert_eq!(entities.iter().count(), 2);
    }

    // ========================================================================
    // Policy Engine Basic Tests
    // ========================================================================

    #[test]
    fn test_policy_engine_creation() {
        let _engine = PolicyEngine::new();
    }

    #[tokio::test]
    async fn test_permit_all_policy() {
        let policy = r#"
            permit(principal, action, resource);
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        // Add the cluster to known clusters
        let mut clusters = HashMap::new();
        clusters.insert("any-cluster".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deny_by_default() {
        let engine = PolicyEngine::new();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_specific_policy() {
        let policy = r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod-frontend"
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod-frontend".to_string(), ClusterAttributes::default());
        clusters.insert("staging".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let alice = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };
        assert!(engine.authorize(&alice, "prod-frontend").await.is_ok());

        // Alice cannot access other clusters
        assert!(engine.authorize(&alice, "staging").await.is_err());

        // Bob cannot access prod-frontend
        let bob = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec![],
        };
        assert!(engine.authorize(&bob, "prod-frontend").await.is_err());
    }

    #[tokio::test]
    async fn test_group_policy() {
        let policy = r#"
            permit(
                principal in Lattice::Group::"admins",
                action == Lattice::Action::"AccessCluster",
                resource
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("any-cluster".to_string(), ClusterAttributes::default());
        clusters.insert("another-cluster".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        // Admin can access any cluster
        let admin = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec!["admins".to_string()],
        };
        assert!(engine.authorize(&admin, "any-cluster").await.is_ok());
        assert!(engine.authorize(&admin, "another-cluster").await.is_ok());

        // Non-admin cannot access
        let user = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };
        assert!(engine.authorize(&user, "any-cluster").await.is_err());
    }

    #[tokio::test]
    async fn test_accessible_clusters() {
        let policy = r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod-frontend"
            );
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"staging-frontend"
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod-frontend".to_string(), ClusterAttributes::default());
        clusters.insert("staging-frontend".to_string(), ClusterAttributes::default());
        clusters.insert("prod-backend".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let alice = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let accessible = engine.accessible_clusters(&alice).await;
        assert_eq!(accessible.len(), 2);
        assert!(accessible.contains(&"prod-frontend".to_string()));
        assert!(accessible.contains(&"staging-frontend".to_string()));
        assert!(!accessible.contains(&"prod-backend".to_string()));
    }

    #[tokio::test]
    async fn test_has_policies() {
        let empty_engine = PolicyEngine::new();
        assert!(!empty_engine.has_policies().await);

        let policy = "permit(principal, action, resource);";
        let engine = PolicyEngine::with_policies(policy).unwrap();
        assert!(engine.has_policies().await);
    }

    // ========================================================================
    // Environment-Based Policy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_environment_based_policy_allows_matching() {
        // Policy: allow developers access to non-prod clusters
        let policy = r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert(
            "staging".to_string(),
            ClusterAttributes {
                environment: Some("staging".to_string()),
                region: "us-west-2".to_string(),
                tier: "standard".to_string(),
            },
        );
        engine.set_clusters(clusters).await;

        let developer = UserIdentity {
            username: "dev@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };

        let result = engine.authorize(&developer, "staging").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_environment_based_policy_denies_prod() {
        // Policy: allow developers access to non-prod clusters
        let policy = r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert(
            "production".to_string(),
            ClusterAttributes {
                environment: Some("prod".to_string()),
                region: "us-west-2".to_string(),
                tier: "premium".to_string(),
            },
        );
        engine.set_clusters(clusters).await;

        let developer = UserIdentity {
            username: "dev@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };

        let result = engine.authorize(&developer, "production").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_missing_environment_label_denied() {
        // Policy requires environment attribute - cluster without it should be denied
        let policy = r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert(
            "unlabeled".to_string(),
            ClusterAttributes {
                environment: None, // No environment label
                region: "us-west-2".to_string(),
                tier: "standard".to_string(),
            },
        );
        engine.set_clusters(clusters).await;

        let developer = UserIdentity {
            username: "dev@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };

        let result = engine.authorize(&developer, "unlabeled").await;
        assert!(result.is_err());
    }

    // ========================================================================
    // Forbid Policy Tests (Deny Precedence)
    // ========================================================================

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let policy = r#"
            // Allow all admins
            permit(
                principal in Lattice::Group::"admins",
                action == Lattice::Action::"AccessCluster",
                resource
            );

            // But deny specific user
            forbid(
                principal == Lattice::User::"contractor@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod"
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        // Regular admin allowed
        let admin = UserIdentity {
            username: "admin@example.com".to_string(),
            groups: vec!["admins".to_string()],
        };
        assert!(engine.authorize(&admin, "prod").await.is_ok());

        // Contractor denied even though they're in admins group
        let contractor = UserIdentity {
            username: "contractor@example.com".to_string(),
            groups: vec!["admins".to_string()],
        };
        assert!(engine.authorize(&contractor, "prod").await.is_err());
    }

    // ========================================================================
    // Context-Based Policy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_time_based_policy_allows_within_hours() {
        // Policy: allow access during business hours (9-18)
        let policy = r#"
            permit(
                principal in Lattice::Group::"support",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.hour >= 9 && context.hour < 18
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let user = UserIdentity {
            username: "support@example.com".to_string(),
            groups: vec!["support".to_string()],
        };

        // Create context with hour=10 (within business hours)
        let context = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(10),
        )])
        .unwrap();

        let result = engine.authorize_with_context(&user, "prod", context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_time_based_policy_denies_outside_hours() {
        // Policy: allow access during business hours (9-18)
        let policy = r#"
            permit(
                principal in Lattice::Group::"support",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.hour >= 9 && context.hour < 18
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let user = UserIdentity {
            username: "support@example.com".to_string(),
            groups: vec!["support".to_string()],
        };

        // Create context with hour=22 (outside business hours)
        let context = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(22),
        )])
        .unwrap();

        let result = engine.authorize_with_context(&user, "prod", context).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_break_glass_policy() {
        // Policy: allow oncall users with break-glass flag and incident ID
        let policy = r#"
            permit(
                principal in Lattice::Group::"oncall",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.breakGlass == true &&
                context has incidentId
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let oncall_user = UserIdentity {
            username: "oncall@example.com".to_string(),
            groups: vec!["oncall".to_string()],
        };

        // With break-glass and incident ID - allowed
        let context_allowed = Context::from_pairs(vec![
            (
                "breakGlass".to_string(),
                RestrictedExpression::new_bool(true),
            ),
            (
                "incidentId".to_string(),
                RestrictedExpression::new_string("INC-12345".to_string()),
            ),
        ])
        .unwrap();

        assert!(engine
            .authorize_with_context(&oncall_user, "prod", context_allowed)
            .await
            .is_ok());

        // Without incident ID - denied
        let context_no_incident = Context::from_pairs(vec![(
            "breakGlass".to_string(),
            RestrictedExpression::new_bool(true),
        )])
        .unwrap();

        assert!(engine
            .authorize_with_context(&oncall_user, "prod", context_no_incident)
            .await
            .is_err());

        // Without break-glass flag - denied
        let context_no_flag = Context::from_pairs(vec![
            (
                "breakGlass".to_string(),
                RestrictedExpression::new_bool(false),
            ),
            (
                "incidentId".to_string(),
                RestrictedExpression::new_string("INC-12345".to_string()),
            ),
        ])
        .unwrap();

        assert!(engine
            .authorize_with_context(&oncall_user, "prod", context_no_flag)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_source_ip_policy() {
        // Policy: allow access only from VPN (10.0.x.x)
        let policy = r#"
            permit(
                principal in Lattice::Group::"engineers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.sourceIp like "10.0.*"
            };
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod".to_string(), ClusterAttributes::default());
        engine.set_clusters(clusters).await;

        let engineer = UserIdentity {
            username: "eng@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        };

        // From VPN - allowed
        let context_vpn = Context::from_pairs(vec![(
            "sourceIp".to_string(),
            RestrictedExpression::new_string("10.0.1.100".to_string()),
        )])
        .unwrap();

        assert!(engine
            .authorize_with_context(&engineer, "prod", context_vpn)
            .await
            .is_ok());

        // From outside - denied
        let context_outside = Context::from_pairs(vec![(
            "sourceIp".to_string(),
            RestrictedExpression::new_string("8.8.8.8".to_string()),
        )])
        .unwrap();

        assert!(engine
            .authorize_with_context(&engineer, "prod", context_outside)
            .await
            .is_err());
    }
}
