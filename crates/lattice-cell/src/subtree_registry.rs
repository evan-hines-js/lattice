//! Subtree Registry - Tracks clusters in this cell's subtree
//!
//! Each cluster maintains awareness of its subtree (all descendants). This enables:
//! - **Routing**: Knowing which agent connection routes to which cluster
//! - **Kubeconfig**: Generating configs with all accessible clusters
//! - **Authorization**: Cedar policies can reference cluster hierarchy
//!
//! State bubbles up from children → parents:
//! - On connect: Agent sends full subtree state
//! - On change: Agent sends delta (add/remove)
//! - Parent aggregates and bubbles up to its own parent
//!
//! Service routes are NOT stored here — they go directly to the
//! `LatticeClusterRoutes` CRD which is the sole source of truth.
//!
//! Uses DashMap for lock-free concurrent reads/writes.

use std::collections::HashMap;

use dashmap::DashMap;

/// Information about a cluster in the subtree
#[derive(Clone, Debug, PartialEq)]
pub struct ClusterInfo {
    /// Cluster name (unique identifier)
    pub name: String,
    /// Immediate parent cluster name
    pub parent: String,
    /// Current phase (Pending, Provisioning, Ready, etc.)
    pub phase: String,
    /// Labels for policy matching
    pub labels: HashMap<String, String>,
}

/// Route information for reaching a cluster
#[derive(Clone, Debug)]
pub struct RouteInfo {
    /// Agent ID to route through (None if this is self)
    pub agent_id: Option<String>,
    /// Whether this cluster is the current cell itself
    pub is_self: bool,
    /// Whether the agent is currently connected (false = temporarily unavailable)
    pub connected: bool,
    /// Cluster info
    pub cluster: ClusterInfo,
}

/// Registry of all clusters in this cell's subtree
///
/// Lock-free via DashMap. Can be queried by the auth proxy
/// to determine routing and by kubeconfig endpoint to list clusters.
#[derive(Clone)]
pub struct SubtreeRegistry {
    /// Our own cluster name
    cluster_name: String,
    /// Map of cluster name → route info
    routes: DashMap<String, RouteInfo>,
}

impl SubtreeRegistry {
    /// Create a new subtree registry
    pub fn new(cluster_name: String) -> Self {
        let routes = DashMap::new();
        routes.insert(
            cluster_name.clone(),
            RouteInfo {
                agent_id: None,
                is_self: true,
                connected: true,
                cluster: ClusterInfo {
                    name: cluster_name.clone(),
                    parent: String::new(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                },
            },
        );

        Self {
            cluster_name,
            routes,
        }
    }

    /// Get this cell's cluster name
    pub fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Get route info for a cluster
    pub async fn get_route(&self, cluster_name: &str) -> Option<RouteInfo> {
        self.routes.get(cluster_name).map(|r| r.clone())
    }

    /// Get all clusters with their labels
    pub async fn all_clusters(&self) -> Vec<(String, HashMap<String, String>)> {
        self.routes
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().cluster.labels.clone()))
            .collect()
    }

    /// Get all clusters accessible via a specific agent
    pub async fn clusters_via_agent(&self, agent_id: &str) -> Vec<String> {
        self.routes
            .iter()
            .filter(|entry| entry.value().agent_id.as_deref() == Some(agent_id))
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Handle full subtree state from an agent (replaces previous state)
    ///
    /// # Security
    /// Rejects attempts to overwrite the self route or routes owned by other
    /// connected agents.
    pub async fn handle_full_sync(&self, agent_id: &str, clusters: Vec<ClusterInfo>) {
        // Remove all clusters previously routed via this agent
        self.routes
            .retain(|_, info| info.agent_id.as_deref() != Some(agent_id));

        // Add new clusters with security guards
        for cluster in clusters {
            self.try_insert_route(agent_id, cluster);
        }
    }

    /// Handle incremental subtree update from an agent
    ///
    /// # Security
    /// Only inserts routes owned by `agent_id`. Rejects attempts to overwrite
    /// routes owned by other agents or the self route.
    pub async fn handle_delta(
        &self,
        agent_id: &str,
        added: Vec<ClusterInfo>,
        removed: Vec<String>,
    ) {
        // Remove clusters — only if routed via this agent
        for name in removed {
            self.routes.remove_if(&name, |_, info| {
                info.agent_id.as_deref() == Some(agent_id)
            });
        }

        // Add clusters with security guards
        for cluster in added {
            self.try_insert_route(agent_id, cluster);
        }
    }

    /// Try to insert a route with security guards.
    ///
    /// Rejects self-route hijacking and cross-agent route hijacking.
    fn try_insert_route(&self, agent_id: &str, cluster: ClusterInfo) {
        let cluster_name = &cluster.name;

        // Reject attempts to overwrite the self route
        if *cluster_name == self.cluster_name {
            tracing::warn!(
                agent_id = %agent_id,
                cluster = %cluster_name,
                "Agent attempted to register a route for the cell itself — rejected"
            );
            return;
        }

        // Reject attempts to overwrite routes owned by other agents
        if let Some(existing) = self.routes.get(cluster_name) {
            if let Some(ref existing_agent) = existing.agent_id {
                if existing_agent != agent_id {
                    if existing.connected {
                        tracing::warn!(
                            agent_id = %agent_id,
                            existing_agent = %existing_agent,
                            cluster = %cluster_name,
                            "Agent attempted to hijack route owned by another agent — rejected"
                        );
                        return;
                    }
                    if cluster.parent != existing.cluster.parent {
                        tracing::warn!(
                            agent_id = %agent_id,
                            existing_agent = %existing_agent,
                            cluster = %cluster_name,
                            "Agent attempted to take over disconnected route with mismatched parent — rejected"
                        );
                        return;
                    }
                }
            }
        }

        self.routes.insert(
            cluster_name.clone(),
            RouteInfo {
                agent_id: Some(agent_id.to_string()),
                is_self: false,
                connected: true,
                cluster,
            },
        );
    }

    /// Handle agent disconnect - mark clusters as disconnected (not removed)
    pub async fn handle_agent_disconnect(&self, agent_id: &str) {
        for mut entry in self.routes.iter_mut() {
            if entry.value().agent_id.as_deref() == Some(agent_id) {
                entry.value_mut().connected = false;
            }
        }
    }

    /// Handle agent reconnect - mark clusters as connected
    pub async fn handle_agent_reconnect(&self, agent_id: &str) {
        for mut entry in self.routes.iter_mut() {
            if entry.value().agent_id.as_deref() == Some(agent_id) {
                entry.value_mut().connected = true;
            }
        }
    }

    /// Check if a cluster is currently connected
    pub async fn is_connected(&self, cluster_name: &str) -> bool {
        self.routes
            .get(cluster_name)
            .map(|r| r.connected)
            .unwrap_or(false)
    }

    /// Get count of clusters in subtree
    pub async fn cluster_count(&self) -> usize {
        self.routes.len()
    }

    /// Check if a cluster is in the subtree
    pub async fn contains(&self, cluster_name: &str) -> bool {
        self.routes.contains_key(cluster_name)
    }

    /// Get clusters by parent
    pub async fn children_of(&self, parent_name: &str) -> Vec<String> {
        self.routes
            .iter()
            .filter(|entry| entry.value().cluster.parent == parent_name)
            .map(|entry| entry.key().clone())
            .collect()
    }
}

impl std::fmt::Debug for SubtreeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeRegistry")
            .field("cluster_name", &self.cluster_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_registry_contains_self() {
        let registry = SubtreeRegistry::new("my-cluster".to_string());

        assert_eq!(registry.cluster_name(), "my-cluster");
        assert!(registry.contains("my-cluster").await);

        let route = registry.get_route("my-cluster").await.unwrap();
        assert!(route.is_self);
        assert!(route.agent_id.is_none());
    }

    #[tokio::test]
    async fn test_full_sync() {
        let registry = SubtreeRegistry::new("parent".to_string());

        let clusters = vec![
            ClusterInfo {
                name: "child-1".to_string(),
                parent: "parent".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
            ClusterInfo {
                name: "grandchild-1".to_string(),
                parent: "child-1".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
        ];

        registry.handle_full_sync("agent-1", clusters).await;

        assert_eq!(registry.cluster_count().await, 3);
        assert!(registry.contains("child-1").await);
        assert!(registry.contains("grandchild-1").await);

        let route = registry.get_route("child-1").await.unwrap();
        assert!(!route.is_self);
        assert_eq!(route.agent_id, Some("agent-1".to_string()));
    }

    #[tokio::test]
    async fn test_full_sync_replaces_previous() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "old-cluster".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;
        assert!(registry.contains("old-cluster").await);

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "new-cluster".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;

        assert!(!registry.contains("old-cluster").await);
        assert!(registry.contains("new-cluster").await);
    }

    #[tokio::test]
    async fn test_delta_add_remove() {
        let registry = SubtreeRegistry::new("parent".to_string());

        let added = vec![ClusterInfo {
            name: "cluster-1".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry.handle_delta("agent-1", added, vec![]).await;
        assert!(registry.contains("cluster-1").await);

        let added2 = vec![ClusterInfo {
            name: "cluster-2".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry
            .handle_delta("agent-1", added2, vec!["cluster-1".to_string()])
            .await;

        assert!(!registry.contains("cluster-1").await);
        assert!(registry.contains("cluster-2").await);
    }

    #[tokio::test]
    async fn test_rejects_self_route_hijack() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_delta(
                "agent-1",
                vec![ClusterInfo {
                    name: "parent".to_string(),
                    parent: "".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
                vec![],
            )
            .await;

        let route = registry.get_route("parent").await.unwrap();
        assert!(route.is_self);
        assert!(route.agent_id.is_none());
    }

    #[tokio::test]
    async fn test_rejects_cross_agent_hijack() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;

        registry
            .handle_delta(
                "agent-2",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
                vec![],
            )
            .await;

        let route = registry.get_route("child-1").await.unwrap();
        assert_eq!(route.agent_id, Some("agent-1".to_string()));
    }

    #[tokio::test]
    async fn test_allows_takeover_of_disconnected_route() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;
        registry.handle_agent_disconnect("agent-1").await;

        registry
            .handle_delta(
                "agent-2",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
                vec![],
            )
            .await;

        let route = registry.get_route("child-1").await.unwrap();
        assert_eq!(route.agent_id, Some("agent-2".to_string()));
        assert!(route.connected);
    }

    #[tokio::test]
    async fn test_disconnect_marks_unavailable() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;

        assert!(registry.is_connected("child-1").await);
        registry.handle_agent_disconnect("agent-1").await;
        assert!(!registry.is_connected("child-1").await);
        assert!(registry.contains("child-1").await); // still in registry
    }

    #[tokio::test]
    async fn test_reconnect_restores_connected() {
        let registry = SubtreeRegistry::new("parent".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![ClusterInfo {
                    name: "child-1".to_string(),
                    parent: "parent".to_string(),
                    phase: "Ready".to_string(),
                    labels: HashMap::new(),
                }],
            )
            .await;

        registry.handle_agent_disconnect("agent-1").await;
        assert!(!registry.is_connected("child-1").await);

        registry.handle_agent_reconnect("agent-1").await;
        assert!(registry.is_connected("child-1").await);
    }

    #[tokio::test]
    async fn test_children_of() {
        let registry = SubtreeRegistry::new("root".to_string());

        registry
            .handle_full_sync(
                "agent-1",
                vec![
                    ClusterInfo {
                        name: "child-1".to_string(),
                        parent: "root".to_string(),
                        phase: "Ready".to_string(),
                        labels: HashMap::new(),
                    },
                    ClusterInfo {
                        name: "grandchild-1".to_string(),
                        parent: "child-1".to_string(),
                        phase: "Ready".to_string(),
                        labels: HashMap::new(),
                    },
                ],
            )
            .await;

        let root_children = registry.children_of("root").await;
        assert_eq!(root_children.len(), 1);
        assert!(root_children.contains(&"child-1".to_string()));

        let child1_children = registry.children_of("child-1").await;
        assert_eq!(child1_children.len(), 1);
        assert!(child1_children.contains(&"grandchild-1".to_string()));
    }
}
