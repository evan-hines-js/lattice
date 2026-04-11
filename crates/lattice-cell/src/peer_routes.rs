//! Peer route synchronization — pushes sibling/parent routes to children
//!
//! On each heartbeat, the parent compares the child's reported peer routes hash
//! with the expected hash. On mismatch, sends a full PeerRouteSync with all
//! routes the child doesn't own (parent + siblings).
//!
//! A `PeerRouteIndex` pre-computes per-cluster hashes and proto routes when the
//! route table changes. Per-heartbeat hash checks are O(clusters) instead of
//! O(routes). The index is rebuilt by the caller when the watch channel signals
//! a route table change.

use std::collections::BTreeMap;

use kube::Client;
use lattice_common::kube_utils::{request_proxy_token, sha256};
use tracing::{debug, error, info, warn};

use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, PeerRouteSync, SubtreeService};

use crate::route_reconciler::TaggedRoute;
use crate::SharedAgentRegistry;

// =============================================================================
// PeerRouteIndex
// =============================================================================

/// Pre-computed peer route data, rebuilt when the route table changes.
///
/// Stores per-cluster proto routes and hashes so that per-heartbeat
/// operations are O(clusters) instead of O(routes).
#[derive(Clone, Debug)]
pub struct PeerRouteIndex {
    /// Proto routes grouped by cluster, sorted within each cluster.
    by_cluster: BTreeMap<String, Vec<SubtreeService>>,
    /// Per-cluster content hash (SHA-256 of sorted routes).
    cluster_hashes: BTreeMap<String, Vec<u8>>,
}

impl PeerRouteIndex {
    /// Build an index from the current route table.
    pub fn build(tagged: &[TaggedRoute]) -> Self {
        let mut by_cluster: BTreeMap<String, Vec<SubtreeService>> = BTreeMap::new();
        for (cluster, r) in tagged {
            by_cluster
                .entry(cluster.clone())
                .or_default()
                .push(tagged_route_to_proto(cluster, r));
        }

        let mut cluster_hashes = BTreeMap::new();
        for (cluster, svcs) in &mut by_cluster {
            svcs.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            cluster_hashes.insert(cluster.clone(), hash_sorted_routes(svcs));
        }

        Self {
            by_cluster,
            cluster_hashes,
        }
    }

    /// Compute the expected hash for a child, excluding its own cluster's routes.
    /// O(clusters) — combines pre-computed per-cluster hashes.
    pub fn hash_excluding(&self, exclude_cluster: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for (name, h) in &self.cluster_hashes {
            if name != exclude_cluster {
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(h);
            }
        }
        if buf.is_empty() {
            return Vec::new();
        }
        sha256(&buf)
    }

    /// Get the peer routes for a child (everything except its own cluster).
    /// Only called on hash mismatch — the slow path that builds the PeerRouteSync payload.
    pub fn peer_routes_for(&self, exclude_cluster: &str) -> Vec<SubtreeService> {
        self.by_cluster
            .iter()
            .filter(|(cluster, _)| cluster.as_str() != exclude_cluster)
            .flat_map(|(_, svcs)| svcs.iter().cloned())
            .collect()
    }

    /// Whether the index has any routes from clusters other than the excluded one.
    pub fn has_peers(&self, exclude_cluster: &str) -> bool {
        self.by_cluster
            .keys()
            .any(|c| c.as_str() != exclude_cluster)
    }
}

// =============================================================================
// Hashing helpers
// =============================================================================

/// Convert a single tagged route to proto format.
fn tagged_route_to_proto(
    cluster: &str,
    r: &lattice_common::crd::ClusterRoute,
) -> SubtreeService {
    SubtreeService {
        name: r.service_name.clone(),
        namespace: r.service_namespace.clone(),
        cluster: cluster.to_string(),
        removed: false,
        hostname: r.hostname.clone(),
        address: r.address.clone(),
        port: r.port as u32,
        protocol: r.protocol.clone(),
        labels: Default::default(),
        allowed_services: r.allowed_services.clone(),
        service_ports: r
            .service_ports
            .iter()
            .map(|(k, &v)| (k.clone(), v as u32))
            .collect(),
    }
}

/// Hash a slice of proto routes that are already sorted by (namespace, name).
///
/// The byte layout must match the agent-side `hash_routes` in
/// `lattice-agent/src/commands/peer_routes.rs` — both serialize fields
/// in the same order with the same byte representations.
fn hash_sorted_routes(sorted_svcs: &[SubtreeService]) -> Vec<u8> {
    let mut buf = Vec::new();
    for s in sorted_svcs {
        buf.extend_from_slice(s.name.as_bytes());
        buf.extend_from_slice(s.namespace.as_bytes());
        buf.extend_from_slice(s.hostname.as_bytes());
        buf.extend_from_slice(s.address.as_bytes());
        buf.extend_from_slice(&(s.port as u16).to_le_bytes());
        buf.extend_from_slice(s.protocol.as_bytes());
        for allowed in &s.allowed_services {
            buf.extend_from_slice(allowed.as_bytes());
        }
        for (name, port) in &s.service_ports {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&(*port as u16).to_le_bytes());
        }
    }
    sha256(&buf)
}

// =============================================================================
// Heartbeat check
// =============================================================================

/// Max age before forcing a peer route resync for token refresh.
/// Set to 25 minutes — well under the 1-hour token lifetime.
const PEER_SYNC_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(25 * 60);

/// Check if a child's peer routes are stale and send a full sync if needed.
///
/// Called on every heartbeat with a pre-built index. Sends a PeerRouteSync if:
/// - The child's reported hash doesn't match the expected hash, OR
/// - The last sync was more than 25 minutes ago (token refresh)
pub async fn check_and_sync_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    child_hash: &[u8],
    index: &PeerRouteIndex,
    proxy_url: &str,
    ca_cert_pem: &str,
    client: &Client,
) {
    if !index.has_peers(child_cluster) {
        return;
    }

    let expected_hash = index.hash_excluding(child_cluster);
    let hash_matches = child_hash == expected_hash;
    let token_fresh = !registry.needs_peer_sync(child_cluster, PEER_SYNC_MAX_AGE);

    if hash_matches && token_fresh {
        return;
    }

    if !hash_matches {
        info!(cluster = %child_cluster, "Peer routes hash mismatch, sending full sync");
    } else {
        debug!(cluster = %child_cluster, "Refreshing peer proxy token");
    }

    let proxy_token = match request_proxy_token(client).await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "Failed to request proxy token for peer route sync");
            return;
        }
    };

    let sync = PeerRouteSync {
        proxy_url: proxy_url.to_string(),
        ca_cert_pem: ca_cert_pem.to_string(),
        proxy_token,
        peer_routes: index.peer_routes_for(child_cluster),
        is_full_sync: true,
    };

    let cmd = CellCommand {
        command_id: format!("peer-routes-{}", child_cluster),
        command: Some(Command::PeerRouteSync(sync)),
    };

    if let Err(e) = registry.send_command(child_cluster, cmd).await {
        warn!(cluster = %child_cluster, error = %e, "Failed to send peer route sync");
    } else {
        registry.mark_peer_sync(child_cluster);
        debug!(cluster = %child_cluster, "Sent peer route sync");
    }
}
