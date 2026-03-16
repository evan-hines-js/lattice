//! Peer route synchronization — pushes sibling/parent routes to children
//!
//! On each heartbeat, the parent compares the child's reported peer routes hash
//! with the expected hash. On mismatch, sends a full PeerRouteSync with all
//! routes the child doesn't own (parent + siblings).

use kube::Client;
use lattice_common::crd::ClusterRoute;
use lattice_common::kube_utils::{request_istiod_proxy_token, sha256};
use tracing::{debug, error, info, warn};

use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, PeerRouteSync, SubtreeService};

use crate::SharedAgentRegistry;

/// Convert ClusterRoutes to SubtreeService proto messages, tagging each with cluster name.
fn routes_to_proto(routes: &[ClusterRoute], cluster_name: &str) -> Vec<SubtreeService> {
    routes
        .iter()
        .map(|r| SubtreeService {
            name: r.service_name.clone(),
            namespace: r.service_namespace.clone(),
            cluster: cluster_name.to_string(),
            removed: false,
            hostname: r.hostname.clone(),
            address: r.address.clone(),
            port: r.port as u32,
            protocol: r.protocol.clone(),
            labels: Default::default(),
            allowed_services: r.allowed_services.clone(),
        })
        .collect()
}

/// Filter routes to exclude a specific cluster's own routes.
fn peer_routes_for(all: &[SubtreeService], exclude: &str) -> Vec<SubtreeService> {
    all.iter()
        .filter(|r| r.cluster != exclude && !r.removed)
        .cloned()
        .collect()
}

/// Compute the content hash for a set of peer routes.
///
/// Groups by cluster, sorts within each cluster by (namespace, name),
/// then hashes the sorted structure. Must match the agent-side hash.
fn hash_peer_routes(routes: &[SubtreeService]) -> Vec<u8> {
    use std::collections::BTreeMap;

    let mut by_cluster: BTreeMap<String, Vec<&SubtreeService>> = BTreeMap::new();
    for svc in routes {
        by_cluster.entry(svc.cluster.clone()).or_default().push(svc);
    }

    let mut per_cluster: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (cluster, mut svcs) in by_cluster {
        svcs.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
        let mut buf = Vec::new();
        for s in svcs {
            buf.extend_from_slice(s.name.as_bytes());
            buf.extend_from_slice(s.namespace.as_bytes());
            buf.extend_from_slice(s.hostname.as_bytes());
            buf.extend_from_slice(s.address.as_bytes());
            buf.extend_from_slice(&(s.port as u16).to_le_bytes());
            buf.extend_from_slice(s.protocol.as_bytes());
        }
        per_cluster.insert(cluster, sha256(&buf));
    }

    let mut outer = Vec::new();
    for (name, h) in &per_cluster {
        outer.extend_from_slice(name.as_bytes());
        outer.extend_from_slice(h);
    }
    sha256(&outer)
}

/// Check if a child's peer routes are stale and send a full sync if needed.
///
/// Called on every heartbeat. Reads the combined route state from the watch
/// channel, computes the expected hash for this child, and sends a PeerRouteSync
/// if the child's reported hash doesn't match.
pub async fn check_and_sync_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    child_hash: &[u8],
    peer_config: &crate::server::PeerRouteConfig,
    client: &Client,
) {
    // Read combined route state (local + children) from watch channel
    let all_cluster_routes = peer_config.all_routes.borrow().clone();
    let all_proto = routes_to_proto(&all_cluster_routes, &peer_config.parent_cluster_name);
    let peers = peer_routes_for(&all_proto, child_cluster);

    let expected_hash = hash_peer_routes(&peers);
    if child_hash == expected_hash {
        return;
    }

    if peers.is_empty() {
        return;
    }

    info!(
        cluster = %child_cluster,
        "Peer routes hash mismatch, sending full sync"
    );

    let proxy_token = match request_istiod_proxy_token(client).await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "Failed to request proxy token for peer route sync");
            return;
        }
    };

    let sync = PeerRouteSync {
        proxy_url: peer_config.proxy_url.clone(),
        ca_cert_pem: peer_config.ca_cert_pem.clone(),
        proxy_token,
        peer_routes: peers,
        is_full_sync: true,
    };

    let cmd = CellCommand {
        command_id: format!("peer-routes-{}", child_cluster),
        command: Some(Command::PeerRouteSync(sync)),
    };

    if let Err(e) = registry.send_command(child_cluster, cmd).await {
        warn!(cluster = %child_cluster, error = %e, "Failed to send peer route sync");
    } else {
        debug!(cluster = %child_cluster, "Sent peer route sync");
    }
}
