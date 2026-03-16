//! Peer route synchronization — pushes sibling routes to children
//!
//! When a child's routes change, the parent pushes all other children's routes
//! to it as a `PeerRouteSync` command. This enables sibling-to-sibling service
//! discovery: each child's istiod creates remote secrets pointing to the parent's
//! auth proxy, which tunnels K8s API requests to the target sibling via gRPC.

use kube::Client;
use lattice_common::kube_utils::sha256;
use tracing::{debug, error, info, warn};

use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, PeerRouteSync, SubtreeService};

use crate::SharedAgentRegistry;

/// Build peer routes for a specific child cluster.
///
/// Returns all routes from all clusters EXCEPT the specified child's own routes.
/// Includes the parent's routes and sibling routes — the child already knows
/// its own routes and only needs peers'.
pub fn peer_routes_for(
    all_routes: &[SubtreeService],
    exclude_cluster: &str,
) -> Vec<SubtreeService> {
    all_routes
        .iter()
        .filter(|r| r.cluster != exclude_cluster && !r.removed)
        .cloned()
        .collect()
}

use lattice_common::kube_utils::request_istiod_proxy_token;

/// Send a `PeerRouteSync` to a specific child with its peer routes.
pub async fn send_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    sibling_routes: Vec<SubtreeService>, // named sibling for the local variable, includes parent
    proxy_url: &str,
    ca_cert_pem: &str,
    proxy_token: &str,
    is_full_sync: bool,
) {
    let sync = PeerRouteSync {
        proxy_url: proxy_url.to_string(),
        ca_cert_pem: ca_cert_pem.to_string(),
        proxy_token: proxy_token.to_string(),
        peer_routes: sibling_routes,
        is_full_sync,
    };

    let cmd = CellCommand {
        command_id: format!("peer-routes-{}", child_cluster),
        command: Some(Command::PeerRouteSync(sync)),
    };

    if let Err(e) = registry.send_command(child_cluster, cmd).await {
        warn!(
            cluster = %child_cluster,
            error = %e,
            "Failed to send peer route sync"
        );
    } else {
        debug!(cluster = %child_cluster, "Sent peer route sync");
    }
}

/// Push peer routes (parent + sibling) to all connected children.
///
/// Called when any child's routes change. Each child receives all routes
/// except its own — including the parent's own services.
pub async fn broadcast_peer_routes(
    registry: &SharedAgentRegistry,
    child_routes: &[SubtreeService],
    proxy_url: &str,
    ca_cert_pem: &str,
    client: &Client,
    parent_cluster_name: &str,
    local_routes: &crate::route_reconciler::LocalRouteReceiver,
) {
    // Include parent's own routes from the watch channel (no API call).
    // Clone immediately to release the borrow guard before any .await.
    let parent_routes = local_routes.borrow().clone();
    let mut all_routes: Vec<SubtreeService> = parent_routes
        .iter()
        .map(|r| SubtreeService {
            name: r.service_name.clone(),
            namespace: r.service_namespace.clone(),
            cluster: parent_cluster_name.to_string(),
            removed: false,
            hostname: r.hostname.clone(),
            address: r.address.clone(),
            port: r.port as u32,
            protocol: r.protocol.clone(),
            labels: Default::default(),
            allowed_services: r.allowed_services.clone(),
        })
        .collect();

    all_routes.extend(child_routes.iter().cloned());

    if all_routes.is_empty() {
        return;
    }

    let proxy_token = match request_istiod_proxy_token(client).await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "Failed to request proxy token for peer route sync");
            return;
        }
    };

    let connected = registry.connected_cluster_names();
    for child in &connected {
        let peers = peer_routes_for(&all_routes, child);
        if peers.is_empty() {
            continue;
        }
        send_peer_routes(
            registry,
            child,
            peers,
            proxy_url,
            ca_cert_pem,
            &proxy_token,
            true,
        )
        .await;
    }
}

/// Compute the hash of peer routes that would be sent to a specific child.
///
/// Must match the hash the agent computes from its local peer CRDs.
/// Uses the same algorithm as `commands::peer_routes::hash_routes` / `hash_peer_state`.
fn compute_peer_hash_for_child(all_routes: &[SubtreeService], exclude_cluster: &str) -> Vec<u8> {
    use std::collections::BTreeMap;

    let peers = peer_routes_for(all_routes, exclude_cluster);

    // Group by cluster, hash each cluster's routes, then hash the map
    // — same structure as the agent's compute_initial_hash
    let mut per_cluster: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut by_cluster: BTreeMap<String, Vec<&SubtreeService>> = BTreeMap::new();
    for svc in &peers {
        by_cluster.entry(svc.cluster.clone()).or_default().push(svc);
    }

    for (cluster, mut svcs) in by_cluster {
        let mut buf = Vec::new();
        svcs.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
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

    let mut outer_buf = Vec::new();
    for (name, route_hash) in &per_cluster {
        outer_buf.extend_from_slice(name.as_bytes());
        outer_buf.extend_from_slice(route_hash);
    }
    sha256(&outer_buf)
}

/// Check if a child's peer routes are stale and send a full sync if needed.
///
/// Called on every heartbeat. Compares the child's reported hash with the
/// expected hash. On mismatch, sends a full `PeerRouteSync`.
pub async fn check_and_sync_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    child_hash: &[u8],
    peer_config: &crate::server::PeerRouteConfig,
    client: &Client,
) {
    let proxy_url = &peer_config.proxy_url;
    let ca_cert_pem = &peer_config.ca_cert_pem;
    let parent_cluster_name = &peer_config.parent_cluster_name;
    let local_routes = &peer_config.local_routes;
    // Build the full route set (parent + all children's subtree services)
    let parent_routes = local_routes.borrow().clone();
    let all_routes: Vec<SubtreeService> = parent_routes
        .iter()
        .map(|r| SubtreeService {
            name: r.service_name.clone(),
            namespace: r.service_namespace.clone(),
            cluster: parent_cluster_name.to_string(),
            removed: false,
            hostname: r.hostname.clone(),
            address: r.address.clone(),
            port: r.port as u32,
            protocol: r.protocol.clone(),
            labels: Default::default(),
            allowed_services: r.allowed_services.clone(),
        })
        .collect();

    // TODO: we need the aggregated child routes here too.
    // For now, only parent routes are checked. The SubtreeState handler
    // broadcasts to all children when child routes change.

    let expected_hash = compute_peer_hash_for_child(&all_routes, child_cluster);

    if child_hash == expected_hash {
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

    let peers = peer_routes_for(&all_routes, child_cluster);
    send_peer_routes(
        registry,
        child_cluster,
        peers,
        proxy_url,
        ca_cert_pem,
        &proxy_token,
        true,
    )
    .await;
}
