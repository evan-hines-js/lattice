//! Path utilities for K8s API proxy
//!
//! Single source of truth for path manipulation functions used across
//! the proxy, router, and exec handlers.

/// Strip /clusters/{cluster_name} prefix from a path to get the K8s API path.
///
/// # Examples
///
/// ```
/// use lattice_api::routing::strip_cluster_prefix;
///
/// assert_eq!(
///     strip_cluster_prefix("/clusters/my-cluster/api/v1/pods", "my-cluster"),
///     "/api/v1/pods"
/// );
/// ```
pub fn strip_cluster_prefix<'a>(full_path: &'a str, cluster_name: &str) -> &'a str {
    let prefix = format!("/clusters/{}", cluster_name);
    full_path.strip_prefix(&prefix).unwrap_or(full_path)
}

/// Parse a URL path with nested `/clusters/{name}` segments into a routing
/// target path and the remaining K8s API path.
///
/// Returns `(target_path, k8s_path)` where `target_path` is the `/`-separated
/// chain of cluster names (e.g. `"child-b/grandchild-c"`) and `k8s_path` is the
/// remaining K8s API path (e.g. `"/api/v1/pods"`).
///
/// # Examples
///
/// ```
/// use lattice_api::routing::parse_cluster_path;
///
/// // Single hop
/// assert_eq!(
///     parse_cluster_path("/clusters/child-1/api/v1/pods"),
///     Some(("child-1".to_string(), "/api/v1/pods".to_string()))
/// );
///
/// // Multi-hop
/// assert_eq!(
///     parse_cluster_path("/clusters/child-b/clusters/grandchild-c/api/v1/pods"),
///     Some(("child-b/grandchild-c".to_string(), "/api/v1/pods".to_string()))
/// );
///
/// // No clusters prefix
/// assert_eq!(parse_cluster_path("/api/v1/pods"), None);
/// ```
pub fn parse_cluster_path(url_path: &str) -> Option<(String, String)> {
    let mut remaining = url_path;
    let mut segments = Vec::new();

    while let Some(rest) = remaining.strip_prefix("/clusters/") {
        // Find the next `/` to extract the cluster name
        let (name, tail) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, ""),
        };

        if name.is_empty() {
            break;
        }

        segments.push(name.to_string());
        remaining = tail;
    }

    if segments.is_empty() {
        return None;
    }

    let target_path = segments.join("/");
    let k8s_path = if remaining.is_empty() {
        "/".to_string()
    } else {
        remaining.to_string()
    };

    Some((target_path, k8s_path))
}

// Re-export from lattice_common for convenience
pub use lattice_common::routing::split_first_hop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_cluster_prefix() {
        assert_eq!(
            strip_cluster_prefix("/clusters/my-cluster/api/v1/pods", "my-cluster"),
            "/api/v1/pods"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_apis() {
        assert_eq!(
            strip_cluster_prefix("/clusters/e2e-mgmt/apis/apps/v1/deployments", "e2e-mgmt"),
            "/apis/apps/v1/deployments"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_exec() {
        assert_eq!(
            strip_cluster_prefix(
                "/clusters/workload-1/api/v1/namespaces/default/pods/nginx/exec",
                "workload-1"
            ),
            "/api/v1/namespaces/default/pods/nginx/exec"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_no_match() {
        assert_eq!(
            strip_cluster_prefix("/api/v1/pods", "my-cluster"),
            "/api/v1/pods"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_root_path() {
        assert_eq!(
            strip_cluster_prefix("/clusters/test-cluster", "test-cluster"),
            ""
        );
    }

    // parse_cluster_path tests

    #[test]
    fn test_parse_cluster_path_single_hop() {
        let (target, k8s) = parse_cluster_path("/clusters/child-1/api/v1/pods").unwrap();
        assert_eq!(target, "child-1");
        assert_eq!(k8s, "/api/v1/pods");
    }

    #[test]
    fn test_parse_cluster_path_multi_hop() {
        let (target, k8s) =
            parse_cluster_path("/clusters/child-b/clusters/grandchild-c/api/v1/pods").unwrap();
        assert_eq!(target, "child-b/grandchild-c");
        assert_eq!(k8s, "/api/v1/pods");
    }

    #[test]
    fn test_parse_cluster_path_three_hops() {
        let (target, k8s) =
            parse_cluster_path("/clusters/a/clusters/b/clusters/c/apis/apps/v1/deployments")
                .unwrap();
        assert_eq!(target, "a/b/c");
        assert_eq!(k8s, "/apis/apps/v1/deployments");
    }

    #[test]
    fn test_parse_cluster_path_no_prefix() {
        assert!(parse_cluster_path("/api/v1/pods").is_none());
    }

    #[test]
    fn test_parse_cluster_path_cluster_root() {
        let (target, k8s) = parse_cluster_path("/clusters/child-1").unwrap();
        assert_eq!(target, "child-1");
        assert_eq!(k8s, "/");
    }

    #[test]
    fn test_parse_cluster_path_exec() {
        let (target, k8s) = parse_cluster_path(
            "/clusters/child-1/clusters/gc-1/api/v1/namespaces/default/pods/nginx/exec",
        )
        .unwrap();
        assert_eq!(target, "child-1/gc-1");
        assert_eq!(k8s, "/api/v1/namespaces/default/pods/nginx/exec");
    }

    // split_first_hop tests are in lattice_common::routing

    #[test]
    fn test_split_first_hop_reexport() {
        // Verify the re-export works
        assert_eq!(split_first_hop("a/b"), ("a", "b"));
    }

    #[test]
    fn test_split_first_hop_empty() {
        assert_eq!(split_first_hop(""), ("", ""));
    }
}
