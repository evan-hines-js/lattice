//! Shared utilities for move operations

use kube::discovery::ApiResource;

/// Build ApiResource from apiVersion and kind
pub fn build_api_resource(api_version: &str, kind: &str) -> ApiResource {
    let (group, version) = parse_api_version(api_version);
    let plural = pluralize_kind(kind);

    ApiResource {
        group,
        version,
        kind: kind.to_string(),
        api_version: api_version.to_string(),
        plural,
    }
}

/// Parse apiVersion into (group, version)
pub fn parse_api_version(api_version: &str) -> (String, String) {
    if let Some((group, version)) = api_version.split_once('/') {
        (group.to_string(), version.to_string())
    } else {
        (String::new(), api_version.to_string())
    }
}

/// Simple pluralization for Kubernetes kinds
pub fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with("ss") {
        format!("{}es", lower)
    } else if lower.ends_with('s') {
        lower
    } else {
        format!("{}s", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_version() {
        assert_eq!(
            parse_api_version("cluster.x-k8s.io/v1beta1"),
            ("cluster.x-k8s.io".to_string(), "v1beta1".to_string())
        );
        assert_eq!(parse_api_version("v1"), (String::new(), "v1".to_string()));
    }

    #[test]
    fn test_pluralize_kind() {
        assert_eq!(pluralize_kind("Cluster"), "clusters");
        assert_eq!(pluralize_kind("Machine"), "machines");
        assert_eq!(pluralize_kind("ClusterClass"), "clusterclasses");
        assert_eq!(pluralize_kind("Secret"), "secrets");
    }

    #[test]
    fn test_build_api_resource() {
        let ar = build_api_resource("cluster.x-k8s.io/v1beta1", "Cluster");
        assert_eq!(ar.group, "cluster.x-k8s.io");
        assert_eq!(ar.version, "v1beta1");
        assert_eq!(ar.kind, "Cluster");
        assert_eq!(ar.plural, "clusters");
    }
}
