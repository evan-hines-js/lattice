//! Routing path utilities for hierarchical cluster proxy
//!
//! Shared helpers for path-based proxy routing. Each cluster in the hierarchy
//! routes requests by peeling off the first segment of a `/`-separated path.

/// Split the first hop from a routing path.
///
/// Returns `(first_segment, remaining_path)`. If the path has only one segment,
/// `remaining_path` is empty.
///
/// # Examples
///
/// ```
/// use lattice_common::routing::split_first_hop;
///
/// assert_eq!(split_first_hop("child-b/grandchild-c"), ("child-b", "grandchild-c"));
/// assert_eq!(split_first_hop("child-b"), ("child-b", ""));
/// assert_eq!(split_first_hop(""), ("", ""));
/// ```
pub fn split_first_hop(target_path: &str) -> (&str, &str) {
    match target_path.find('/') {
        Some(pos) => (&target_path[..pos], &target_path[pos + 1..]),
        None => (target_path, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_first_hop_single() {
        assert_eq!(split_first_hop("child-b"), ("child-b", ""));
    }

    #[test]
    fn test_split_first_hop_two() {
        assert_eq!(
            split_first_hop("child-b/grandchild-c"),
            ("child-b", "grandchild-c")
        );
    }

    #[test]
    fn test_split_first_hop_three() {
        assert_eq!(split_first_hop("a/b/c"), ("a", "b/c"));
    }

    #[test]
    fn test_split_first_hop_empty() {
        assert_eq!(split_first_hop(""), ("", ""));
    }
}
