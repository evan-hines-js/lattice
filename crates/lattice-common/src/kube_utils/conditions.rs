//! Kubernetes condition checking utilities.

/// The "Ready" condition type for nodes
pub const CONDITION_READY: &str = "Ready";
/// The "Available" condition type for deployments
pub const CONDITION_AVAILABLE: &str = "Available";
/// The "True" status value for conditions
pub const STATUS_TRUE: &str = "True";

/// Check if a Kubernetes condition of the given type has status "True"
///
/// This is a helper for checking conditions on nodes, deployments, and other
/// resources that use the standard Kubernetes condition format.
///
/// # Arguments
/// * `conditions` - Optional slice of conditions (e.g., from status.conditions)
/// * `condition_type` - The condition type to check (e.g., "Ready", "Available")
///
/// # Returns
/// `true` if a condition with the given type exists and has status "True"
pub fn has_condition<T>(conditions: Option<&[T]>, condition_type: &str) -> bool
where
    T: HasConditionFields,
{
    conditions
        .map(|conds| {
            conds
                .iter()
                .any(|c| c.type_field() == condition_type && c.status_field() == STATUS_TRUE)
        })
        .unwrap_or(false)
}

/// Trait for types that have condition-like fields (type and status)
pub trait HasConditionFields {
    /// Get the condition type field value
    fn type_field(&self) -> &str;
    /// Get the condition status field value
    fn status_field(&self) -> &str;
}

macro_rules! impl_has_condition_fields {
    ($type:ty) => {
        impl HasConditionFields for $type {
            fn type_field(&self) -> &str {
                &self.type_
            }
            fn status_field(&self) -> &str {
                &self.status
            }
        }
    };
}

impl_has_condition_fields!(k8s_openapi::api::core::v1::NodeCondition);
impl_has_condition_fields!(k8s_openapi::api::apps::v1::DeploymentCondition);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_condition_with_ready() {
        use k8s_openapi::api::core::v1::NodeCondition;

        let conditions = vec![
            NodeCondition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
            NodeCondition {
                type_: "MemoryPressure".to_string(),
                status: "False".to_string(),
                ..Default::default()
            },
        ];

        assert!(has_condition(Some(conditions.as_slice()), CONDITION_READY));
        assert!(!has_condition(
            Some(conditions.as_slice()),
            CONDITION_AVAILABLE
        ));
    }

    #[test]
    fn test_has_condition_not_ready() {
        use k8s_openapi::api::core::v1::NodeCondition;

        let conditions = vec![NodeCondition {
            type_: "Ready".to_string(),
            status: "False".to_string(),
            ..Default::default()
        }];

        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_has_condition_none() {
        assert!(!has_condition::<k8s_openapi::api::core::v1::NodeCondition>(
            None,
            CONDITION_READY
        ));
    }

    #[test]
    fn test_has_condition_empty() {
        let conditions: Vec<k8s_openapi::api::core::v1::NodeCondition> = vec![];
        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_has_condition_deployment() {
        use k8s_openapi::api::apps::v1::DeploymentCondition;

        let conditions = vec![
            DeploymentCondition {
                type_: "Available".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
            DeploymentCondition {
                type_: "Progressing".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
        ];

        assert!(has_condition(
            Some(conditions.as_slice()),
            CONDITION_AVAILABLE
        ));
        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_constants() {
        assert_eq!(CONDITION_READY, "Ready");
        assert_eq!(CONDITION_AVAILABLE, "Available");
        assert_eq!(STATUS_TRUE, "True");
    }
}
