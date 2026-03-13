//! LatticeMeshMember admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeMeshMember;

use super::{reject_system_namespace, Validator};

/// Validates LatticeMeshMember CREATE and UPDATE requests
pub struct MeshMemberValidator;

impl Validator for MeshMemberValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticemeshmembers")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        if let Some(denied) = reject_system_namespace(request) {
            return denied;
        }

        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = serde_json::to_value(obj).unwrap_or_default();
        let member: LatticeMeshMember = match serde_json::from_value(raw) {
            Ok(m) => m,
            Err(e) => {
                return response.deny(format!("failed to deserialize LatticeMeshMember: {e}"))
            }
        };

        if let Err(e) = member.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::make_admission_request;

    fn valid_mesh_member_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeMeshMember",
            "metadata": { "name": "prometheus", "namespace": "monitoring" },
            "spec": {
                "target": {
                    "selector": { "app": "prometheus" }
                },
                "ports": [
                    { "port": 9090, "name": "metrics" }
                ]
            }
        })
    }

    #[test]
    fn allows_valid_mesh_member() {
        let validator = MeshMemberValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticemeshmembers",
            valid_mesh_member_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid mesh member should be allowed");
    }

    #[test]
    fn allows_empty_ports_and_deps() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeMeshMember",
            "metadata": { "name": "empty-member", "namespace": "default" },
            "spec": {
                "target": {
                    "selector": { "app": "test" }
                },
                "ports": [],
                "dependencies": [],
                "egress": []
            }
        });

        let validator = MeshMemberValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticemeshmembers", json);
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "empty mesh member should be allowed so all workloads participate in the graph"
        );
    }

    #[test]
    fn denies_invalid_port_name() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeMeshMember",
            "metadata": { "name": "bad-port", "namespace": "default" },
            "spec": {
                "target": {
                    "selector": { "app": "test" }
                },
                "ports": [
                    { "port": 8080, "name": "INVALID" }
                ]
            }
        });

        let validator = MeshMemberValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticemeshmembers", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "invalid port name should be denied");
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "latticemeshmembers",
                valid_mesh_member_json(),
            )
        };
        let validator = MeshMemberValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }
}
