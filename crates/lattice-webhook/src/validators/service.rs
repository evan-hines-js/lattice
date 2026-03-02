//! LatticeService admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeService;

use super::{reject_system_namespace, Validator};

/// Validates LatticeService CREATE and UPDATE requests
pub struct ServiceValidator;

impl Validator for ServiceValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticeservices")
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
        let service: LatticeService = match serde_json::from_value(raw) {
            Ok(s) => s,
            Err(e) => return response.deny(format!("failed to deserialize LatticeService: {e}")),
        };

        if let Err(e) = service.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::{
        make_admission_request, make_admission_request_in_namespace,
    };

    fn valid_service_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeService",
            "metadata": { "name": "my-service", "namespace": "default" },
            "spec": {
                "workload": {
                    "containers": {
                        "main": {
                            "image": "nginx:latest",
                            "resources": {
                                "limits": {
                                    "cpu": "500m",
                                    "memory": "256Mi"
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn allows_valid_service() {
        let validator = ServiceValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeservices",
            valid_service_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid service should be allowed");
    }

    #[test]
    fn denies_service_with_replicas_exceeding_autoscaling_max() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeService",
            "metadata": { "name": "bad-service", "namespace": "default" },
            "spec": {
                "workload": {
                    "containers": {
                        "main": {
                            "image": "nginx:latest",
                            "resources": {
                                "limits": {
                                    "cpu": "500m",
                                    "memory": "256Mi"
                                }
                            }
                        }
                    }
                },
                "replicas": 10,
                "autoscaling": { "max": 5 }
            }
        });

        let validator = ServiceValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticeservices", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "replicas exceeding autoscaling max should be denied"
        );
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "latticeservices",
                valid_service_json(),
            )
        };
        let validator = ServiceValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }

    #[test]
    fn denies_resource_in_system_namespace() {
        let validator = ServiceValidator;
        let request = make_admission_request_in_namespace(
            "lattice.dev",
            "v1alpha1",
            "latticeservices",
            "kube-system",
            valid_service_json(),
        );
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "service in system namespace should be denied"
        );
        let message = &response.result.message;
        assert!(
            message.contains("system namespace"),
            "error should mention system namespace, got: {message}"
        );
    }
}
