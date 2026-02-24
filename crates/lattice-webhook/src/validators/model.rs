//! LatticeModel admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeModel;

use super::Validator;

/// Validates LatticeModel CREATE and UPDATE requests
pub struct ModelValidator;

impl Validator for ModelValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticemodels")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = serde_json::to_value(obj).unwrap_or_default();
        let model: LatticeModel = match serde_json::from_value(raw) {
            Ok(m) => m,
            Err(e) => return response.deny(format!("failed to deserialize LatticeModel: {e}")),
        };

        if let Err(e) = model.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::make_admission_request;

    fn valid_model_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeModel",
            "metadata": { "name": "my-model", "namespace": "default" },
            "spec": {
                "roles": {
                    "prefill": {
                        "replicas": 1,
                        "entryWorkload": {
                            "containers": {
                                "main": { "image": "vllm:latest" }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn allows_valid_model() {
        let validator = ModelValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticemodels",
            valid_model_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid model should be allowed");
    }

    #[test]
    fn allows_model_with_no_roles() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeModel",
            "metadata": { "name": "empty-model", "namespace": "default" },
            "spec": {
                "roles": {}
            }
        });

        let validator = ModelValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticemodels", json);
        let response = validator.validate(&request);
        assert!(response.allowed, "model with no roles should be allowed");
    }

    #[test]
    fn denies_role_with_replicas_exceeding_autoscaling_max() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeModel",
            "metadata": { "name": "bad-model", "namespace": "default" },
            "spec": {
                "roles": {
                    "decode": {
                        "replicas": 10,
                        "entryWorkload": {
                            "containers": {
                                "main": { "image": "vllm:latest" }
                            }
                        },
                        "autoscaling": { "max": 5 }
                    }
                }
            }
        });

        let validator = ModelValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticemodels", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "role with replicas exceeding autoscaling max should be denied"
        );

        let message = &response.result.message;
        assert!(
            message.contains("decode"),
            "error should mention the role name, got: {message}"
        );
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "latticemodels",
                valid_model_json(),
            )
        };
        let validator = ModelValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }
}
