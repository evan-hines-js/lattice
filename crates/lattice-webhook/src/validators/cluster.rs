//! LatticeCluster admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeCluster;

use super::Validator;

/// Validates LatticeCluster CREATE and UPDATE requests
pub struct ClusterValidator;

impl Validator for ClusterValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticeclusters")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = serde_json::to_value(obj).unwrap_or_default();
        let cluster: LatticeCluster = match serde_json::from_value(raw) {
            Ok(c) => c,
            Err(e) => return response.deny(format!("failed to deserialize LatticeCluster: {e}")),
        };

        if let Err(e) = cluster.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::make_admission_request;

    fn valid_cluster_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeCluster",
            "metadata": { "name": "test-cluster" },
            "spec": {
                "providerRef": "aws-prod",
                "provider": {
                    "kubernetes": {
                        "version": "1.32.0",
                        "certSANs": ["127.0.0.1"]
                    },
                    "config": {
                        "docker": {}
                    }
                },
                "nodes": {
                    "controlPlane": { "replicas": 1 },
                    "workerPools": {
                        "default": { "replicas": 2 }
                    }
                }
            }
        })
    }

    #[test]
    fn allows_valid_cluster() {
        let validator = ClusterValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            valid_cluster_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid cluster should be allowed");
    }

    #[test]
    fn denies_empty_provider_ref() {
        let mut json = valid_cluster_json();
        json["spec"]["providerRef"] = serde_json::json!("");

        let validator = ClusterValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticeclusters", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "empty providerRef should be denied");

        let message = &response.result.message;
        assert!(
            message.contains("provider_ref"),
            "error message should mention provider_ref, got: {message}"
        );
    }

    #[test]
    fn denies_zero_control_plane_replicas() {
        let mut json = valid_cluster_json();
        json["spec"]["nodes"]["controlPlane"]["replicas"] = serde_json::json!(0);

        let validator = ClusterValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticeclusters", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "zero control plane replicas should be denied"
        );
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "latticeclusters",
                valid_cluster_json(),
            )
        };
        let validator = ClusterValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }
}
