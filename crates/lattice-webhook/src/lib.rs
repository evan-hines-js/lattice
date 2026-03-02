//! Kubernetes ValidatingAdmissionWebhook server for Lattice CRDs
//!
//! Validates Lattice CRD specs at admission time by reusing existing
//! `validate()` methods from `lattice-common`. Runs as an HTTPS server
//! on port 9443 with self-signed TLS.
//!
//! ## Architecture
//!
//! - Each CRD has a `Validator` implementation that deserializes the
//!   admission request and calls the spec's `validate()` method.
//! - A `ValidatorRegistry` maps (group, version, resource) to the
//!   correct validator.
//! - A single POST endpoint at `/validate` handles all CRD types.
//! - TLS certificates are self-signed, stored in a K8s Secret, and
//!   the CA is injected into the `ValidatingWebhookConfiguration`.

mod certs;
mod config;
mod error;
mod handler;
mod server;
mod validators;

pub use crate::error::Error;

/// Start the admission webhook HTTPS server.
///
/// Generates or loads TLS credentials, then serves the `/validate`
/// endpoint on `0.0.0.0:9443`. This function runs until the server
/// is shut down.
///
/// Designed to be spawned on all pods (stateless validation). Call
/// this before leader election.
pub async fn start_webhook_server(client: kube::Client) -> Result<(), Error> {
    let tls = certs::ensure_tls(&client).await?;
    server::serve(tls).await
}

/// Apply the ValidatingWebhookConfiguration using the CA from the TLS Secret.
///
/// Should be called by the leader after CRDs are installed. Reads the
/// CA certificate from the webhook TLS Secret (created by `start_webhook_server`)
/// and injects it into the webhook configuration so the API server knows
/// to send admission requests to the webhook.
pub async fn ensure_webhook_configuration(client: &kube::Client) -> Result<(), Error> {
    config::ensure_webhook_configuration(client).await
}

// Test helper module shared by all validator tests
#[cfg(test)]
pub(crate) mod test_helpers {
    use kube::core::admission::{AdmissionRequest, AdmissionReview};
    use kube::core::DynamicObject;

    /// Build an AdmissionRequest with the given GVR, namespace, and object JSON.
    ///
    /// Constructs a full AdmissionReview JSON and deserializes it, which
    /// ensures all fields are correctly populated regardless of struct
    /// visibility or version changes in kube-rs.
    pub fn make_admission_request(
        group: &str,
        version: &str,
        resource: &str,
        object_json: serde_json::Value,
    ) -> AdmissionRequest<DynamicObject> {
        make_admission_request_in_namespace(group, version, resource, "default", object_json)
    }

    /// Build an AdmissionRequest targeting a specific namespace.
    pub fn make_admission_request_in_namespace(
        group: &str,
        version: &str,
        resource: &str,
        namespace: &str,
        object_json: serde_json::Value,
    ) -> AdmissionRequest<DynamicObject> {
        let review_json = serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid",
                "namespace": namespace,
                "kind": {
                    "group": group,
                    "version": version,
                    "kind": "TestKind"
                },
                "resource": {
                    "group": group,
                    "version": version,
                    "resource": resource
                },
                "operation": "CREATE",
                "userInfo": {
                    "username": "test-user"
                },
                "object": object_json,
                "dryRun": false
            }
        });

        let review: AdmissionReview<DynamicObject> =
            serde_json::from_value(review_json).expect("test AdmissionReview should deserialize");
        review
            .try_into()
            .expect("test AdmissionReview should convert to AdmissionRequest")
    }

    /// Build an UPDATE AdmissionRequest with both object and oldObject JSON.
    ///
    /// Same as `make_admission_request` but sets `"operation": "UPDATE"` and
    /// includes `"oldObject"` for mutation detection.
    pub fn make_update_admission_request(
        group: &str,
        version: &str,
        resource: &str,
        object_json: serde_json::Value,
        old_object_json: serde_json::Value,
    ) -> AdmissionRequest<DynamicObject> {
        let review_json = serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid",
                "namespace": "default",
                "kind": {
                    "group": group,
                    "version": version,
                    "kind": "TestKind"
                },
                "resource": {
                    "group": group,
                    "version": version,
                    "resource": resource
                },
                "operation": "UPDATE",
                "userInfo": {
                    "username": "test-user"
                },
                "object": object_json,
                "oldObject": old_object_json,
                "dryRun": false
            }
        });

        let review: AdmissionReview<DynamicObject> =
            serde_json::from_value(review_json).expect("test AdmissionReview should deserialize");
        review
            .try_into()
            .expect("test AdmissionReview should convert to AdmissionRequest")
    }
}
