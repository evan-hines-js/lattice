//! Pod template JSON serialization for batch/serving workloads
//!
//! Converts a `CompiledPodTemplate` into a JSON value suitable for use in
//! Volcano VCJob task templates and Kthena ModelServing role templates.

use crate::CompiledPodTemplate;

/// Inject labels into a pod template's metadata.
///
/// Used by job and model compilers to add group-level labels (e.g.
/// `lattice.dev/training-job`, `istio.io/dataplane-mode: none`) after
/// the initial pod template has been serialized to JSON.
pub fn inject_pod_labels(template: &mut serde_json::Value, labels: &[(&str, &str)]) {
    let labels_obj = template
        .pointer_mut("/metadata/labels")
        .and_then(|v| v.as_object_mut());
    if let Some(obj) = labels_obj {
        for (key, value) in labels {
            obj.insert(key.to_string(), serde_json::json!(value));
        }
    }
}

/// Convert a `CompiledPodTemplate` into a JSON value for batch/serving workload templates.
///
/// Produces a pod template spec structure as JSON, avoiding dependency on the service
/// crate's serialization types. Returns `serde_json::Error` on serialization failure.
pub fn pod_template_to_json(
    pt: CompiledPodTemplate,
) -> Result<serde_json::Value, serde_json::Error> {
    use serde::de::Error as _;

    let mut spec = serde_json::json!({
        "serviceAccountName": pt.service_account_name,
        "automountServiceAccountToken": false,
        "containers": pt.containers,
    });

    let spec_obj = spec
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::custom("pod spec is not a JSON object"))?;

    if !pt.init_containers.is_empty() {
        spec_obj.insert(
            "initContainers".to_string(),
            serde_json::to_value(&pt.init_containers)?,
        );
    }
    if !pt.volumes.is_empty() {
        spec_obj.insert("volumes".to_string(), serde_json::to_value(&pt.volumes)?);
    }
    if let Some(ref sc) = pt.security_context {
        spec_obj.insert("securityContext".to_string(), serde_json::to_value(sc)?);
    }
    if let Some(hn) = pt.host_network {
        spec_obj.insert("hostNetwork".to_string(), serde_json::Value::Bool(hn));
    }
    if let Some(spn) = pt.share_process_namespace {
        spec_obj.insert(
            "shareProcessNamespace".to_string(),
            serde_json::Value::Bool(spn),
        );
    }
    if !pt.topology_spread_constraints.is_empty() {
        spec_obj.insert(
            "topologySpreadConstraints".to_string(),
            serde_json::to_value(&pt.topology_spread_constraints)?,
        );
    }
    if let Some(ref ns) = pt.node_selector {
        spec_obj.insert("nodeSelector".to_string(), serde_json::to_value(ns)?);
    }
    if !pt.tolerations.is_empty() {
        spec_obj.insert(
            "tolerations".to_string(),
            serde_json::to_value(&pt.tolerations)?,
        );
    }
    if let Some(ref rcn) = pt.runtime_class_name {
        spec_obj.insert(
            "runtimeClassName".to_string(),
            serde_json::Value::String(rcn.clone()),
        );
    }
    if !pt.scheduling_gates.is_empty() {
        spec_obj.insert(
            "schedulingGates".to_string(),
            serde_json::to_value(&pt.scheduling_gates)?,
        );
    }
    if !pt.image_pull_secrets.is_empty() {
        spec_obj.insert(
            "imagePullSecrets".to_string(),
            serde_json::to_value(&pt.image_pull_secrets)?,
        );
    }
    if let Some(ref affinity) = pt.affinity {
        spec_obj.insert("affinity".to_string(), serde_json::to_value(affinity)?);
    }

    Ok(serde_json::json!({
        "metadata": {
            "labels": pt.labels
        },
        "spec": spec
    }))
}
