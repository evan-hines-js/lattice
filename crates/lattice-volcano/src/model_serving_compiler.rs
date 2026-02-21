//! ModelServing compilation from LatticeModel specs
//!
//! Maps LatticeModel fields to Kthena ModelServing resources for disaggregated
//! inference serving with gang scheduling.

use std::collections::BTreeMap;

use lattice_common::crd::LatticeModel;

use crate::types::{
    GangPolicy, ModelServing, ModelServingMetadata, ModelServingRole, ModelServingSpec,
    OwnerReference, ServingGroupTemplate,
};

/// Compile a LatticeModel into a Kthena ModelServing resource.
///
/// Takes the LatticeModel and pre-serialized pod template JSON for each role.
/// The caller (lattice-model compiler) is responsible for compiling workload specs
/// into pod templates via `WorkloadCompiler` and serializing them.
pub fn compile_model_serving(
    model: &LatticeModel,
    role_pod_templates: &BTreeMap<String, serde_json::Value>,
) -> ModelServing {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");
    let uid = model.metadata.uid.as_deref().unwrap_or_default();

    let roles = compile_roles(&model.spec.roles, role_pod_templates);
    let gang_policy = compute_gang_policy(&model.spec.roles);

    ModelServing {
        api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
        kind: "ModelServing".to_string(),
        metadata: ModelServingMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: vec![OwnerReference {
                api_version: "lattice.dev/v1alpha1".to_string(),
                kind: "LatticeModel".to_string(),
                name: name.to_string(),
                uid: uid.to_string(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            }],
        },
        spec: ModelServingSpec {
            scheduler_name: model.spec.scheduler_name.clone(),
            replicas: 1,
            template: ServingGroupTemplate {
                roles,
                gang_policy: Some(gang_policy),
                service_name: Some(name.to_string()),
            },
            recovery_policy: model.spec.recovery_policy.clone(),
            rollout_strategy: None,
        },
    }
}

fn compile_roles(
    role_specs: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    pod_templates: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, ModelServingRole> {
    role_specs
        .iter()
        .filter_map(|(role_name, role_spec)| {
            let template = pod_templates.get(role_name)?.clone();
            Some((
                role_name.clone(),
                ModelServingRole {
                    replicas: role_spec.replicas,
                    template,
                },
            ))
        })
        .collect()
}

fn compute_gang_policy(
    role_specs: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
) -> GangPolicy {
    let min_role_replicas = role_specs
        .iter()
        .map(|(name, spec)| (name.clone(), spec.replicas))
        .collect();

    GangPolicy { min_role_replicas }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{LatticeModelSpec, ModelRoleSpec, RuntimeSpec, WorkloadSpec};

    fn test_model(roles: BTreeMap<String, ModelRoleSpec>) -> LatticeModel {
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("test-uid-456".to_string());
        model
    }

    fn test_pod_template(image: &str) -> serde_json::Value {
        serde_json::json!({
            "metadata": {
                "labels": {"app": "test"}
            },
            "spec": {
                "containers": [{
                    "name": "main",
                    "image": image
                }]
            }
        })
    }

    #[test]
    fn single_role_model_serving() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: 2,
                worker_replicas: 0,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
            },
        );

        let model = test_model(roles);
        let templates =
            BTreeMap::from([("decode".to_string(), test_pod_template("decoder:latest"))]);

        let ms = compile_model_serving(&model, &templates);

        assert_eq!(ms.api_version, "workload.serving.volcano.sh/v1alpha1");
        assert_eq!(ms.kind, "ModelServing");
        assert_eq!(ms.metadata.name, "test-model");
        assert_eq!(ms.spec.scheduler_name, "volcano");
        assert_eq!(ms.spec.template.roles.len(), 1);
        assert_eq!(ms.spec.template.roles["decode"].replicas, 2);
    }

    #[test]
    fn multi_role_model_serving() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "prefill".to_string(),
            ModelRoleSpec {
                replicas: 1,
                worker_replicas: 0,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
            },
        );
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: 4,
                worker_replicas: 0,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
            },
        );

        let model = test_model(roles);
        let templates = BTreeMap::from([
            ("prefill".to_string(), test_pod_template("prefill:latest")),
            ("decode".to_string(), test_pod_template("decode:latest")),
        ]);

        let ms = compile_model_serving(&model, &templates);

        assert_eq!(ms.spec.template.roles.len(), 2);
        assert_eq!(ms.spec.template.roles["prefill"].replicas, 1);
        assert_eq!(ms.spec.template.roles["decode"].replicas, 4);
    }

    #[test]
    fn owner_reference_set() {
        let model = test_model(BTreeMap::new());
        let ms = compile_model_serving(&model, &BTreeMap::new());

        assert_eq!(ms.metadata.owner_references.len(), 1);
        let oref = &ms.metadata.owner_references[0];
        assert_eq!(oref.kind, "LatticeModel");
        assert_eq!(oref.name, "test-model");
        assert_eq!(oref.controller, Some(true));
        assert_eq!(oref.block_owner_deletion, Some(true));
    }

    #[test]
    fn gang_policy_computed_from_replicas() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "prefill".to_string(),
            ModelRoleSpec {
                replicas: 1,
                worker_replicas: 0,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
            },
        );
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: 3,
                worker_replicas: 0,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
            },
        );

        let model = test_model(roles);
        let templates = BTreeMap::from([
            ("prefill".to_string(), test_pod_template("prefill:latest")),
            ("decode".to_string(), test_pod_template("decode:latest")),
        ]);

        let ms = compile_model_serving(&model, &templates);

        let gang = ms.spec.template.gang_policy.as_ref().unwrap();
        assert_eq!(gang.min_role_replicas["prefill"], 1);
        assert_eq!(gang.min_role_replicas["decode"], 3);
    }

    #[test]
    fn recovery_policy_propagated() {
        let spec = LatticeModelSpec {
            recovery_policy: Some("RestartAll".to_string()),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let ms = compile_model_serving(&model, &BTreeMap::new());
        assert_eq!(ms.spec.recovery_policy, Some("RestartAll".to_string()));
    }
}
