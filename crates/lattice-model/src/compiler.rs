//! ModelCompiler — orchestrates per-role compilation for LatticeModel
//!
//! For each role:
//! - Compiles workload via `WorkloadCompiler` → pod template + config resources
//! - Compiles Tetragon tracing policies via `lattice_tetragon`
//! - Aggregates mesh members, config, and tracing policies
//!
//! Then builds a Kthena ModelServing from the aggregated pod templates.

use std::collections::BTreeMap;

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{LatticeMeshMember, LatticeModel, ProviderType};
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::tetragon::TracingPolicyNamespaced;
use lattice_volcano::ModelServing;
use lattice_workload::{CompiledConfig, WorkloadCompiler};

use crate::error::ModelError;

/// Complete compiled output for a LatticeModel
#[derive(Debug)]
pub struct CompiledModel {
    /// Kthena ModelServing resource
    pub model_serving: ModelServing,
    /// Aggregated config resources from all roles (ConfigMaps, Secrets, ESO, PVCs)
    pub config: CompiledConfig,
    /// LatticeMeshMember CRs — one per role that participates in the mesh
    pub mesh_members: Vec<LatticeMeshMember>,
    /// Tetragon TracingPolicyNamespaced resources — per-role runtime enforcement
    pub tracing_policies: Vec<TracingPolicyNamespaced>,
}

/// Compile a LatticeModel into Kubernetes resources.
///
/// For each role, runs the shared `WorkloadCompiler` pipeline and `lattice_tetragon`
/// policy compiler, then aggregates results into a single `CompiledModel`.
///
/// This function is pure compilation — it does NOT register roles in the service graph.
/// The caller (controller) is responsible for graph registration after successful compilation
/// and cleanup on failure.
pub async fn compile_model(
    model: &LatticeModel,
    graph: &ServiceGraph,
    cluster_name: &str,
    provider_type: ProviderType,
    cedar: &PolicyEngine,
) -> Result<CompiledModel, ModelError> {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model
        .metadata
        .namespace
        .as_deref()
        .ok_or(ModelError::MissingNamespace)?;

    if model.spec.roles.is_empty() {
        return Err(ModelError::NoRoles);
    }

    let mut pod_templates: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut config = CompiledConfig::default();
    let mut mesh_members = Vec::new();
    let mut tracing_policies = Vec::new();

    for (role_name, role_spec) in &model.spec.roles {
        let role_full_name = format!("{}-{}", name, role_name);

        // Compile workload → pod template + config resources + mesh member
        let compiled = WorkloadCompiler::new(
            &role_full_name,
            namespace,
            &role_spec.workload,
            &role_spec.runtime,
            provider_type,
        )
        .with_cedar(cedar)
        .with_cluster_name(cluster_name)
        .with_graph(graph)
        .with_image_pull_secrets(&role_spec.runtime.image_pull_secrets)
        .compile()
        .await
        .map_err(|e| ModelError::RoleCompilation {
            role: role_name.clone(),
            source: e,
        })?;

        // Convert CompiledPodTemplate to JSON for ModelServing
        let template_json = lattice_workload::pod_template_to_json(compiled.pod_template)
            .map_err(ModelError::Serialization)?;
        pod_templates.insert(role_name.clone(), template_json);

        // Collect config resources
        config.merge(compiled.config);

        // Collect mesh member
        if let Some(mm) = compiled.mesh_member {
            mesh_members.push(mm);
        }

        // Compile Tetragon tracing policies for this role
        let policies = lattice_tetragon::compile_tracing_policies(
            &role_full_name,
            namespace,
            &role_spec.workload,
            &role_spec.runtime,
            &[],
        );
        tracing_policies.extend(policies);
    }

    // Build ModelServing from aggregated pod templates
    let model_serving = lattice_volcano::compile_model_serving(model, &pod_templates);

    Ok(CompiledModel {
        model_serving,
        config,
        mesh_members,
        tracing_policies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, LatticeModelSpec, ModelRoleSpec, RuntimeSpec, WorkloadSpec,
    };

    fn make_model(roles: BTreeMap<String, ModelRoleSpec>) -> LatticeModel {
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-456".to_string());
        model
    }

    fn make_role(image: &str, replicas: u32) -> ModelRoleSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: image.to_string(),
                ..Default::default()
            },
        );
        ModelRoleSpec {
            replicas,
            worker_replicas: 0,
            workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            runtime: RuntimeSpec::default(),
        }
    }

    fn permit_all_cedar() -> PolicyEngine {
        PolicyEngine::with_policies("permit(principal, action, resource);").unwrap()
    }

    #[tokio::test]
    async fn compile_single_role_model() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 2));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert_eq!(compiled.model_serving.spec.template.roles.len(), 1);
        assert_eq!(
            compiled.model_serving.spec.template.roles["decode"].replicas,
            2
        );
        assert!(compiled.tracing_policies.is_empty());
    }

    #[tokio::test]
    async fn compile_multi_role_model() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role("prefill:latest", 1));
        roles.insert("decode".to_string(), make_role("decode:latest", 4));

        let model = make_model(roles);
        let graph = ServiceGraph::new();
        let cedar = permit_all_cedar();

        let compiled = compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar)
            .await
            .unwrap();

        assert_eq!(compiled.model_serving.spec.template.roles.len(), 2);
    }

    #[tokio::test]
    async fn empty_roles_returns_error() {
        let model = make_model(BTreeMap::new());
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result =
            compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
        assert!(matches!(result, Err(ModelError::NoRoles)));
    }

    #[tokio::test]
    async fn missing_namespace_returns_error() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role("decoder:latest", 1));
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let model = LatticeModel::new("test-model", spec);
        // No namespace set

        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();

        let result =
            compile_model(&model, &graph, "test-cluster", ProviderType::Docker, &cedar).await;
        assert!(matches!(result, Err(ModelError::MissingNamespace)));
    }
}
