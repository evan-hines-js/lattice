//! Bootstrap bundle generation
//!
//! `generate_bootstrap_bundle()` is the single source of truth for
//! bootstrap manifests. Both the install command (management cluster)
//! and the bootstrap webhook (child clusters) call it.

use kube::CustomResourceExt;
use lattice_crd::crd::{LatticeCluster, LbAdvertisement};

use super::addons;
use super::errors::BootstrapError;
use super::types::{BootstrapBundleConfig, ManifestGenerator};

pub async fn generate_bootstrap_bundle<G: ManifestGenerator>(
    generator: &G,
    config: &BootstrapBundleConfig<'_>,
) -> Result<Vec<String>, BootstrapError> {
    let facts = config.facts;
    let mut manifests = generator
        .generate(
            config.image,
            config.registry_credentials,
            Some(&facts.cluster_name),
            Some(facts.provider),
        )
        .await?;
    // Cilium ships in the bundle so the cluster has a CNI before the
    // operator Deployment can schedule. Its DaemonSet tolerates NotReady,
    // so it lands on the bare node, programs networking, and unblocks
    // every other Deployment in the same bundle.
    manifests.extend(lattice_cilium::install::manifests::render_cilium_manifests(
        config.api_server_endpoint,
    ));

    if let Some(adv) = facts.lb_advertisement.as_ref() {
        manifests.extend(render_lb_resources(&facts.cluster_name, adv)?);
    }

    manifests.extend(addons::generate_for_provider(
        facts.provider,
        &facts.k8s_version,
        &facts.cluster_name,
        facts.autoscaling_enabled,
    ));

    let crd_definition = serde_json::to_string(&LatticeCluster::crd()).map_err(|e| {
        BootstrapError::Internal(format!("failed to serialize LatticeCluster CRD: {e}"))
    })?;
    manifests.push(crd_definition);
    manifests.push(facts.cluster_manifest.clone());

    Ok(manifests)
}

fn render_lb_resources(
    cluster_name: &str,
    adv: &LbAdvertisement,
) -> Result<Vec<String>, BootstrapError> {
    match adv {
        LbAdvertisement::L2 { cidr } => crate::cilium::generate_l2_lb_resources(cidr).map_err(|e| {
            BootstrapError::Internal(format!("failed to generate Cilium L2 LB resources: {e}"))
        }),
        LbAdvertisement::Bgp { peer, pools } => {
            let req = crate::cilium::BgpLbRequest {
                cluster_name,
                bgp_peer: peer,
                pools,
            };
            crate::cilium::generate_bgp_lb_resources(&req).map_err(|e| {
                BootstrapError::Internal(format!("failed to generate Cilium BGP LB resources: {e}"))
            })
        }
    }
}
