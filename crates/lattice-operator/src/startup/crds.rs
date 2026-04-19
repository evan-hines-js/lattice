//! CRD installation utilities
//!
//! Provides functions for installing Lattice CRDs on startup using server-side apply.
//! CRDs are organized into common (all modes) and per-mode sets.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, CustomResourceExt};

use lattice_crd::crd::{
    BackupStore, CedarPolicy, CertIssuer, CertManagerInstall, CiliumInstall, DNSProvider,
    ESOInstall, ImageProvider, InfraProvider, IstioInstall, LatticeCluster, LatticeClusterBackup,
    LatticeClusterRoutes, LatticeJob, LatticeMeshMember, LatticeModel, LatticePackage,
    KedaInstall, LatticeQuota, LatticeRestore, LatticeService, MetricsServerInstall, OIDCProvider,
    SecretProvider, TetragonInstall, VeleroInstall, VolcanoInstall,
};

/// CRD definition with name and resource
struct CrdDef {
    name: &'static str,
    crd: CustomResourceDefinition,
}

/// CRDs needed by all modes
fn common_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "cedarpolicies.lattice.dev",
            crd: CedarPolicy::crd(),
        },
        CrdDef {
            name: "dnsproviders.lattice.dev",
            crd: DNSProvider::crd(),
        },
        CrdDef {
            name: "certissuers.lattice.dev",
            crd: CertIssuer::crd(),
        },
        CrdDef {
            name: "latticequotas.lattice.dev",
            crd: LatticeQuota::crd(),
        },
    ]
}

/// CRDs needed only by Cluster mode
fn cluster_only_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "latticeclusters.lattice.dev",
            crd: LatticeCluster::crd(),
        },
        CrdDef {
            name: "infraproviders.lattice.dev",
            crd: InfraProvider::crd(),
        },
        CrdDef {
            name: "secretproviders.lattice.dev",
            crd: SecretProvider::crd(),
        },
        CrdDef {
            name: "oidcproviders.lattice.dev",
            crd: OIDCProvider::crd(),
        },
        CrdDef {
            name: "imageproviders.lattice.dev",
            crd: ImageProvider::crd(),
        },
        CrdDef {
            name: "latticeclusterroutes.lattice.dev",
            crd: LatticeClusterRoutes::crd(),
        },
        CrdDef {
            name: "tetragoninstalls.lattice.dev",
            crd: TetragonInstall::crd(),
        },
        CrdDef {
            name: "esoinstalls.lattice.dev",
            crd: ESOInstall::crd(),
        },
        CrdDef {
            name: "certmanagerinstalls.lattice.dev",
            crd: CertManagerInstall::crd(),
        },
        CrdDef {
            name: "volcanoinstalls.lattice.dev",
            crd: VolcanoInstall::crd(),
        },
        CrdDef {
            name: "ciliuminstalls.lattice.dev",
            crd: CiliumInstall::crd(),
        },
        CrdDef {
            name: "istioinstalls.lattice.dev",
            crd: IstioInstall::crd(),
        },
        CrdDef {
            name: "metricsserverinstalls.lattice.dev",
            crd: MetricsServerInstall::crd(),
        },
        CrdDef {
            name: "veleroinstalls.lattice.dev",
            crd: VeleroInstall::crd(),
        },
        CrdDef {
            name: "kedainstalls.lattice.dev",
            crd: KedaInstall::crd(),
        },
    ]
}

/// CRDs needed only by Service mode
fn service_only_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "latticeservices.lattice.dev",
            crd: LatticeService::crd(),
        },
        CrdDef {
            name: "backupstores.lattice.dev",
            crd: BackupStore::crd(),
        },
        CrdDef {
            name: "latticeclusterbackups.lattice.dev",
            crd: LatticeClusterBackup::crd(),
        },
        CrdDef {
            name: "latticerestores.lattice.dev",
            crd: LatticeRestore::crd(),
        },
        CrdDef {
            name: "latticemeshmembers.lattice.dev",
            crd: LatticeMeshMember::crd(),
        },
        CrdDef {
            name: "latticejobs.lattice.dev",
            crd: LatticeJob::crd(),
        },
        CrdDef {
            name: "latticemodels.lattice.dev",
            crd: LatticeModel::crd(),
        },
        CrdDef {
            name: "latticepackages.lattice.dev",
            crd: LatticePackage::crd(),
        },
    ]
}

/// Every Lattice CRD manifest as JSON, regardless of operator mode.
///
/// Used by out-of-process tooling (`lattice uninstall`) that needs Lattice CRDs
/// applied to a bare kind cluster without running the full operator. Keeps the
/// CRD list single-sourced with `ensure_cluster_crds`/`ensure_service_crds`.
pub fn all_crd_manifests() -> Vec<String> {
    let mut all = common_crds();
    all.extend(cluster_only_crds());
    all.extend(service_only_crds());
    all.into_iter()
        .map(|def| serde_json::to_string(&def.crd).expect("serialize CRD"))
        .collect()
}

/// Install a set of CRDs using server-side apply
async fn install_crds(client: &Client, crds_to_install: Vec<CrdDef>) -> anyhow::Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-operator").force();

    for def in crds_to_install {
        tracing::info!("Installing {} CRD...", def.name);
        crds.patch(def.name, &params, &Patch::Apply(&def.crd))
            .await
            .map_err(|e| anyhow::anyhow!("failed to install {} CRD: {}", def.name, e))?;
    }

    Ok(())
}

/// Ensure CRDs needed by Cluster mode are installed
pub async fn ensure_cluster_crds(client: &Client) -> anyhow::Result<()> {
    tracing::info!("Installing Cluster mode CRDs...");
    let mut all = common_crds();
    all.extend(cluster_only_crds());
    install_crds(client, all).await?;
    tracing::info!("Cluster mode CRDs installed/updated");
    Ok(())
}

/// Ensure CRDs needed by Service mode are installed
pub async fn ensure_service_crds(client: &Client) -> anyhow::Result<()> {
    tracing::info!("Installing Service mode CRDs...");
    let mut all = common_crds();
    all.extend(service_only_crds());
    install_crds(client, all).await?;
    tracing::info!("Service mode CRDs installed/updated");
    Ok(())
}
